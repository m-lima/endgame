use crate::{dencrypt, types};

type OidcClient = openidconnect::core::CoreClient<
    openidconnect::EndpointSet,
    openidconnect::EndpointNotSet,
    openidconnect::EndpointNotSet,
    openidconnect::EndpointNotSet,
    openidconnect::EndpointMaybeSet,
    openidconnect::EndpointMaybeSet,
>;

static OIDC_CLIENTS: std::sync::LazyLock<
    std::sync::RwLock<std::collections::HashMap<u64, OidcClient>>,
> = std::sync::LazyLock::new(|| std::sync::RwLock::new(std::collections::HashMap::new()));
static CLIENT: std::sync::LazyLock<openidconnect::reqwest::blocking::Client> =
    std::sync::LazyLock::new(|| {
        openidconnect::reqwest::blocking::ClientBuilder::new()
            .redirect(openidconnect::reqwest::redirect::Policy::none())
            .build()
            .expect("Could not create HTTP client")
    });

pub fn discover(
    issuer: &openidconnect::IssuerUrl,
    client_id: openidconnect::ClientId,
    client_secret: openidconnect::ClientSecret,
    redirect: openidconnect::RedirectUrl,
) -> Option<u64> {
    let mut hasher = std::hash::DefaultHasher::new();
    std::hash::Hash::hash(issuer.as_bytes(), &mut hasher);
    std::hash::Hash::hash(client_id.as_bytes(), &mut hasher);
    std::hash::Hash::hash(redirect.as_bytes(), &mut hasher);
    let key = std::hash::Hasher::finish(&hasher).saturating_add(1);

    let mut clients = OIDC_CLIENTS.write().ok()?;
    if clients.contains_key(&key) {
        return Some(key);
    }

    let metadata = openidconnect::core::CoreProviderMetadata::discover(issuer, &*CLIENT).ok()?;

    let client = openidconnect::core::CoreClient::from_provider_metadata(
        metadata,
        client_id,
        Some(client_secret),
    )
    .set_redirect_uri(redirect);

    clients.insert(key, client);

    Some(key)
}

fn build_state(redirect: openidconnect::url::Url) -> types::State {
    let mut nonce = [0; 32];
    rand::RngCore::fill_bytes(&mut rand::rng(), &mut nonce);
    let timestamp = types::Timestamp::now();

    types::State::new(nonce, timestamp, redirect)
}

pub fn get_auth_url(
    key: crypter::Key,
    id: u64,
    redirect_url: openidconnect::url::Url,
) -> Option<openidconnect::url::Url> {
    let state = build_state(redirect_url);
    let nonce = base64::Engine::encode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        state.nonce,
    );
    let state = dencrypt::encrypt(key, &state)?;

    let clients = OIDC_CLIENTS.read().ok()?;
    let client = clients.get(&id)?;
    let (url, _, _) = client
        .authorize_url(
            openidconnect::core::CoreAuthenticationFlow::AuthorizationCode,
            || openidconnect::CsrfToken::new(state),
            || openidconnect::Nonce::new(nonce),
        )
        .add_scopes([
            openidconnect::Scope::new(String::from("email")),
            openidconnect::Scope::new(String::from("profile")),
        ])
        .url();
    Some(url)
}

pub fn exchange_code(key: crypter::Key, id: u64, url: &str) -> Option<openidconnect::url::Url> {
    const FIVE_MINUTES: u64 = 60 * 5;

    let url = openidconnect::url::Url::parse(url).ok()?;
    let mut query = url.query_pairs();

    let state = query
        .find_map(|(k, v)| (k == "state").then_some(v))
        .and_then(|s| dencrypt::decrypt::<types::State>(key, s.as_bytes()))
        .filter(|s| s.timestamp >= types::Timestamp::now() - FIVE_MINUTES)?;
    let code = query
        .find_map(|(k, v)| (k == "code").then_some(v))
        .map(String::from)
        .map(openidconnect::AuthorizationCode::new)?;

    let clients = OIDC_CLIENTS.read().ok()?;
    let client = clients.get(&id)?;

    let token = client.exchange_code(code).ok()?.request(&*CLIENT).ok()?;
    let nonce = openidconnect::Nonce::new(base64::Engine::encode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        state.nonce,
    ));
    token
        .extra_fields()
        .id_token()?
        .claims(&client.id_token_verifier(), &nonce)
        .ok()?;
    Some(state.redirect)
}
