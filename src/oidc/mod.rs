use crate::types;

type OidcClient = openidconnect::core::CoreClient<
    openidconnect::EndpointSet,
    openidconnect::EndpointNotSet,
    openidconnect::EndpointNotSet,
    openidconnect::EndpointNotSet,
    openidconnect::EndpointMaybeSet,
    openidconnect::EndpointMaybeSet,
>;

static CLIENTS: std::sync::LazyLock<std::sync::RwLock<std::collections::HashMap<u64, OidcClient>>> =
    std::sync::LazyLock::new(|| std::sync::RwLock::new(std::collections::HashMap::new()));

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

    let mut clients = CLIENTS.write().ok()?;
    if clients.contains_key(&key) {
        return Some(key);
    }

    let client = openidconnect::reqwest::blocking::ClientBuilder::new()
        .redirect(openidconnect::reqwest::redirect::Policy::none())
        .build()
        .ok()?;

    let metadata = openidconnect::core::CoreProviderMetadata::discover(issuer, &client).ok()?;

    let client = openidconnect::core::CoreClient::from_provider_metadata(
        metadata,
        client_id,
        Some(client_secret),
    )
    .set_redirect_uri(redirect);

    clients.insert(key, client);

    Some(key)
}

fn build_state(redirect: String) -> types::State {
    const FIVE_MINUTES: u64 = 60 * 5;
    let mut nonce = [0; 32];
    rand::RngCore::fill_bytes(&mut rand::rng(), &mut nonce);
    let timestamp = types::Timestamp::now() + FIVE_MINUTES;

    types::State::new(nonce, timestamp, redirect)
}

pub fn get_auth_url(
    key: crypter::Key,
    id: u64,
    redirect_url: openidconnect::url::Url,
) -> Option<openidconnect::url::Url> {
    let clients = CLIENTS.read().ok()?;
    let client = clients.get(&id)?;
    let state = build_state(redirect_url.into());
    let nonce = base64::Engine::encode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        state.nonce(),
    );
    let state = crate::dencrypt::encrypt(key, &state)?;
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
