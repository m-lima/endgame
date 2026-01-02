pub mod token;

use crate::{dencrypt, types};

type Result<T = ()> = anyhow::Result<T>;

struct Requester {
    client: reqwest::Client,
    rt: tokio::runtime::Runtime,
}

static REQUESTER: std::sync::LazyLock<Requester> = std::sync::LazyLock::new(|| Requester {
    client: reqwest::ClientBuilder::new()
        .redirect(openidconnect::reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(5 * 60))
        .build()
        .expect("Could not create HTTP client"),

    rt: tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("Could not build async runtime"),
});

static CONFIGS: atomic_refcell::AtomicRefCell<Vec<DiscoveryDocument>> =
    atomic_refcell::AtomicRefCell::new(Vec::new());

pub fn discover(discovery_url: &str) -> Result<usize> {
    const DISCOVERY_SUFFIX: &str = "/.well-known/openid-configuration";

    let discovery_url = if discovery_url.ends_with(DISCOVERY_SUFFIX) {
        url::Url::parse(discovery_url)
    } else {
        let url = discovery_url.strip_suffix('/').unwrap_or(discovery_url);
        let url = format!("{url}{DISCOVERY_SUFFIX}");
        url::Url::parse(&url)
    }?;

    let mut issuer = discovery_url.clone();
    issuer
        .path_segments_mut()
        .map_err(|()| anyhow::anyhow!("URL for discovery is not complete"))?
        .pop()
        .pop();

    let mut configs = CONFIGS.borrow_mut();
    if let Some(idx) = configs.iter().position(|c| c.issuer == issuer) {
        return Ok(idx);
    }

    let body = REQUESTER.rt.block_on(async {
        let response = REQUESTER
            .client
            .get(discovery_url)
            .timeout(std::time::Duration::from_secs(60))
            .send()
            .await?;
        let body = response.bytes().await?;
        Result::Ok(body)
    })?;

    let config = serde_json::from_slice::<DiscoveryDocument>(&body)?;
    if config.issuer != issuer {
        anyhow::bail!(
            "Issuer ({}) did not match the provided discovery URL ({issuer})",
            config.issuer
        );
    }

    let idx = configs.len();
    configs.push(config);

    Ok(idx)
}

pub fn get_redirect_login_url(
    key: crypter::Key,
    oidc_id: usize,
    client_id: &str,
    callback: &url::Url,
    redirect: url::Url,
) -> Result<openidconnect::url::Url> {
    let state = {
        let mut nonce = [0; 32];
        rand::RngCore::fill_bytes(&mut rand::rng(), &mut nonce);
        let timestamp = types::Timestamp::now();

        types::State::new(nonce, timestamp, redirect)
    };
    let nonce = base64::Engine::encode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        state.nonce,
    );
    let state = dencrypt::encrypt(key, &state)?;

    let configs = CONFIGS.borrow();
    let config = configs
        .get(oidc_id)
        .ok_or_else(|| anyhow::anyhow!("No configuration found for OIDC id {oidc_id}"))?;

    let mut url = config.authorization_endpoint.clone();
    url.query_pairs_mut()
        .append_pair("client_id", client_id)
        .append_pair("response_type", "code")
        .append_pair("scope", "openid email profile")
        .append_pair("redirect_uri", callback.as_str())
        .append_pair("state", &state)
        .append_pair("nonce", &nonce);

    Ok(url)
}

pub fn exchange_code(
    query: &str,
    key: crypter::Key,
    oidc_id: usize,
    client_id: &str,
    client_secret: &str,
    callback: url::Url,
) -> Result<Option<openidconnect::url::Url>> {
    fn get_param<'q>(query: &'q str, param: &str) -> Option<&'q str> {
        query
            .split('&')
            .filter_map(|p| p.strip_prefix(param))
            .find_map(|p| {
                if p.is_empty() {
                    Some("")
                } else {
                    p.strip_prefix('=')
                }
            })
    }

    // TODO
    const FIVE_MINUTES: u64 = 60 * 5 * 100_000;

    eprintln!("Will parse: {query}");
    eprintln!("Will get state");
    let Some(state) = get_param(query, "state")
        .and_then(|s| dencrypt::decrypt::<types::State>(key, s.as_bytes()))
        .filter(|s| s.timestamp >= types::Timestamp::now() - FIVE_MINUTES)
    else {
        return Ok(None);
    };
    eprintln!("State {state:?}");
    eprintln!("Will get code");
    let Some(code) = get_param(query, "code") else {
        return Ok(None);
    };
    eprintln!("Code {code:?}");

    eprintln!("Will get config");
    let configs = CONFIGS.borrow();
    let config = configs
        .get(oidc_id)
        .ok_or_else(|| anyhow::anyhow!("No configuration found for OIDC id {oidc_id}"))?;
    eprintln!("Got config");

    eprintln!("Will exchange token");
    let body = REQUESTER.rt.block_on(async {
        let response = REQUESTER
            .client
            .post(config.token_endpoint.clone())
            .form(&TokenExchange {
                code,
                client_id,
                client_secret,
                callback_uri: callback,
                grant_type: "authorization_code",
            })
            .send()
            .await?;
        let body = response.bytes().await?;
        Result::Ok(body)
    })?;
    let token = serde_json::from_slice::<TokenExchangeResponse>(&body)?;

    eprintln!("TOKEN:{token:?}");

    // TODO
    // let token = client.exchange_code(code).ok()?.request(&*CLIENT).ok();
    // eprintln!("Sent");
    // let token = token?;
    // let nonce = openidconnect::Nonce::new(base64::Engine::encode(
    //     &base64::engine::general_purpose::URL_SAFE_NO_PAD,
    //     state.nonce,
    // ));
    // eprintln!("Exchanged token. Nonce {nonce:?}");
    // eprintln!("Will get id token");
    // let id_token = token
    //     .extra_fields()
    //     .id_token()?
    //     .claims(&client.id_token_verifier(), &nonce)
    //     .ok()?;
    // let email = id_token.email();
    // let given_name = id_token.given_name();
    // let family_name = id_token.family_name();
    //
    // let refresh_token = openidconnect::OAuth2TokenResponse::refresh_token(&token);
    // let expiration = types::Timestamp::now()
    //     + openidconnect::OAuth2TokenResponse::expires_in(&token).map_or(3600, |d| d.as_secs());
    //
    // eprintln!("EMAIL:      {email:?}");
    // eprintln!("GIVEN:      {given_name:?}");
    // eprintln!("FAMILY:     {family_name:?}");
    // eprintln!("TOKEN:      {refresh_token:?}");
    // eprintln!("EXPIRATION: {expiration:?}");
    // eprintln!();
    // eprintln!("TOKEN:      {token:?}");
    // eprintln!("ID_TOKEN:   {id_token:?}");

    Ok(Some(state.redirect))
}

#[derive(Debug, serde::Deserialize)]
struct DiscoveryDocument {
    issuer: url::Url,
    authorization_endpoint: url::Url,
    token_endpoint: url::Url,
    // TODO
    // jwks_uri: url::Url,
}

#[derive(Debug, serde::Serialize)]
struct TokenExchange<'a> {
    code: &'a str,
    client_id: &'a str,
    client_secret: &'a str,
    callback_uri: url::Url,
    grant_type: &'static str,
}

#[derive(Debug, serde::Deserialize)]
// TODO
#[allow(unused)]
struct TokenExchangeResponse {
    access_token: String,
    exipers_in: u32,
    id_token: String,
    token_type: String,
    refresh_token: Option<String>,
}
