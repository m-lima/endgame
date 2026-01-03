pub mod token;

use crate::{dencrypt, types};

type Result<T = ()> = anyhow::Result<T>;

// TODO: Categorize the errors here and remove anyhow
enum Error {
    BadConfig(Option<Box<dyn std::error::Error>>, &'static str),
    BadRequest,
    BadPayloadFromUpstream,
    NotAuthed,
}

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

    let body = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let response = reqwest::ClientBuilder::new()
                .timeout(std::time::Duration::from_secs(60))
                .build()?
                .get(discovery_url)
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
    struct Requester {
        client: reqwest::Client,
        rt: tokio::runtime::Runtime,
    }

    static REQUESTER: std::sync::LazyLock<Requester> = std::sync::LazyLock::new(|| {
        let layer = treetrace::Layer::builder(treetrace::Stderr).build();
        let subscriber =
            tracing_subscriber::layer::SubscriberExt::with(tracing_subscriber::registry(), layer);
        tracing::subscriber::set_global_default(subscriber).unwrap();

        Requester {
            client: reqwest::ClientBuilder::new()
                .redirect(openidconnect::reqwest::redirect::Policy::none())
                .timeout(std::time::Duration::from_secs(60))
                .build()
                .expect("Could not create HTTP client"),

            rt: tokio::runtime::Builder::new_multi_thread()
                .worker_threads(1)
                .enable_all()
                .build()
                .expect("Could not build async runtime"),
        }
    });

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

    let Some(state) = get_param(query, "state")
        .and_then(|s| dencrypt::decrypt::<types::State>(key, s.as_bytes()))
        .filter(|s| s.timestamp >= types::Timestamp::now() - FIVE_MINUTES)
    else {
        return Ok(None);
    };
    eprintln!("State {state:?}");
    let Some(code) = get_param(query, "code")
        .map(|c| percent_encoding::percent_decode(c.as_bytes()).collect::<Vec<_>>())
        .map(String::from_utf8)
    else {
        return Ok(None);
    };
    let code = code?;
    eprintln!("Code {code:?}");

    let configs = CONFIGS.borrow();
    let config = configs
        .get(oidc_id)
        .ok_or_else(|| anyhow::anyhow!("No configuration found for OIDC id {oidc_id}"))?;

    let payload = TokenExchange {
        code,
        client_id: String::from(client_id),
        client_secret: String::from(client_secret),
        redirect_uri: callback,
        grant_type: "authorization_code",
    };
    let endpoint = config.token_endpoint.clone();

    REQUESTER.rt.spawn(async move {
        tracing::info!(token = ?payload, "Will exchange token");
        let response = match REQUESTER.client.post(endpoint).form(&payload).send().await {
            Ok(r) => r,
            Err(error) => {
                tracing::error!(?error, "Failed to call endpoint");
                return Err(error.into());
            }
        };
        let body = match response.bytes().await {
            Ok(r) => r,
            Err(error) => {
                tracing::error!(?error, "Failed to get bytes");
                return Err(error.into());
            }
        };
        let token = match serde_json::from_slice::<TokenExchangeResponse>(&body) {
            Ok(r) => r,
            Err(error) => {
                tracing::error!(?error, "Failed to parse");
                tracing::warn!(body = %String::from_utf8_lossy(&body), "Original body");
                return Err(error.into());
            }
        };
        tracing::info!("Exchanged token: {token:?}");
        Result::Ok(body)
    });

    eprintln!("Exiting");

    Ok(Some(state.redirect))
}

fn decode_jwt(token: &str) -> JwtPayload {
    let payload = token.split('.').nth(1).unwrap();
    let payload =
        base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, payload).unwrap();
    serde_json::from_slice(&payload).unwrap()
}

#[derive(Debug, serde::Deserialize)]
struct DiscoveryDocument {
    issuer: url::Url,
    authorization_endpoint: url::Url,
    token_endpoint: url::Url,
}

#[derive(Debug, serde::Deserialize)]
struct JwtPayload {
    iss: String,
    email: String,
    given_name: Option<String>,
    family_name: Option<String>,
}

#[derive(Debug, serde::Serialize)]
struct TokenExchange {
    code: String,
    client_id: String,
    client_secret: String,
    redirect_uri: url::Url,
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
