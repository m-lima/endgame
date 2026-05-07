mod types;

#[derive(Debug, serde::Deserialize)]
struct Jwt {
    iss: url::Url,
    nonce: String,
    email: String,
    given_name: Option<String>,
    family_name: Option<String>,
    picture: Option<String>,
}

pub enum Error {
    MissingConfiguration,
    Encryption,
    Exchange(ExchangeError),
}

impl Error {
    fn response<T>(_: T) -> Self {
        Self::Exchange(ExchangeError::Response)
    }

    fn request(err: reqwest::Error) -> Self {
        Self::Exchange(ExchangeError::Request(err))
    }

    fn jwt(msg: &'static str) -> Self {
        Self::Exchange(ExchangeError::Jwt(msg))
    }
}

pub enum ExchangeError {
    Response,
    Request(reqwest::Error),
    Jwt(&'static str),
}

struct Requester {
    client: reqwest::Client,
    rt: tokio::runtime::Runtime,
}

// Here, we build the runtime
// It needs to live in the worker process, so that it can share memory with nginx
// This is important for, e.g., allocating `ngx_str_t`s
static REQUESTER: std::sync::LazyLock<Requester> = std::sync::LazyLock::new(|| Requester {
    client: reqwest::ClientBuilder::new()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(60))
        .build()
        .expect("Could not create HTTP client"),

    rt: tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .expect("Could not build async runtime"),
});

pub fn get_redirect_login_url(
    master_key: crypter::Key,
    oidc_id: usize,
    oidc_signature: u32,
    redirect: url::Url,
    select_account: bool,
) -> Result<url::Url, Error> {
    let configs = super::CONFIGS.borrow();
    let config = configs
        .get(oidc_id)
        .filter(|c| c.signature == oidc_signature)
        .ok_or(Error::MissingConfiguration)?;

    let state = {
        let mut nonce = [0; 32];
        rand::RngCore::fill_bytes(&mut rand::rng(), &mut nonce);
        let timestamp = endgame::types::Timestamp::now();

        types::State::new(nonce, timestamp, redirect, oidc_id, oidc_signature)
    };
    let nonce = base64::Engine::encode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        state.nonce,
    );
    let state = endgame::dencrypt::encrypt(master_key, &state).ok_or(Error::Encryption)?;

    let mut url = config.idp.authorization_endpoint.clone();
    url.query_pairs_mut()
        .append_pair("client_id", config.client_id)
        .append_pair("response_type", "code")
        .append_pair("scope", "openid email profile")
        .append_pair("redirect_uri", config.client_callback_url.as_str())
        .append_pair("state", &state)
        .append_pair("nonce", &nonce);

    if select_account {
        url.query_pairs_mut()
            .append_pair("prompt", "select_account");
    }

    Ok(url)
}

pub fn exchange_token<F: 'static + Send + FnOnce(Result<(String, url::Url), Error>)>(
    query: &str,
    master_key: crypter::Key,
    finalizer: F,
) -> Result<(), ()> {
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

    let state = get_param(query, "state")
        .and_then(|s| endgame::dencrypt::decrypt::<types::State>(master_key, s.as_bytes()))
        .filter(|s| {
            s.timestamp >= endgame::types::Timestamp::now() - std::time::Duration::from_secs(60)
        })
        .ok_or(())?;

    let code = get_param(query, "code")
        .map(|c| percent_encoding::percent_decode(c.as_bytes()).collect::<Vec<_>>())
        .and_then(|c| String::from_utf8(c).ok())
        .ok_or(())?;

    REQUESTER
        .rt
        .spawn(async { finalizer(async_exchange(state, code).await) });

    Ok(())
}

async fn async_exchange(state: types::State, code: String) -> Result<(String, url::Url), Error> {
    let configs = super::CONFIGS.borrow();
    let config = configs
        .get(state.oidc_id)
        .filter(|c| c.signature == state.oidc_signature)
        .ok_or(Error::MissingConfiguration)?;

    let jwt = get_id_token(code, config).await?;
    let jwt = decode_jwt(&jwt, config)?;

    let nonce = base64::Engine::encode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        state.nonce,
    );

    if jwt.iss != config.idp.issuer {
        return Err(Error::jwt("Issuer mismatch"));
    }
    if jwt.nonce != nonce {
        return Err(Error::jwt("Nonce mismatch"));
    }
    if jwt.email.trim().is_empty() {
        return Err(Error::jwt("Email is empty"));
    }

    make_cookie(jwt, config).map(|cookie| (cookie, state.redirect))
}

async fn get_id_token(code: String, config: &super::OidcConfig) -> Result<String, Error> {
    #[derive(Debug, serde::Deserialize)]
    struct Response {
        id_token: String,
    }

    #[derive(Debug, serde::Serialize)]
    struct Request<'a> {
        code: String,
        client_id: &'a str,
        client_secret: &'a str,
        redirect_uri: &'a url::Url,
        grant_type: &'static str,
    }

    let request = Request {
        code,
        client_id: config.client_id,
        client_secret: config.client_secret,
        redirect_uri: &config.client_callback_url,
        grant_type: "authorization_code",
    };

    REQUESTER
        .client
        .post(config.idp.token_endpoint.clone())
        .form(&request)
        .send()
        .await
        .map_err(Error::request)?
        .error_for_status()
        .map_err(Error::response)?
        .json::<Response>()
        .await
        .map_err(Error::response)
        .map(|r| r.id_token)
}

fn decode_jwt(token: &str, config: &super::OidcConfig) -> Result<Jwt, Error> {
    let Ok(header) = jsonwebtoken::decode_header(token) else {
        return Err(Error::jwt("Could not decode jwt header"));
    };
    let Some(kid) = header.kid else {
        return Err(Error::jwt("No kid in header"));
    };

    let Some(jwk) = config.idp.jwks.find(&kid) else {
        return Err(Error::jwt("Could not find known kid"));
    };

    let mut validation = jsonwebtoken::Validation::new(header.alg);
    validation.set_audience(&[config.client_id]);
    validation.validate_exp = true;

    jsonwebtoken::decode(token, jwk, &validation)
        .map(|t| t.claims)
        .map_err(|_| Error::jwt("Failed validation"))
}

fn make_cookie(jwt: Jwt, config: &super::OidcConfig) -> Result<String, Error> {
    let cookie = endgame::dencrypt::encrypt(
        config.key,
        &endgame::types::Token {
            timestamp: endgame::types::Timestamp::now() + config.session_ttl,
            email: jwt.email,
            given_name: jwt.given_name,
            family_name: jwt.family_name,
            picture: jwt.picture,
        },
    )
    .ok_or(Error::Encryption)?;

    let session_domain = config
        .session_domain
        .as_ref()
        .map_or_else(String::new, |d| format!("Domain={d};"));

    Ok(format!(
        "{session_name}={cookie};Path=/;{session_domain}Max-Age={session_ttl};Secure;HttpOnly;SameSite=lax",
        session_name = config.session_name,
        session_ttl = config.session_ttl.as_secs(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    pub fn random_array<const L: usize>() -> [u8; L] {
        let mut value = [0; L];
        rand::RngCore::fill_bytes(&mut rand::rng(), &mut value);
        value
    }

    #[test]
    fn state_round_trip() {
        let state = types::State {
            nonce: random_array(),
            timestamp: endgame::types::Timestamp::now(),
            redirect: url::Url::parse("http://localhost").unwrap(),
            oidc_id: usize::from_ne_bytes(random_array()),
            oidc_signature: rand::random(),
        };

        let key = random_array();

        let encrypted = endgame::dencrypt::encrypt(key, &state).unwrap();
        let decrypted =
            endgame::dencrypt::decrypt::<types::State>(key, encrypted.as_bytes()).unwrap();

        assert_eq!(state, decrypted);
    }
}
