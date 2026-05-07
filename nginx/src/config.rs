pub enum Error {
    BadUrl(url::ParseError),
    UrlNotAbsolute,
    Request(Box<dyn std::error::Error>),
    BadIssuer(String, String),
    Jwt(&'static str),
}

pub fn clear() {
    let mut configs = super::CONFIGS.borrow_mut();
    configs.clear();
}

// allow(clippy::too_many_arguments): With the reference, these args will never be sent again
#[allow(clippy::too_many_arguments)]
pub(crate) fn push(
    key: crypter::Key,
    discovery_url: &str,
    session_name: &'static str,
    session_ttl: u64,
    session_domain: Option<&'static str>,
    client_id: &'static str,
    client_secret: &'static str,
    client_callback_url: &'static str,
) -> Result<(usize, u32), Error> {
    const DISCOVERY_SUFFIX: &str = "/.well-known/openid-configuration";

    let discovery_url = if discovery_url.ends_with(DISCOVERY_SUFFIX) {
        url::Url::parse(discovery_url)
    } else {
        let url = discovery_url.strip_suffix('/').unwrap_or(discovery_url);
        let url = format!("{url}{DISCOVERY_SUFFIX}");
        url::Url::parse(&url)
    }
    .map_err(Error::BadUrl)?;

    let mut issuer = discovery_url.clone();
    issuer
        .path_segments_mut()
        .map_err(|()| Error::UrlNotAbsolute)?
        .pop()
        .pop();
    let mut configs = super::CONFIGS.borrow_mut();

    let session_ttl = std::time::Duration::from_secs(session_ttl);
    let client_callback_url = url::Url::parse(client_callback_url).map_err(Error::BadUrl)?;

    if let Some(idx) = configs.iter().position(|c| {
        c.key == key
            && c.idp.issuer == issuer
            && c.session_name == session_name
            && c.session_ttl == session_ttl
            && c.session_domain == session_domain
            && c.client_id == client_id
            && c.client_secret == client_secret
            && c.client_callback_url == client_callback_url
    }) {
        // Safety: I just got this index now
        return Ok((idx, unsafe { configs.get_unchecked(idx).signature }));
    }

    let idp = if let Some(config) = configs.iter().find(|c| c.idp.issuer == issuer) {
        config.idp.clone()
    } else {
        discover(discovery_url).map(std::sync::Arc::new)?
    };

    if idp.issuer != issuer {
        return Err(Error::BadIssuer(idp.issuer.to_string(), issuer.to_string()));
    }

    let config = super::OidcConfig::new(
        key,
        idp,
        session_name,
        session_ttl,
        session_domain,
        client_id,
        client_secret,
        client_callback_url,
    );
    let id = configs.len();
    let signature = config.signature;
    configs.push(config);

    Ok((id, signature))
}

fn discover(discovery_url: url::Url) -> Result<super::DiscoveryDocument, Error> {
    macro_rules! bad_request {
        ($msg: literal) => {{
            |e| {
                log_err!($msg, e);
                Error::Request(Box::new(e))
            }
        }};
    }

    #[derive(Debug, serde::Deserialize)]
    struct RawDiscoveryDocument {
        issuer: url::Url,
        authorization_endpoint: url::Url,
        token_endpoint: url::Url,
        jwks_uri: url::Url,
    }

    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(bad_request!("tokio"))?
        .block_on(async {
            let client = reqwest::ClientBuilder::new()
                .timeout(std::time::Duration::from_secs(60))
                .build()
                .map_err(bad_request!("build"))?;

            let discovery_document = client
                .get(discovery_url)
                .send()
                .await
                .map_err(bad_request!("send discovery request"))?
                .json::<RawDiscoveryDocument>()
                .await
                .map_err(bad_request!("receive discovery document"))?;

            let jwks = client
                .get(discovery_document.jwks_uri)
                .send()
                .await
                .map_err(bad_request!("send jwks request"))?
                .json::<jsonwebtoken::jwk::JwkSet>()
                .await
                .map_err(bad_request!("receive jwks"))?;

            jwks.try_into().map(|jwks| super::DiscoveryDocument {
                issuer: discovery_document.issuer,
                authorization_endpoint: discovery_document.authorization_endpoint,
                token_endpoint: discovery_document.token_endpoint,
                jwks,
            })
        })
}
