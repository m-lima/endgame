pub enum Error {
    BadUrl(url::ParseError),
    UrlNotAbsolute,
    Request(Box<dyn std::error::Error>),
    BadIssuer(String, String),
}

#[derive(Debug, serde::Deserialize)]
struct DiscoveryDocument {
    issuer: url::Url,
    authorization_endpoint: url::Url,
    token_endpoint: url::Url,
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
    session_name: &str,
    session_ttl: u64,
    session_domain: &str,
    client_id: &str,
    client_secret: &str,
    client_callback_url: &str,
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

    let session_domain = if session_domain.is_empty() {
        None
    } else {
        Some(String::from(session_domain))
    };

    let client_callback_url = url::Url::parse(client_callback_url).map_err(Error::BadUrl)?;

    // TODO: Check that these match
    if let Some(idx) = configs.iter().position(|c| {
        c.key == key
            && c.issuer == issuer
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

    // TODO: Don't call discover if the issuer matches
    let config = discover(discovery_url)?;

    if config.issuer != issuer {
        return Err(Error::BadIssuer(
            config.issuer.to_string(),
            issuer.to_string(),
        ));
    }

    let config = super::OidcConfig::new(
        key,
        issuer,
        config.authorization_endpoint,
        config.token_endpoint,
        String::from(session_name),
        session_ttl,
        session_domain,
        String::from(client_id),
        String::from(client_secret),
        client_callback_url,
    );
    let id = configs.len();
    let signature = config.signature;
    configs.push(config);

    Ok((id, signature))
}

fn discover(discovery_url: url::Url) -> Result<DiscoveryDocument, Error> {
    macro_rules! bad_request {
        ($msg: literal) => {{
            |e| {
                eprintln!(concat!($msg, ": {:?}"), e);
                Error::Request(Box::new(e))
            }
        }};
    }

    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(bad_request!("tokio"))?
        .block_on(async {
            reqwest::ClientBuilder::new()
                .timeout(std::time::Duration::from_secs(60))
                .build()
                .map_err(bad_request!("build"))?
                .get(discovery_url)
                .send()
                .await
                .map_err(bad_request!("send"))?
                .json::<DiscoveryDocument>()
                .await
                .map_err(bad_request!("send"))
        })
}
