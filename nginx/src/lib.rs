#![warn(clippy::pedantic)]
#![allow(clippy::missing_errors_doc)]

macro_rules! log_err {
    ($msg: expr, $err: expr) => {
        eprintln!(
            concat!("[", env!("CARGO_CRATE_NAME"), "] ", $msg, ": {}"),
            $err
        )
    };
    ($msg: expr) => {
        eprintln!(concat!("[", env!("CARGO_CRATE_NAME"), "] ", $msg))
    };
}

mod config;
mod ffi;
mod runtime;

#[repr(transparent)]
#[derive(Debug, Clone)]
struct Jwks(Vec<Jwk>);

impl Jwks {
    fn find(&self, kid: &str) -> Option<&jsonwebtoken::DecodingKey> {
        self.0.iter().find(|Jwk(k, _)| k == kid).map(|Jwk(_, k)| k)
    }
}

impl TryFrom<jsonwebtoken::jwk::JwkSet> for Jwks {
    type Error = config::Error;

    fn try_from(value: jsonwebtoken::jwk::JwkSet) -> Result<Self, Self::Error> {
        let this = value
            .keys
            .into_iter()
            .filter_map(|mut jwk| jwk.common.key_id.take().map(|kid| (kid, jwk)))
            .map(|(kid, jwk)| (&jwk).try_into().map(|key| Jwk(kid, key)))
            .collect::<Result<_, _>>()
            .map_err(|_| Self::Error::Jwt("Could not generate decoding key"))
            .map(Self)?;

        if this.0.is_empty() {
            Err(Self::Error::Jwt("No valid JWK present"))
        } else {
            Ok(this)
        }
    }
}

#[derive(Debug, Clone)]
struct Jwk(String, jsonwebtoken::DecodingKey);

#[derive(Debug)]
struct DiscoveryDocument {
    issuer: url::Url,
    authorization_endpoint: url::Url,
    token_endpoint: url::Url,
    jwks: Jwks,
}

#[derive(Debug)]
struct OidcConfig {
    signature: u32,
    key: crypter::Key,
    idp: std::sync::Arc<DiscoveryDocument>,
    session_name: &'static str,
    session_ttl: std::time::Duration,
    session_domain: Option<&'static str>,
    client_id: &'static str,
    client_secret: &'static str,
    client_callback_url: url::Url,
}

impl OidcConfig {
    // allow(clippy::too_many_arguments): I'm creating this to avoid passing too many args
    #[allow(clippy::too_many_arguments)]
    fn new(
        key: crypter::Key,
        idp: std::sync::Arc<DiscoveryDocument>,
        session_name: &'static str,
        session_ttl: std::time::Duration,
        session_domain: Option<&'static str>,
        client_id: &'static str,
        client_secret: &'static str,
        client_callback_url: url::Url,
    ) -> Self {
        Self {
            signature: rand::random(),
            key,
            idp,
            session_name,
            session_ttl,
            session_domain,
            client_id,
            client_secret,
            client_callback_url,
        }
    }
}

static CONFIGS: atomic_refcell::AtomicRefCell<Vec<OidcConfig>> =
    atomic_refcell::AtomicRefCell::new(Vec::new());
