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

// TODO: Check that the memory stays consistent (even on reload)
#[derive(Debug, serde::Deserialize)]
struct OidcConfig {
    signature: u32,
    key: crypter::Key,
    issuer: url::Url,
    authorization_endpoint: url::Url,
    token_endpoint: url::Url,
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
        issuer: url::Url,
        authorization_endpoint: url::Url,
        token_endpoint: url::Url,
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
            issuer,
            authorization_endpoint,
            token_endpoint,
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
