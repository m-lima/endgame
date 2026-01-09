pub mod config;
pub mod runtime;

// TODO: Maybe not use String and use `ngx_str_t` (need to check if the worker will barf)
#[derive(Debug, serde::Deserialize)]
struct OidcConfig {
    signature: u32,
    key: crypter::Key,
    issuer: url::Url,
    authorization_endpoint: url::Url,
    token_endpoint: url::Url,
    session_name: String,
    session_ttl: std::time::Duration,
    session_domain: Option<String>,
    client_id: String,
    client_secret: String,
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
        session_name: String,
        session_ttl: std::time::Duration,
        session_domain: Option<String>,
        client_id: String,
        client_secret: String,
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
