#[derive(Debug, serde::Deserialize)]
struct DiscoveryDocument {
    issuer: url::Url,
    authorization_endpoint: url::Url,
    token_endpoint: url::Url,
}

static CONFIGS: atomic_refcell::AtomicRefCell<Vec<DiscoveryDocument>> =
    atomic_refcell::AtomicRefCell::new(Vec::new());

pub mod config {
    pub enum Error {
        BadUrl(url::ParseError),
        UrlNotAbsolute,
        Request(Box<dyn std::error::Error>),
        BadIssuer(String, String),
    }

    pub fn discover(discovery_url: &str) -> Result<usize, Error> {
        macro_rules! bad_request {
            ($msg: literal) => {{
                |e| {
                    eprintln!(concat!($msg, ": {:?}"), e);
                    Error::Request(Box::new(e))
                }
            }};
        }

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
        if let Some(idx) = configs.iter().position(|c| c.issuer == issuer) {
            return Ok(idx);
        }

        let config = tokio::runtime::Builder::new_current_thread()
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
                    .json::<super::DiscoveryDocument>()
                    .await
                    .map_err(bad_request!("send"))
            })?;

        if config.issuer != issuer {
            return Err(Error::BadIssuer(
                config.issuer.to_string(),
                issuer.to_string(),
            ));
        }

        let idx = configs.len();
        configs.push(config);

        Ok(idx)
    }
}

pub mod runtime {
    pub mod redirect {
        use crate::{dencrypt, types};

        pub enum Error {
            MissingConfiguration,
            Encryption,
        }

        pub fn get_redirect_login_url(
            key: crypter::Key,
            oidc_id: usize,
            client_id: &str,
            callback: &url::Url,
            redirect: url::Url,
        ) -> Result<url::Url, Error> {
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
            let state = dencrypt::encrypt(key, &state).ok_or(Error::Encryption)?;

            let configs = super::super::CONFIGS.borrow();
            let config = configs.get(oidc_id).ok_or(Error::MissingConfiguration)?;

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
    }

    pub mod code {
        use crate::{dencrypt, types};

        struct Requester {
            client: reqwest::Client,
            rt: tokio::runtime::Runtime,
        }

        // Here, we build the runtime
        // It needs to live in the worker process, so that it can share memory with nginx
        // This is important for, e.g., allocating `ngx_str_t`s
        static REQUESTER: std::sync::LazyLock<Requester> = std::sync::LazyLock::new(|| {
            let layer = treetrace::Layer::builder(treetrace::Stderr).build();
            let subscriber = tracing_subscriber::layer::SubscriberExt::with(
                tracing_subscriber::registry(),
                layer,
            );
            tracing::subscriber::set_global_default(subscriber).unwrap();

            Requester {
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
            }
        });

        pub enum Error {
            MissingConfiguration,
            BadQueryParam,
        }

        pub use future::Error as FutureError;

        pub fn exchange<F: 'static + Send + FnOnce(Result<(String, url::Url), future::Error>)>(
            query: &str,
            key: crypter::Key,
            oidc_id: usize,
            client_id: &str,
            client_secret: &str,
            callback: url::Url,
            finalizer: F,
        ) -> Result<(), Error> {
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

            let state = get_param(query, "state")
                .and_then(|s| dencrypt::decrypt::<types::State>(key, s.as_bytes()))
                .filter(|s| s.timestamp >= types::Timestamp::now() - FIVE_MINUTES)
                .ok_or(Error::BadQueryParam)?;

            let code = get_param(query, "code")
                .map(|c| percent_encoding::percent_decode(c.as_bytes()).collect::<Vec<_>>())
                .and_then(|c| String::from_utf8(c).ok())
                .ok_or(Error::BadQueryParam)?;

            let configs = super::super::CONFIGS.borrow();
            let config = configs.get(oidc_id).ok_or(Error::MissingConfiguration)?;

            // TODO
            // let endpoint = config.token_endpoint.clone();
            let endpoint = url::Url::parse("http://127.0.0.1/auth/ok").unwrap();
            let issuer = config.issuer.clone();

            REQUESTER.rt.spawn(future::exchange(
                key,
                endpoint,
                code,
                String::from(client_id),
                String::from(client_secret),
                callback,
                state.nonce,
                issuer,
                state.redirect,
                finalizer,
            ));

            Ok(())
        }

        mod future {
            use super::{dencrypt, types};

            #[derive(Debug, serde::Serialize)]
            struct Request {
                code: String,
                client_id: String,
                client_secret: String,
                redirect_uri: url::Url,
                grant_type: &'static str,
            }

            #[derive(Debug, serde::Deserialize)]
            struct Response {
                id_token: String,
            }

            #[derive(Debug, serde::Deserialize)]
            struct Jwt {
                iss: url::Url,
                nonce: String,
                email: String,
                given_name: Option<String>,
                family_name: Option<String>,
            }

            // allow(clippy::too_many_arguments): need to pass the whole context
            #[allow(clippy::too_many_arguments)]
            pub async fn exchange<F: FnOnce(Result<(String, url::Url), Error>)>(
                key: crypter::Key,
                endpoint: url::Url,
                code: String,
                client_id: String,
                client_secret: String,
                callback: url::Url,
                nonce: [u8; 32],
                issuer: url::Url,
                redirect: url::Url,
                finalizer: F,
            ) {
                let request = Request {
                    code,
                    client_id,
                    client_secret,
                    redirect_uri: callback,
                    grant_type: "authorization_code",
                };

                finalizer(exchange_fallible(key, endpoint, request, nonce, issuer, redirect).await);
            }

            pub enum Error {
                Request(reqwest::Error),
                Response,
                Encryption,
            }

            impl Error {
                fn response<T>(_: T) -> Self {
                    Self::Response
                }
            }

            async fn exchange_fallible(
                key: crypter::Key,
                endpoint: url::Url,
                request: Request,
                nonce: [u8; 32],
                issuer: url::Url,
                redirect: url::Url,
            ) -> Result<(String, url::Url), Error> {
                let response = super::REQUESTER
                    .client
                    .post(endpoint)
                    .form(&request)
                    .send()
                    .await
                    .map_err(Error::Request)?
                    .error_for_status()
                    .map_err(Error::response)?
                    .json::<Response>()
                    .await
                    .map_err(Error::response)?;

                let jwt = decode_jwt(&response.id_token)?;

                let nonce = base64::Engine::encode(
                    &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                    nonce,
                );

                if jwt.iss != issuer || jwt.nonce != nonce || jwt.email.trim().is_empty() {
                    Err(Error::Response)
                } else {
                    let token = types::Token {
                        timestamp: types::Timestamp::now(),
                        email: jwt.email,
                        given_name: jwt.given_name,
                        family_name: jwt.family_name,
                    };
                    dencrypt::encrypt(key, &token)
                        .map(|c| (c, redirect))
                        .ok_or(Error::Encryption)
                }
            }

            fn decode_jwt(token: &str) -> Result<Jwt, Error> {
                let payload = token.split('.').nth(1).ok_or(Error::Response)?;
                let payload = base64::Engine::decode(
                    &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                    payload,
                )
                .map_err(Error::response)?;
                serde_json::from_slice(&payload).map_err(Error::response)
            }
        }
    }
}
