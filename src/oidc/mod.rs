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
            () => {
                |e| Error::Request(Box::new(e))
            };
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

        let body = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(bad_request!())?
            .block_on(async {
                let response = reqwest::ClientBuilder::new()
                    .timeout(std::time::Duration::from_secs(60))
                    .build()
                    .map_err(bad_request!())?
                    .get(discovery_url)
                    .send()
                    .await
                    .map_err(bad_request!())?;
                let body = response.bytes().await.map_err(bad_request!())?;
                Result::Ok(body)
            })?;

        let config =
            serde_json::from_slice::<super::DiscoveryDocument>(&body).map_err(bad_request!())?;
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
                .append_pair("nonce", &nonce)
                .append_pair("access_type", "offline");

            Ok(url)
        }
    }

    pub mod code {
        use crate::{dencrypt, types};

        struct Requester {
            client: reqwest::Client,
            rt: tokio::runtime::Runtime,
        }

        static REQUESTER: std::sync::LazyLock<Requester> = std::sync::LazyLock::new(|| {
            let layer = treetrace::Layer::builder(treetrace::Stderr).build();
            let subscriber = tracing_subscriber::layer::SubscriberExt::with(
                tracing_subscriber::registry(),
                layer,
            );
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

        pub enum Error {
            MissingConfiguration,
            BadQueryParam,
        }

        pub fn exchange(
            query: &str,
            key: crypter::Key,
            oidc_id: usize,
            client_id: &str,
            client_secret: &str,
            callback: url::Url,
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

            let _state = get_param(query, "state")
                .and_then(|s| dencrypt::decrypt::<types::State>(key, s.as_bytes()))
                .filter(|s| s.timestamp >= types::Timestamp::now() - FIVE_MINUTES)
                .ok_or(Error::BadQueryParam)?;

            let code = get_param(query, "code")
                .map(|c| percent_encoding::percent_decode(c.as_bytes()).collect::<Vec<_>>())
                .and_then(|c| String::from_utf8(c).ok())
                .ok_or(Error::BadQueryParam)?;

            let configs = super::super::CONFIGS.borrow();
            let config = configs.get(oidc_id).ok_or(Error::MissingConfiguration)?;

            let endpoint = config.token_endpoint.clone();

            REQUESTER.rt.spawn(future::exchange(
                endpoint,
                code,
                String::from(client_id),
                String::from(client_secret),
                callback,
            ));

            Ok(())
        }

        mod future {
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
                refresh_token: Option<String>,
            }

            #[derive(Debug, serde::Deserialize)]
            struct Jwt {
                iss: String,
                expires_in: u64,
                nonce: String,
                email: String,
                given_name: Option<String>,
                family_name: Option<String>,
            }

            pub async fn exchange(
                endpoint: url::Url,
                code: String,
                client_id: String,
                client_secret: String,
                redirect_uri: url::Url,
            ) {
                let payload = Request {
                    code,
                    client_id,
                    client_secret,
                    redirect_uri,
                    grant_type: "authorization_code",
                };

                tracing::info!(token = ?payload, "Will exchange token");
                let response = match super::REQUESTER
                    .client
                    .post(endpoint)
                    .form(&payload)
                    .send()
                    .await
                {
                    Ok(r) => r,
                    Err(error) => {
                        tracing::error!(?error, "Failed to call endpoint");
                        todo!()
                        // return Err(error.into());
                    }
                };
                let body = match response.bytes().await {
                    Ok(r) => r,
                    Err(error) => {
                        tracing::error!(?error, "Failed to get bytes");
                        todo!()
                        // return Err(error.into());
                    }
                };
                let token = match serde_json::from_slice::<Response>(&body) {
                    Ok(r) => r,
                    Err(error) => {
                        tracing::error!(?error, "Failed to parse");
                        tracing::warn!(body = %String::from_utf8_lossy(&body), "Original body");
                        todo!()
                        // return Err(error.into());
                    }
                };
                tracing::info!("Exchanged token: {token:?}");
            }

            fn decode_jwt(token: &str) -> Jwt {
                let payload = token.split('.').nth(1).unwrap();
                let payload = base64::Engine::decode(
                    &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                    payload,
                )
                .unwrap();
                serde_json::from_slice(&payload).unwrap()
            }
        }
    }
}
