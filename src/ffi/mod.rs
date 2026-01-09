mod types;

mod conf {
    use super::types::{EndgameKey, EndgameOidc, ngx_str_t};
    use crate::oidc::config as oidc;

    macro_rules! bail {
        ($err: literal) => {
            return $err.as_ptr().cast_mut()
        };
        ($err: literal, $msg: literal, $reason: expr) => {{
            log_err!($msg, $reason);
            bail!($err);
        }};
    }

    macro_rules! as_str {
        ($value: ident) => {{
            let Some(value) = $value.as_option() else {
                bail!(c"is null");
            };
            let Ok(value) = str::from_utf8(value) else {
                bail!(c"is not valid UTF-8");
            };
            let value = value.trim();
            if value.is_empty() {
                bail!(c"is empty");
            }
            value
        }};
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn endgame_conf_clear() {
        oidc::clear();
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn endgame_conf_random_key() -> EndgameKey {
        let mut key = EndgameKey {
            bytes: Default::default(),
        };
        rand::RngCore::fill_bytes(&mut rand::rng(), &mut key.bytes);
        key
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn endgame_conf_load_key(
        path: ngx_str_t,
        key: &mut EndgameKey,
    ) -> *mut libc::c_char {
        let path = std::path::PathBuf::from(as_str!(path));
        if !path.exists() {
            bail!(c"does not exist");
        }

        let mut file = match std::fs::File::open(path) {
            Ok(file) => file,
            Err(e) => bail!(c"is unreadable", "Could not open path", e),
        };

        let mut bytes = 0;
        while bytes < key.bytes.len() {
            match std::io::Read::read(&mut file, &mut key.bytes[bytes..]) {
                Err(e) => bail!(c"is unreadable", "Could not read file", e),
                Ok(0) => bail!(c"is not large enough. Need 32 bytes"),
                Ok(b) => bytes += b,
            }
        }

        match std::io::Read::read(&mut file, &mut [0; 1]) {
            Ok(0) => std::ptr::null_mut(),
            Ok(_) => bail!(c"is too large. Need 32 bytes"),
            Err(e) => bail!(c"is unreadable", "Could not read file", e),
        }
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn endgame_conf_push(
        key: EndgameKey,
        discovery_url: ngx_str_t,
        session_name: ngx_str_t,
        session_ttl: u64,
        session_domain: ngx_str_t,
        client_id: ngx_str_t,
        client_secret: ngx_str_t,
        client_callback_url: ngx_str_t,
        oidc_ref: &mut EndgameOidc,
    ) -> *mut libc::c_char {
        let discovery_url = as_str!(discovery_url);
        let session_name = as_str!(session_name);
        let session_domain = as_str!(session_domain);
        let client_id = as_str!(client_id);
        let client_secret = as_str!(client_secret);
        let client_callback_url = as_str!(client_callback_url);

        match oidc::push(
            key.bytes,
            discovery_url,
            session_name,
            session_ttl,
            session_domain,
            client_id,
            client_secret,
            client_callback_url,
        ) {
            Ok((id, signature)) => {
                oidc_ref.id = id;
                oidc_ref.signature = signature;
                std::ptr::null_mut()
            }
            // TODO: Check how these errors will print
            Err(oidc::Error::BadUrl(err)) => {
                bail!(
                    c"does not have a valid URL for client_callback_url",
                    "Could not parse the URL",
                    err
                )
            }
            Err(oidc::Error::UrlNotAbsolute) => {
                bail!(c"does not have an absolute URL for client_callback_url")
            }
            Err(oidc::Error::Request(err)) => {
                bail!(
                    c"could not fetch client_callback_url",
                    "Failed to make request",
                    err
                )
            }
            Err(oidc::Error::BadIssuer(left, right)) => {
                bail!(
                    c"does not match the discovered issuer",
                    "Mismatched issuer",
                    format!("{left} != {right}")
                )
            }
        }
    }
}

mod runtime {
    use super::types::{EndgameError, EndgameKey, ngx_str_t};
    use crate::{dencrypt, types};

    macro_rules! bail {
        ($name: ident, $problem: literal) => {
            return crate::ffi::types::EndgameError::new(
                500,
                concat!("Parameter `", stringify!($name), "` is ", $problem),
            )
        };
    }

    macro_rules! attempt {
        (if $check: expr, $name: ident, $problem: literal) => {
            if !$check {
                bail!($name, $problem);
            }
        };
        (or $value: expr, $name: ident, $problem: literal) => {
            match $value {
                Some(value) => value,
                None => bail!($name, $problem),
            }
        };
        (ok $value: expr, $name: ident, $problem: literal) => {
            match $value {
                Ok(value) => value,
                Err(err) => {
                    log_err!(
                        concat!("Error while parsing `", stringify!($name), "`"),
                        err
                    );
                    bail!($name, $problem);
                }
            }
        };
    }

    macro_rules! arg {
        (bytes $value:ident) => {
            attempt!(or $value.as_option(), $value, "null")
        };
        (str $value:ident) => {{
            let value = arg!(bytes $value);
            let value = attempt!(ok str::from_utf8(value), $value, "not valid UTF-8");
            value
        }};
        (url $value: ident) => {
            attempt!(ok url::Url::parse(arg!(str $value)), $value, "not a valid URL")
        };
    }

    macro_rules! to_str {
        ($value: expr, $pool: ident) => {
            match ngx_str_t::copy($value, $pool) {
                Some(v) => v,
                None => return EndgameError::new(500, "Failed to allocate return value"),
            }
        };
        (opt $value: expr, $pool: ident) => {
            match $value {
                Some(v) => to_str!(v, $pool),
                None => ngx_str_t::none(),
            }
        };
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn endgame_auth_redirect_login_url(
        master_key: EndgameKey,
        oidc_ref: super::types::EndgameOidc,
        redirect_host: ngx_str_t,
        redirect_path: ngx_str_t,
        login_url: &mut ngx_str_t,
        pool: *mut libc::c_void,
    ) -> EndgameError {
        use crate::oidc::runtime::redirect as oidc;

        let redirect = {
            let host = arg!(str redirect_host);
            let path = arg!(str redirect_path);
            match url::Url::parse(&format!("https://{host}{path}")) {
                Ok(url) => url,
                Err(err) => {
                    log_err!("The constructed redirect URL is not valid", err);
                    return EndgameError::new(500, "The constructed redirect URL is not valid");
                }
            }
        };

        match oidc::get_redirect_login_url(
            master_key.bytes,
            oidc_ref.id,
            oidc_ref.signature,
            redirect,
        ) {
            Ok(url) => {
                *login_url = to_str!(url, pool);
                EndgameError::none()
            }
            Err(oidc::Error::MissingConfiguration) => {
                EndgameError::new(500, "Missing OIDC configuration for redirection")
            }
            Err(oidc::Error::Encryption) => EndgameError::new(500, "Failed to encrypt state"),
        }
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn endgame_auth_exchange_token(
        master_key: EndgameKey,
        query: ngx_str_t,
        request: *const libc::c_void,
        pipe: std::os::fd::RawFd,
        pool: *mut libc::c_void,
    ) -> EndgameError {
        use super::types::EndgameResult;
        use crate::oidc::runtime::code as oidc;

        let request = request as usize;
        let pool = pool as usize;
        let finalizer = move |result: Result<(String, url::Url), oidc::FutureError>| {
            let request = request as _;
            let pool = pool as _;

            let payload = match result {
                Ok((cookie, redirect)) => {
                    // TODO: Do we need to make this last longer so that we can use a login hint?
                    if let Some((cookie, redirect)) = ngx_str_t::copy(cookie, pool)
                        .and_then(|c| ngx_str_t::copy(redirect, pool).map(|r| (c, r)))
                    {
                        EndgameResult {
                            request,
                            status: 0,
                            cookie,
                            redirect,
                        }
                    } else {
                        log_err!("Failed to allocate return value");
                        EndgameResult {
                            request,
                            status: 500,
                            cookie: ngx_str_t::none(),
                            redirect: ngx_str_t::none(),
                        }
                    }
                }
                Err(err) => {
                    let status = match err {
                        oidc::FutureError::MissingConfiguration => {
                            log_err!("Missing OIDC configuration for code exchange");
                            500
                        }
                        oidc::FutureError::Request(error) => {
                            log_err!("Failed to make request to code exchange endpoint", error);
                            500
                        }
                        oidc::FutureError::Response => 401,
                        oidc::FutureError::Encryption => {
                            log_err!("Failed to encrypt cookie");
                            500
                        }
                    };
                    EndgameResult {
                        request,
                        status,
                        cookie: ngx_str_t::none(),
                        redirect: ngx_str_t::none(),
                    }
                }
            };

            let data = std::ptr::from_ref(&payload).cast();
            unsafe { libc::write(pipe, data, size_of::<EndgameResult>()) };
        };

        let query = arg!(str query);

        match oidc::exchange(query, master_key.bytes, finalizer) {
            Ok(()) => EndgameError::none(),
            Err(_) => EndgameError::no_msg(400),
        }
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn endgame_token_decrypt(
        key: EndgameKey,
        src: ngx_str_t,
        email: &mut ngx_str_t,
        given_name: &mut ngx_str_t,
        family_name: &mut ngx_str_t,
        pool: *mut libc::c_void,
    ) -> EndgameError {
        macro_rules! nullify {
            ($value: ident) => {
                if !$value.is_null() {
                    *$value = ngx_str_t::none();
                }
            };
        }
        nullify!(email);
        nullify!(given_name);
        nullify!(family_name);

        let src = arg!(bytes src);

        if let Some(token) = dencrypt::decrypt::<types::Token>(key.bytes, src)
            .filter(|t| t.timestamp >= types::Timestamp::now())
        {
            *email = to_str!(token.email, pool);
            *given_name = to_str!(opt token.given_name, pool);
            *family_name = to_str!(opt token.family_name, pool);
        }

        EndgameError::none()
    }
}
