mod types;

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

mod conf {
    use super::types::{Key, ngx_str_t};
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
    pub extern "C" fn endgame_conf_load_key(path: ngx_str_t, key: &mut Key) -> *mut libc::c_char {
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
    pub extern "C" fn endgame_conf_oidc_discover(
        discovery_url: ngx_str_t,
        oidc_id: &mut usize,
    ) -> *mut libc::c_char {
        let discovery_url = as_str!(discovery_url);

        match oidc::discover(discovery_url) {
            Ok(id) => {
                *oidc_id = id;
                std::ptr::null_mut()
            }
            Err(oidc::Error::BadUrl(err)) => {
                bail!(c"is not a valid URL", "Could not parse the URL", err)
            }
            Err(oidc::Error::UrlNotAbsolute) => {
                bail!(c"is not an absolute URL")
            }
            Err(oidc::Error::Request(err)) => {
                bail!(c"could not be fetched", "Failed to make request", err)
            }
            Err(oidc::Error::BadIssuer(left, right)) => {
                bail!(
                    c"does no match the discovered issuer",
                    "Mismatched issuer",
                    format!("{left} != {right}")
                )
            }
        }
    }
}

mod runtime {
    use super::types::{Error, Key, ngx_str_t};
    use crate::{dencrypt, types};

    macro_rules! bail {
        ($name: ident, $problem: literal) => {
            return crate::ffi::types::Error::new(
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
                None => return Error::new(500, "Failed to allocate return value"),
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
        key: Key,
        oidc_id: usize,
        client_id: ngx_str_t,
        callback_url: ngx_str_t,
        redirect_host: ngx_str_t,
        redirect_path: ngx_str_t,
        login_url: &mut ngx_str_t,
        pool: *mut libc::c_void,
    ) -> Error {
        use crate::oidc::runtime::redirect as oidc;

        let client_id = arg!(str client_id);
        let callback_url = arg!(url callback_url);
        let redirect = {
            let host = arg!(str redirect_host);
            let path = arg!(str redirect_path);
            match url::Url::parse(&format!("https://{host}{path}")) {
                Ok(url) => url,
                Err(err) => {
                    log_err!("The constructed redirect URL is not valid", err);
                    return Error::new(500, "The constructed redirect URL is not valid");
                }
            }
        };

        match oidc::get_redirect_login_url(key.bytes, oidc_id, client_id, &callback_url, redirect) {
            Ok(url) => {
                *login_url = to_str!(url, pool);
                Error::none()
            }
            Err(oidc::Error::MissingConfiguration) => {
                Error::new(500, "Missing OIDC configuration for redirection")
            }
            Err(oidc::Error::Encryption) => Error::new(500, "Failed to encrypt state"),
        }
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn endgame_auth_exchange_token(
        query: ngx_str_t,
        key: Key,
        oidc_id: usize,
        client_id: ngx_str_t,
        client_secret: ngx_str_t,
        callback_url: ngx_str_t,
        session_name: ngx_str_t,
        session_domain: ngx_str_t,
        session_ttl: i64,
        request: *const libc::c_void,
        pipe: std::os::fd::RawFd,
        pool: *mut libc::c_void,
    ) -> Error {
        use super::types::LoginResult;
        use crate::oidc::runtime::code as oidc;

        let session_name = arg!(str session_name);
        let session_domain = arg!(str session_domain);
        let request = request as usize;
        let pool = pool as usize;
        let finalizer = move |result: Result<(String, url::Url), oidc::FutureError>| {
            let request = request as _;
            let pool = pool as _;

            let payload = match result {
                Ok((cookie, redirect)) => {
                    let cookie = if session_domain.is_empty() {
                        format!(
                            "{session_name}={cookie};Path=/;Max-Age={session_ttl};Secure;HttpOnly;SameSite=lax"
                        )
                    } else {
                        format!(
                            "{session_name}={cookie};Path=/;Domain={session_domain};Max-Age={session_ttl};Secure;HttpOnly;SameSite=lax"
                        )
                    };
                    if let Some((cookie, redirect)) = ngx_str_t::copy(cookie, pool)
                        .and_then(|c| ngx_str_t::copy(redirect, pool).map(|r| (c, r)))
                    {
                        LoginResult {
                            request,
                            status: 0,
                            cookie,
                            redirect,
                        }
                    } else {
                        log_err!("Failed to allocate return value");
                        LoginResult {
                            request,
                            status: 500,
                            cookie: ngx_str_t::none(),
                            redirect: ngx_str_t::none(),
                        }
                    }
                }
                Err(err) => {
                    let status = match err {
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
                    LoginResult {
                        request,
                        status,
                        cookie: ngx_str_t::none(),
                        redirect: ngx_str_t::none(),
                    }
                }
            };

            let data = std::ptr::from_ref(&payload).cast();
            unsafe { libc::write(pipe, data, size_of::<LoginResult>()) };
        };

        let query = arg!(str query);
        let client_id = arg!(str client_id);
        let client_secret = arg!(str client_secret);
        let callback = arg!(url callback_url);

        match oidc::exchange(
            query,
            key.bytes,
            oidc_id,
            client_id,
            client_secret,
            callback,
            finalizer,
        ) {
            Ok(()) => Error::none(),
            Err(oidc::Error::MissingConfiguration) => {
                Error::new(500, "Missing OIDC configuration for redirection")
            }
            Err(oidc::Error::BadQueryParam) => Error::no_msg(400),
        }
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn endgame_token_decrypt(
        key: Key,
        src: ngx_str_t,
        max_age_secs: u64,
        email: &mut ngx_str_t,
        given_name: &mut ngx_str_t,
        family_name: &mut ngx_str_t,
        pool: *mut libc::c_void,
    ) -> Error {
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

        let min_timestamp = types::Timestamp::now() - max_age_secs;

        if let Some(token) = dencrypt::decrypt::<types::Token>(key.bytes, src)
            .filter(|t| t.timestamp >= min_timestamp)
        {
            *email = to_str!(token.email, pool);
            *given_name = to_str!(opt token.given_name, pool);
            *family_name = to_str!(opt token.family_name, pool);
        }

        Error::none()
    }
}
