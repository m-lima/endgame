use super::types::{EndgameError, EndgameKey, EndgameResult, ngx_str_t};
use crate::oidc::runtime as oidc;
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

    match oidc::get_redirect_login_url(master_key.bytes, oidc_ref.id, oidc_ref.signature, redirect)
    {
        Ok(url) => {
            *login_url = to_str!(url, pool);
            EndgameError::none()
        }
        Err(oidc::Error::MissingConfiguration) => {
            EndgameError::new(500, "Missing OIDC configuration for redirection")
        }
        Err(oidc::Error::Encryption) => EndgameError::new(500, "Failed to encrypt state"),
        Err(oidc::Error::Response | oidc::Error::Request(_)) => unreachable!(),
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
    let request = request as usize;
    let pool = pool as usize;
    let finalizer = move |result: Result<(String, url::Url), oidc::Error>| {
        let request = request as _;
        let pool = pool as _;

        let payload = match result {
            Ok((cookie, redirect)) => {
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
                    oidc::Error::MissingConfiguration => {
                        log_err!("Missing OIDC configuration for code exchange");
                        500
                    }
                    oidc::Error::Request(error) => {
                        log_err!("Failed to make request to code exchange endpoint", error);
                        500
                    }
                    oidc::Error::Response => 401,
                    oidc::Error::Encryption => {
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

    match oidc::exchange_token(query, master_key.bytes, finalizer) {
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
