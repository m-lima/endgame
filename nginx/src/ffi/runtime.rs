use super::{
    super::runtime as oidc,
    types::{EndgameError, EndgameKey, EndgameResult, ngx_str_t, ngx_table_elt_t},
};

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
    redirect: ngx_str_t,
    select_account: bool,
    login_url: &mut ngx_str_t,
    pool: *mut libc::c_void,
) -> EndgameError {
    let redirect = arg!(url redirect);

    match oidc::get_redirect_login_url(
        master_key.bytes,
        oidc_ref.id,
        oidc_ref.signature,
        redirect,
        select_account,
    ) {
        Ok(url) => {
            *login_url = to_str!(url, pool);
            EndgameError::none()
        }
        Err(oidc::Error::MissingConfiguration) => {
            EndgameError::new(500, "Missing OIDC configuration for redirection")
        }
        Err(oidc::Error::Encryption) => EndgameError::new(500, "Failed to encrypt state"),
        Err(oidc::Error::Exchange(_)) => unreachable!(),
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
                    oidc::Error::Encryption => {
                        log_err!("Failed to encrypt cookie");
                        500
                    }
                    oidc::Error::Exchange(oidc::ExchangeError::Response) => 401,
                    oidc::Error::Exchange(oidc::ExchangeError::Request(error)) => {
                        log_err!("Failed to make request to code exchange endpoint", error);
                        500
                    }
                    oidc::Error::Exchange(oidc::ExchangeError::Jwt(error)) => {
                        log_err!("Failed to validate JWT", error);
                        401
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
        Err(()) => EndgameError::no_msg(400),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn endgame_token_decrypt(
    key: EndgameKey,
    cookies: &ngx_table_elt_t,
    name: ngx_str_t,
    email: &mut ngx_str_t,
    given_name: &mut ngx_str_t,
    family_name: &mut ngx_str_t,
    picture: &mut ngx_str_t,
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
    nullify!(picture);

    let name = arg!(bytes name);
    let mut cookies = Some(cookies);

    while let Some(cookie_line) = cookies {
        let Some(cookie_bytes) = cookie_line.value() else {
            continue;
        };

        for cookie in cookie_bytes.split(|b| *b == b';') {
            let Some(cookie) = extract_cookie(name, cookie) else {
                continue;
            };

            if let Some(token) =
                endgame::dencrypt::decrypt::<endgame::types::Token>(key.bytes, cookie)
                    .filter(|t| t.timestamp >= endgame::types::Timestamp::now())
            {
                *email = to_str!(token.email, pool);
                *given_name = to_str!(opt token.given_name, pool);
                *family_name = to_str!(opt token.family_name, pool);
                *picture = to_str!(opt token.picture, pool);
                break;
            }
        }
        cookies = cookie_line.next();
    }

    EndgameError::none()
}

fn extract_cookie<'c>(name: &[u8], cookie: &'c [u8]) -> Option<&'c [u8]> {
    let cookie = cookie.trim_ascii_start();
    if cookie.len() <= name.len() || !cookie[..name.len()].eq_ignore_ascii_case(name) {
        return None;
    }

    let mut cookie = &cookie[name.len()..];
    while !cookie.is_empty() {
        if cookie[0].is_ascii_whitespace() {
            cookie = &cookie[1..];
        } else if cookie[0] == b'=' {
            cookie = &cookie[1..];
            break;
        } else {
            return None;
        }
    }

    let cookie = cookie.trim_ascii_start();
    if cookie.is_empty() {
        None
    } else {
        Some(cookie)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_empty() {
        assert_eq!(extract_cookie(b"name", b""), None);
    }

    #[test]
    fn extract_wrong_name() {
        assert_eq!(extract_cookie(b"name", b"namer=123"), None);
    }

    #[test]
    fn extract_simple() {
        assert_eq!(extract_cookie(b"name", b"name=123"), Some("123".as_bytes()));
    }

    #[test]
    fn extract_trim() {
        assert_eq!(
            extract_cookie(b"name", b" 	name	 =	 123	 "),
            Some("123	 ".as_bytes())
        );
    }
}
