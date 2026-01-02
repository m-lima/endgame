mod types;

macro_rules! attempt {
    ($value: expr, $name: ident, $problem: literal) => {
        match $value {
            Some(value) => value,
            None => {
                return crate::ffi::types::Error::new(concat!(
                    "Parameter `",
                    stringify!($name),
                    "` is ",
                    $problem
                ))
            }
        }
    };
    (url $name: ident) => {
        attempt!(ok url::Url::parse(as_str!($name)), $name, "not a valid URL")
    };
    (ok $value: expr, $name: ident, $problem: literal) => {
        attempt!(
            $value
                .map_err(|err| {
                    eprintln!(
                        concat!(
                            env!("CARGO_CRATE_NAME"),
                            ": Error while parsing `",
                            stringify!($name),
                            "`: {:?}"
                        ),
                        err
                    )
                })
                .ok(),
            $name,
            $problem
        )
    };
    (ret $value: expr, $ret: ident, $problem: literal) => {
        match $value {
            Ok(value) => {
                *$ret = value;
                Error::none()
            }
            Err(error) => {
                eprintln!(
                    concat!(env!("CARGO_CRATE_NAME"), ": ", $problem, ": {:?}"),
                    error
                );
                Error::new($problem)
            }
        }
    };
}

macro_rules! as_str {
    ($value: ident) => {{
        let value = attempt!($value.as_option(), $value, "null");
        let value = attempt!(ok
            str::from_utf8(value),
            $value,
            "not valid UTF-8"
        );
        let value = value.trim();
        attempt!(
            (!value.is_empty()).then_some(value),
            $value,
            "empty"
        )
    }};
}

macro_rules! check_null {
    ($value: ident) => {
        attempt!($value.ptr.is_null().then_some(()), $value, "null");
    };
    ($value: ident $($rest: ident) *) => {{
        check_null!($value);
        check_null!($($rest) *);
    }};
}

mod conf {
    use super::types::{Error, Key, ngx_str_t};
    use crate::oidc;

    #[unsafe(no_mangle)]
    pub extern "C" fn endgame_conf_load_key(path: ngx_str_t, key: &mut Key) -> Error {
        let path = std::path::PathBuf::from(as_str!(path));
        if !path.exists() {
            return Error::new("Path does not exist");
        }

        let Ok(mut file) = std::fs::File::open(path) else {
            return Error::new("Could not open path");
        };

        let mut bytes = 0;
        while bytes < key.bytes.len() {
            match std::io::Read::read(&mut file, &mut key.bytes[bytes..]) {
                Ok(0) => return Error::new("Key is not large enough. Need 32 bytes"),
                Err(_) => return Error::new("Could not read file"),
                Ok(b) => bytes += b,
            }
        }

        match std::io::Read::read(&mut file, &mut [0; 1]) {
            Ok(0) => Error::none(),
            Ok(_) => Error::new("Key is too large. Need 32 bytes"),
            Err(_) => Error::new("Could not read file"),
        }
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn endgame_conf_oidc_discover(
        discovery_url: ngx_str_t,
        oidc_id: &mut usize,
    ) -> Error {
        attempt!(ret oidc::discover(as_str!(discovery_url)), oidc_id, "Could not discover OIDC configuration")
    }
}

mod auth {
    use super::types::{Error, Key, RustSlice, ngx_str_t};
    use crate::{oidc, types::Timestamp};

    macro_rules! make_uri {
        ($host: ident, $path: ident) => {{
            let host = as_str!($host);
            let path = as_str!($path);
            match url::Url::parse(&format!("https://{host}{path}")) {
                Ok(url) => url,
                Err(error) => {
                    eprintln!(
                        concat!(
                            env!("CARGO_CRATE_NAME"),
                            ": The constructed redirect URL is not valid: {:?}"
                        ),
                        error
                    );
                    return Error::new("The constructed redirect URL is not valid");
                }
            }
        }};
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn endgame_auth_redirect_login_url(
        key: Key,
        oidc_id: usize,
        client_id: ngx_str_t,
        callback_url: ngx_str_t,
        redirect_host: ngx_str_t,
        redirect_path: ngx_str_t,
        auth_url: &mut RustSlice,
    ) -> Error {
        check_null!(auth_url);
        let client_id = as_str!(client_id);
        let callback_url = attempt!(url callback_url);
        let redirect = make_uri!(redirect_host, redirect_path);

        attempt!(
            ret
            oidc::get_redirect_login_url(
                key.bytes,
                oidc_id,
                client_id,
                &callback_url,
                redirect,
            ).map(|url| url.to_string().into()),
            auth_url,
            "Failed to create authentication URL"
        )
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn endgame_auth_exchange_token(
        query: ngx_str_t,
        key: Key,
        oidc_id: usize,
        client_id: ngx_str_t,
        client_secret: ngx_str_t,
        // callback_host: ngx_str_t,
        // callback_path: ngx_str_t,
        callback_url: ngx_str_t,
    ) -> Error {
        let query = as_str!(query);
        let client_id = as_str!(client_id);
        let client_secret = as_str!(client_secret);
        // let callback = make_uri!(callback_host, callback_path);
        let callback = attempt!(url callback_url);
        // TODO
        let _ = oidc::exchange_code(
            query,
            key.bytes,
            oidc_id,
            client_id,
            client_secret,
            callback,
        );
        Error::new("yoooooo")
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn endgame_token_decrypt(
        key: Key,
        src: ngx_str_t,
        max_age_secs: u64,
        email: &mut RustSlice,
        given_name: &mut RustSlice,
        family_name: &mut RustSlice,
    ) -> Error {
        check_null!(email given_name family_name);

        let Some(src) = src.as_option() else {
            return Error::new("Source is null");
        };

        let min_timestamp = Timestamp::now() - max_age_secs;

        if let Some(token) = oidc::token::decrypt(key.bytes, src, min_timestamp) {
            *email = token.email.into();
            *given_name = token.given_name.map_or(RustSlice::none(), RustSlice::from);
            *family_name = token.family_name.map_or(RustSlice::none(), RustSlice::from);
        }

        Error::none()
    }
}
