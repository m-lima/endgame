mod types;

use crate::{dencrypt, oidc};
use types::{Error, Key, RustSlice, ngx_str_t};

#[unsafe(no_mangle)]
pub extern "C" fn endgame_decrypt(
    key: Key,
    src: ngx_str_t,
    max_age_secs: u64,
    email: &mut RustSlice,
    given_name: &mut RustSlice,
    family_name: &mut RustSlice,
) -> Error {
    if !email.ptr.is_null() {
        return Error::new("Email is not null");
    }

    if !given_name.ptr.is_null() {
        return Error::new("Given name is not null");
    }

    if !family_name.ptr.is_null() {
        return Error::new("Family name is not null");
    }

    let Some(src) = src.as_option() else {
        return Error::new("Source is null");
    };

    let Some(min_timestamp) = dencrypt::age_to_unix_epoch(max_age_secs) else {
        return Error::new("Could not create timestamp in Unix epoch");
    };

    if let Some(token) = dencrypt::decrypt(key.bytes, src).filter(|t| t.timestamp >= min_timestamp)
    {
        *email = token.email.into();
        *given_name = token.given_name.map_or(RustSlice::none(), RustSlice::from);
        *family_name = token.family_name.map_or(RustSlice::none(), RustSlice::from);
    }

    Error::none()
}

#[unsafe(no_mangle)]
pub extern "C" fn endgame_load_key(path: ngx_str_t, key: &mut Key) -> Error {
    let Some(path) = path.as_option() else {
        return Error::new("Path is null");
    };

    let Ok(path) = str::from_utf8(path) else {
        return Error::new("Path is not valid UTF-8");
    };

    let path = std::path::PathBuf::from(path);
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
pub extern "C" fn endgame_oidc_discover(
    issuer: ngx_str_t,
    client_id: ngx_str_t,
    client_secret: ngx_str_t,
    redirect_url: ngx_str_t,
) -> Error {
    macro_rules! as_str {
        ($value: ident) => {{
            let Some(value) = $value.as_option() else {
                return Error::new(concat!("Parameter `", stringify!($value), "` is null"));
            };
            let Ok(value) = str::from_utf8(value) else {
                return Error::new(concat!(
                    "Parameter `",
                    stringify!($value),
                    "` is not valid UTF-8"
                ));
            };
            value.trim()
        }};
        (url $value: ident) => {{
            let Ok(value) = openidconnect::url::Url::parse(as_str!($value)) else {
                return Error::new(concat!(
                    "Parameter `",
                    stringify!($value),
                    "` is not a valid URL"
                ));
            };
            value
        }};
    }

    let issuer = as_str!(url issuer);
    let client_id = as_str!(client_id);
    let client_secret = as_str!(client_secret);
    let redirect_url = as_str!(url redirect_url);

    if oidc::discover(issuer, client_id, client_secret, redirect_url).is_none() {
        Error::new("Could not discover OIDC configuration")
    } else {
        Error::none()
    }
}
