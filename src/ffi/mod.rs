mod types;

use crate::{oidc, token, types::Timestamp};
use types::{Error, Key, RustSlice, ngx_str_t};

macro_rules! attempt {
    ($value: expr, $name: expr, $problem: literal) => {
        match $value {
            Some(value) => value,
            None => return Error::new(concat!("Parameter `", $name, "` is ", $problem)),
        }
    };
}

macro_rules! as_str {
    ($value: ident) => {{
        let value = attempt!($value.as_option(), stringify!($value), "null");
        let value = attempt!(
            str::from_utf8(value).ok(),
            stringify!($value),
            "not valid UTF-8"
        );
        let value = value.trim();
        attempt!(
            (!value.is_empty()).then_some(value),
            stringify!($value),
            "empty"
        )
    }};
}

macro_rules! as_string {
    ($value: ident) => {
        String::from(as_str!($value))
    };
}

macro_rules! check_null {
    ($value: ident) => {
        attempt!($value.ptr.is_null().then_some(()), stringify!($value), "null");
    };
    ($value: ident $($rest: ident) *) => {{
        check_null!($value);
        check_null!($($rest) *);
    }};
}

#[unsafe(no_mangle)]
pub extern "C" fn endgame_load_key(path: ngx_str_t, key: &mut Key) -> Error {
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

    if let Some(token) = token::decrypt(key.bytes, src, min_timestamp) {
        *email = token.email.into();
        *given_name = token.given_name.map_or(RustSlice::none(), RustSlice::from);
        *family_name = token.family_name.map_or(RustSlice::none(), RustSlice::from);
    }

    Error::none()
}

#[unsafe(no_mangle)]
pub extern "C" fn endgame_oidc_discover(
    discovery_url: ngx_str_t,
    client_id: ngx_str_t,
    client_secret: ngx_str_t,
    callback_url: ngx_str_t,
    oidc_id: &mut u64,
) -> Error {
    let discovery_url = attempt!(
        openidconnect::IssuerUrl::new(as_string!(discovery_url)).ok(),
        "discovery_url",
        "not a valid URL"
    );
    let client_id = openidconnect::ClientId::new(as_string!(client_id));
    let client_secret = openidconnect::ClientSecret::new(as_string!(client_secret));
    let callback_url = attempt!(
        openidconnect::RedirectUrl::new(as_string!(callback_url)).ok(),
        "callback_url",
        "not a valid URL"
    );

    match oidc::discover(&discovery_url, client_id, client_secret, callback_url) {
        Some(id) => {
            *oidc_id = id;
            Error::none()
        }
        None => Error::new("Could not discover OIDC configuration"),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn endgame_oidc_get_url(
    key: Key,
    id: u64,
    redirect_host: ngx_str_t,
    redirect_uri: ngx_str_t,
    auth_url: &mut RustSlice,
) -> Error {
    check_null!(auth_url);
    let redirect_host = as_str!(redirect_host);
    let redirect_uri = as_str!(redirect_uri);
    let Ok(redirect) =
        openidconnect::url::Url::parse(&format!("https://{redirect_host}{redirect_uri}"))
    else {
        return Error::new("The constructed redirect URL is not valid");
    };
    match oidc::get_auth_url(key.bytes, id, redirect) {
        Some(url) => {
            *auth_url = url.to_string().into();
            Error::none()
        }
        None => Error::new("Failed to create authentication URL"),
    }
}
