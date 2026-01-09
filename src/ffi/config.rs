use super::types::{EndgameKey, EndgameOidc, ngx_str_t};
use crate::oidc::config as oidc;

macro_rules! bail {
    ($err: literal) => {
        return $err.as_ptr().cast_mut()
    };
    ($err: literal, $value: ident) => {
        return concat!($err, " ", stringify!($value), "\0")
            .as_ptr()
            .cast_mut()
            .cast()
    };
    ($err: literal, $msg: literal, $reason: expr) => {{
        log_err!($msg, $reason);
        bail!($err);
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
    let Some(path) = path.as_option() else {
        bail!(c"is null");
    };
    let Ok(path) = str::from_utf8(path) else {
        bail!(c"is not valid UTF-8");
    };
    let path = path.trim();
    if path.is_empty() {
        bail!(c"is empty");
    }
    let path = std::path::PathBuf::from(path);
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
    macro_rules! as_str {
        ($value: ident) => {{
            let Some(value) = $value.as_option() else {
                bail!("has null", $value);
            };
            let Ok(value) = str::from_utf8(value) else {
                bail!("has invalid UTF-8 for", $value);
            };
            let value = value.trim();
            if value.is_empty() {
                bail!("has empty", $value);
            }
            value
        }};
    }

    let discovery_url = as_str!(discovery_url);
    let session_name = as_str!(session_name);
    let client_id = as_str!(client_id);
    let client_secret = as_str!(client_secret);
    let client_callback_url = as_str!(client_callback_url);

    let session_domain = session_domain
        .as_option()
        .and_then(|s| str::from_utf8(s).ok())
        .map(str::trim)
        .filter(|s| !s.is_empty());

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
