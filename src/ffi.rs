use crate::types::{CSlice, Error, RustError, RustSlice};

#[must_use]
#[unsafe(no_mangle)]
pub extern "C" fn endgame_encrypt(
    key: &Key,
    email: CSlice,
    given_name: CSlice,
    family_name: CSlice,
    dst: &mut RustSlice,
) -> Error {
    fn deref<'a>(slice: CSlice) -> Option<&'a [u8]> {
        slice
            .as_option()
            .map(<[u8]>::trim_ascii)
            .filter(|s| !s.is_empty())
    }

    if !dst.ptr.is_null() {
        return Error::new("Destination is not null");
    }

    let Some(email) = deref(email) else {
        return Error::new("Email is null");
    };

    match crate::core::encrypt(
        &key.bytes,
        email,
        deref(given_name),
        deref(family_name),
        None,
    ) {
        Ok(payload) => {
            *dst = RustSlice::from(payload);
            Error::default()
        }
        Err(err) => Error::new(err.as_str()),
    }
}

#[must_use]
#[unsafe(no_mangle)]
pub extern "C" fn endgame_decrypt(
    key: &Key,
    src: CSlice,
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

    let decrypted = match crate::core::decrypt(&key.bytes, src, max_age_secs) {
        Ok(Some(decrypted)) => decrypted,
        Ok(None) => return Error::default(),
        Err(err) => return Error::new(err.as_str()),
    };

    *email = decrypted.0.into();
    if let Some(decrypted) = decrypted.1 {
        *given_name = decrypted.into();
    }
    if let Some(decrypted) = decrypted.2 {
        *family_name = decrypted.into();
    }

    Error::default()
}

#[must_use]
#[unsafe(no_mangle)]
pub extern "C" fn endgame_load_key(path: CSlice, key: &mut Key) -> Error {
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
        Ok(0) => Error::default(),
        Ok(_) => Error::new("Key is too large. Need 32 bytes"),
        Err(_) => Error::new("Could not read file"),
    }
}
