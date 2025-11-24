use crate::ffi::{CSlice, Error, RustSlice};

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct Key {
    pub bytes: [u8; 32],
}

impl<T: Into<[u8; 32]>> From<T> for Key {
    fn from(value: T) -> Self {
        Self {
            bytes: value.into(),
        }
    }
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct Nonce {
    pub bytes: [u8; 24],
}

impl<T: Into<[u8; 24]>> From<T> for Nonce {
    fn from(value: T) -> Self {
        Self {
            bytes: value.into(),
        }
    }
}

#[must_use]
#[unsafe(no_mangle)]
pub extern "C" fn endgame_encrypt_raw(key: &Key, src: CSlice, dst: &mut RustSlice) -> Error {
    if !dst.ptr.is_null() {
        return Error::from("Destination is not null");
    }

    let Some(src) = src.as_option() else {
        return Error::from("Source is null");
    };

    match crate::core::encrypt(&key.bytes, src) {
        Ok(payload) => {
            *dst = RustSlice::from(payload);
            Error::default()
        }
        Err(err) => Error::from(err.as_str()),
    }
}

#[must_use]
#[unsafe(no_mangle)]
pub extern "C" fn endgame_decrypt_raw(key: &Key, src: CSlice, dst: &mut RustSlice) -> Error {
    if !dst.ptr.is_null() {
        return Error::from("Destination is not null");
    }

    let Some(src) = src.as_option() else {
        return Error::from("Source is null");
    };

    match crate::core::decrypt(&key.bytes, src) {
        Ok(payload) => {
            *dst = RustSlice::from(payload);
            Error::default()
        }
        Err(err) => Error::from(err.as_str()),
    }
}

#[must_use]
#[unsafe(no_mangle)]
pub extern "C" fn endgame_encrypt(
    key: &Key,
    email: CSlice,
    given_name: CSlice,
    family_name: CSlice,
    dst: &mut RustSlice,
) -> Error {
    if !dst.ptr.is_null() {
        return Error::from("Destination is not null");
    }

    let Some(email) = email
        .as_option()
        .map(<[u8]>::trim_ascii)
        .filter(|s| !s.is_empty())
    else {
        return Error::from("Email is null");
    };

    let given_name = given_name
        .as_option()
        .map(<[u8]>::trim_ascii)
        .filter(|s| !s.is_empty());
    let family_name = family_name
        .as_option()
        .map(<[u8]>::trim_ascii)
        .filter(|s| !s.is_empty());

    let Ok(now) = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs().to_ne_bytes())
    else {
        return Error::from("Could not generate timestamp");
    };

    let mut buffer = Vec::with_capacity(
        now.len()
            + size_of::<usize>()
            + email.len()
            + size_of::<usize>()
            + given_name.map_or(0, <[u8]>::len)
            + size_of::<usize>()
            + family_name.map_or(0, <[u8]>::len),
    );
    buffer.extend_from_slice(&now);
    buffer.extend_from_slice(&email.len().to_ne_bytes());
    buffer.extend_from_slice(email);
    if let Some(slice) = given_name {
        buffer.extend_from_slice(&slice.len().to_ne_bytes());
        buffer.extend_from_slice(slice);
    } else {
        buffer.extend_from_slice(&0_usize.to_ne_bytes());
    }
    if let Some(slice) = family_name {
        buffer.extend_from_slice(&slice.len().to_ne_bytes());
        buffer.extend_from_slice(slice);
    } else {
        buffer.extend_from_slice(&0_usize.to_ne_bytes());
    }

    match crate::core::encrypt(&key.bytes, buffer.as_slice()) {
        Ok(payload) => {
            *dst = RustSlice::from(payload);
            Error::default()
        }
        Err(err) => Error::from(err.as_str()),
    }
}

#[must_use]
#[unsafe(no_mangle)]
pub extern "C" fn endgame_decrypt_cookie(
    key: &Key,
    src: CSlice,
    max_age_secs: u64,
    email: &mut RustSlice,
    given_name: &mut RustSlice,
    family_name: &mut RustSlice,
) -> Error {
    if !email.ptr.is_null() {
        return Error::from("Email is not null");
    }

    if !given_name.ptr.is_null() {
        return Error::from("Given name is not null");
    }

    if !family_name.ptr.is_null() {
        return Error::from("Family name is not null");
    }

    let Some(src) = src.as_option() else {
        return Error::from("Source is null");
    };

    let Ok(min_timestamp) = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() - max_age_secs)
    else {
        return Error::from("Could not generate timestamp");
    };

    let payload = match crate::core::decrypt(&key.bytes, src) {
        Ok(payload) => payload,
        Err(err) => return Error::from(err.as_str()),
    };

    let mut bytes = [0; size_of::<u64>()];
    bytes.copy_from_slice(&payload[..size_of::<u64>()]);
    let timestamp = u64::from_ne_bytes(bytes);

    if timestamp > min_timestamp {
        let mut start = size_of::<u64>();
        let mut end = start + size_of::<usize>();

        let mut bytes = [0; size_of::<usize>()];
        bytes.copy_from_slice(&payload[start..end]);
        let len = usize::from_ne_bytes(bytes);

        start = end;
        end += len;

        *email = Vec::from(&payload[start..end]).into();

        start = end;
        end += size_of::<usize>();

        bytes.copy_from_slice(&payload[start..end]);
        let len = usize::from_ne_bytes(bytes);

        start = end;
        end += len;

        *given_name = Vec::from(&payload[start..end]).into();

        start = end;
        end += size_of::<usize>();

        bytes.copy_from_slice(&payload[start..end]);
        let len = usize::from_ne_bytes(bytes);

        start = end;
        end += len;

        *family_name = Vec::from(&payload[start..end]).into();
    }

    Error::default()
}
