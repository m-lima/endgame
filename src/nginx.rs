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
