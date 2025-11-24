use crate::ffi::{CSlice, RustSlice};

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
#[unsafe(export_name = "endgame_encrypt_raw")]
pub extern "C" fn encrypt_raw(key: &Key, data: CSlice) -> RustSlice {
    data.as_option()
        .and_then(|d| crate::core::encrypt(&key.bytes, d).ok())
        .map_or_else(RustSlice::default, RustSlice::from)
}

#[must_use]
#[unsafe(export_name = "endgame_decrypt_raw")]
pub extern "C" fn decrypt_raw(key: &Key, data: CSlice) -> RustSlice {
    data.as_option()
        .and_then(|d| crate::core::decrypt(&key.bytes, d).ok())
        .map_or_else(RustSlice::default, RustSlice::from)
}
