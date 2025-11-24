use crate::{
    ffi::{Error, RustSlice},
    nginx::Key,
};

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct KeyBase64 {
    bytes: [u8; 176],
}

impl KeyBase64 {
    #[unsafe(no_mangle)]
    pub extern "C" fn endgame_base64_into_key(self, dst: &mut Key) -> Error {
        match base64::Engine::decode_slice(
            &base64::engine::general_purpose::STANDARD,
            self.bytes,
            &mut dst.bytes,
        ) {
            Ok(32) => Error(RustSlice::default()),
            Ok(bytes) => Error(RustSlice::from(format!("Expected 24 bytes, got {bytes}"))),
            Err(err) => Error(RustSlice::from(err.to_string())),
        }
    }
}
