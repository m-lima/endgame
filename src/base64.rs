use crate::{ffi::RustError, nginx::Key};

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct KeyBase64 {
    bytes: [u8; 176],
}

impl KeyBase64 {
    #[unsafe(no_mangle)]
    pub extern "C" fn endgame_base64_into_key(self, dst: &mut Key) -> RustError {
        match base64::Engine::decode_slice(
            &base64::engine::general_purpose::STANDARD,
            self.bytes,
            &mut dst.bytes,
        ) {
            Ok(32) => RustError::default(),
            Ok(bytes) => RustError::from(format!("Expected 24 bytes, got {bytes}")),
            Err(err) => RustError::from(err.to_string()),
        }
    }
}
