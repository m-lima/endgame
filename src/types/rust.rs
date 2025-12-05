use super::{CSlice, Error, Key, Nonce, RustError, RustSlice};

impl CSlice {
    pub const fn new(value: &'static [u8]) -> Self {
        Self {
            ptr: value.as_ptr(),
            len: value.len(),
        }
    }

    #[inline]
    pub const fn str(value: &'static str) -> Self {
        Self::new(value.as_bytes())
    }

    pub const fn as_option<'a>(self) -> Option<&'a [u8]> {
        if self.ptr.is_null() {
            None
        } else {
            Some(unsafe { std::slice::from_raw_parts(self.ptr, self.len) })
        }
    }
}

impl From<Vec<u8>> for RustSlice {
    fn from(value: Vec<u8>) -> Self {
        let slice = RustSlice {
            ptr: value.as_ptr(),
            len: value.len(),
            cap: value.capacity(),
        };
        std::mem::forget(value);
        slice
    }
}

impl From<String> for RustSlice {
    fn from(value: String) -> Self {
        value.into_bytes().into()
    }
}

impl Error {
    pub const fn new(msg: &'static str) -> Self {
        Self(CSlice::new(msg.as_bytes()))
    }
}

impl<T: Into<RustSlice>> From<T> for RustError {
    fn from(value: T) -> Self {
        Self(value.into())
    }
}

impl<T: Into<[u8; 32]>> From<T> for Key {
    fn from(value: T) -> Self {
        Self {
            bytes: value.into(),
        }
    }
}

impl<T: Into<[u8; 24]>> From<T> for Nonce {
    fn from(value: T) -> Self {
        Self {
            bytes: value.into(),
        }
    }
}
