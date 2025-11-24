#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct CSlice {
    ptr: *const u8,
    len: usize,
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct RustSlice {
    ptr: *const u8,
    len: usize,
    cap: usize,
}

#[repr(transparent)]
#[derive(Copy, Clone, Debug, Default)]
pub struct Error(pub RustSlice);

impl CSlice {
    #[must_use]
    #[unsafe(no_mangle)]
    pub extern "C" fn endgame_c_slice_new(ptr: *const u8, len: usize) -> Self {
        Self { ptr, len }
    }
}

impl CSlice {
    #[inline]
    #[must_use]
    pub fn as_option<'a>(self) -> Option<&'a [u8]> {
        self.into()
    }
}

impl From<&[u8]> for CSlice {
    fn from(value: &[u8]) -> Self {
        Self {
            ptr: value.as_ptr(),
            len: value.len(),
        }
    }
}

impl From<CSlice> for Option<&'_ [u8]> {
    fn from(value: CSlice) -> Self {
        use std::ops::Not;
        value
            .ptr
            .is_null()
            .not()
            .then_some(unsafe { std::slice::from_raw_parts(value.ptr, value.len) })
    }
}

impl RustSlice {
    #[must_use]
    #[unsafe(no_mangle)]
    pub extern "C" fn endgame_rust_slice_null() -> Self {
        Self::default()
    }

    #[must_use]
    #[unsafe(no_mangle)]
    pub extern "C" fn endgame_rust_slice_as_c_slice(self) -> CSlice {
        CSlice {
            ptr: self.ptr,
            len: self.len,
        }
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn endgame_rust_slice_free(self) {
        if !self.ptr.is_null() {
            drop(unsafe { Vec::from_raw_parts(self.ptr.cast_mut(), self.len, self.cap) });
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
