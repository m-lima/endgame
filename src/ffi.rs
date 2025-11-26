// TODO: Match ngx_str_t
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct CSlice {
    pub ptr: *const u8,
    pub len: usize,
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct RustSlice {
    pub ptr: *const u8,
    pub len: usize,
    pub cap: usize,
}

#[repr(transparent)]
#[derive(Copy, Clone, Debug, Default)]
pub struct Error(pub CSlice);

#[repr(transparent)]
#[derive(Copy, Clone, Debug, Default)]
pub struct RustError(pub RustSlice);

impl CSlice {
    #[must_use]
    #[unsafe(no_mangle)]
    pub extern "C" fn endgame_c_slice_trim(self) -> Self {
        self.as_option().map_or(self, |s| Self::new(s.trim_ascii()))
    }
}

impl CSlice {
    #[must_use]
    pub const fn new(value: &'static [u8]) -> Self {
        Self {
            ptr: value.as_ptr(),
            len: value.len(),
        }
    }

    #[inline]
    #[must_use]
    pub const fn str(value: &'static str) -> Self {
        Self::new(value.as_bytes())
    }

    #[must_use]
    pub const fn as_option<'a>(self) -> Option<&'a [u8]> {
        if self.ptr.is_null() {
            None
        } else {
            Some(unsafe { std::slice::from_raw_parts(self.ptr, self.len) })
        }
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
    pub extern "C" fn endgame_rust_slice_free(&mut self) {
        if !self.ptr.is_null() && self.cap > 0 {
            drop(unsafe { Vec::from_raw_parts(self.ptr.cast_mut(), self.len, self.cap) });
            self.ptr = std::ptr::null();
            self.len = 0;
            self.cap = 0;
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
    #[must_use]
    pub const fn new(msg: &'static str) -> Self {
        Self(CSlice::new(msg.as_bytes()))
    }
}

impl<T: Into<RustSlice>> From<T> for RustError {
    fn from(value: T) -> Self {
        Self(value.into())
    }
}
