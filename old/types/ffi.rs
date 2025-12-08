use super::{CSlice, RustSlice};

impl CSlice {
    #[unsafe(no_mangle)]
    pub extern "C" fn endgame_c_slice_trim(&mut self) {
        if let Some(trimmed) = self.as_option().map(<[u8]>::trim_ascii) {
            *self = Self::new(trimmed);
        }
    }
}

impl RustSlice {
    #[unsafe(no_mangle)]
    pub extern "C" fn endgame_rust_slice_null() -> Self {
        Self::default()
    }

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
