// allow(non_camel_case_types): to match the nginx type
#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct ngx_str_t {
    pub len: usize,
    pub data: *mut u8,
}

impl ngx_str_t {
    pub const fn new(msg: &'static str) -> Self {
        Self {
            len: msg.len(),
            data: msg.as_ptr().cast_mut(),
        }
    }

    pub const fn none() -> Self {
        Self {
            len: 0,
            data: std::ptr::null_mut(),
        }
    }
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct Key {
    pub bytes: [u8; 32],
}

impl From<crypter::Key> for Key {
    fn from(bytes: crypter::Key) -> Self {
        Self { bytes }
    }
}

impl From<Key> for crypter::Key {
    fn from(value: Key) -> Self {
        value.bytes
    }
}

impl ngx_str_t {
    pub const fn as_option<'a>(self) -> Option<&'a [u8]> {
        if self.data.is_null() {
            None
        } else {
            Some(unsafe { std::slice::from_raw_parts(self.data, self.len) })
        }
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn endgame_ngx_str_t_trim(string: &mut ngx_str_t) {
        if let Some(trimmed) = string.as_option().map(<[u8]>::trim_ascii) {
            *string = ngx_str_t {
                len: trimmed.len(),
                data: trimmed.as_ptr().cast_mut(),
            };
        }
    }
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct RustSlice {
    pub ptr: *mut u8,
    pub len: usize,
    pub cap: usize,
}

impl RustSlice {
    pub const fn none() -> Self {
        Self {
            ptr: std::ptr::null_mut(),
            len: 0,
            cap: 0,
        }
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn endgame_rust_slice_null() -> Self {
        Self::none()
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn endgame_rust_slice_free(&mut self) {
        if !self.ptr.is_null() && self.cap > 0 {
            drop(unsafe { Vec::from_raw_parts(self.ptr, self.len, self.cap) });
            self.ptr = std::ptr::null_mut();
            self.len = 0;
            self.cap = 0;
        }
    }
}

impl From<Vec<u8>> for RustSlice {
    fn from(mut value: Vec<u8>) -> Self {
        let slice = RustSlice {
            ptr: value.as_mut_ptr(),
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

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct Error {
    pub status: u16,
    pub msg: ngx_str_t,
}

impl Error {
    pub const fn new(status: u16, msg: &'static str) -> Self {
        Self {
            status,
            msg: ngx_str_t::new(msg),
        }
    }

    pub const fn no_msg(status: u16) -> Self {
        Self {
            status,
            msg: ngx_str_t::none(),
        }
    }

    pub const fn none() -> Self {
        Self::no_msg(0)
    }
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct Token {
    pub request: *const libc::c_void,
    pub status: u16,
    pub error: ngx_str_t,
    pub cookie: RustSlice,
}
