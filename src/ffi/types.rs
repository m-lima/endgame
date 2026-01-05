unsafe extern "C" {
    fn ngx_pnalloc(pool: *mut libc::c_void, size: usize) -> *mut libc::c_void;
}

// allow(non_camel_case_types): to match the nginx type
#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct ngx_str_t {
    len: usize,
    data: *mut u8,
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

    pub const fn is_null(&self) -> bool {
        self.data.is_null()
    }

    pub fn copy<T: AsRef<str>>(value: T, pool: *mut libc::c_void) -> Option<Self> {
        let value = value.as_ref().as_bytes();
        let ptr = unsafe { ngx_pnalloc(pool, value.len()).cast::<u8>() };

        if ptr.is_null() {
            None
        } else {
            let data = unsafe { std::slice::from_raw_parts_mut(ptr, value.len()) };
            data.copy_from_slice(value);
            Some(ngx_str_t {
                data: data.as_mut_ptr(),
                len: data.len(),
            })
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
pub struct LoginResult {
    pub request: *const libc::c_void,
    pub status: u16,
    pub cookie: ngx_str_t,
    pub redirect: ngx_str_t,
}
