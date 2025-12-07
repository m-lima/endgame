#![warn(clippy::pedantic)]

// pub mod core;
// pub mod nginx;
//
// pub(crate) mod ffi;
// pub(crate) mod types;

mod ffi {
    mod types {
        // allow(non_camel_case_types): to match the nginx type
        #[allow(non_camel_case_types)]
        #[repr(C)]
        #[derive(Copy, Clone, Debug)]
        pub struct ngx_str_t {
            pub len: usize,
            pub data: *mut u8,
        }

        #[repr(transparent)]
        #[derive(Copy, Clone, Debug)]
        pub struct Key(pub [u8; 32]);

        impl From<crypter::Key> for Key {
            fn from(value: crypter::Key) -> Self {
                Self(value)
            }
        }

        impl From<Key> for crypter::Key {
            fn from(value: Key) -> Self {
                value.0
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
            pub len: usize,
            pub data: *const u8,
        }

        impl Error {
            pub const fn new(msg: &'static str) -> Self {
                Self {
                    len: msg.len(),
                    data: msg.as_ptr(),
                }
            }

            pub const fn none() -> Self {
                Self {
                    len: 0,
                    data: std::ptr::null(),
                }
            }
        }
    }

    use crate::dencrypt;
    use types::{Error, Key, RustSlice, ngx_str_t};

    #[unsafe(no_mangle)]
    pub extern "C" fn endgame_decrypt(
        key: &Key,
        src: ngx_str_t,
        max_age_secs: u64,
        email: &mut RustSlice,
        given_name: &mut RustSlice,
        family_name: &mut RustSlice,
    ) -> Error {
        if !email.ptr.is_null() {
            return Error::new("Email is not null");
        }

        if !given_name.ptr.is_null() {
            return Error::new("Given name is not null");
        }

        if !family_name.ptr.is_null() {
            return Error::new("Family name is not null");
        }

        let Some(src) = src.as_option() else {
            return Error::new("Source is null");
        };

        let Some(min_timestamp) = dencrypt::age_to_unix_epoch(max_age_secs) else {
            return Error::new("Could not create timestamp in Unix epoch");
        };

        if let Some(user) = dencrypt::decrypt(key.0, src).filter(|t| t.timestamp >= min_timestamp) {
            *email = user.email.into();
            *given_name = user.given_name.map_or(RustSlice::none(), RustSlice::from);
            *family_name = user.family_name.map_or(RustSlice::none(), RustSlice::from);
        }

        Error::none()
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn endgame_load_key(path: ngx_str_t, key: &mut Key) -> Error {
        let Some(path) = path.as_option() else {
            return Error::new("Path is null");
        };

        let Ok(path) = str::from_utf8(path) else {
            return Error::new("Path is not valid UTF-8");
        };

        let path = std::path::PathBuf::from(path);
        if !path.exists() {
            return Error::new("Path does not exist");
        }

        let Ok(mut file) = std::fs::File::open(path) else {
            return Error::new("Could not open path");
        };

        let mut bytes = 0;
        while bytes < key.0.len() {
            match std::io::Read::read(&mut file, &mut key.0[bytes..]) {
                Ok(0) => return Error::new("Key is not large enough. Need 32 bytes"),
                Err(_) => return Error::new("Could not read file"),
                Ok(b) => bytes += b,
            }
        }

        match std::io::Read::read(&mut file, &mut [0; 1]) {
            Ok(0) => Error::none(),
            Ok(_) => Error::new("Key is too large. Need 32 bytes"),
            Err(_) => Error::new("Could not read file"),
        }
    }
}

pub mod dencrypt {
    pub struct Token {
        pub timestamp: Timestamp,
        pub email: String,
        pub given_name: Option<String>,
        pub family_name: Option<String>,
    }

    #[derive(Copy, Clone, Debug, Default, Ord, PartialOrd, Eq, PartialEq)]
    pub struct Timestamp(u64);

    #[must_use]
    pub fn age_to_unix_epoch(age_secs: u64) -> Option<Timestamp> {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| Timestamp(d.as_secs() - age_secs))
            .ok()
    }

    #[must_use]
    pub fn encrypt(key: crypter::Key, token: &Token) -> Option<String> {
        #[inline]
        const fn size(string: &str) -> usize {
            size_of::<usize>() + string.len()
        }

        #[inline]
        fn write(string: &str, buffer: &mut Vec<u8>) {
            buffer.extend_from_slice(&string.len().to_le_bytes());
            buffer.extend_from_slice(string.as_bytes());
        }

        let Token {
            timestamp,
            email,
            given_name,
            family_name,
        } = token;
        let email = email.as_str();
        let given_name = given_name.as_ref().map_or("", String::as_str);
        let family_name = family_name.as_ref().map_or("", String::as_str);

        let mut buffer = Vec::with_capacity(
            size_of::<u64>() + size(email) + size(given_name) + size(family_name),
        );

        buffer.extend_from_slice(&timestamp.0.to_le_bytes());
        write(email, &mut buffer);
        write(given_name, &mut buffer);
        write(family_name, &mut buffer);

        crypter::encrypt(&key, buffer.as_slice())
            .map(|e| base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &e))
    }

    pub fn decrypt(key: crypter::Key, payload: &[u8]) -> Option<Token> {
        macro_rules! try_read {
            ($in: ident, $type: ident) => {{
                let mut bytes = [0; size_of::<usize>()];
                std::io::Read::read_exact(&mut $in, &mut bytes).ok()?;
                $type::from_le_bytes(bytes)
            }};

            ($in: ident) => {{
                let len = try_read!($in, usize);
                if len == 0 {
                    None
                } else {
                    let mut data = vec![0; len];
                    std::io::Read::read_exact(&mut $in, &mut data).ok()?;
                    String::from_utf8(data).ok()
                }
            }};
        }

        let payload =
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, payload).ok()?;
        let mut payload = crypter::decrypt(&key, payload).map(std::io::Cursor::new)?;

        let timestamp = Timestamp(try_read!(payload, u64));
        let email = try_read!(payload)?;
        let given_name = try_read!(payload);
        let family_name = try_read!(payload);

        Some(Token {
            timestamp,
            email,
            given_name,
            family_name,
        })
    }
}
