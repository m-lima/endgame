use crate::ffi::{CSlice, Error, RustSlice};

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
#[unsafe(no_mangle)]
pub extern "C" fn endgame_encrypt(
    key: &Key,
    email: CSlice,
    given_name: CSlice,
    family_name: CSlice,
    dst: &mut RustSlice,
) -> Error {
    fn deref<'a>(slice: CSlice) -> Option<&'a [u8]> {
        slice
            .as_option()
            .map(<[u8]>::trim_ascii)
            .filter(|s| !s.is_empty())
    }

    fn size(slice: Option<&[u8]>) -> usize {
        slice.map_or(0, <[u8]>::len)
    }

    fn serialize(buffer: &mut Vec<u8>, slice: Option<&[u8]>) {
        if let Some(slice) = slice {
            buffer.extend_from_slice(&slice.len().to_ne_bytes());
            buffer.extend_from_slice(slice);
        } else {
            buffer.extend_from_slice(&0_usize.to_ne_bytes());
        }
    }

    if !dst.ptr.is_null() {
        return Error::new("Destination is not null");
    }

    if email.ptr.is_null() {
        return Error::new("Email is null");
    }

    let email = deref(email);
    let given_name = deref(given_name);
    let family_name = deref(family_name);

    let Ok(now) = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs().to_ne_bytes())
    else {
        return Error::new("Could not generate timestamp");
    };

    let mut buffer =
        Vec::with_capacity(now.len() + size(email) + size(given_name) + size(family_name));
    buffer.extend_from_slice(&now);
    serialize(&mut buffer, email);
    serialize(&mut buffer, given_name);
    serialize(&mut buffer, family_name);

    match crate::core::encrypt(&key.bytes, buffer.as_slice()) {
        Ok(payload) => {
            *dst = RustSlice::from(payload);
            Error::default()
        }
        Err(err) => Error::new(err.as_str()),
    }
}

#[must_use]
#[unsafe(no_mangle)]
pub extern "C" fn endgame_decrypt(
    key: &Key,
    src: CSlice,
    max_age_secs: u64,
    email: &mut RustSlice,
    given_name: &mut RustSlice,
    family_name: &mut RustSlice,
) -> Error {
    const EOF_ERROR: Error = Error::new("Payload was too short");

    macro_rules! try_read {
        ($in: ident, $out: ident, $else: block) => {
            match std::io::Read::read_exact(&mut $in, &mut $out) {
                Ok(_) => $else,
                Err(_) => return EOF_ERROR,
            }
        };

        ($in: ident, $out: ident, $type: ident) => {
            try_read!($in, $out, { $type::from_ne_bytes($out) })
        };

        ($in: ident, $slice: ident) => {{
            let mut bytes = [0; size_of::<usize>()];
            let len = try_read!($in, bytes, usize);
            let mut data = vec![0; len];
            try_read!($in, data, { *$slice = data.into() });
        }};
    }

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

    let Ok(min_timestamp) = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() - max_age_secs)
    else {
        return Error::new("Could not generate timestamp");
    };

    let mut payload = match crate::core::decrypt(&key.bytes, src) {
        Ok(payload) => std::io::Cursor::new(payload),
        Err(err) => return Error::new(err.as_str()),
    };

    let mut bytes = [0; size_of::<u64>()];
    let timestamp = try_read!(payload, bytes, u64);

    if timestamp > min_timestamp {
        try_read!(payload, email);
        try_read!(payload, given_name);
        try_read!(payload, family_name);
    }

    Error::default()
}

// trait Serde {
//     fn size(&self) -> usize;
//     fn write(&self, buffer: &mut Vec<u8>);
//     fn read(&self, buffer: &mut Vec<u8>);
// }
//
// impl Serde for &[u8] {
//     fn size(&self) -> usize {
//         size_of::<usize>() + self.len()
//     }
//
//     fn write(&self, buffer: &mut Vec<u8>) {
//         buffer.extend_from_slice(&self.len().to_ne_bytes());
//         buffer.extend_from_slice(self);
//     }
// }
//
// impl Serde for Option<&[u8]> {
//     fn size(&self) -> usize {
//         match self {
//             Some(slice) => slice.size(),
//             None => size_of::<usize>(),
//         }
//     }
//
//     fn write(&self, buffer: &mut Vec<u8>) {
//         match self {
//             Some(slice) => slice.write(buffer),
//             None => 0_usize.to_ne_bytes().write(buffer),
//         }
//     }
// }
