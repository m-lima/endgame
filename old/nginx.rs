use crate::ffi::{CSlice, Error, RustSlice};

pub fn encrypt(
    key: &[u8; 32],
    email: &[u8],
    given: Option<&[u8]>,
    family: Option<&[u8]>,
    timestamp: Option<u64>,
) -> Result<Vec<u8>, Error> {
    let now = timestamp
        .or_else(|| {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .ok()
        })
        .ok_or(Error::Timestamp)?;

    let mut buffer = Vec::with_capacity(now.size() + email.size() + given.size() + family.size());
    now.write(&mut buffer);
    email.write(&mut buffer);
    given.write(&mut buffer);
    family.write(&mut buffer);

    crypter::encrypt(&key, buffer.as_slice())
}

pub fn decrypt<'k, 'p, K: Into<&'k chacha::Key>, P: Into<&'p [u8]>>(
    key: K,
    payload: P,
    max_age_secs: u64,
) -> Result<Option<(String, Option<String>, Option<String>)>, Error> {
    macro_rules! try_read {
        ($in: ident, $out: ident, $else: block) => {
            match std::io::Read::read_exact(&mut $in, &mut $out) {
                Ok(_) => $else,
                Err(_) => return Err(Error::PayloadTooShort),
            }
        };

        ($in: ident, $out: ident, $type: ident) => {
            try_read!($in, $out, { $type::from_ne_bytes($out) })
        };

        ($in: ident) => {{
            let mut bytes = [0; size_of::<usize>()];
            let len = try_read!($in, bytes, usize);
            if len == 0 {
                None
            } else {
                let mut data = vec![0; len];
                try_read!($in, data, {
                    String::from_utf8(data)
                        .map_err(Error::InvalidUtf8)
                        .map(Some)?
                })
            }
        }};
    }

    let min_timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() - max_age_secs)
        .map_err(|_| Error::Timestamp)?;

    let mut payload = decrypt_raw(key, payload).map(std::io::Cursor::new)?;
    let mut bytes = [0; size_of::<u64>()];

    let timestamp = try_read!(payload, bytes, u64);
    let email = try_read!(payload);
    let given = try_read!(payload);
    let family = try_read!(payload);

    if timestamp < min_timestamp {
        return Ok(None);
    }

    let Some(email) = email else {
        return Ok(None);
    };

    Ok(Some((email, given, family)))
}
