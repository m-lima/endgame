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

    let mut buffer =
        Vec::with_capacity(size_of::<u64>() + size(email) + size(given_name) + size(family_name));

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
