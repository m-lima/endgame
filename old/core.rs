use chacha20poly1305::{self as chacha, XChaCha20Poly1305 as Cipher};

pub fn encrypt_raw<'k, 'p, K: Into<&'k chacha::Key>, P: Into<&'p [u8]>>(
    key: K,
    payload: P,
) -> Result<Vec<u8>, Error> {
    let nonce = <Cipher as chacha::AeadCore>::generate_nonce(chacha::aead::OsRng);
    let cipher = <Cipher as chacha::KeyInit>::new(key.into());
    chacha::aead::Aead::encrypt(&cipher, &nonce, payload.into())
        .map(|encrypted| {
            let mut vec = Vec::with_capacity(nonce.len() + encrypted.len());
            vec.extend_from_slice(&nonce);
            vec.extend(encrypted);
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, vec).into_bytes()
        })
        .map_err(Error::Encryption)
}

pub fn decrypt_raw<'k, 'p, K: Into<&'k chacha::Key>, P: Into<&'p [u8]>>(
    key: K,
    payload: P,
) -> Result<Vec<u8>, Error> {
    const NONCE_LEN: usize = 24;

    let payload =
        base64::Engine::decode(&base64::engine::general_purpose::STANDARD, payload.into())
            .map_err(Error::Decoding)?;

    if payload.len() < NONCE_LEN {
        return Err(Error::Nonce);
    }

    let cipher = <Cipher as chacha::KeyInit>::new(key.into());

    // SAFETY: Length was check just above
    let (nonce, payload) = unsafe { payload.split_at_unchecked(24) };

    // allow(deprecated): Using the version that chacha20poly1305 uses
    #[allow(deprecated)]
    let nonce = chacha::XNonce::from_slice(nonce);

    chacha::aead::Aead::decrypt(&cipher, nonce, payload).map_err(Error::Decryption)
}

#[derive(Debug, Clone)]
pub enum Error {
    Encryption(chacha::Error),
    Decryption(chacha::Error),
    Decoding(base64::DecodeError),
    Nonce,
    Timestamp,
    PayloadTooShort,
    InvalidUtf8(std::string::FromUtf8Error),
}

impl Error {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Encryption(_) => "Failed to encrypt",
            Self::Decryption(_) => "Failed to decrypt",
            Self::Decoding(_) => "Failed to decode",
            Self::Nonce => "Payload not large enough to contain the 24-byte nonce",
            Self::Timestamp => "Could not generate timestamp",
            Self::PayloadTooShort => "Payload was too short",
            Self::InvalidUtf8(_) => "Invalid UTF-8 in payload",
        }
    }
}

impl std::error::Error for Error {}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Encryption(error) | Self::Decryption(error) => error.fmt(f),
            Self::Decoding(error) => error.fmt(f),
            Self::Nonce => f.write_str(Self::Nonce.as_str()),
            Self::Timestamp => f.write_str(Self::Timestamp.as_str()),
            Self::PayloadTooShort => f.write_str(Self::Timestamp.as_str()),
            Self::InvalidUtf8(error) => error.fmt(f),
        }
    }
}

trait Serialize {
    fn size(&self) -> usize;
    fn write(&self, buffer: &mut Vec<u8>);
}

impl Serialize for u64 {
    fn size(&self) -> usize {
        size_of::<Self>()
    }

    fn write(&self, buffer: &mut Vec<u8>) {
        buffer.extend_from_slice(&self.to_ne_bytes());
    }
}

impl Serialize for &[u8] {
    fn size(&self) -> usize {
        size_of::<usize>() + self.len()
    }

    fn write(&self, buffer: &mut Vec<u8>) {
        buffer.extend_from_slice(&self.len().to_ne_bytes());
        buffer.extend_from_slice(self);
    }
}

impl Serialize for Option<&[u8]> {
    fn size(&self) -> usize {
        size_of::<usize>()
    }

    fn write(&self, buffer: &mut Vec<u8>) {
        buffer.extend_from_slice(&0_usize.to_ne_bytes());
    }
}
