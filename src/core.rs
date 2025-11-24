use chacha20poly1305::{self as chacha, XChaCha20Poly1305 as Cipher};

pub fn encrypt<'k, 'p, K: Into<&'k chacha::Key>, P: Into<&'p [u8]>>(
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
            vec
        })
        .map_err(Error::Aead)
}

pub fn decrypt<'k, 'p, K: Into<&'k chacha::Key>, P: Into<&'p [u8]>>(
    key: K,
    payload: P,
) -> Result<Vec<u8>, Error> {
    const NONCE_LEN: usize = 24;

    let payload = payload.into();
    if payload.len() < NONCE_LEN {
        return Err(Error::Nonce);
    }

    let cipher = <Cipher as chacha::KeyInit>::new(key.into());

    // SAFETY: Lenght was check just above
    let (nonce, payload) = unsafe { payload.split_at_unchecked(24) };

    // allow(deprecated): Using the version that chacha20poly1305 uses
    #[allow(deprecated)]
    let nonce = chacha::XNonce::from_slice(nonce);

    chacha::aead::Aead::decrypt(&cipher, nonce, payload).map_err(Error::Aead)
}

#[derive(Debug, Clone)]
pub enum Error {
    Aead(chacha::Error),
    Nonce,
}

impl std::error::Error for Error {}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Aead(error) => error.fmt(f),
            Self::Nonce => f.write_str("Payload not large enough to contain the 24-byte nonce"),
        }
    }
}
