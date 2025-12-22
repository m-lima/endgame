use crate::io;

#[must_use]
pub fn encrypt<P: io::Out>(key: crypter::Key, payload: &P) -> Option<String> {
    let mut buffer = Vec::with_capacity(payload.size());
    payload.write(&mut buffer).ok()?;

    let encrypted = crypter::encrypt(&key, buffer.as_slice())?;

    Some(base64::Engine::encode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        &encrypted,
    ))
}

pub fn decrypt<P: io::In>(key: crypter::Key, payload: &[u8]) -> Option<P> {
    let payload =
        base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, payload).ok()?;

    let mut payload = crypter::decrypt(&key, payload).map(std::io::Cursor::new)?;

    P::read(&mut payload).ok()
}
