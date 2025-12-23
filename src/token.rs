use crate::{dencrypt, types};

pub fn decrypt(
    key: crypter::Key,
    payload: &[u8],
    min_timestamp: types::Timestamp,
) -> Option<types::Token> {
    dencrypt::decrypt::<types::Token>(key, payload).filter(|t| t.timestamp >= min_timestamp)
}
