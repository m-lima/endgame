use super::super::RedirectUri;

#[derive(Debug, PartialEq)]
pub struct State {
    pub nonce: [u8; 32],
    pub timestamp: endgame::types::Timestamp,
    pub redirect: RedirectUri,
    pub oidc_id: usize,
    pub oidc_signature: u32,
}

impl State {
    #[must_use]
    pub fn new(
        nonce: [u8; 32],
        timestamp: endgame::types::Timestamp,
        redirect: RedirectUri,
        oidc_id: usize,
        oidc_signature: u32,
    ) -> Self {
        Self {
            nonce,
            timestamp,
            redirect,
            oidc_id,
            oidc_signature,
        }
    }
}

impl endgame::types::io::Out for State {
    fn size(&self) -> usize {
        self.nonce.size() + self.timestamp.size() + self.redirect.as_ref().size()
    }

    fn write<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        self.nonce.write(writer)?;
        self.timestamp.write(writer)?;
        self.redirect.as_ref().write(writer)?;
        self.oidc_id.write(writer)?;
        self.oidc_signature.write(writer)
    }
}

impl endgame::types::io::In for State {
    fn read<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let nonce = <[u8; 32]>::read(reader)?;
        let timestamp = endgame::types::Timestamp::read(reader)?;
        let redirect = Option::read(reader)?
            .and_then(|ref u| RedirectUri::parse(u))
            .ok_or(std::io::ErrorKind::InvalidData)?;
        let oidc_id = usize::read(reader)?;
        let oidc_signature = u32::read(reader)?;

        Ok(Self {
            nonce,
            timestamp,
            redirect,
            oidc_id,
            oidc_signature,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{super::tests::random_array, RedirectUri, State};

    fn round_trip<T: endgame::types::io::In + endgame::types::io::Out>(
        value: &T,
    ) -> std::io::Result<T> {
        let mut bytes = Vec::new();
        value.write(&mut bytes)?;
        T::read(&mut std::io::Cursor::new(bytes))
    }

    #[test]
    fn state() {
        let original = State {
            nonce: random_array(),
            timestamp: endgame::types::Timestamp::now(),
            redirect: RedirectUri::from_static("http://localhost"),
            oidc_id: usize::from_ne_bytes(random_array()),
            oidc_signature: rand::random(),
        };
        let recovered = round_trip(&original).unwrap();
        assert_eq!(original, recovered);
    }
}
