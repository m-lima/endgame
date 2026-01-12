pub mod io;

#[derive(Copy, Clone, Debug, Default, Ord, PartialOrd, Eq, PartialEq)]
pub struct Timestamp(u64);

impl Timestamp {
    #[must_use]
    pub fn new(timestamp: u64) -> Self {
        Self(timestamp)
    }

    /// Gets `now` as a timestamp
    ///
    /// # Panics
    /// If `now` is before the birth of Unix
    #[must_use]
    pub fn now() -> Self {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| Timestamp(d.as_secs()))
            .unwrap()
    }

    #[must_use]
    pub fn secs(self) -> u64 {
        self.0
    }
}

impl std::ops::Sub<std::time::Duration> for Timestamp {
    type Output = Self;

    fn sub(self, rhs: std::time::Duration) -> Self::Output {
        Self(self.0 - rhs.as_secs())
    }
}

impl std::ops::Add<std::time::Duration> for Timestamp {
    type Output = Self;

    fn add(self, rhs: std::time::Duration) -> Self::Output {
        Self(self.0 + rhs.as_secs())
    }
}

impl io::Out for Timestamp {
    fn size(&self) -> usize {
        self.0.size()
    }

    fn write<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        self.0.write(writer)
    }
}

impl io::In for Timestamp {
    fn read<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        u64::read(reader).map(Self)
    }
}

#[derive(Debug, PartialEq)]
pub struct Token {
    pub timestamp: Timestamp,
    pub email: String,
    pub given_name: Option<String>,
    pub family_name: Option<String>,
}

impl io::Out for Token {
    fn size(&self) -> usize {
        self.timestamp.size()
            + self.email.size()
            + self.given_name.as_deref().size()
            + self.family_name.as_deref().size()
    }

    fn write<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        self.timestamp.write(writer)?;
        self.email.write(writer)?;
        self.given_name.as_deref().write(writer)?;
        self.family_name.as_deref().write(writer)
    }
}

impl io::In for Token {
    fn read<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let timestamp = Timestamp::read(reader)?;
        let email = Option::read(reader)?.ok_or(std::io::ErrorKind::InvalidData)?;
        let given_name = Option::read(reader)?;
        let family_name = Option::read(reader)?;

        Ok(Self {
            timestamp,
            email,
            given_name,
            family_name,
        })
    }
}

#[derive(Debug, PartialEq)]
pub struct State {
    pub nonce: [u8; 32],
    pub timestamp: Timestamp,
    pub redirect: url::Url,
    pub oidc_id: usize,
    pub oidc_signature: u32,
}

impl State {
    #[must_use]
    pub fn new(
        nonce: [u8; 32],
        timestamp: Timestamp,
        redirect: url::Url,
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

impl io::Out for State {
    fn size(&self) -> usize {
        self.nonce.size() + self.timestamp.size() + self.redirect.as_str().size()
    }

    fn write<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        self.nonce.write(writer)?;
        self.timestamp.write(writer)?;
        self.redirect.as_str().write(writer)?;
        self.oidc_id.write(writer)?;
        self.oidc_signature.write(writer)
    }
}

impl io::In for State {
    fn read<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let nonce = <[u8; 32]>::read(reader)?;
        let timestamp = Timestamp::read(reader)?;
        let redirect = Option::read(reader)?
            .and_then(|ref u| url::Url::parse(u).ok())
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
    mod round_trip {
        use super::super::*;
        use crate::tests::random_array;

        fn round_trip<T: io::In + io::Out>(value: &T) -> std::io::Result<T> {
            let mut bytes = Vec::new();
            value.write(&mut bytes)?;
            T::read(&mut std::io::Cursor::new(bytes))
        }

        #[test]
        fn timestamp() {
            let original = Timestamp::now();
            let recovered = round_trip(&original).unwrap();
            assert_eq!(original, recovered);
        }

        #[test]
        fn token() {
            let original = Token {
                timestamp: Timestamp::now(),
                email: String::from("email"),
                given_name: None,
                family_name: Some(String::from("given")),
            };
            let recovered = round_trip(&original).unwrap();
            assert_eq!(original, recovered);
        }

        #[test]
        fn state() {
            let original = State {
                nonce: random_array(),
                timestamp: Timestamp::now(),
                redirect: url::Url::parse("http://localhost").unwrap(),
                oidc_id: usize::from_ne_bytes(random_array()),
                oidc_signature: rand::random(),
            };
            let recovered = round_trip(&original).unwrap();
            assert_eq!(original, recovered);
        }
    }
}
