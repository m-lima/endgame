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
    pub picture: Option<String>,
}

impl io::Out for Token {
    fn size(&self) -> usize {
        self.timestamp.size()
            + self.email.size()
            + self.given_name.as_deref().size()
            + self.family_name.as_deref().size()
            + self.picture.as_deref().size()
    }

    fn write<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        self.timestamp.write(writer)?;
        self.email.write(writer)?;
        self.given_name.as_deref().write(writer)?;
        self.family_name.as_deref().write(writer)?;
        self.picture.as_deref().write(writer)
    }
}

impl io::In for Token {
    fn read<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let timestamp = Timestamp::read(reader)?;
        let email = Option::read(reader)?.ok_or(std::io::ErrorKind::InvalidData)?;
        let given_name = Option::read(reader)?;
        let family_name = Option::read(reader)?;
        let picture = Option::read(reader)?;

        Ok(Self {
            timestamp,
            email,
            given_name,
            family_name,
            picture,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
            picture: Some(String::from("pic")),
        };
        let recovered = round_trip(&original).unwrap();
        assert_eq!(original, recovered);
    }
}
