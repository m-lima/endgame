pub trait Out {
    fn size(&self) -> usize;
    fn write<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()>;
}

pub trait In: Sized {
    fn read<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self>;
}

impl<const L: usize> Out for [u8; L] {
    fn size(&self) -> usize {
        L
    }

    fn write<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        writer.write_all(self)
    }
}

impl Out for [u8] {
    fn size(&self) -> usize {
        self.len().size() + self.len()
    }

    fn write<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        self.len().write(writer)?;
        writer.write_all(self)
    }
}

impl Out for str {
    fn size(&self) -> usize {
        self.as_bytes().size()
    }

    fn write<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        self.as_bytes().write(writer)
    }
}

impl Out for Option<&str> {
    fn size(&self) -> usize {
        self.unwrap_or_default().size()
    }

    fn write<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        self.unwrap_or_default().write(writer)
    }
}

impl<const L: usize> In for [u8; L] {
    fn read<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let mut bytes = [0; L];
        reader.read_exact(&mut bytes)?;
        Ok(bytes)
    }
}

impl In for Option<String> {
    fn read<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let len = usize::read(&mut *reader)?;
        if len == 0 {
            Ok(None)
        } else {
            let mut bytes = vec![0; len];
            reader.read_exact(&mut bytes)?;
            let string = String::from_utf8(bytes).map_err(|_| std::io::ErrorKind::InvalidData)?;
            Ok(Some(string))
        }
    }
}

macro_rules! impl_io_num {
    ($type: ty) => {
        impl Out for $type {
            fn size(&self) -> usize {
                size_of::<Self>()
            }

            fn write<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
                writer.write_all(&self.to_le_bytes())
            }
        }

        impl In for $type {
            fn read<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
                let mut bytes = [0; size_of::<Self>()];
                reader.read_exact(&mut bytes)?;
                Ok(Self::from_le_bytes(bytes))
            }
        }
    };
    ($type: ty, $($rest: ty),*) => {
        impl_io_num!($type);
        impl_io_num!($($rest),*);
    }
}

impl_io_num!(u64, u32, usize);
