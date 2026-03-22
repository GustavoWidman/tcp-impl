pub trait FromBytes: Sized {
    type Error;
    fn from_bytes(bytes: &[u8]) -> Result<Self, Self::Error>;
}

pub trait ToBytes {
    fn to_bytes(&self) -> Vec<u8>;
}
