use std::io::Result;

/// Trait for deserialization from bytes
pub trait FromBytes: Sized {
    fn from_bytes(bytes: &[u8]) -> Result<Self>;
}

/// Trait for serialization to bytes
pub trait ToBytes {
    fn to_bytes(&self) -> Result<Vec<u8>>;
}
