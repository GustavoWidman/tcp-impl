use std::{
    io::{Error, ErrorKind, Result},
    net::Ipv4Addr,
};

use crate::common::checksum::rfc1071_checksum;
use crate::common::traits::{FromBytes, ToBytes};
use crate::proto::headers::{pseudo::TcpPseudoHeader, tcp::TcpHeader};

pub struct TcpSegment {
    pub header: TcpHeader,
    pub payload: Vec<u8>,
}

impl TcpSegment {
    pub fn new(header: TcpHeader, payload: Vec<u8>) -> Self {
        Self { header, payload }
    }

    pub fn checksum(&self, src: &Ipv4Addr, dst: &Ipv4Addr) -> Result<u16> {
        let tcp_header_bytes = {
            let mut h = self.header.clone();
            h.checksum = 0;
            h.to_bytes()?
        };
        let tcp_length = (tcp_header_bytes.len() + self.payload.len()) as u16;
        let pseudo = TcpPseudoHeader::new(src, dst, tcp_length);
        let pseudo_bytes = pseudo.to_bytes()?;

        let mut buf =
            Vec::with_capacity(pseudo_bytes.len() + tcp_header_bytes.len() + self.payload.len());
        buf.extend_from_slice(&pseudo_bytes);
        buf.extend_from_slice(&tcp_header_bytes);
        buf.extend_from_slice(&self.payload);

        Ok(rfc1071_checksum(&buf))
    }

    pub fn with_checksum(mut self, src: &Ipv4Addr, dst: &Ipv4Addr) -> Result<Self> {
        self.header.checksum = self.checksum(src, dst)?;
        Ok(self)
    }
}

impl ToBytes for TcpSegment {
    fn to_bytes(&self) -> Result<Vec<u8>> {
        let header_bytes = self.header.to_bytes()?;
        let mut buf = Vec::with_capacity(header_bytes.len() + self.payload.len());
        buf.extend_from_slice(&header_bytes);
        buf.extend_from_slice(&self.payload);
        Ok(buf)
    }
}

impl FromBytes for TcpSegment {
    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 20 {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "TCP segment requires at least 20 bytes",
            ));
        }
        let header = TcpHeader::from_bytes(&bytes[..20])?;
        let payload = bytes[20..].to_vec();
        Ok(Self { header, payload })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_syn_segment_checksum_validates() {
        let src = Ipv4Addr::new(127, 0, 0, 1);
        let dst = Ipv4Addr::new(10, 0, 0, 1);

        let hdr = TcpHeader::syn(12345, 4444, 1000);
        let segment = TcpSegment::new(hdr, vec![])
            .with_checksum(&src, &dst)
            .expect("with_checksum should succeed");

        let bytes = segment.to_bytes().expect("to_bytes should succeed");

        // Reconstruct pseudo-header + tcp bytes and verify checksum is 0
        let tcp_length = bytes.len() as u16;
        let pseudo = TcpPseudoHeader::new(&src, &dst, tcp_length);
        let pseudo_bytes = pseudo.to_bytes().expect("pseudo to_bytes should succeed");

        let mut verify_buf = Vec::with_capacity(pseudo_bytes.len() + bytes.len());
        verify_buf.extend_from_slice(&pseudo_bytes);
        verify_buf.extend_from_slice(&bytes);

        assert_eq!(
            rfc1071_checksum(&verify_buf),
            0,
            "RFC 1071 checksum over pseudo-header + segment should be 0"
        );
    }
}
