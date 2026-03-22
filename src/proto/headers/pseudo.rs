use std::{io::Result, net::Ipv4Addr};

use crate::common::traits::ToBytes;

pub struct TcpPseudoHeader {
    src_addr: [u8; 4],
    dst_addr: [u8; 4],
    zeros: u8,
    protocol: u8,
    tcp_length: u16,
}

impl TcpPseudoHeader {
    pub fn new(src_ip: &Ipv4Addr, dst_ip: &Ipv4Addr, tcp_length: u16) -> Self {
        Self {
            src_addr: src_ip.octets(),
            dst_addr: dst_ip.octets(),
            zeros: 0,
            protocol: 6,
            tcp_length,
        }
    }
}

impl ToBytes for TcpPseudoHeader {
    fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut buf = Vec::with_capacity(12);
        buf.extend_from_slice(&self.src_addr);
        buf.extend_from_slice(&self.dst_addr);
        buf.push(self.zeros);
        buf.push(self.protocol);
        buf.extend_from_slice(&self.tcp_length.to_be_bytes());
        Ok(buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_to_bytes_length_and_order() {
        let src = Ipv4Addr::new(192, 168, 1, 1);
        let dst = Ipv4Addr::new(10, 0, 0, 1);
        let pseudo = TcpPseudoHeader::new(&src, &dst, 200);
        let bytes = pseudo.to_bytes().expect("to_bytes should succeed");

        assert_eq!(bytes.len(), 12);
        // src_addr
        assert_eq!(&bytes[0..4], &[192, 168, 1, 1]);
        // dst_addr
        assert_eq!(&bytes[4..8], &[10, 0, 0, 1]);
        // zeros
        assert_eq!(bytes[8], 0);
        // protocol (TCP = 6)
        assert_eq!(bytes[9], 6);
        // tcp_length big-endian 200 = 0x00C8
        assert_eq!(&bytes[10..12], &[0x00, 0xC8]);
    }
}
