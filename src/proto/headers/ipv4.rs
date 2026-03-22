use std::io::{Error, ErrorKind, Result};

use crate::common::checksum::rfc1071_checksum;
use crate::common::traits::{FromBytes, ToBytes};

#[derive(Debug, Clone)]
pub struct Ipv4Header {
    pub version: u8,
    pub ihl: u8,
    pub dscp: u8,
    pub ecn: u8,
    pub total_length: u16,
    pub id: u16,
    pub flags: u8,
    pub fragment_offset: u16,
    pub ttl: u8,
    pub protocol: u8,
    pub checksum: u16,
    pub src_addr: [u8; 4],
    pub dst_addr: [u8; 4],
}

impl Ipv4Header {
    pub fn new(
        total_length: u16,
        id: u16,
        ttl: u8,
        protocol: u8,
        src_addr: [u8; 4],
        dst_addr: [u8; 4],
    ) -> Self {
        Self {
            version: 4,
            ihl: 5,
            dscp: 0,
            ecn: 0,
            total_length,
            id,
            flags: 0,
            fragment_offset: 0,
            ttl,
            protocol,
            checksum: 0,
            src_addr,
            dst_addr,
        }
    }

    pub fn payload_offset(&self) -> usize {
        (self.ihl as usize) * 4
    }
}

impl ToBytes for Ipv4Header {
    fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; 20];

        buf[0] = (self.version << 4) | (self.ihl & 0x0F);
        buf[1] = (self.dscp << 2) | (self.ecn & 0x03);
        let tl = self.total_length.to_be_bytes();
        buf[2] = tl[0];
        buf[3] = tl[1];
        let id = self.id.to_be_bytes();
        buf[4] = id[0];
        buf[5] = id[1];
        let flags_frag =
            (((self.flags as u16) << 13) | (self.fragment_offset & 0x1FFF)).to_be_bytes();
        buf[6] = flags_frag[0];
        buf[7] = flags_frag[1];
        buf[8] = self.ttl;
        buf[9] = self.protocol;
        // bytes 10-11: checksum — set to 0 first, then compute
        buf[10] = 0;
        buf[11] = 0;
        buf[12..16].copy_from_slice(&self.src_addr);
        buf[16..20].copy_from_slice(&self.dst_addr);

        let cksum = rfc1071_checksum(&buf);
        let ck = cksum.to_be_bytes();
        buf[10] = ck[0];
        buf[11] = ck[1];

        Ok(buf)
    }
}

impl FromBytes for Ipv4Header {
    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 20 {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "IPv4 header requires at least 20 bytes",
            ));
        }

        let version = bytes[0] >> 4;
        let ihl = bytes[0] & 0x0F;

        if ihl < 5 {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "IPv4 IHL must be at least 5",
            ));
        }

        let dscp = bytes[1] >> 2;
        let ecn = bytes[1] & 0x03;
        let total_length = u16::from_be_bytes([bytes[2], bytes[3]]);
        let id = u16::from_be_bytes([bytes[4], bytes[5]]);
        let flags_frag = u16::from_be_bytes([bytes[6], bytes[7]]);
        let flags = (flags_frag >> 13) as u8;
        let fragment_offset = flags_frag & 0x1FFF;
        let ttl = bytes[8];
        let protocol = bytes[9];
        let checksum = u16::from_be_bytes([bytes[10], bytes[11]]);
        let src_addr = [bytes[12], bytes[13], bytes[14], bytes[15]];
        let dst_addr = [bytes[16], bytes[17], bytes[18], bytes[19]];

        Ok(Self {
            version,
            ihl,
            dscp,
            ecn,
            total_length,
            id,
            flags,
            fragment_offset,
            ttl,
            protocol,
            checksum,
            src_addr,
            dst_addr,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_to_bytes_produces_valid_checksum() {
        let hdr = Ipv4Header::new(40, 1, 64, 6, [192, 168, 1, 1], [10, 0, 0, 1]);
        let bytes = hdr.to_bytes().expect("to_bytes should succeed");
        assert_eq!(bytes.len(), 20);
        // A valid packet's checksum over its own header bytes should equal 0
        assert_eq!(rfc1071_checksum(&bytes), 0);
    }

    #[test]
    fn test_round_trip() {
        let hdr = Ipv4Header::new(40, 42, 128, 17, [10, 0, 0, 1], [10, 0, 0, 2]);
        let bytes = hdr.to_bytes().expect("to_bytes should succeed");
        let parsed = Ipv4Header::from_bytes(&bytes).expect("from_bytes should succeed");

        assert_eq!(parsed.version, hdr.version);
        assert_eq!(parsed.ihl, hdr.ihl);
        assert_eq!(parsed.dscp, hdr.dscp);
        assert_eq!(parsed.ecn, hdr.ecn);
        assert_eq!(parsed.total_length, hdr.total_length);
        assert_eq!(parsed.id, hdr.id);
        assert_eq!(parsed.flags, hdr.flags);
        assert_eq!(parsed.fragment_offset, hdr.fragment_offset);
        assert_eq!(parsed.ttl, hdr.ttl);
        assert_eq!(parsed.protocol, hdr.protocol);
        assert_eq!(parsed.src_addr, hdr.src_addr);
        assert_eq!(parsed.dst_addr, hdr.dst_addr);
    }
}
