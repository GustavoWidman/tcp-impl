use std::io::{Error, ErrorKind, Result};

use crate::common::traits::{FromBytes, ToBytes};

#[derive(Debug, Clone, Default)]
pub struct TcpHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq_num: u32,
    pub ack_num: u32,
    pub data_offset: u8,
    pub reserved: u8,
    pub ns: bool,
    pub cwr: bool,
    pub ece: bool,
    pub urg: bool,
    pub ack: bool,
    pub psh: bool,
    pub rst: bool,
    pub syn: bool,
    pub fin: bool,
    pub window_size: u16,
    pub checksum: u16,
    pub urgent_ptr: u16,
}

impl TcpHeader {
    pub fn header_len(&self) -> usize {
        (self.data_offset as usize) * 4
    }

    fn base(src_port: u16, dst_port: u16, seq: u32) -> Self {
        Self {
            src_port,
            dst_port,
            seq_num: seq,
            ack_num: 0,
            data_offset: 5,
            reserved: 0,
            ns: false,
            cwr: false,
            ece: false,
            urg: false,
            ack: false,
            psh: false,
            rst: false,
            syn: false,
            fin: false,
            window_size: 65535,
            checksum: 0,
            urgent_ptr: 0,
        }
    }

    pub fn syn(src_port: u16, dst_port: u16, seq: u32) -> Self {
        Self {
            syn: true,
            ..Self::base(src_port, dst_port, seq)
        }
    }

    pub fn syn_ack(src_port: u16, dst_port: u16, seq: u32, ack: u32) -> Self {
        Self {
            syn: true,
            ack: true,
            ack_num: ack,
            ..Self::base(src_port, dst_port, seq)
        }
    }

    pub fn ack(src_port: u16, dst_port: u16, seq: u32, ack: u32) -> Self {
        Self {
            ack: true,
            ack_num: ack,
            ..Self::base(src_port, dst_port, seq)
        }
    }

    pub fn psh_ack(src_port: u16, dst_port: u16, seq: u32, ack: u32) -> Self {
        Self {
            psh: true,
            ack: true,
            ack_num: ack,
            ..Self::base(src_port, dst_port, seq)
        }
    }

    pub fn fin_ack(src_port: u16, dst_port: u16, seq: u32, ack: u32) -> Self {
        Self {
            fin: true,
            ack: true,
            ack_num: ack,
            ..Self::base(src_port, dst_port, seq)
        }
    }
}

impl ToBytes for TcpHeader {
    fn to_bytes(&self) -> Result<Vec<u8>> {
        let len = self.header_len();
        let mut buf = vec![0u8; len];

        let sp = self.src_port.to_be_bytes();
        buf[0] = sp[0];
        buf[1] = sp[1];
        let dp = self.dst_port.to_be_bytes();
        buf[2] = dp[0];
        buf[3] = dp[1];
        let seq = self.seq_num.to_be_bytes();
        buf[4] = seq[0];
        buf[5] = seq[1];
        buf[6] = seq[2];
        buf[7] = seq[3];
        let ack = self.ack_num.to_be_bytes();
        buf[8] = ack[0];
        buf[9] = ack[1];
        buf[10] = ack[2];
        buf[11] = ack[3];
        // byte 12: data_offset (4 bits) | reserved (3 bits) | NS (1 bit)
        buf[12] = (self.data_offset << 4) | ((self.reserved & 0x07) << 1) | (self.ns as u8);
        // byte 13: CWR | ECE | URG | ACK | PSH | RST | SYN | FIN
        buf[13] = ((self.cwr as u8) << 7)
            | ((self.ece as u8) << 6)
            | ((self.urg as u8) << 5)
            | ((self.ack as u8) << 4)
            | ((self.psh as u8) << 3)
            | ((self.rst as u8) << 2)
            | ((self.syn as u8) << 1)
            | (self.fin as u8);
        let ws = self.window_size.to_be_bytes();
        buf[14] = ws[0];
        buf[15] = ws[1];
        let ck = self.checksum.to_be_bytes();
        buf[16] = ck[0];
        buf[17] = ck[1];
        let up = self.urgent_ptr.to_be_bytes();
        buf[18] = up[0];
        buf[19] = up[1];

        Ok(buf)
    }
}

impl FromBytes for TcpHeader {
    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 20 {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "TCP header requires at least 20 bytes",
            ));
        }

        let src_port = u16::from_be_bytes([bytes[0], bytes[1]]);
        let dst_port = u16::from_be_bytes([bytes[2], bytes[3]]);
        let seq_num = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        let ack_num = u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
        let data_offset = bytes[12] >> 4;
        let reserved = (bytes[12] >> 1) & 0x07;
        let ns = (bytes[12] & 0x01) != 0;
        let cwr = (bytes[13] & 0x80) != 0;
        let ece = (bytes[13] & 0x40) != 0;
        let urg = (bytes[13] & 0x20) != 0;
        let ack = (bytes[13] & 0x10) != 0;
        let psh = (bytes[13] & 0x08) != 0;
        let rst = (bytes[13] & 0x04) != 0;
        let syn = (bytes[13] & 0x02) != 0;
        let fin = (bytes[13] & 0x01) != 0;
        let window_size = u16::from_be_bytes([bytes[14], bytes[15]]);
        let checksum = u16::from_be_bytes([bytes[16], bytes[17]]);
        let urgent_ptr = u16::from_be_bytes([bytes[18], bytes[19]]);

        Ok(Self {
            src_port,
            dst_port,
            seq_num,
            ack_num,
            data_offset,
            reserved,
            ns,
            cwr,
            ece,
            urg,
            ack,
            psh,
            rst,
            syn,
            fin,
            window_size,
            checksum,
            urgent_ptr,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_syn_serializes_to_20_bytes_with_syn_flag() {
        let hdr = TcpHeader::syn(12345, 4444, 1000);
        let bytes = hdr.to_bytes().expect("to_bytes should succeed");
        assert_eq!(bytes.len(), 20);
        // SYN bit is bit 1 of byte 13
        assert_ne!(bytes[13] & 0x02, 0, "SYN flag should be set");
        // ACK, FIN should not be set
        assert_eq!(bytes[13] & 0x10, 0, "ACK flag should not be set");
        assert_eq!(bytes[13] & 0x01, 0, "FIN flag should not be set");
    }

    #[test]
    fn test_round_trip() {
        let hdr = TcpHeader::syn_ack(8080, 54321, 999, 1001);
        let bytes = hdr.to_bytes().expect("to_bytes should succeed");
        let parsed = TcpHeader::from_bytes(&bytes).expect("from_bytes should succeed");

        assert_eq!(parsed.src_port, hdr.src_port);
        assert_eq!(parsed.dst_port, hdr.dst_port);
        assert_eq!(parsed.seq_num, hdr.seq_num);
        assert_eq!(parsed.ack_num, hdr.ack_num);
        assert_eq!(parsed.data_offset, hdr.data_offset);
        assert_eq!(parsed.syn, hdr.syn);
        assert_eq!(parsed.ack, hdr.ack);
        assert_eq!(parsed.fin, hdr.fin);
        assert_eq!(parsed.psh, hdr.psh);
        assert_eq!(parsed.window_size, hdr.window_size);
        assert_eq!(parsed.checksum, hdr.checksum);
        assert_eq!(parsed.urgent_ptr, hdr.urgent_ptr);
    }
}
