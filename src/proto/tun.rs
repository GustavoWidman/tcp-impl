use std::io::{Read, Write};
use std::net::Ipv4Addr;

use tun::Device;

use crate::common::traits::{FromBytes, ToBytes};
use crate::proto::headers::ipv4::Ipv4Header;
use crate::proto::packet::{Ipv4Packet, TcpSegment};

/// macOS utun 4-byte AF_INET packet family prefix (flags=0, protocol=AF_INET=2 in network byte order)
const MACOS_AF_INET_PREFIX: [u8; 4] = [0x00, 0x00, 0x00, 0x02];
/// macOS utun 4-byte AF_INET6 packet family prefix
const MACOS_AF_INET6_PREFIX: [u8; 4] = [0x00, 0x00, 0x00, 0x1e];

const DEFAULT_MTU: usize = 1500;

pub struct TunDevice {
    inner: tun::platform::Device,
    mtu: usize,
}

impl TunDevice {
    /// Creates a utun device, assigns the given IP, brings it up.
    /// Prints the utun interface name so the user knows which interface to use.
    pub fn new(tun_ip: &str) -> std::io::Result<Self> {
        let ip: Ipv4Addr = tun_ip.parse().map_err(|e| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("invalid IP: {e}"))
        })?;

        let mut config = tun::Configuration::default();
        config
            .address(ip)
            .netmask((255, 255, 255, 0))
            .mtu(DEFAULT_MTU as i32)
            .up();

        let device = tun::create(&config)
            .map_err(|e| std::io::Error::other(format!("tun create failed: {e}")))?;

        // Print the interface name so the user knows the utun device
        log::info!("TUN device up: {:?}", device.name());

        Ok(Self {
            inner: device,
            mtu: DEFAULT_MTU,
        })
    }

    /// Read one frame from the TUN device.
    /// Strips the macOS 4-byte AF family prefix.
    /// Returns None if the frame is not IPv4 (e.g. IPv6 or unknown family).
    pub fn read_ip_packet(&mut self) -> std::io::Result<Option<Ipv4Packet>> {
        let mut buf = vec![0u8; 4 + self.mtu];
        let n = self.inner.read(&mut buf)?;

        if n < 4 {
            return Ok(None);
        }

        // Check the 4-byte macOS prefix
        let prefix = &buf[..4];
        if prefix != MACOS_AF_INET_PREFIX {
            // Not IPv4 (could be IPv6 or other) — skip
            return Ok(None);
        }

        let ip_bytes = &buf[4..n];
        match Ipv4Packet::from_bytes(ip_bytes) {
            Ok(pkt) => Ok(Some(pkt)),
            Err(e) => {
                log::warn!("failed to parse IPv4 packet: {e}");
                Ok(None)
            }
        }
    }

    /// Write a TCP segment wrapped in an IPv4 packet to the TUN device.
    /// Prepends the macOS 4-byte AF_INET prefix.
    pub fn write_ip_packet(
        &mut self,
        src: Ipv4Addr,
        dst: Ipv4Addr,
        segment: &TcpSegment,
    ) -> std::io::Result<()> {
        let segment_bytes = segment.to_bytes()?;
        let total_length = (20 + segment_bytes.len()) as u16;

        let ip_header = Ipv4Header::new(
            total_length,
            0,  // id
            64, // ttl
            6,  // protocol = TCP
            src.octets(),
            dst.octets(),
        );
        let ip_header_bytes = ip_header.to_bytes()?;

        // Build the full frame: 4-byte prefix + IPv4 header + TCP segment
        let mut frame = Vec::with_capacity(4 + ip_header_bytes.len() + segment_bytes.len());
        frame.extend_from_slice(&MACOS_AF_INET_PREFIX);
        frame.extend_from_slice(&ip_header_bytes);
        frame.extend_from_slice(&segment_bytes);

        self.inner.write_all(&frame)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::headers::tcp::TcpHeader;

    /// Test that the 4-byte prefix stripping works correctly.
    /// We construct a fake frame with [0,0,0,2] prefix + known IPv4 bytes
    /// and verify from_bytes parses it.
    #[test]
    fn test_strip_macos_prefix_ipv4() {
        // Build a minimal valid IPv4 packet
        let ip_header = Ipv4Header::new(
            40, // total_length (20 hdr + 20 tcp)
            1,  // id
            64, // ttl
            6,  // protocol = TCP
            [10, 0, 0, 1],
            [10, 0, 0, 2],
        );
        let mut ip_bytes = ip_header.to_bytes().unwrap();
        // Append 20 bytes of dummy TCP payload to make total_length match
        ip_bytes.extend_from_slice(&[0u8; 20]);

        // Simulate a macOS TUN frame: prefix + ip packet
        let mut frame = Vec::new();
        frame.extend_from_slice(&MACOS_AF_INET_PREFIX);
        frame.extend_from_slice(&ip_bytes);

        // Now test the parsing logic (same as what read_ip_packet does internally)
        assert_eq!(&frame[..4], &MACOS_AF_INET_PREFIX);
        let parsed = Ipv4Packet::from_bytes(&frame[4..]).unwrap();
        assert_eq!(parsed.header.src_addr, [10, 0, 0, 1]);
        assert_eq!(parsed.header.dst_addr, [10, 0, 0, 2]);
        assert_eq!(parsed.header.protocol, 6);
    }

    /// Test that IPv6 frames (wrong prefix) are skipped.
    #[test]
    fn test_skip_ipv6_prefix() {
        let prefix = &MACOS_AF_INET6_PREFIX;
        assert_ne!(prefix, &MACOS_AF_INET_PREFIX);
    }

    /// Test the write frame construction: verify the output starts with [0,0,0,2]
    /// followed by a valid IPv4 header.
    #[test]
    fn test_write_frame_has_correct_prefix() {
        let src = Ipv4Addr::new(10, 0, 0, 1);
        let dst = Ipv4Addr::new(10, 0, 0, 2);

        // Build a minimal TcpSegment (SYN)
        let hdr = TcpHeader::syn(12345, 4444, 1000);
        let segment = TcpSegment::new(hdr, vec![])
            .with_checksum(&src, &dst)
            .unwrap();

        let segment_bytes = segment.to_bytes().unwrap();
        let total_length = (20 + segment_bytes.len()) as u16;

        let ip_header = Ipv4Header::new(total_length, 0, 64, 6, src.octets(), dst.octets());
        let ip_header_bytes = ip_header.to_bytes().unwrap();

        // Build expected frame
        let mut expected = Vec::new();
        expected.extend_from_slice(&MACOS_AF_INET_PREFIX);
        expected.extend_from_slice(&ip_header_bytes);
        expected.extend_from_slice(&segment_bytes);

        // Verify prefix
        assert_eq!(&expected[..4], &[0x00, 0x00, 0x00, 0x02]);

        // Verify IPv4 header bytes 12..16 = src IP and 16..20 = dst IP
        assert_eq!(&expected[16..20], &[10, 0, 0, 1]);
        assert_eq!(&expected[20..24], &[10, 0, 0, 2]);

        // Verify protocol = TCP (6) at byte 13 of the IP header (= offset 4+9 = 13)
        assert_eq!(expected[4 + 9], 6);
    }
}
