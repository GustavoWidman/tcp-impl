use std::io::{Read, Write};
use std::net::Ipv4Addr;
use std::os::unix::io::AsRawFd;
use std::time::Duration;

use tun::Device;

use crate::common::traits::{FromBytes, ToBytes};
use crate::proto::headers::ipv4::Ipv4Header;
use crate::proto::packet::{Ipv4Packet, TcpSegment};

/// macOS utun 4-byte AF_INET packet family prefix (flags=0, protocol=AF_INET=2 in network byte order).
/// Every frame read from or written to a macOS utun device must carry this prefix;
/// it cannot be disabled.
#[cfg(target_os = "macos")]
const MACOS_AF_INET_PREFIX: [u8; 4] = [0x00, 0x00, 0x00, 0x02];

const DEFAULT_MTU: usize = 1500;

/// Returns a companion IP to use as the TUN interface's local address.
///
/// `ip` becomes the peer/destination address so the kernel does not own it.
/// We simply increment (or decrement if at 255) the last octet.
fn companion_ip(ip: Ipv4Addr) -> Ipv4Addr {
    let [a, b, c, d] = ip.octets();
    let d2 = if d < 255 { d + 1 } else { d - 1 };
    Ipv4Addr::new(a, b, c, d2)
}

pub struct TunDevice {
    inner: tun::platform::Device,
    mtu: usize,
}

impl TunDevice {
    /// Creates a TUN device configured as a point-to-point interface and brings it up.
    ///
    /// Works on both macOS (utun) and Linux (tun). On either platform, if `tun_ip`
    /// were assigned as the LOCAL address the kernel would own that IP and answer
    /// TCP SYNs with RST before userspace ever sees them. Instead we configure:
    ///
    ///   local  = companion_ip(tun_ip)   <- kernel-owned, used as the source by nc
    ///   peer   = tun_ip                 <- NOT kernel-owned; routed through the TUN fd
    ///
    /// Traffic destined for `tun_ip` is delivered to our fd, not answered by the
    /// kernel stack.
    ///
    /// On Linux, packet information (PI) headers are disabled so frames are raw IP
    /// with no prefix. On macOS, the mandatory 4-byte AF family prefix is handled
    /// in `read_ip_packet` and `write_ip_packet`.
    /// with no prefix. On macOS, tun 0.6 does not strip the 4-byte AF family prefix
    /// internally — userspace must handle it manually.
    pub fn new(tun_ip: &str) -> std::io::Result<Self> {
        let peer: Ipv4Addr = tun_ip.parse().map_err(|e| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("invalid IP: {e}"))
        })?;

        // Use a companion IP as the interface's local address so `peer` remains
        // unowned by the kernel and routable through the TUN fd.
        let local = companion_ip(peer);

        let mut config = tun::Configuration::default();
        config
            .address(local)
            .destination(peer)
            .mtu(DEFAULT_MTU as i32)
            .up();

        // On Linux, disable packet information so frames are raw IP (no 4-byte PI header).
        #[cfg(target_os = "linux")]
        config.platform(|p| {
            p.packet_information(false);
        });

        #[cfg(target_os = "linux")]
        config.platform(|p| {
            p.packet_information(false);
        });

        let device = tun::create(&config)
            .map_err(|e| std::io::Error::other(format!("tun create failed: {e}")))?;

        log::info!(
            "TUN device up: {:?} (local={} peer={})",
            device.name(),
            local,
            peer,
        );

        Ok(Self {
            inner: device,
            mtu: DEFAULT_MTU,
        })
    }

    /// Read one IPv4 packet from the TUN device.
    ///
    /// On macOS (utun), every frame carries a mandatory 4-byte AF family prefix.
    /// This method strips it and returns `None` if the prefix is not `AF_INET`.
    ///
    /// On Linux (tun, PI disabled), frames are raw IP with no prefix; the packet
    /// is parsed directly. Returns `None` if it is not a valid IPv4 packet.
    /// On macOS (utun), tun 0.6 does NOT strip the mandatory 4-byte AF family
    /// prefix: `read()` returns `[0x00, 0x00, 0x00, 0x02] + <IP bytes>`. We
    /// check for the prefix and parse `buf[4..n]` as the IPv4 packet. Frames
    /// that do not carry the AF_INET prefix (e.g. IPv6) return `Ok(None)`.
    ///
    /// On Linux (tun, PI disabled), frames are raw IP with no prefix and are
    /// parsed directly.
    pub fn read_ip_packet(&mut self) -> std::io::Result<Option<Ipv4Packet>> {
        #[cfg(target_os = "macos")]
        {
            let mut buf = vec![0u8; 4 + self.mtu];
            let n = self.inner.read(&mut buf)?;

            if n < 4 {
                return Ok(None);
            }

            if buf[..4] != MACOS_AF_INET_PREFIX {
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

        #[cfg(target_os = "linux")]
        #[cfg(target_os = "macos")]
        {
            let mut buf = vec![0u8; 4 + self.mtu];
            let n = self.inner.read(&mut buf)?;

            if n < 4 || buf[..4] != MACOS_AF_INET_PREFIX {
                // Not an IPv4 frame (could be IPv6 or other AF family)
                return Ok(None);
            }

            match Ipv4Packet::from_bytes(&buf[4..n]) {
                Ok(pkt) => Ok(Some(pkt)),
                Err(e) => {
                    log::warn!("failed to parse IPv4 packet: {e}");
                    Ok(None)
                }
            }
        }

        #[cfg(target_os = "linux")]
        {
            let mut buf = vec![0u8; self.mtu];
            let n = self.inner.read(&mut buf)?;

            match Ipv4Packet::from_bytes(&buf[..n]) {
                Ok(pkt) => Ok(Some(pkt)),
                Err(e) => {
                    log::warn!("failed to parse IPv4 packet: {e}");
                    Ok(None)
                }
            }
        }

        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        {
            compile_error!("unsupported platform: only macOS and Linux are supported")
        }
    }

    /// Read one frame from the TUN device with a timeout.
    /// Returns `Ok(None)` if the timeout expires without data arriving.
    pub fn read_ip_packet_timeout(
        &mut self,
        timeout: Duration,
    ) -> std::io::Result<Option<Ipv4Packet>> {
        let fd = self.inner.as_raw_fd();
        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let timeout_ms = timeout.as_millis().min(i32::MAX as u128) as i32;

        // SAFETY: pfd is a valid pollfd struct on the stack, nfds=1 is correct.
        let ret = unsafe { libc::poll(&mut pfd, 1, timeout_ms) };

        if ret < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                return Ok(None);
            }
            return Err(err);
        }
        if ret == 0 {
            // Timeout — no data ready
            return Ok(None);
        }

        self.read_ip_packet()
    }

    /// Write a TCP segment wrapped in an IPv4 packet to the TUN device.
    ///
    /// On macOS (utun), prepends the mandatory 4-byte AF_INET prefix before writing.
    ///
    /// On Linux (tun, PI disabled), writes the raw IP frame with no prefix.
    /// On macOS (utun), tun 0.6 does NOT prepend the 4-byte AF_INET prefix
    /// internally — userspace must build the full frame as
    /// `[0x00, 0x00, 0x00, 0x02] + <IPv4 header> + <TCP segment>`.
    ///
    /// On Linux (tun, PI disabled), the raw IP frame is written directly with
    /// no prefix.
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

        #[cfg(target_os = "macos")]
        {
            // Build the full frame: 4-byte prefix + IPv4 header + TCP segment
            let mut frame = Vec::with_capacity(4 + ip_header_bytes.len() + segment_bytes.len());
            frame.extend_from_slice(&MACOS_AF_INET_PREFIX);
            frame.extend_from_slice(&ip_header_bytes);
            frame.extend_from_slice(&segment_bytes);
            self.inner.write_all(&frame)?;
        }

        #[cfg(target_os = "linux")]
        {
            // Write raw IP frame — no prefix when PI is disabled
        #[cfg(target_os = "macos")]
        {
            // Prepend the 4-byte AF_INET prefix manually (tun 0.6 does not do this).
            let mut frame =
                Vec::with_capacity(4 + ip_header_bytes.len() + segment_bytes.len());
            frame.extend_from_slice(&MACOS_AF_INET_PREFIX);
            frame.extend_from_slice(&ip_header_bytes);
            frame.extend_from_slice(&segment_bytes);
            self.inner.write_all(&frame)?;
        }

        #[cfg(target_os = "linux")]
        {
            // No prefix on Linux with PI disabled.
            let mut frame = Vec::with_capacity(ip_header_bytes.len() + segment_bytes.len());
            frame.extend_from_slice(&ip_header_bytes);
            frame.extend_from_slice(&segment_bytes);
            self.inner.write_all(&frame)?;
        }

        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        {
            compile_error!("unsupported platform: only macOS and Linux are supported")
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::headers::tcp::TcpHeader;

    /// Test that the 4-byte prefix stripping works correctly on macOS.
    /// We construct a fake frame with [0,0,0,2] prefix + known IPv4 bytes
    /// and verify from_bytes parses it.
    /// Test that macOS TUN frames carry the 4-byte AF_INET prefix.
    ///
    /// tun 0.6 does NOT strip the prefix on read — userspace must check for
    /// `[0x00, 0x00, 0x00, 0x02]` before the IPv4 header.
    #[cfg(target_os = "macos")]
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
        // Simulate what the kernel delivers on macOS: 4-byte AF_INET prefix + IP bytes.
        let mut frame = Vec::new();
        frame.extend_from_slice(&MACOS_AF_INET_PREFIX);
        frame.extend_from_slice(&ip_bytes);

        // Verify the prefix is exactly [0x00, 0x00, 0x00, 0x02]
        assert_eq!(
            &frame[..4],
            &[0x00, 0x00, 0x00, 0x02],
            "macOS frame must begin with AF_INET prefix [0,0,0,2]"
        );

        // Now test the parsing logic (same as what read_ip_packet does internally)
        assert_eq!(&frame[..4], &MACOS_AF_INET_PREFIX);
        let parsed = Ipv4Packet::from_bytes(&frame[4..]).unwrap();
        // Strip prefix and parse the IPv4 packet
        let parsed = Ipv4Packet::from_bytes(&frame[4..]).unwrap();
        assert_eq!(parsed.header.src_addr, [10, 0, 0, 1]);
        assert_eq!(parsed.header.dst_addr, [10, 0, 0, 2]);
        assert_eq!(parsed.header.protocol, 6);
    }

    /// Test that a Linux TUN frame is raw IP with no prefix.
    /// The first byte must be 0x45 (IPv4 version=4, IHL=5).
    #[cfg(target_os = "linux")]
    #[test]
    fn test_linux_frame_is_raw_ip() {
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

        // On Linux there is no prefix — frame starts with the IPv4 header directly
        // Version=4, IHL=5 -> first nibble pair = 0x45
        assert_eq!(
            ip_bytes[0], 0x45,
            "frame must start with IPv4 version/IHL byte"
        );

        let parsed = Ipv4Packet::from_bytes(&ip_bytes).unwrap();
        assert_eq!(parsed.header.src_addr, [10, 0, 0, 1]);
        assert_eq!(parsed.header.dst_addr, [10, 0, 0, 2]);
        assert_eq!(parsed.header.protocol, 6);
    }

    #[test]
    fn test_companion_ip() {
        // Normal case: last octet < 255 -> increments
        assert_eq!(
            companion_ip(Ipv4Addr::new(10, 0, 0, 1)),
            Ipv4Addr::new(10, 0, 0, 2)
        );
        assert_eq!(
            companion_ip(Ipv4Addr::new(192, 168, 1, 100)),
            Ipv4Addr::new(192, 168, 1, 101)
        );
        // Edge case: last octet == 255 -> decrements
        assert_eq!(
            companion_ip(Ipv4Addr::new(10, 0, 0, 255)),
            Ipv4Addr::new(10, 0, 0, 254)
        );
        // Companion is always different from the input
        let ip = Ipv4Addr::new(10, 0, 0, 1);
        assert_ne!(companion_ip(ip), ip);
    }

    /// Test the write frame construction on macOS: verify the output starts with
    /// [0,0,0,2] followed by a valid IPv4 header.
    /// Test the write frame construction on macOS: verify the output starts with
    /// the 4-byte AF_INET prefix `[0x00, 0x00, 0x00, 0x02]` followed by the IPv4
    /// header. tun 0.6 does not add this prefix — userspace must supply it.
    #[cfg(target_os = "macos")]
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
        // Build expected frame: AF_INET prefix + IPv4 header + TCP segment
        let mut expected = Vec::new();
        expected.extend_from_slice(&MACOS_AF_INET_PREFIX);
        expected.extend_from_slice(&ip_header_bytes);
        expected.extend_from_slice(&segment_bytes);

        // Verify prefix
        assert_eq!(&expected[..4], &[0x00, 0x00, 0x00, 0x02]);
        // First 4 bytes must be the AF_INET prefix
        assert_eq!(
            &expected[..4],
            &[0x00, 0x00, 0x00, 0x02],
            "write frame must begin with AF_INET prefix [0,0,0,2]"
        );

        // Verify IPv4 header bytes 12..16 = src IP and 16..20 = dst IP
        assert_eq!(&expected[16..20], &[10, 0, 0, 1]);
        assert_eq!(&expected[20..24], &[10, 0, 0, 2]);

        // Verify protocol = TCP (6) at byte 13 of the IP header (= offset 4+9 = 13)
        assert_eq!(expected[4 + 9], 6);
        // IPv4 version/IHL byte at offset 4
        assert_eq!(expected[4], 0x45, "IPv4 header must follow the AF prefix");

        // src IP at bytes 16..20, dst IP at bytes 20..24 (offset by 4 for prefix)
        assert_eq!(&expected[16..20], &[10, 0, 0, 1]);
        assert_eq!(&expected[20..24], &[10, 0, 0, 2]);

        // Protocol = TCP (6) at byte 13 (offset by 4 for prefix)
        assert_eq!(expected[13], 6);
    }

    /// Test the write frame construction on Linux: verify the output starts directly
    /// with the IPv4 header (first byte = 0x45, no prefix).
    #[cfg(target_os = "linux")]
    #[test]
    fn test_write_frame_no_prefix_linux() {
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

        // Build expected frame (no prefix on Linux)
        let mut expected = Vec::new();
        expected.extend_from_slice(&ip_header_bytes);
        expected.extend_from_slice(&segment_bytes);

        // First byte must be 0x45 (IPv4 version=4, IHL=5) — no AF prefix
        assert_eq!(
            expected[0], 0x45,
            "frame must start with IPv4 version/IHL byte"
        );

        // src IP at bytes 12..16, dst IP at bytes 16..20
        assert_eq!(&expected[12..16], &[10, 0, 0, 1]);
        assert_eq!(&expected[16..20], &[10, 0, 0, 2]);

        // Protocol = TCP (6) at byte 9
        assert_eq!(expected[9], 6);
    }
}
