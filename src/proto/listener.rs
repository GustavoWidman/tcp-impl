use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use colored::Colorize;

use crate::common::traits::FromBytes;
use crate::proto::connection::{TcpAction, TcpConnection, TcpState};
use crate::proto::headers::tcp::TcpHeader;
use crate::proto::packet::TcpSegment;
use crate::proto::tun::TunDevice;

pub struct TcpListener {
    tun: TunDevice,
    local_ip: Ipv4Addr,
    port: u16,
}

impl TcpListener {
    pub fn new(tun: TunDevice, local_ip: Ipv4Addr, port: u16) -> Self {
        Self {
            tun,
            local_ip,
            port,
        }
    }

    /// Consume the listener and return the underlying TUN device.
    pub fn into_tun(self) -> TunDevice {
        self.tun
    }

    pub fn accept(&mut self, shutdown: Arc<AtomicBool>) -> std::io::Result<TcpConnection> {
        log::info!("listening on {}:{}", self.local_ip, self.port);

        let local_addr: SocketAddrV4 =
            format!("{}:{}", self.local_ip, self.port)
                .parse()
                .map_err(|e| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!("invalid addr: {e}"),
                    )
                })?;

        let mut conn = TcpConnection::new_listener(local_addr);

        loop {
            if shutdown.load(Ordering::Relaxed) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Interrupted,
                    "shutdown",
                ));
            }

            let pkt = match self.tun.read_ip_packet_timeout(Duration::from_millis(50))? {
                Some(p) => p,
                None => continue,
            };

            // Skip non-TCP
            if pkt.header.protocol != 6 {
                continue;
            }

            // Parse TCP header (at least 20 bytes needed)
            if pkt.payload.len() < 20 {
                continue;
            }
            let seg_hdr = match TcpHeader::from_bytes(&pkt.payload) {
                Ok(h) => h,
                Err(e) => {
                    log::warn!("failed to parse TCP header: {e}");
                    continue;
                }
            };

            // Skip if not our port
            if seg_hdr.dst_port != self.port {
                continue;
            }

            let remote_ip = Ipv4Addr::from(pkt.header.src_addr);
            let remote_port = seg_hdr.src_port;

            // Compute actual payload (skip TCP options via data_offset)
            let hdr_len = seg_hdr.header_len().max(20);
            let tcp_payload = if pkt.payload.len() > hdr_len {
                &pkt.payload[hdr_len..]
            } else {
                &[]
            };

            // Log incoming segment
            match &conn.state {
                TcpState::Listen if seg_hdr.syn && !seg_hdr.ack => {
                    log::debug!("{} recv SYN seq={}", "<-".cyan(), seg_hdr.seq_num);
                }
                TcpState::SynReceived if seg_hdr.ack => {
                    log::debug!("{} recv ACK — connection established", "<-".cyan());
                }
                _ => {}
            }

            let actions = conn.handle(&seg_hdr, tcp_payload);

            for action in actions {
                match action {
                    TcpAction::Send(hdr, payload) => {
                        if hdr.syn && hdr.ack {
                            log::debug!(
                                "{} sent SYN-ACK seq={} ack={}",
                                "->".green(),
                                hdr.seq_num,
                                hdr.ack_num
                            );
                            log::info!(
                                "connection from {}",
                                format!("{}:{}", remote_ip, remote_port).blue()
                            );
                        }
                        let segment = TcpSegment::new(hdr, payload)
                            .with_checksum(&self.local_ip, &remote_ip)?;
                        self.tun
                            .write_ip_packet(self.local_ip, remote_ip, &segment)?;
                    }
                    TcpAction::Close | TcpAction::Reset => {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::ConnectionReset,
                            "connection reset during handshake",
                        ));
                    }
                    TcpAction::Deliver(_) => {}
                }
            }

            if conn.state == TcpState::Established {
                conn.remote_addr = Some(SocketAddrV4::new(remote_ip, remote_port));
                return Ok(conn);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::connection::TcpAction;

    #[test]
    fn test_handshake_segment_sequence() {
        // SYN from 10.0.0.2:54321 -> 10.0.0.1:4444, seq=100
        let mut conn = TcpConnection::new_listener("10.0.0.1:4444".parse().unwrap());
        let syn_hdr = TcpHeader {
            src_port: 54321,
            dst_port: 4444,
            seq_num: 100,
            syn: true,
            window_size: 65535,
            ..Default::default()
        };

        let actions = conn.handle(&syn_hdr, &[]);
        assert!(matches!(conn.state, TcpState::SynReceived));

        // Should produce exactly one Send(SYN+ACK)
        assert_eq!(actions.len(), 1);
        let (reply_hdr, _) = match &actions[0] {
            TcpAction::Send(h, p) => (h, p),
            _ => panic!("expected TcpAction::Send"),
        };
        assert!(reply_hdr.syn && reply_hdr.ack, "reply must be SYN+ACK");
        assert_eq!(reply_hdr.ack_num, 101, "ack_num must be remote seq + 1");

        // ACK completing the handshake
        let ack_hdr = TcpHeader {
            src_port: 54321,
            dst_port: 4444,
            seq_num: 101,
            ack_num: reply_hdr.seq_num.wrapping_add(1),
            ack: true,
            window_size: 65535,
            ..Default::default()
        };
        let actions2 = conn.handle(&ack_hdr, &[]);
        assert!(matches!(conn.state, TcpState::Established));
        assert!(
            actions2.is_empty(),
            "no reply needed for the completing ACK"
        );
    }
}
