use std::net::Ipv4Addr;

use colored::Colorize;

use crate::common::traits::FromBytes;
use crate::proto::connection::{TcpAction, TcpConnection, TcpState};
use crate::proto::headers::tcp::TcpHeader;
use crate::proto::packet::TcpSegment;
use crate::proto::tun::TunDevice;

/// Drive the active-open three-way handshake to completion.
///
/// `conn` must be in `SynSent` state (created via `TcpConnection::new_connector`).
/// `syn_hdr` is the SYN header returned by `new_connector`.
///
/// Sends the SYN, then reads from `tun` until the connection reaches `Established`.
pub fn connect(
    tun: &mut TunDevice,
    conn: &mut TcpConnection,
    syn_hdr: TcpHeader,
) -> std::io::Result<()> {
    let local_ip = *conn.local_addr.ip();
    let remote_addr = conn
        .remote_addr
        .expect("connector requires remote_addr to be set");
    let remote_ip = *remote_addr.ip();
    let remote_port = remote_addr.port();

    log::info!("connecting to {}", remote_addr);

    // Send initial SYN
    let isn = syn_hdr.seq_num;
    let segment = TcpSegment::new(syn_hdr, vec![]).with_checksum(&local_ip, &remote_ip)?;
    tun.write_ip_packet(local_ip, remote_ip, &segment)?;
    log::debug!("sent SYN seq={}", isn);

    // Wait for SYN-ACK and complete the handshake
    loop {
        let pkt = match tun.read_ip_packet()? {
            Some(p) => p,
            None => continue,
        };

        if pkt.header.protocol != 6 {
            continue;
        }
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

        let src_ip = Ipv4Addr::from(pkt.header.src_addr);

        // Filter: only from the remote we're connecting to, for our local port
        if src_ip != remote_ip || seg_hdr.src_port != remote_port {
            continue;
        }
        if seg_hdr.dst_port != conn.local_addr.port() {
            continue;
        }

        let hdr_len = seg_hdr.header_len().max(20);
        let tcp_payload = if pkt.payload.len() > hdr_len {
            pkt.payload[hdr_len..].to_vec()
        } else {
            vec![]
        };

        if seg_hdr.syn && seg_hdr.ack {
            log::debug!(
                "recv SYN-ACK seq={} ack={}",
                seg_hdr.seq_num,
                seg_hdr.ack_num
            );
        }

        let actions = conn.handle(&seg_hdr, &tcp_payload);

        for action in actions {
            match action {
                TcpAction::Send(hdr, payload) => {
                    if hdr.ack && !hdr.syn {
                        log::debug!("sent ACK seq={} ack={}", hdr.seq_num, hdr.ack_num);
                    }
                    let segment =
                        TcpSegment::new(hdr, payload).with_checksum(&local_ip, &remote_ip)?;
                    tun.write_ip_packet(local_ip, remote_ip, &segment)?;
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
            log::info!(
                "connection established with {}",
                format!("{}", remote_addr).green()
            );
            return Ok(());
        }
    }
}
