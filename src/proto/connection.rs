use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::common::traits::FromBytes;
use crate::proto::headers::tcp::TcpHeader;
use crate::proto::packet::TcpSegment;
use crate::proto::tun::TunDevice;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TcpState {
    Closed,
    Listen,
    SynSent,
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
    LastAck,
    TimeWait,
}

#[derive(Debug)]
pub enum TcpAction {
    Send(TcpHeader, Vec<u8>),
    Deliver(Vec<u8>),
    Close,
    Reset,
}

pub struct TcpConnection {
    pub state: TcpState,
    pub local_addr: SocketAddrV4,
    pub remote_addr: Option<SocketAddrV4>,
    pub send_seq: u32,
    pub recv_seq: u32,
    pub send_window: u16,
    pub recv_window: u16,
}

impl TcpConnection {
    fn derive_isn(local_port: u16) -> u32 {
        let secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        (secs as u32) ^ (local_port as u32)
    }

    pub fn new_listener(local: SocketAddrV4) -> Self {
        Self {
            state: TcpState::Listen,
            local_addr: local,
            remote_addr: None,
            send_seq: 0,
            recv_seq: 0,
            send_window: 65535,
            recv_window: 65535,
        }
    }

    pub fn handle(&mut self, seg: &TcpHeader, payload: &[u8]) -> Vec<TcpAction> {
        // Rule 1: RST in any state → Closed
        if seg.rst {
            self.state = TcpState::Closed;
            return vec![TcpAction::Close];
        }

        let local_port = self.local_addr.port();
        let remote_port = seg.src_port;

        match self.state {
            // Rule 2: Listen + SYN (not ACK)
            TcpState::Listen if seg.syn && !seg.ack => {
                let isn = Self::derive_isn(local_port);
                self.send_seq = isn.wrapping_add(1);
                self.recv_seq = seg.seq_num.wrapping_add(1);
                self.state = TcpState::SynReceived;
                let hdr = TcpHeader::syn_ack(local_port, remote_port, isn, self.recv_seq);
                vec![TcpAction::Send(hdr, vec![])]
            }

            // Rule 3: SynReceived + ACK (ack_num matches send_seq)
            TcpState::SynReceived if seg.ack && seg.ack_num == self.send_seq => {
                self.state = TcpState::Established;
                vec![]
            }

            // Rule 4: Established + data (PSH or non-empty payload, not FIN, not RST)
            TcpState::Established if (seg.psh || !payload.is_empty()) && !seg.fin => {
                self.recv_seq = seg.seq_num.wrapping_add(payload.len() as u32);
                let ack_hdr = TcpHeader::ack(local_port, remote_port, self.send_seq, self.recv_seq);
                vec![
                    TcpAction::Send(ack_hdr, vec![]),
                    TcpAction::Deliver(payload.to_vec()),
                ]
            }

            // Rule 5: Established + FIN
            TcpState::Established if seg.fin => {
                self.recv_seq = seg.seq_num.wrapping_add(1);
                self.state = TcpState::CloseWait;
                let ack_hdr = TcpHeader::ack(local_port, remote_port, self.send_seq, self.recv_seq);
                vec![TcpAction::Send(ack_hdr, vec![])]
            }

            // Rule 6: FinWait1 + ACK (ack_num matches send_seq)
            TcpState::FinWait1 if seg.ack && seg.ack_num == self.send_seq => {
                self.state = TcpState::FinWait2;
                vec![]
            }

            // Rule 7: FinWait2 + FIN
            TcpState::FinWait2 if seg.fin => {
                self.recv_seq = seg.seq_num.wrapping_add(1);
                // Transition through TimeWait to Closed
                self.state = TcpState::Closed;
                let ack_hdr = TcpHeader::ack(local_port, remote_port, self.send_seq, self.recv_seq);
                vec![TcpAction::Send(ack_hdr, vec![]), TcpAction::Close]
            }

            // Rule 8: LastAck + ACK (ack_num matches send_seq)
            TcpState::LastAck if seg.ack && seg.ack_num == self.send_seq => {
                self.state = TcpState::Closed;
                vec![TcpAction::Close]
            }

            _ => vec![],
        }
    }

    pub fn close(&mut self) -> Option<TcpAction> {
        let local_port = self.local_addr.port();
        let remote_port = self.remote_addr.map(|a| a.port()).unwrap_or(0);

        match self.state {
            TcpState::Established => {
                self.state = TcpState::FinWait1;
                self.send_seq = self.send_seq.wrapping_add(1);
                let hdr = TcpHeader::fin_ack(
                    local_port,
                    remote_port,
                    self.send_seq.wrapping_sub(1),
                    self.recv_seq,
                );
                Some(TcpAction::Send(hdr, vec![]))
            }
            TcpState::CloseWait => {
                self.state = TcpState::LastAck;
                self.send_seq = self.send_seq.wrapping_add(1);
                let hdr = TcpHeader::fin_ack(
                    local_port,
                    remote_port,
                    self.send_seq.wrapping_sub(1),
                    self.recv_seq,
                );
                Some(TcpAction::Send(hdr, vec![]))
            }
            _ => None,
        }
    }

    pub fn send_data(&mut self, data: &[u8]) -> Vec<TcpAction> {
        if self.state != TcpState::Established {
            return vec![];
        }
        let src_port = self.local_addr.port();
        let dst_port = self.remote_addr.map(|a| a.port()).unwrap_or(0);
        let seq = self.send_seq;
        let ack = self.recv_seq;
        let hdr = TcpHeader::psh_ack(src_port, dst_port, seq, ack);
        self.send_seq = self.send_seq.wrapping_add(data.len() as u32);
        vec![TcpAction::Send(hdr, data.to_vec())]
    }

    pub fn run(self, tun: TunDevice) -> std::io::Result<()> {
        use std::io::{BufRead, Write};
        use std::sync::{Arc, Mutex, mpsc};

        let conn = Arc::new(Mutex::new(self));
        let tun = Arc::new(Mutex::new(tun));

        let (out_tx, out_rx) = mpsc::channel::<(TcpHeader, Vec<u8>)>();

        // Thread 2 (send): read stdin lines → call send_data → queue segments
        let conn_send = Arc::clone(&conn);
        std::thread::spawn(move || {
            let stdin = std::io::stdin();
            let mut line = String::new();
            loop {
                line.clear();
                let n = stdin.lock().read_line(&mut line).unwrap_or(0);
                if n == 0 {
                    // EOF: initiate close
                    let mut c = conn_send.lock().unwrap();
                    if let Some(TcpAction::Send(hdr, payload)) = c.close() {
                        out_tx.send((hdr, payload)).ok();
                    }
                    break;
                }
                let mut c = conn_send.lock().unwrap();
                for action in c.send_data(line.as_bytes()) {
                    if let TcpAction::Send(hdr, payload) = action {
                        out_tx.send((hdr, payload)).ok();
                    }
                }
            }
        });

        // Thread 1 (recv): main thread owns TUN read; drains outgoing queue between reads
        let stdout = std::io::stdout();
        loop {
            // Drain any queued outgoing segments from send thread
            while let Ok((hdr, payload)) = out_rx.try_recv() {
                let c = conn.lock().unwrap();
                let local_ip = *c.local_addr.ip();
                let remote_ip = c.remote_addr.map(|a| *a.ip()).unwrap_or(local_ip);
                drop(c);
                let segment = TcpSegment::new(hdr, payload)
                    .with_checksum(&local_ip, &remote_ip)?;
                tun.lock().unwrap().write_ip_packet(local_ip, remote_ip, &segment)?;
            }

            // Blocking TUN read
            let pkt = {
                let mut t = tun.lock().unwrap();
                t.read_ip_packet()?
            };
            let pkt = match pkt {
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
                Err(_) => continue,
            };

            let remote_ip = Ipv4Addr::from(pkt.header.src_addr);

            // Filter: only packets from our established remote
            {
                let c = conn.lock().unwrap();
                if let Some(remote_addr) = c.remote_addr {
                    if *remote_addr.ip() != remote_ip || remote_addr.port() != seg_hdr.src_port {
                        continue;
                    }
                }
            }

            let hdr_len = (seg_hdr.data_offset as usize * 4).max(20);
            let tcp_payload = if pkt.payload.len() > hdr_len {
                pkt.payload[hdr_len..].to_vec()
            } else {
                vec![]
            };

            let local_ip = {
                let c = conn.lock().unwrap();
                *c.local_addr.ip()
            };

            let actions = conn.lock().unwrap().handle(&seg_hdr, &tcp_payload);

            let mut should_close = false;
            for action in actions {
                match action {
                    TcpAction::Send(hdr, payload) => {
                        let segment = TcpSegment::new(hdr, payload)
                            .with_checksum(&local_ip, &remote_ip)?;
                        tun.lock().unwrap().write_ip_packet(local_ip, remote_ip, &segment)?;
                    }
                    TcpAction::Deliver(data) => {
                        let mut out = stdout.lock();
                        out.write_all(&data)?;
                        out.flush()?;
                    }
                    TcpAction::Close | TcpAction::Reset => {
                        should_close = true;
                    }
                }
            }

            if should_close {
                break;
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn syn_seg(seq: u32) -> TcpHeader {
        TcpHeader { syn: true, seq_num: seq, ..Default::default() }
    }

    fn ack_seg(seq: u32, ack_num: u32) -> TcpHeader {
        TcpHeader { ack: true, seq_num: seq, ack_num, ..Default::default() }
    }

    fn psh_ack_seg(seq: u32, ack_num: u32) -> TcpHeader {
        TcpHeader { psh: true, ack: true, seq_num: seq, ack_num, ..Default::default() }
    }

    fn fin_ack_seg(seq: u32, ack_num: u32) -> TcpHeader {
        TcpHeader { fin: true, ack: true, seq_num: seq, ack_num, ..Default::default() }
    }

    fn rst_seg() -> TcpHeader {
        TcpHeader { rst: true, ..Default::default() }
    }

    #[test]
    fn test_syn_received() {
        let mut conn = TcpConnection::new_listener("10.0.0.1:4444".parse().unwrap());
        let syn = syn_seg(1000);
        let actions = conn.handle(&syn, &[]);
        assert_eq!(conn.state, TcpState::SynReceived);
        assert_eq!(conn.recv_seq, 1001);
        let has_syn_ack = actions.iter().any(|a| matches!(a, TcpAction::Send(h, _) if h.syn && h.ack));
        assert!(has_syn_ack, "should send SYN-ACK");
    }

    #[test]
    fn test_three_way_handshake() {
        let mut conn = TcpConnection::new_listener("10.0.0.1:4444".parse().unwrap());
        conn.handle(&syn_seg(1000), &[]);
        assert_eq!(conn.state, TcpState::SynReceived);

        let final_ack = ack_seg(1001, conn.send_seq);
        let actions = conn.handle(&final_ack, &[]);
        assert_eq!(conn.state, TcpState::Established);
        assert!(actions.is_empty());
    }

    #[test]
    fn test_data_transfer() {
        let mut conn = TcpConnection::new_listener("10.0.0.1:4444".parse().unwrap());
        conn.handle(&syn_seg(1000), &[]);
        conn.handle(&ack_seg(1001, conn.send_seq), &[]);
        assert_eq!(conn.state, TcpState::Established);

        let data = b"hello";
        let psh = psh_ack_seg(1001, conn.send_seq);
        let actions = conn.handle(&psh, data);

        let has_deliver = actions.iter().any(|a| matches!(a, TcpAction::Deliver(d) if d == b"hello"));
        let has_ack = actions.iter().any(|a| matches!(a, TcpAction::Send(h, _) if h.ack && !h.syn));
        assert!(has_deliver, "should deliver data to application");
        assert!(has_ack, "should send ACK");
        assert_eq!(conn.recv_seq, 1001 + 5);
    }

    #[test]
    fn test_passive_close() {
        let mut conn = TcpConnection::new_listener("10.0.0.1:4444".parse().unwrap());
        conn.handle(&syn_seg(1000), &[]);
        conn.handle(&ack_seg(1001, conn.send_seq), &[]);
        assert_eq!(conn.state, TcpState::Established);

        // Remote sends FIN
        let fin = fin_ack_seg(1001, conn.send_seq);
        let actions = conn.handle(&fin, &[]);
        assert_eq!(conn.state, TcpState::CloseWait);
        let has_ack = actions.iter().any(|a| matches!(a, TcpAction::Send(h, _) if h.ack));
        assert!(has_ack);

        // We initiate our close
        let close_action = conn.close().expect("close should return an action");
        assert_eq!(conn.state, TcpState::LastAck);
        assert!(matches!(close_action, TcpAction::Send(h, _) if h.fin));

        // Remote ACKs our FIN
        let final_ack = ack_seg(1002, conn.send_seq);
        let actions = conn.handle(&final_ack, &[]);
        assert_eq!(conn.state, TcpState::Closed);
        assert!(actions.iter().any(|a| matches!(a, TcpAction::Close)));
    }

    #[test]
    fn test_rst_closes_connection() {
        let mut conn = TcpConnection::new_listener("10.0.0.1:4444".parse().unwrap());
        conn.handle(&syn_seg(1000), &[]);
        conn.handle(&ack_seg(1001, conn.send_seq), &[]);
        assert_eq!(conn.state, TcpState::Established);

        let actions = conn.handle(&rst_seg(), &[]);
        assert_eq!(conn.state, TcpState::Closed);
        assert!(actions.iter().any(|a| matches!(a, TcpAction::Close)));
    }

    #[test]
    fn test_sequence_numbers() {
        let mut conn = TcpConnection::new_listener("10.0.0.1:4444".parse().unwrap());
        conn.handle(&syn_seg(5000), &[]);
        let send_seq_after_syn_ack = conn.send_seq;
        conn.handle(&ack_seg(5001, conn.send_seq), &[]);

        // Send some data
        let payload = b"world";
        conn.handle(&psh_ack_seg(5001, conn.send_seq), payload);
        assert_eq!(conn.recv_seq, 5001 + payload.len() as u32);

        // send_seq should not change when receiving data (only changes when we send)
        assert_eq!(conn.send_seq, send_seq_after_syn_ack);
    }

    fn established_conn() -> TcpConnection {
        let mut conn = TcpConnection::new_listener("10.0.0.1:4444".parse().unwrap());
        conn.remote_addr = Some("10.0.0.2:5555".parse().unwrap());
        conn.state = TcpState::Established;
        conn.send_seq = 1000;
        conn.recv_seq = 2000;
        conn
    }

    #[test]
    fn test_send_data_advances_seq() {
        let mut conn = established_conn();
        let initial_seq = conn.send_seq;
        let actions = conn.send_data(b"hello");
        assert_eq!(conn.send_seq, initial_seq + 5);
        assert_eq!(actions.len(), 1);
        match &actions[0] {
            TcpAction::Send(hdr, payload) => {
                assert!(hdr.psh, "should have PSH flag");
                assert!(hdr.ack, "should have ACK flag");
                assert_eq!(hdr.seq_num, initial_seq);
                assert_eq!(hdr.ack_num, conn.recv_seq);
                assert_eq!(payload, b"hello");
            }
            _ => panic!("expected TcpAction::Send"),
        }
    }

    #[test]
    fn test_recv_data_delivers_and_acks() {
        let mut conn = established_conn();
        let initial_recv_seq = conn.recv_seq;
        let hdr = TcpHeader {
            psh: true,
            ack: true,
            seq_num: initial_recv_seq,
            ack_num: conn.send_seq,
            src_port: 5555,
            ..Default::default()
        };
        let actions = conn.handle(&hdr, b"world");
        assert_eq!(conn.recv_seq, initial_recv_seq + 5, "recv_seq should advance by payload len");
        let has_deliver = actions.iter().any(|a| matches!(a, TcpAction::Deliver(d) if d == b"world"));
        let has_ack = actions.iter().any(|a| matches!(a, TcpAction::Send(h, _) if h.ack && !h.syn));
        assert!(has_deliver, "should deliver data");
        assert!(has_ack, "should send ACK");
    }

    #[test]
    fn test_send_data_not_established() {
        let mut conn = TcpConnection::new_listener("10.0.0.1:4444".parse().unwrap());
        let actions = conn.send_data(b"hello");
        assert!(actions.is_empty(), "send_data should do nothing when not Established");
    }

    #[test]
    fn test_active_close_fin_wait() {
        let mut conn = TcpConnection::new_listener("10.0.0.1:4444".parse().unwrap());
        conn.handle(&syn_seg(1000), &[]);
        conn.handle(&ack_seg(1001, conn.send_seq), &[]);
        assert_eq!(conn.state, TcpState::Established);

        // We initiate close
        let close_action = conn.close().expect("close should return action");
        assert_eq!(conn.state, TcpState::FinWait1);
        assert!(matches!(close_action, TcpAction::Send(h, _) if h.fin));

        // Remote ACKs our FIN
        let ack = ack_seg(1001, conn.send_seq);
        conn.handle(&ack, &[]);
        assert_eq!(conn.state, TcpState::FinWait2);

        // Remote sends FIN
        let fin = fin_ack_seg(1001, conn.send_seq);
        let actions = conn.handle(&fin, &[]);
        assert_eq!(conn.state, TcpState::Closed);
        assert!(actions.iter().any(|a| matches!(a, TcpAction::Close)));
    }
}
