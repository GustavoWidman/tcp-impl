use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use colored::Colorize;

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
    #[allow(dead_code)] // 2MSL timer not implemented; FinWait2 goes directly to Closed
    TimeWait,
}

#[derive(Debug)]
pub enum TcpAction {
    Send(TcpHeader, Vec<u8>),
    Deliver(Vec<u8>),
    Close,
    #[allow(dead_code)] // RST sending not yet implemented; RST receipt transitions to Close
    Reset,
}

pub struct TcpConnection {
    pub state: TcpState,
    pub local_addr: SocketAddrV4,
    pub remote_addr: Option<SocketAddrV4>,
    pub send_seq: u32,
    pub recv_seq: u32,
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
        }
    }

    /// Create a connection in SynSent state for active open. Returns the connection
    /// and the initial SYN header that the caller must send.
    pub fn new_connector(local: SocketAddrV4, remote: SocketAddrV4) -> (Self, TcpHeader) {
        let isn = Self::derive_isn(local.port());
        let conn = Self {
            state: TcpState::SynSent,
            local_addr: local,
            remote_addr: Some(remote),
            send_seq: isn.wrapping_add(1), // SYN consumes one sequence number
            recv_seq: 0,
        };
        let hdr = TcpHeader::syn(local.port(), remote.port(), isn);
        (conn, hdr)
    }

    pub fn handle(&mut self, seg: &TcpHeader, payload: &[u8]) -> Vec<TcpAction> {
        // Rule 1: RST in any state -> Closed
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

            // SynSent + SYN-ACK (ack_num matches our send_seq) -> Established, send ACK
            TcpState::SynSent if seg.syn && seg.ack && seg.ack_num == self.send_seq => {
                self.recv_seq = seg.seq_num.wrapping_add(1);
                self.state = TcpState::Established;
                let ack_hdr = TcpHeader::ack(local_port, remote_port, self.send_seq, self.recv_seq);
                vec![TcpAction::Send(ack_hdr, vec![])]
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

            // Rule 6b: FinWait1 + FIN (simultaneous close — their FIN arrives before our ACK)
            TcpState::FinWait1 if seg.fin => {
                self.recv_seq = seg.seq_num.wrapping_add(1);
                self.state = TcpState::Closing;
                let ack_hdr = TcpHeader::ack(local_port, remote_port, self.send_seq, self.recv_seq);
                vec![TcpAction::Send(ack_hdr, vec![])]
            }

            // Rule 7: FinWait2 + FIN
            TcpState::FinWait2 if seg.fin => {
                self.recv_seq = seg.seq_num.wrapping_add(1);
                // Skip TimeWait: no 2MSL timer in this impl
                self.state = TcpState::Closed;
                let ack_hdr = TcpHeader::ack(local_port, remote_port, self.send_seq, self.recv_seq);
                vec![TcpAction::Send(ack_hdr, vec![]), TcpAction::Close]
            }

            // Rule 8: LastAck + ACK (ack_num matches send_seq)
            TcpState::LastAck if seg.ack && seg.ack_num == self.send_seq => {
                self.state = TcpState::Closed;
                vec![TcpAction::Close]
            }

            // Rule 9: Closing + ACK -> TimeWait -> Closed (immediate, no 2*MSL)
            TcpState::Closing if seg.ack && seg.ack_num == self.send_seq => {
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

    /// Read the next chunk of application data from the TCP connection.
    ///
    /// Polls the TUN device with a short timeout. If a TCP segment arrives,
    /// processes it through the state machine and returns any delivered payload.
    /// Returns `Ok(None)` if the timeout expires without data, or if the
    /// connection has closed.
    pub fn read(&mut self, tun: &mut TunDevice) -> std::io::Result<Option<Vec<u8>>> {
        let pkt = match tun.read_ip_packet_timeout(Duration::from_millis(50))? {
            Some(p) => p,
            None => return Ok(None),
        };

        if pkt.header.protocol != 6 {
            return Ok(None);
        }
        if pkt.payload.len() < 20 {
            return Ok(None);
        }

        let seg_hdr = match TcpHeader::from_bytes(&pkt.payload) {
            Ok(h) => h,
            Err(_) => return Ok(None),
        };

        let remote_ip = Ipv4Addr::from(pkt.header.src_addr);

        // Filter: only packets from our established remote
        if let Some(remote_addr) = self.remote_addr
            && (*remote_addr.ip() != remote_ip || remote_addr.port() != seg_hdr.src_port)
        {
            return Ok(None);
        }

        let hdr_len = seg_hdr.header_len().max(20);
        let tcp_payload = if pkt.payload.len() > hdr_len {
            pkt.payload[hdr_len..].to_vec()
        } else {
            vec![]
        };

        let local_ip = *self.local_addr.ip();

        let actions = self.handle(&seg_hdr, &tcp_payload);

        let mut delivered = None;
        let mut should_close = false;

        for action in actions {
            match action {
                TcpAction::Send(hdr, payload) => {
                    if hdr.ack && !hdr.psh && !hdr.fin {
                        log::debug!(
                            "{} sent ACK seq={} ack={}",
                            "->".green(),
                            hdr.seq_num,
                            hdr.ack_num
                        );
                    }
                    let segment =
                        TcpSegment::new(hdr, payload).with_checksum(&local_ip, &remote_ip)?;
                    tun.write_ip_packet(local_ip, remote_ip, &segment)?;
                }
                TcpAction::Deliver(data) => {
                    delivered = Some(data);
                }
                TcpAction::Close | TcpAction::Reset => {
                    should_close = true;
                }
            }
        }

        // If remote closed first, complete our half of the close.
        if self.state == TcpState::CloseWait
            && let Some(TcpAction::Send(hdr, payload)) = self.close()
        {
            let remote_ip = self.remote_addr.map(|a| *a.ip()).unwrap_or(local_ip);
            log::debug!(
                "{} sent FIN+ACK seq={} ack={}",
                "->".green(),
                hdr.seq_num,
                hdr.ack_num
            );
            let segment = TcpSegment::new(hdr, payload).with_checksum(&local_ip, &remote_ip)?;
            tun.write_ip_packet(local_ip, remote_ip, &segment)?;
        }

        if should_close {
            return Ok(None);
        }

        Ok(delivered)
    }

    /// Send application data through the TCP connection.
    ///
    /// Calls `send_data` to produce the PSH+ACK segment, then writes the
    /// resulting segment to the TUN device.
    pub fn write(&mut self, tun: &mut TunDevice, data: &[u8]) -> std::io::Result<()> {
        let local_ip = *self.local_addr.ip();
        let remote_ip = self.remote_addr.map(|a| *a.ip()).ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::NotConnected, "no remote addr")
        })?;

        for action in self.send_data(data) {
            if let TcpAction::Send(hdr, payload) = action {
                log::debug!(
                    "{} sent PSH+ACK seq={} ack={} len={}",
                    "->".green(),
                    hdr.seq_num,
                    hdr.ack_num,
                    payload.len()
                );
                let segment = TcpSegment::new(hdr, payload).with_checksum(&local_ip, &remote_ip)?;
                tun.write_ip_packet(local_ip, remote_ip, &segment)?;
            }
        }

        Ok(())
    }

    pub fn run(self, tun: TunDevice, shutdown: Arc<AtomicBool>) -> std::io::Result<()> {
        use std::io::{BufRead, Write};
        use std::sync::{Mutex, mpsc};

        let conn = Arc::new(Mutex::new(self));
        let tun = Arc::new(Mutex::new(tun));

        let (out_tx, out_rx) = mpsc::channel::<(TcpHeader, Vec<u8>)>();

        // Thread 2 (send): read stdin lines -> call send_data -> queue segments
        let conn_send = Arc::clone(&conn);
        std::thread::spawn(move || {
            let stdin = std::io::stdin();
            let mut line = String::new();
            loop {
                line.clear();
                let n = stdin.lock().read_line(&mut line).unwrap_or(0);
                if n == 0 {
                    // EOF: initiate close
                    let mut c = conn_send.lock().expect("mutex not poisoned");
                    if let Some(TcpAction::Send(hdr, payload)) = c.close() {
                        out_tx.send((hdr, payload)).ok();
                    }
                    break;
                }
                let mut c = conn_send.lock().expect("mutex not poisoned");
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
                let c = conn.lock().expect("mutex not poisoned");
                let local_ip = *c.local_addr.ip();
                let remote_ip = c.remote_addr.map(|a| *a.ip()).unwrap_or(local_ip);
                drop(c);
                if hdr.psh {
                    log::debug!(
                        "{} sent PSH+ACK seq={} ack={} len={}",
                        "->".green(),
                        hdr.seq_num,
                        hdr.ack_num,
                        payload.len()
                    );
                } else if hdr.fin {
                    log::debug!(
                        "{} sent FIN+ACK seq={} ack={}",
                        "->".green(),
                        hdr.seq_num,
                        hdr.ack_num
                    );
                }
                let segment = TcpSegment::new(hdr, payload).with_checksum(&local_ip, &remote_ip)?;
                tun.lock()
                    .expect("mutex not poisoned")
                    .write_ip_packet(local_ip, remote_ip, &segment)?;
            }

            // Check for shutdown signal (Ctrl+C)
            if shutdown.load(Ordering::Relaxed) {
                let mut c = conn.lock().expect("mutex not poisoned");
                if let Some(TcpAction::Send(hdr, payload)) = c.close() {
                    let local_ip = *c.local_addr.ip();
                    let remote_ip = c.remote_addr.map(|a| *a.ip()).unwrap_or(local_ip);
                    drop(c);
                    let segment =
                        TcpSegment::new(hdr, payload).with_checksum(&local_ip, &remote_ip)?;
                    tun.lock()
                        .expect("mutex not poisoned")
                        .write_ip_packet(local_ip, remote_ip, &segment)?;
                }
                break;
            }

            // Non-blocking TUN read with timeout so we can drain the outgoing queue
            let pkt = {
                let mut t = tun.lock().expect("mutex not poisoned");
                t.read_ip_packet_timeout(Duration::from_millis(50))?
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
                let c = conn.lock().expect("mutex not poisoned");
                if let Some(remote_addr) = c.remote_addr
                    && (*remote_addr.ip() != remote_ip || remote_addr.port() != seg_hdr.src_port)
                {
                    continue;
                }
            }

            // Log incoming packet at DEBUG level (after filter — don't log spurious packets)
            {
                let hdr_len = seg_hdr.header_len().max(20);
                let payload_len = pkt.payload.len().saturating_sub(hdr_len);
                if seg_hdr.fin {
                    log::debug!("{} recv FIN seq={}", "<-".cyan(), seg_hdr.seq_num);
                } else if seg_hdr.psh || payload_len > 0 {
                    log::debug!(
                        "{} recv PSH+ACK seq={} ack={} len={}",
                        "<-".cyan(),
                        seg_hdr.seq_num,
                        seg_hdr.ack_num,
                        payload_len
                    );
                } else if seg_hdr.ack {
                    log::debug!(
                        "{} recv ACK seq={} ack={}",
                        "<-".cyan(),
                        seg_hdr.seq_num,
                        seg_hdr.ack_num
                    );
                }
            }

            let hdr_len = seg_hdr.header_len().max(20);
            let tcp_payload = if pkt.payload.len() > hdr_len {
                pkt.payload[hdr_len..].to_vec()
            } else {
                vec![]
            };

            let local_ip = {
                let c = conn.lock().expect("mutex not poisoned");
                *c.local_addr.ip()
            };

            let actions = conn
                .lock()
                .expect("mutex not poisoned")
                .handle(&seg_hdr, &tcp_payload);

            let mut should_close = false;
            for action in actions {
                match action {
                    TcpAction::Send(hdr, payload) => {
                        if hdr.fin {
                            log::debug!(
                                "{} sent FIN+ACK seq={} ack={}",
                                "->".green(),
                                hdr.seq_num,
                                hdr.ack_num
                            );
                        } else if hdr.ack {
                            log::debug!(
                                "{} sent ACK seq={} ack={}",
                                "->".green(),
                                hdr.seq_num,
                                hdr.ack_num
                            );
                        }
                        let segment =
                            TcpSegment::new(hdr, payload).with_checksum(&local_ip, &remote_ip)?;
                        tun.lock()
                            .expect("mutex not poisoned")
                            .write_ip_packet(local_ip, remote_ip, &segment)?;
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

            // If remote closed first, complete our half of the close immediately.
            let state = conn.lock().expect("mutex not poisoned").state.clone();
            if state == TcpState::CloseWait {
                let mut c = conn.lock().expect("mutex not poisoned");
                if let Some(TcpAction::Send(hdr, payload)) = c.close() {
                    let remote_ip = c.remote_addr.map(|a| *a.ip()).unwrap_or(local_ip);
                    log::debug!(
                        "{} sent FIN+ACK seq={} ack={}",
                        "->".green(),
                        hdr.seq_num,
                        hdr.ack_num
                    );
                    drop(c);
                    let segment =
                        TcpSegment::new(hdr, payload).with_checksum(&local_ip, &remote_ip)?;
                    tun.lock()
                        .expect("mutex not poisoned")
                        .write_ip_packet(local_ip, remote_ip, &segment)?;
                }
                // Wait for the final ACK of our FIN before exiting
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn syn_seg(seq: u32) -> TcpHeader {
        TcpHeader {
            syn: true,
            seq_num: seq,
            ..Default::default()
        }
    }

    fn ack_seg(seq: u32, ack_num: u32) -> TcpHeader {
        TcpHeader {
            ack: true,
            seq_num: seq,
            ack_num,
            ..Default::default()
        }
    }

    fn psh_ack_seg(seq: u32, ack_num: u32) -> TcpHeader {
        TcpHeader {
            psh: true,
            ack: true,
            seq_num: seq,
            ack_num,
            ..Default::default()
        }
    }

    fn fin_ack_seg(seq: u32, ack_num: u32) -> TcpHeader {
        TcpHeader {
            fin: true,
            ack: true,
            seq_num: seq,
            ack_num,
            ..Default::default()
        }
    }

    fn rst_seg() -> TcpHeader {
        TcpHeader {
            rst: true,
            ..Default::default()
        }
    }

    #[test]
    fn test_syn_received() {
        let mut conn = TcpConnection::new_listener("10.0.0.1:4444".parse().unwrap());
        let syn = syn_seg(1000);
        let actions = conn.handle(&syn, &[]);
        assert_eq!(conn.state, TcpState::SynReceived);
        assert_eq!(conn.recv_seq, 1001);
        let has_syn_ack = actions
            .iter()
            .any(|a| matches!(a, TcpAction::Send(h, _) if h.syn && h.ack));
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

        let has_deliver = actions
            .iter()
            .any(|a| matches!(a, TcpAction::Deliver(d) if d == b"hello"));
        let has_ack = actions
            .iter()
            .any(|a| matches!(a, TcpAction::Send(h, _) if h.ack && !h.syn));
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
        let has_ack = actions
            .iter()
            .any(|a| matches!(a, TcpAction::Send(h, _) if h.ack));
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
        assert_eq!(
            conn.recv_seq,
            initial_recv_seq + 5,
            "recv_seq should advance by payload len"
        );
        let has_deliver = actions
            .iter()
            .any(|a| matches!(a, TcpAction::Deliver(d) if d == b"world"));
        let has_ack = actions
            .iter()
            .any(|a| matches!(a, TcpAction::Send(h, _) if h.ack && !h.syn));
        assert!(has_deliver, "should deliver data");
        assert!(has_ack, "should send ACK");
    }

    #[test]
    fn test_simultaneous_close() {
        let mut conn = established_conn();

        // We initiate close -> FinWait1
        let close_action = conn.close().expect("close should return action");
        assert_eq!(conn.state, TcpState::FinWait1);
        assert!(matches!(close_action, TcpAction::Send(h, _) if h.fin));

        // Remote sends FIN before ACKing ours -> Closing
        // ack_num = 999 does not match conn.send_seq (1001), so Rule 6 doesn't fire
        let fin = fin_ack_seg(conn.recv_seq, 999);
        let actions = conn.handle(&fin, &[]);
        assert_eq!(conn.state, TcpState::Closing);
        assert!(
            actions
                .iter()
                .any(|a| matches!(a, TcpAction::Send(h, _) if h.ack))
        );

        // Remote ACKs our FIN -> Closed
        let ack = ack_seg(conn.recv_seq, conn.send_seq);
        let actions = conn.handle(&ack, &[]);
        assert_eq!(conn.state, TcpState::Closed);
        assert!(actions.iter().any(|a| matches!(a, TcpAction::Close)));
    }

    #[test]
    fn test_send_data_not_established() {
        let mut conn = TcpConnection::new_listener("10.0.0.1:4444".parse().unwrap());
        let actions = conn.send_data(b"hello");
        assert!(
            actions.is_empty(),
            "send_data should do nothing when not Established"
        );
    }

    #[test]
    fn test_connector_new() {
        let local: SocketAddrV4 = "10.0.0.2:54321".parse().unwrap();
        let remote: SocketAddrV4 = "10.0.0.1:4444".parse().unwrap();
        let (conn, syn_hdr) = TcpConnection::new_connector(local, remote);
        assert_eq!(conn.state, TcpState::SynSent);
        assert_eq!(conn.remote_addr, Some(remote));
        assert!(syn_hdr.syn, "initial segment must be SYN");
        assert!(!syn_hdr.ack, "initial SYN must not have ACK");
        assert_eq!(syn_hdr.src_port, 54321);
        assert_eq!(syn_hdr.dst_port, 4444);
        // send_seq is ISN+1 because SYN consumed one sequence number
        assert_eq!(conn.send_seq, syn_hdr.seq_num.wrapping_add(1));
    }

    #[test]
    fn test_active_open_syn_ack() {
        let local: SocketAddrV4 = "10.0.0.2:54321".parse().unwrap();
        let remote: SocketAddrV4 = "10.0.0.1:4444".parse().unwrap();
        let (mut conn, syn_hdr) = TcpConnection::new_connector(local, remote);

        let server_isn = 9000u32;
        // Server sends SYN-ACK acknowledging our SYN
        let syn_ack = TcpHeader {
            syn: true,
            ack: true,
            seq_num: server_isn,
            ack_num: syn_hdr.seq_num.wrapping_add(1),
            src_port: 4444,
            dst_port: 54321,
            ..Default::default()
        };

        let actions = conn.handle(&syn_ack, &[]);
        assert_eq!(
            conn.state,
            TcpState::Established,
            "SYN-ACK should move to Established"
        );
        assert_eq!(conn.recv_seq, server_isn.wrapping_add(1));

        let has_ack = actions
            .iter()
            .any(|a| matches!(a, TcpAction::Send(h, _) if h.ack && !h.syn));
        assert!(has_ack, "should send final ACK to complete handshake");
    }

    #[test]
    fn test_active_open_wrong_ack_ignored() {
        let local: SocketAddrV4 = "10.0.0.2:54321".parse().unwrap();
        let remote: SocketAddrV4 = "10.0.0.1:4444".parse().unwrap();
        let (mut conn, syn_hdr) = TcpConnection::new_connector(local, remote);

        // SYN-ACK with wrong ack_num should not advance state
        let bad_syn_ack = TcpHeader {
            syn: true,
            ack: true,
            seq_num: 9000,
            ack_num: syn_hdr.seq_num.wrapping_add(999), // wrong — not ISN+1
            src_port: 4444,
            dst_port: 54321,
            ..Default::default()
        };

        let actions = conn.handle(&bad_syn_ack, &[]);
        assert_eq!(
            conn.state,
            TcpState::SynSent,
            "wrong ack_num must not advance state"
        );
        assert!(actions.is_empty(), "no response for unmatched SYN-ACK");
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
