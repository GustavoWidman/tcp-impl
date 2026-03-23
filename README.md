# tcp-impl

![rust](https://img.shields.io/badge/rust-2024-orange?logo=rust)
![license](https://img.shields.io/badge/license-MIT-blue)

a from-scratch TCP implementation over a TUN interface, in rust.

> **want the full story on how i built this?** check out my blog post: [https://blog.guswid.com/tcp-impl](https://blog.guswid.com/tcp-impl)

because sometimes relying on the OS's TCP stack just isn't fun enough.

## features

- **TUN-based I/O** — creates a virtual network interface and reads/writes raw IP packets directly, bypassing the kernel's TCP implementation entirely. works on macOS (utun) and Linux (tun).
- **manual TCP state machine** — implements RFC 793 handshake, data transfer, passive close, active close, and simultaneous close without touching the socket API once.
- **manual checksums** — RFC 1071 computed by hand over the pseudo-header and TCP segment. also computes the IPv4 header checksum. no kernel help.
- **listener and sender modes** — passive open (listener waits for connections, re-accepts after disconnect) and active open (sender dials a kernel TCP server).
- **graceful shutdown** — `ctrl+c` sends a proper TCP FIN and waits for the four-way teardown before exiting.
- **configurable verbosity** — color-coded directional logging (`←`/`→`) so you can watch every handshake segment in real time.

## prerequisites

- rust toolchain (2024 edition)
- root/administrator privileges (the TUN device won't open without it)
- macOS or Linux

## installation

```bash
git clone https://github.com/GustavoWidman/tcp-impl.git
cd tcp-impl
cargo build --release
```

## usage

run everything with `sudo`. the TUN device creation fails immediately without it.

### listener mode

start the listener, then connect with netcat from another terminal:

```bash
# terminal 1
sudo ./target/release/tcp-impl listener --tun-ip 10.0.0.1 --port 4444

# terminal 2 (macOS / netcat-openbsd)
nc 10.0.0.1 4444

# terminal 2 (linux — GNU nc 0.7.1, no -4 flag)
nc -s 0.0.0.0 10.0.0.1 4444
```

type lines in either terminal. they flow through the hand-rolled TCP stack. after the connection closes, the listener automatically re-accepts the next one.

### sender mode

the sender dials a kernel TCP server. start the server first, then the sender:

```bash
# terminal 1 — kernel TCP server (macOS)
nc -l 4444

# terminal 1 — kernel TCP server (linux, force IPv4)
nc -l -p 4444 -s 0.0.0.0

# terminal 2 — connect from userspace TCP
# tun-ip becomes the peer address; the TUN's local address is tun-ip+1
sudo ./target/release/tcp-impl sender --tun-ip 10.0.0.2 --connect 10.0.0.3:4444
```

the TUN creates `local=10.0.0.3` (kernel-owned) and `peer=10.0.0.2` (yours). the SYN goes out as `10.0.0.2 → 10.0.0.3`, the kernel delivers it to nc, and the handshake completes through userspace.

### verbosity

```bash
sudo ./target/release/tcp-impl -v debug listener --tun-ip 10.0.0.1
```

levels: `error` / `warn` / `info` (default) / `debug` / `trace`

at `debug` you see every segment:

```
← recv SYN seq=1234567890
→ sent SYN-ACK seq=987654321 ack=1234567891
← recv ACK — connection established
← recv PSH+ACK seq=1234567891 ack=987654322 len=6
→ sent ACK seq=987654322 ack=1234567897
→ sent PSH+ACK seq=987654322 ack=1234567897 len=4
← recv FIN seq=1234567897
→ sent FIN+ACK seq=987654326 ack=1234567898
← recv ACK seq=1234567898 ack=987654327
```

## how it works

**TUN interface**: instead of a standard socket, this creates a virtual network interface configured in point-to-point mode. traffic destined for the peer IP arrives in the TUN file descriptor as raw IP packets — the kernel never sees it as a TCP connection. on macOS every frame carries a mandatory 4-byte AF family prefix that is stripped on read and prepended on write. on Linux, packet information is disabled (`IFF_NO_PI`) so frames are raw IP with no prefix.

**point-to-point addressing**: `--tun-ip X` sets the peer address (what your userspace TCP owns). the interface's local address is `X+1` (the kernel-owned companion). this is why SYNs to the peer reach your fd instead of the kernel stack — the kernel only owns the companion address, not the peer.

**state machine**: `TcpConnection` implements RFC 793: Listen → SynReceived → Established ↔ data ↔ FinWait1/2 / CloseWait / LastAck / Closing → Closed. SYN and FIN each consume one sequence number. data advances by payload length. pure function of segment flags — no timers, no retransmit, no window scaling. happy path only (by design).

**checksums**: TCP requires an RFC 1071 one's-complement checksum over a 12-byte pseudo-header (src IP, dst IP, zero byte, protocol=6, TCP length) + TCP header + payload. IPv4 gets its own checksum over the 20-byte header. both computed from scratch.

**threading**: `run()` spawns a stdin reader thread that queues outgoing segments via mpsc. the main thread polls the TUN with a 50 ms timeout, drains the queue between reads, and processes incoming packets. `ctrl+c` sets an `AtomicBool` which the main loop checks each iteration, triggers `close()`, and waits for the final ACK before exiting.

## platform notes

| platform | TUN device | frame format |
|---|---|---|
| macOS | utun (next available) | 4-byte AF_INET prefix + IPv4 |
| Linux | /dev/net/tun | raw IPv4 (PI disabled) |

## license

[MIT](LICENSE)
