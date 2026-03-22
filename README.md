# tcp-impl

![rust](https://img.shields.io/badge/rust-2021-orange?logo=rust)
![license](https://img.shields.io/badge/license-MIT-blue)

a from-scratch TCP implementation over a TUN interface, in rust.

because sometimes relying on the OS's TCP stack just isn't fun enough.

## features

- **TUN-based I/O** - creates a utun device and reads/writes raw IP packets directly, bypassing the kernel's TCP implementation entirely.
- **manual TCP state machine** - implements RFC 793 handshake, data transfer, passive close, active close, and simultaneous close without touching the socket API once.
- **manual checksums** - RFC 1071 computed by hand over the pseudo-header and TCP segment. also computes the IPv4 header checksum. no kernel help.
- **configurable verbosity** - color-coded logging so you can watch every handshake segment in real time if you want.

## prerequisites

- rust toolchain (2021 edition)
- root/administrator privileges (the TUN device won't open without it, the OS will tell you this loudly)
- macOS (utun framing is macOS-specific -- linux uses a different packet prefix scheme)

## installation

```bash
git clone https://github.com/GustavoWidman/tcp-impl.git
cd tcp-impl
cargo build --release
```

## usage

run everything with `sudo`. the TUN device creation fails immediately without it.

### listener mode

start the listener:

```bash
sudo ./target/release/tcp-impl listener --tun-ip 10.0.0.1 --port 4444
```

in another terminal, connect with netcat:

```bash
nc 10.0.0.1 4444
```

type lines in the netcat terminal and they arrive through your hand-rolled TCP stack. type lines in the listener terminal to echo them back.

### verbosity

use `-v` or `--verbosity` to control the noise level:

- `error` - only when things break
- `warn` - might be about to break
- `info` - default. shows the utun device name, port, and connection info
- `debug` - shows each handshake segment (SYN, SYN-ACK, ACK)
- `trace` - full packet dumps

## how it works

**TUN interface**: instead of using a standard socket, this creates a utun device with a /24 address (default 10.0.0.1/24). traffic destined for that IP goes into the TUN file descriptor as raw IP packets rather than hitting the kernel TCP stack. on macOS, each frame has a 4-byte AF family prefix that has to be stripped on read and prepended on write. the rest is a standard IPv4 packet.

**state machine**: `TcpConnection` implements RFC 793's state machine: Listen, SynReceived, Established, CloseWait, LastAck, FinWait1, FinWait2, Closing, Closed. SYN consumes one sequence number. FIN consumes one. data advances the receive sequence number by payload length. the state machine is a pure function of incoming segment flags -- no timers, no retransmit, no window scaling. it works for the happy path.

**checksums**: TCP requires an RFC 1071 checksum over a 12-byte pseudo-header (src IP, dst IP, zero byte, protocol=6, TCP length) concatenated with the TCP header and payload. IPv4 gets its own RFC 1071 checksum over the 20-byte header. both are computed from scratch using the standard ones'-complement sum algorithm.

## license

MIT.
