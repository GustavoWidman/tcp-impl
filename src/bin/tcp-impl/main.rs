mod cli;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use clap::Parser;

fn main() -> std::io::Result<()> {
    let args = cli::Args::parse();
    tcp_impl::utils::log::Logger::init(args.verbosity);

    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_flag = Arc::clone(&shutdown);
    ctrlc::set_handler(move || {
        log::info!("received Ctrl+C, initiating graceful shutdown");
        shutdown_flag.store(true, Ordering::Relaxed);
    })
    .map_err(|e| std::io::Error::other(format!("failed to set Ctrl+C handler: {e}")))?;

    match args.command {
        cli::Command::Listener { tun_ip, port } => {
            let tun = tcp_impl::TunDevice::new(&tun_ip.to_string())?;
            log::info!("listening on {}:{}", tun_ip, port);
            log::info!("run: nc {} {}", tun_ip, port);

            let mut listener = tcp_impl::TcpListener::new(tun, tun_ip, port);
            loop {
                let conn = match listener.accept(Arc::clone(&shutdown)) {
                    Ok(c) => c,
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => break,
                    Err(e) => return Err(e),
                };
                log::info!(
                    "connection established with {}",
                    conn.remote_addr
                        .expect("accept guarantees remote_addr is set")
                );
                let tun = listener.into_tun();
                conn.run(tun, Arc::clone(&shutdown))?;
                log::info!("connection closed");
                if shutdown.load(Ordering::Relaxed) {
                    break;
                }
                // Reclaim the TUN device for the next accept
                let tun = tcp_impl::TunDevice::new(&tun_ip.to_string())?;
                listener = tcp_impl::TcpListener::new(tun, tun_ip, port);
                log::info!("waiting for new connection on {}:{}", tun_ip, port);
            }
        }
        cli::Command::Sender { tun_ip, connect } => {
            let mut tun = tcp_impl::TunDevice::new(&tun_ip.to_string())?;
            let local_addr: std::net::SocketAddrV4 =
                format!("{}:{}", tun_ip, 54321u16).parse().map_err(|e| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!("invalid local addr: {e}"),
                    )
                })?;
            let (mut conn, syn_hdr) = tcp_impl::TcpConnection::new_connector(local_addr, connect);
            tcp_impl::connector::connect(&mut tun, &mut conn, syn_hdr)?;
            log::info!(
                "connection established with {}",
                conn.remote_addr
                    .expect("connect guarantees remote_addr is set")
            );
            conn.run(tun, shutdown)?;
            log::info!("connection closed");
        }
    }

    Ok(())
}
