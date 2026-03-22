mod cli;
mod common;
mod proto;
mod utils;

use clap::Parser;

fn main() -> std::io::Result<()> {
    let args = cli::Args::parse();
    utils::log::Logger::init(&args);

    match args.command {
        cli::Command::Listener { tun_ip, port } => {
            let tun = proto::tun::TunDevice::new(&tun_ip.to_string())?;
            log::info!("listening on {}:{}", tun_ip, port);
            log::info!("run: nc {} {}", tun_ip, port);

            let mut listener = proto::listener::TcpListener::new(tun, tun_ip, port);
            let conn = listener.accept()?;
            log::info!(
                "connection established with {}",
                conn.remote_addr
                    .expect("accept guarantees remote_addr is set")
            );
            let tun = listener.into_tun();
            conn.run(tun)?;
            log::info!("connection closed");
        }
        cli::Command::Sender { tun_ip, connect } => {
            let mut tun = proto::tun::TunDevice::new(&tun_ip.to_string())?;
            let local_addr: std::net::SocketAddrV4 =
                format!("{}:{}", tun_ip, 54321u16).parse().map_err(|e| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!("invalid local addr: {e}"),
                    )
                })?;
            let (mut conn, syn_hdr) =
                proto::connection::TcpConnection::new_connector(local_addr, connect);
            proto::connector::connect(&mut tun, &mut conn, syn_hdr)?;
            log::info!(
                "connection established with {}",
                conn.remote_addr
                    .expect("connect guarantees remote_addr is set")
            );
            conn.run(tun)?;
            log::info!("connection closed");
        }
    }

    Ok(())
}
