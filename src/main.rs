#![allow(dead_code)]

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
            log::info!("connection established with {}", conn.remote_addr.unwrap());
            let tun = listener.into_tun();
            conn.run(tun)?;
            log::info!("connection closed");
        }
        cli::Command::Sender { tun_ip, connect } => {
            log::info!("sender mode — tun-ip={} connect={}", tun_ip, connect);
            log::warn!("sender mode not yet implemented");
        }
    }

    Ok(())
}
