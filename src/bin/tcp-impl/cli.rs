use clap::{Parser, Subcommand};
use std::net::{Ipv4Addr, SocketAddrV4};

#[derive(Parser, Debug)]
#[command(name = "tcp-impl", about = "TCP over TUN implementation")]
pub struct Args {
    #[arg(short, long, default_value = "info")]
    pub verbosity: log::LevelFilter,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Listen for incoming TCP connections on TUN
    Listener {
        #[arg(long, default_value = "10.0.0.1")]
        tun_ip: Ipv4Addr,
        #[arg(short, long, default_value = "4444")]
        port: u16,
    },
    /// Initiate a TCP connection via TUN
    Sender {
        #[arg(long, default_value = "10.0.0.2")]
        tun_ip: Ipv4Addr,
        #[arg(short, long)]
        connect: SocketAddrV4,
    },
}
