use clap::{Parser, Subcommand};
use std::net::SocketAddrV4;

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
        #[arg(short, long)]
        addr: SocketAddrV4,
        #[arg(short, long)]
        port: u16,
    },
    /// Initiate a TCP connection via TUN
    Sender {
        #[arg(short, long)]
        bind: SocketAddrV4,
        #[arg(short, long)]
        addr: SocketAddrV4,
    },
}
