#![allow(dead_code)]

mod cli;
mod common;
mod proto;
mod utils;

use clap::Parser;

fn main() {
    let args = cli::Args::parse();
    utils::log::Logger::init(&args);

    match &args.command {
        cli::Command::Listener { addr, port } => {
            log::info!("Listening on {}:{}", addr, port);
        }
        cli::Command::Sender { bind, addr } => {
            log::info!("Connecting from {} to {}", bind, addr);
        }
    }
}
