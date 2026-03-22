use crate::cli::Args;

pub struct Logger;

impl Logger {
    pub fn init(args: &Args) {
        env_logger::Builder::new()
            .filter_level(args.verbosity)
            .init();
    }
}
