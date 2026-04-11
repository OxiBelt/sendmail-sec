use std::path::PathBuf;

use clap::Parser;

#[derive(Debug, Parser)]
#[command(author, version, about = "Secure local SMTP ingress and OpenPGP relay")]
pub struct Cli {
    #[arg(short, long, value_name = "PATH")]
    pub config: PathBuf,

    #[arg(long, help = "Load and validate the configuration, then exit")]
    pub check_config: bool,
}
