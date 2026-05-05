mod app;
mod cli;
mod config;
mod listener;
mod message;
mod openpgp;
mod remote_smtp;
mod tls;

use anyhow::Context;
use clap::Parser;
use tracing_subscriber::{EnvFilter, fmt, prelude::*};

use crate::{app::App, cli::Cli, config::AppConfig};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
  let cli: Cli = Cli::parse();
  let config: AppConfig =
    AppConfig::load(&cli.config).with_context(|| format!("loading {}", cli.config.display()))?;

  init_tracing(&config.logging.filter)?;

  if cli.check_config {
    tracing::info!("configuration is valid");
    return Ok(());
  }

  App::from_config(config).await?.run().await
}

fn init_tracing(filter: &str) -> anyhow::Result<()> {
  tracing_subscriber::registry()
    .with(EnvFilter::try_new(filter).or_else(|_| EnvFilter::try_new("info"))?)
    .with(fmt::layer().with_target(false))
    .try_init()
    .context("failed to initialize tracing")?;
  Ok(())
}
