use std::sync::Arc;

use crate::{
  config::AppConfig, listener::SmtpListener, openpgp::OpenPgpService,
  remote_smtp::RemoteSmtpClient, tls::OutboundTls,
};

pub struct App {
  listener: SmtpListener,
}

impl App {
  pub async fn from_config(config: AppConfig) -> anyhow::Result<Self> {
    let tls: Arc<OutboundTls> = Arc::new(OutboundTls::from_config(&config.tls)?);
    let log_recipient_addresses = config.logging.log_recipient_addresses;
    let openpgp: Arc<OpenPgpService> = Arc::new(OpenPgpService::new(&config, tls.clone()).await?);
    let remote: Arc<RemoteSmtpClient> = Arc::new(RemoteSmtpClient::new(
      config.remote_smtp.clone(),
      tls,
      log_recipient_addresses,
    ));

    let listener: SmtpListener =
      SmtpListener::new(config.listen, openpgp, remote, log_recipient_addresses);
    Ok(Self { listener })
  }

  pub async fn run(self) -> anyhow::Result<()> {
    self.listener.run().await
  }
}
