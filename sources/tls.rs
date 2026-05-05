use std::{fs, sync::Arc};

use anyhow::{Context, bail};
use reqwest::Certificate;
use rustls::{ClientConfig, RootCertStore};
use tokio_rustls::TlsConnector;
use webpki_roots::TLS_SERVER_ROOTS;

use crate::config::TlsConfig;

#[derive(Clone)]
pub struct OutboundTls {
  client_config: Arc<ClientConfig>,
  http_roots: Vec<Certificate>,
}

impl OutboundTls {
  pub fn from_config(config: &TlsConfig) -> anyhow::Result<Self> {
    let mut root_store: RootCertStore = RootCertStore::empty();
    root_store.extend(TLS_SERVER_ROOTS.iter().cloned());

    let mut http_roots = Vec::new();

    for path in &config.extra_root_certificates {
      let pem = fs::read(path)
        .with_context(|| format!("failed to read extra root certificate {}", path.display()))?;

      for cert in rustls_pemfile::certs(&mut &pem[..]) {
        let cert = cert
          .with_context(|| format!("failed to parse PEM certificate from {}", path.display()))?;
        root_store
          .add(cert.clone())
          .with_context(|| format!("invalid root certificate in {}", path.display()))?;
        http_roots
          .push(Certificate::from_der(cert.as_ref()).with_context(|| {
            format!("failed to build HTTP certificate from {}", path.display())
          })?);
      }
    }

    let client_config = ClientConfig::builder()
      .with_root_certificates(root_store)
      .with_no_client_auth();

    Ok(Self {
      client_config: Arc::new(client_config),
      http_roots,
    })
  }

  pub fn connector(&self) -> TlsConnector {
    TlsConnector::from(self.client_config.clone())
  }

  pub fn http_client(
    &self,
    timeout_secs: u64,
    user_agent: &str,
  ) -> anyhow::Result<reqwest::Client> {
    if timeout_secs == 0 {
      bail!("HTTP timeout must be greater than zero");
    }

    let mut builder = reqwest::Client::builder()
      .use_rustls_tls()
      .https_only(true)
      .timeout(std::time::Duration::from_secs(timeout_secs))
      .user_agent(user_agent);

    for cert in &self.http_roots {
      builder = builder.add_root_certificate(cert.clone());
    }

    builder
      .build()
      .context("failed to build Rustls HTTP client")
  }
}
