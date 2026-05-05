use std::{
  fs,
  net::{IpAddr, SocketAddr},
  path::{Path, PathBuf},
};

use anyhow::{Context, bail};
use ipnet::IpNet;
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct AppConfig {
  #[serde(default)]
  pub listen: ListenConfig,
  pub remote_smtp: RemoteSmtpConfig,
  #[serde(default)]
  pub tls: TlsConfig,
  #[serde(default)]
  pub openpgp: OpenPgpConfig,
  #[serde(default)]
  pub logging: LoggingConfig,
}

impl AppConfig {
  pub fn load(path: &Path) -> anyhow::Result<Self> {
    let raw: Vec<u8> =
      fs::read(path).with_context(|| format!("failed to read config file {}", path.display()))?;

    let mut config: AppConfig = match path
      .extension()
      .and_then(|ext: &std::ffi::OsStr| ext.to_str())
    {
      Some("json") => serde_json::from_slice::<Self>(&raw)
        .with_context(|| format!("failed to parse JSON config {}", path.display()))?,
      Some("yaml") | Some("yml") => serde_yaml::from_slice::<Self>(&raw)
        .with_context(|| format!("failed to parse YAML config {}", path.display()))?,
      _ => serde_yaml::from_slice::<Self>(&raw)
        .or_else(|_| serde_json::from_slice::<Self>(&raw))
        .with_context(|| {
          format!(
            "failed to parse config {}; expected YAML or JSON",
            path.display()
          )
        })?,
    };

    config.resolve_relative_paths(path);
    config.validate()?;
    Ok(config)
  }

  fn resolve_relative_paths(&mut self, path: &Path) {
    let Some(base_dir) = path.parent() else {
      return;
    };

    for certificate in &mut self.tls.extra_root_certificates {
      if certificate.is_relative() {
        *certificate = base_dir.join(&certificate);
      }
    }

    for file in &mut self.openpgp.local_key_files {
      if file.is_relative() {
        *file = base_dir.join(&file);
      }
    }

    for directory in &mut self.openpgp.local_key_directories {
      if directory.is_relative() {
        *directory = base_dir.join(&directory);
      }
    }
  }

  fn validate(&self) -> anyhow::Result<()> {
    if self.listen.auth.username.is_empty() {
      bail!("listen.auth.username must not be empty");
    }

    if self.listen.auth.password.is_empty() {
      bail!("listen.auth.password must not be empty");
    }

    if self.listen.message_size_limit_bytes == 0 {
      bail!("listen.message_size_limit_bytes must be greater than zero");
    }

    if self.listen.allowed_networks.is_empty() {
      bail!("listen.allowed_networks must not be empty");
    }

    if self.remote_smtp.host.trim().is_empty() {
      bail!("remote_smtp.host must not be empty");
    }

    if self.remote_smtp.hello_name.trim().is_empty() {
      bail!("remote_smtp.hello_name must not be empty");
    }

    if self.remote_smtp.port == 0 {
      bail!("remote_smtp.port must be greater than zero");
    }

    if self.remote_smtp.connect_timeout_secs == 0 {
      bail!("remote_smtp.connect_timeout_secs must be greater than zero");
    }

    if self.remote_smtp.command_timeout_secs == 0 {
      bail!("remote_smtp.command_timeout_secs must be greater than zero");
    }

    match &self.remote_smtp.auth {
      RemoteAuthConfig::Plain { username, password } => {
        if username.is_empty() || password.is_empty() {
          bail!("remote_smtp.auth PLAIN requires non-empty username and password");
        }
      }
      RemoteAuthConfig::Oauthbearer {
        username,
        access_token,
        ..
      }
      | RemoteAuthConfig::Xoauth2 {
        username,
        access_token,
      } => {
        if username.is_empty() || access_token.is_empty() {
          bail!("remote_smtp.auth OAuth mechanisms require non-empty username and access_token");
        }
      }
    }

    if !self.openpgp.enable_wkd
      && !self.openpgp.enable_keys_openpgp_org
      && self.openpgp.local_key_files.is_empty()
      && self.openpgp.local_key_directories.is_empty()
    {
      bail!("at least one OpenPGP key source must be enabled");
    }

    Ok(())
  }
}

#[derive(Debug, Clone, Deserialize)]
pub struct ListenConfig {
  #[serde(default = "default_listen_bind")]
  pub bind: SocketAddr,
  #[serde(default = "default_listen_banner")]
  pub banner: String,
  pub auth: InboundAuthConfig,
  #[serde(default = "default_allowed_networks")]
  pub allowed_networks: Vec<IpNet>,
  #[serde(default = "default_message_size_limit")]
  pub message_size_limit_bytes: usize,
}

impl Default for ListenConfig {
  fn default() -> Self {
    Self {
      bind: default_listen_bind(),
      banner: default_listen_banner(),
      auth: InboundAuthConfig {
        username: String::new(),
        password: String::new(),
      },
      allowed_networks: default_allowed_networks(),
      message_size_limit_bytes: default_message_size_limit(),
    }
  }
}

#[derive(Debug, Clone, Deserialize)]
pub struct InboundAuthConfig {
  pub username: String,
  pub password: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RemoteSmtpConfig {
  pub host: String,
  #[serde(default = "default_remote_port")]
  pub port: u16,
  #[serde(default)]
  pub tls_mode: RemoteTlsMode,
  #[serde(default = "default_hello_name")]
  pub hello_name: String,
  pub auth: RemoteAuthConfig,
  #[serde(default = "default_connect_timeout_secs")]
  pub connect_timeout_secs: u64,
  #[serde(default = "default_command_timeout_secs")]
  pub command_timeout_secs: u64,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum RemoteTlsMode {
  #[default]
  Starttls,
  Wrapper,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "mechanism", rename_all = "snake_case")]
pub enum RemoteAuthConfig {
  #[serde(alias = "PLAIN")]
  Plain { username: String, password: String },
  #[serde(alias = "OAUTHBEARER")]
  Oauthbearer {
    username: String,
    access_token: String,
    #[serde(default)]
    authzid: Option<String>,
  },
  #[serde(alias = "XOAUTH2")]
  Xoauth2 {
    username: String,
    access_token: String,
  },
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct TlsConfig {
  #[serde(default)]
  pub extra_root_certificates: Vec<PathBuf>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct OpenPgpConfig {
  #[serde(default)]
  pub local_key_files: Vec<PathBuf>,
  #[serde(default)]
  pub local_key_directories: Vec<PathBuf>,
  #[serde(default = "default_true")]
  pub enable_wkd: bool,
  #[serde(default = "default_true")]
  pub enable_keys_openpgp_org: bool,
  #[serde(default = "default_key_cache_ttl_secs")]
  pub key_cache_ttl_secs: u64,
  #[serde(default = "default_http_timeout_secs")]
  pub http_timeout_secs: u64,
  #[serde(default)]
  pub encryption_mode: EncryptionMode,
}

impl Default for OpenPgpConfig {
  fn default() -> Self {
    Self {
      local_key_files: Vec::new(),
      local_key_directories: Vec::new(),
      enable_wkd: true,
      enable_keys_openpgp_org: true,
      key_cache_ttl_secs: default_key_cache_ttl_secs(),
      http_timeout_secs: default_http_timeout_secs(),
      encryption_mode: EncryptionMode::default(),
    }
  }
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum EncryptionMode {
  #[default]
  PgpMimeBody,
  FullMessage,
}

#[derive(Debug, Clone, Deserialize)]
pub struct LoggingConfig {
  #[serde(default = "default_log_filter")]
  pub filter: String,
}

impl Default for LoggingConfig {
  fn default() -> Self {
    Self {
      filter: default_log_filter(),
    }
  }
}

fn default_listen_bind() -> SocketAddr {
  SocketAddr::new(IpAddr::from([0, 0, 0, 0]), 2525)
}

fn default_listen_banner() -> String {
  "sendmail-sec".to_string()
}

fn default_message_size_limit() -> usize {
  25 * 1024 * 1024
}

fn default_remote_port() -> u16 {
  587
}

fn default_hello_name() -> String {
  "localhost".to_string()
}

fn default_connect_timeout_secs() -> u64 {
  15
}

fn default_command_timeout_secs() -> u64 {
  30
}

fn default_key_cache_ttl_secs() -> u64 {
  3600
}

fn default_http_timeout_secs() -> u64 {
  10
}

fn default_log_filter() -> String {
  "info".to_string()
}

fn default_true() -> bool {
  true
}

fn default_allowed_networks() -> Vec<IpNet> {
  [
    "127.0.0.0/8",
    "::1/128",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "fc00::/7",
    "fe80::/10",
  ]
  .into_iter()
  .map(|cidr| cidr.parse().expect("default CIDR must be valid"))
  .collect()
}
