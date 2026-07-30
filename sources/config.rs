use std::{
  collections::HashMap,
  fs,
  net::{IpAddr, SocketAddr},
  path::{Path, PathBuf},
};

use anyhow::{Context, bail};
use ipnet::IpNet;
use serde::{Deserialize, Deserializer, de};

use crate::secret::SecretString;

#[derive(Debug, Clone)]
pub struct AppConfig {
  pub listen: ListenConfig,
  pub remote_smtp: RemoteSmtpConfig,
  pub tls: TlsConfig,
  pub openpgp: OpenPgpConfig,
  pub logging: LoggingConfig,
}

#[derive(Deserialize)]
struct ParsedAppConfig {
  #[serde(default)]
  listen: ListenConfig,
  remote_smtp: RemoteSmtpConfig,
  #[serde(default)]
  tls: TlsConfig,
  #[serde(default)]
  openpgp: OpenPgpConfig,
  #[serde(default)]
  logging: LoggingConfig,
}

impl From<ParsedAppConfig> for AppConfig {
  fn from(parsed: ParsedAppConfig) -> Self {
    Self {
      listen: parsed.listen,
      remote_smtp: parsed.remote_smtp,
      tls: parsed.tls,
      openpgp: parsed.openpgp,
      logging: parsed.logging,
    }
  }
}

impl AppConfig {
  pub fn load(path: &Path) -> anyhow::Result<Self> {
    let raw: Vec<u8> =
      fs::read(path).with_context(|| format!("failed to read config file {}", path.display()))?;

    let parsed: ParsedAppConfig = match path
      .extension()
      .and_then(|ext: &std::ffi::OsStr| ext.to_str())
    {
      Some("json") => serde_json::from_slice(&raw)
        .with_context(|| format!("failed to parse JSON config {}", path.display()))?,
      Some("yaml") | Some("yml") => serde_norway::from_slice(&raw)
        .with_context(|| format!("failed to parse YAML config {}", path.display()))?,
      _ => serde_norway::from_slice(&raw)
        .or_else(|_| serde_json::from_slice(&raw))
        .with_context(|| {
          format!(
            "failed to parse config {}; expected YAML or JSON",
            path.display()
          )
        })?,
    };

    let mut config = Self::from(parsed);
    config.resolve_relative_paths(path);
    config.resolve_secret_files()?;
    config.normalize_unencrypted_recipients()?;
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

    self.listen.auth.password.resolve_relative_path(base_dir);
    match &mut self.remote_smtp.auth {
      RemoteAuthConfig::Plain { password, .. } => password.resolve_relative_path(base_dir),
      RemoteAuthConfig::Oauthbearer { access_token, .. }
      | RemoteAuthConfig::Xoauth2 { access_token, .. } => {
        access_token.resolve_relative_path(base_dir);
      }
    }
  }

  fn resolve_secret_files(&mut self) -> anyhow::Result<()> {
    self
      .listen
      .auth
      .password
      .resolve_file("listen.auth.password_file")?;

    match &mut self.remote_smtp.auth {
      RemoteAuthConfig::Plain { password, .. } => {
        password.resolve_file("remote_smtp.auth.password_file")?;
      }
      RemoteAuthConfig::Oauthbearer { access_token, .. }
      | RemoteAuthConfig::Xoauth2 { access_token, .. } => {
        access_token.resolve_file("remote_smtp.auth.access_token_file")?;
      }
    }

    Ok(())
  }

  fn normalize_unencrypted_recipients(&mut self) -> anyhow::Result<()> {
    let mut seen = HashMap::new();

    for (index, recipient) in self.openpgp.unencrypted_recipients.iter_mut().enumerate() {
      let normalized = normalize_configured_email(&recipient.address)
        .with_context(|| format!("openpgp.unencrypted_recipients[{index}].address is invalid"))?;

      if let Some(previous_index) = seen.insert(normalized.clone(), index) {
        bail!("openpgp.unencrypted_recipients[{index}].address duplicates entry {previous_index}");
      }

      recipient.address = normalized;
    }

    Ok(())
  }

  fn validate(&self) -> anyhow::Result<()> {
    if self.listen.auth.username.is_empty() {
      bail!("listen.auth.username must not be empty");
    }

    if self
      .listen
      .auth
      .password
      .expose()
      .context("validating listen.auth.password")?
      .is_empty()
    {
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
        if username.is_empty()
          || password
            .expose()
            .context("validating remote_smtp.auth.password")?
            .is_empty()
        {
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
        if username.is_empty()
          || access_token
            .expose()
            .context("validating remote_smtp.auth.access_token")?
            .is_empty()
        {
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
        password: SecretString::inline(String::new()),
      },
      allowed_networks: default_allowed_networks(),
      message_size_limit_bytes: default_message_size_limit(),
    }
  }
}

#[derive(Debug, Clone)]
pub struct InboundAuthConfig {
  pub username: String,
  pub password: SecretString,
}

#[derive(Deserialize)]
struct RawInboundAuthConfig {
  username: String,
  #[serde(default)]
  password: Option<String>,
  #[serde(default)]
  password_file: Option<PathBuf>,
}

impl<'de> Deserialize<'de> for InboundAuthConfig {
  fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
  where
    D: Deserializer<'de>,
  {
    let raw = RawInboundAuthConfig::deserialize(deserializer)?;
    let password = SecretString::from_sources(
      raw.password,
      raw.password_file,
      "listen.auth.password",
      "listen.auth.password_file",
    )
    .map_err(de::Error::custom)?;

    Ok(Self {
      username: raw.username,
      password,
    })
  }
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

#[derive(Debug, Clone)]
pub enum RemoteAuthConfig {
  Plain {
    username: String,
    password: SecretString,
  },
  Oauthbearer {
    username: String,
    access_token: SecretString,
    authzid: Option<String>,
  },
  Xoauth2 {
    username: String,
    access_token: SecretString,
  },
}

#[derive(Deserialize)]
#[serde(tag = "mechanism", rename_all = "snake_case")]
enum RawRemoteAuthConfig {
  #[serde(alias = "PLAIN")]
  Plain {
    username: String,
    #[serde(default)]
    password: Option<String>,
    #[serde(default)]
    password_file: Option<PathBuf>,
  },
  #[serde(alias = "OAUTHBEARER")]
  Oauthbearer {
    username: String,
    #[serde(default)]
    access_token: Option<String>,
    #[serde(default)]
    access_token_file: Option<PathBuf>,
    #[serde(default)]
    authzid: Option<String>,
  },
  #[serde(alias = "XOAUTH2")]
  Xoauth2 {
    username: String,
    #[serde(default)]
    access_token: Option<String>,
    #[serde(default)]
    access_token_file: Option<PathBuf>,
  },
}

impl<'de> Deserialize<'de> for RemoteAuthConfig {
  fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
  where
    D: Deserializer<'de>,
  {
    match RawRemoteAuthConfig::deserialize(deserializer)? {
      RawRemoteAuthConfig::Plain {
        username,
        password,
        password_file,
      } => Ok(Self::Plain {
        username,
        password: SecretString::from_sources(
          password,
          password_file,
          "remote_smtp.auth.password",
          "remote_smtp.auth.password_file",
        )
        .map_err(de::Error::custom)?,
      }),
      RawRemoteAuthConfig::Oauthbearer {
        username,
        access_token,
        access_token_file,
        authzid,
      } => Ok(Self::Oauthbearer {
        username,
        access_token: SecretString::from_sources(
          access_token,
          access_token_file,
          "remote_smtp.auth.access_token",
          "remote_smtp.auth.access_token_file",
        )
        .map_err(de::Error::custom)?,
        authzid,
      }),
      RawRemoteAuthConfig::Xoauth2 {
        username,
        access_token,
        access_token_file,
      } => Ok(Self::Xoauth2 {
        username,
        access_token: SecretString::from_sources(
          access_token,
          access_token_file,
          "remote_smtp.auth.access_token",
          "remote_smtp.auth.access_token_file",
        )
        .map_err(de::Error::custom)?,
      }),
    }
  }
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
  #[serde(default)]
  pub unencrypted_recipients: Vec<UnencryptedRecipientConfig>,
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
      unencrypted_recipients: Vec::new(),
    }
  }
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct UnencryptedRecipientConfig {
  pub address: String,
  #[serde(default)]
  pub allow_split_delivery: bool,
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
  #[serde(default)]
  pub log_recipient_addresses: bool,
}

impl Default for LoggingConfig {
  fn default() -> Self {
    Self {
      filter: default_log_filter(),
      log_recipient_addresses: false,
    }
  }
}

fn normalize_configured_email(value: &str) -> anyhow::Result<String> {
  if value.is_empty()
    || value.trim() != value
    || !value.is_ascii()
    || value
      .bytes()
      .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
    || value.contains(['<', '>', ','])
  {
    bail!("expected a bare ASCII email address without whitespace");
  }

  let mut parts = value.split('@');
  let local = parts.next().unwrap_or_default();
  let domain = parts.next().unwrap_or_default();

  if local.is_empty() || domain.is_empty() || parts.next().is_some() {
    bail!("expected exactly one non-empty local and domain part");
  }

  Ok(format!(
    "{}@{}",
    local.to_ascii_lowercase(),
    domain.to_ascii_lowercase()
  ))
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

#[cfg(test)]
#[path = "config_tests.rs"]
mod tests;
