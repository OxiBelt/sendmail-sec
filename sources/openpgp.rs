use std::{
  collections::{HashMap, HashSet},
  fs,
  io::Write,
  path::{Path, PathBuf},
  sync::Arc,
  time::{Duration, Instant},
};

use anyhow::{Context, bail};
use reqwest::{Client, StatusCode};
use sequoia_openpgp as openpgp;
use sha1::{Digest, Sha1};
use tokio::sync::RwLock;
use tracing::{debug, warn};

use openpgp::{
  Cert,
  armor::Kind,
  cert::CertParser,
  parse::{PacketParser, Parse},
  policy::StandardPolicy,
  serialize::stream::{Armorer, Encryptor, LiteralWriter, Message},
};

use crate::{
  config::{AppConfig, OpenPgpConfig},
  message::{
    DeliveryKind, Envelope, PreparedDelivery, RecipientDeliveryPlan, RecipientGroup, RelayMessage,
    build_encrypted_message, collect_encryption_recipients, plaintext_for_encryption,
    plan_recipient_deliveries,
  },
  tls::OutboundTls,
};

const APP_USER_AGENT: &str = concat!(env!("CARGO_PKG_NAME"), "/", env!("CARGO_PKG_VERSION"));
const ZBASE32: &[u8; 32] = b"ybndrfg8ejkmcpqxot1uwisza345h769";

pub struct OpenPgpService {
  config: OpenPgpConfig,
  http_client: Client,
  local_index: HashMap<String, Vec<Cert>>,
  cache: RwLock<HashMap<String, CachedCerts>>,
  log_recipient_addresses: bool,
}

#[derive(Debug, Clone)]
struct CachedCerts {
  expires_at: Instant,
  certs: Vec<Cert>,
}

impl OpenPgpService {
  pub async fn new(config: &AppConfig, tls: Arc<OutboundTls>) -> anyhow::Result<Self> {
    let http_client = tls.http_client(config.openpgp.http_timeout_secs, APP_USER_AGENT)?;
    let local_index = build_local_key_index(&config.openpgp)?;

    Ok(Self {
      config: config.openpgp.clone(),
      http_client,
      local_index,
      cache: RwLock::new(HashMap::new()),
      log_recipient_addresses: config.logging.log_recipient_addresses,
    })
  }

  pub async fn prepare_deliveries(
    &self,
    envelope: &Envelope,
    raw_message: &[u8],
  ) -> anyhow::Result<Vec<PreparedDelivery>> {
    match plan_recipient_deliveries(envelope, &self.config.unencrypted_recipients)? {
      RecipientDeliveryPlan::Encrypted(group) => {
        let delivery = self
          .prepare_encrypted_delivery(group, raw_message, &HashSet::new())
          .await?;
        Ok(vec![delivery])
      }
      RecipientDeliveryPlan::Unencrypted(group) => {
        Ok(vec![prepare_unencrypted_delivery(group, raw_message)])
      }
      RecipientDeliveryPlan::Split {
        encrypted,
        unencrypted,
      } => {
        let excluded_recipients = unencrypted
          .normalized_recipients
          .iter()
          .cloned()
          .collect::<HashSet<_>>();
        let encrypted = self
          .prepare_encrypted_delivery(encrypted, raw_message, &excluded_recipients)
          .await?;
        let unencrypted = prepare_unencrypted_delivery(unencrypted, raw_message);
        Ok(vec![encrypted, unencrypted])
      }
    }
  }

  async fn prepare_encrypted_delivery(
    &self,
    group: RecipientGroup,
    raw_message: &[u8],
    excluded_recipients: &HashSet<String>,
  ) -> anyhow::Result<PreparedDelivery> {
    let recipients =
      collect_encryption_recipients(raw_message, &group.envelope, excluded_recipients)?;
    let plaintext = plaintext_for_encryption(raw_message, self.config.encryption_mode.clone())?;

    let mut certs = Vec::new();
    for recipient in &recipients {
      certs.extend(self.resolve_recipient_certs(recipient).await?);
    }
    let certs = deduplicate_certs(certs);

    if certs.is_empty() {
      bail!("no OpenPGP certificates resolved for recipients");
    }

    let armored_ciphertext = encrypt_to_armored_message(&plaintext, &certs)?;
    let data = build_encrypted_message(raw_message, &armored_ciphertext)?;

    Ok(PreparedDelivery {
      kind: DeliveryKind::Encrypted,
      normalized_recipients: group.normalized_recipients,
      message: RelayMessage {
        envelope: group.envelope,
        data,
      },
    })
  }

  async fn resolve_recipient_certs(&self, recipient: &str) -> anyhow::Result<Vec<Cert>> {
    let recipient = match normalize_lookup_email(recipient) {
      Ok(recipient) => recipient,
      Err(error) => {
        if self.log_recipient_addresses {
          debug!(
            recipient,
            error = %error,
            "invalid OpenPGP lookup recipient"
          );
        }
        return Err(error);
      }
    };

    if let Some(certs) = self.cached_lookup(&recipient).await {
      return Ok(certs);
    }

    if let Some(certs) = self.local_index.get(&recipient).cloned() {
      self.cache_success(&recipient, certs.clone()).await;
      return Ok(certs);
    }

    if self.config.enable_wkd
      && let Some(certs) = self.fetch_from_wkd(&recipient).await?
    {
      self.cache_success(&recipient, certs.clone()).await;
      return Ok(certs);
    }

    if self.config.enable_keys_openpgp_org
      && let Some(certs) = self.fetch_from_keys_openpgp_org(&recipient).await?
    {
      self.cache_success(&recipient, certs.clone()).await;
      return Ok(certs);
    }

    if self.log_recipient_addresses {
      debug!(recipient, "no OpenPGP public key found for recipient");
    }
    bail!("no OpenPGP public key found for a required recipient");
  }

  async fn cached_lookup(&self, recipient: &str) -> Option<Vec<Cert>> {
    let cache = self.cache.read().await;
    let entry = cache.get(recipient)?;
    if entry.expires_at > Instant::now() {
      return Some(entry.certs.clone());
    }
    None
  }

  async fn cache_success(&self, recipient: &str, certs: Vec<Cert>) {
    let ttl = Duration::from_secs(self.config.key_cache_ttl_secs);
    let mut cache = self.cache.write().await;
    cache.insert(
      recipient.to_string(),
      CachedCerts {
        expires_at: Instant::now() + ttl,
        certs,
      },
    );
  }

  async fn fetch_from_wkd(&self, recipient: &str) -> anyhow::Result<Option<Vec<Cert>>> {
    let (local, domain) = split_email(recipient)?;
    let local_hash = zbase32_sha1(local);
    let direct_url = format!(
      "https://{domain}/.well-known/openpgpkey/hu/{local_hash}?l={}",
      urlencoding::encode(local)
    );
    let advanced_url = format!(
      "https://openpgpkey.{domain}/.well-known/openpgpkey/{domain}/hu/{local_hash}?l={}",
      urlencoding::encode(local)
    );

    for url in [advanced_url, direct_url] {
      match self.fetch_certs(&url, recipient).await {
        Ok(Some(certs)) => return Ok(Some(certs)),
        Ok(None) => continue,
        Err(error) => {
          warn!(error = %error, "WKD lookup failed");
          if self.log_recipient_addresses {
            debug!(
              recipient,
              %url,
              error = %error,
              "WKD lookup failure details"
            );
          }
        }
      }
    }

    Ok(None)
  }

  async fn fetch_from_keys_openpgp_org(
    &self,
    recipient: &str,
  ) -> anyhow::Result<Option<Vec<Cert>>> {
    let url = format!(
      "https://keys.openpgp.org/vks/v1/by-email/{}",
      urlencoding::encode(recipient)
    );
    let result = self.fetch_certs(&url, recipient).await;
    if let Err(error) = &result
      && self.log_recipient_addresses
    {
      debug!(
        recipient,
        %url,
        error = %error,
        "keys.openpgp.org lookup failure details"
      );
    }
    result
  }

  async fn fetch_certs(&self, url: &str, recipient: &str) -> anyhow::Result<Option<Vec<Cert>>> {
    let response =
      self.http_client.get(url).send().await.map_err(|error| {
        anyhow::anyhow!("failed to request OpenPGP key: {}", error.without_url())
      })?;

    match response.status() {
      StatusCode::OK => {
        let body = response
          .bytes()
          .await
          .context("failed to read key response body")?;
        let certs = parse_certs(&body).context("failed to parse OpenPGP certificate response")?;
        let certs = filter_certs_for_email(certs, recipient);
        if certs.is_empty() {
          bail!("retrieved OpenPGP keys did not match the required recipient");
        }
        Ok(Some(certs))
      }
      StatusCode::NOT_FOUND | StatusCode::NO_CONTENT | StatusCode::GONE => Ok(None),
      status => bail!("unexpected HTTP status {status} from OpenPGP key service"),
    }
  }
}

fn prepare_unencrypted_delivery(group: RecipientGroup, raw_message: &[u8]) -> PreparedDelivery {
  PreparedDelivery {
    kind: DeliveryKind::Unencrypted,
    normalized_recipients: group.normalized_recipients,
    message: RelayMessage {
      envelope: group.envelope,
      data: raw_message.to_vec(),
    },
  }
}

fn build_local_key_index(config: &OpenPgpConfig) -> anyhow::Result<HashMap<String, Vec<Cert>>> {
  let mut index: HashMap<String, Vec<Cert>> = HashMap::new();
  let mut files = config.local_key_files.clone();

  for directory in &config.local_key_directories {
    let mut entries = read_directory_files(directory)?;
    files.append(&mut entries);
  }

  for file in files {
    let data = fs::read(&file)
      .with_context(|| format!("failed to read local key file {}", file.display()))?;
    let certs = parse_certs(&data)
      .with_context(|| format!("failed to parse local key file {}", file.display()))?;

    for cert in certs {
      for email in cert_userids(&cert) {
        index.entry(email).or_default().push(cert.clone());
      }
    }
  }

  for certs in index.values_mut() {
    *certs = deduplicate_certs(std::mem::take(certs));
  }

  Ok(index)
}

fn read_directory_files(path: &Path) -> anyhow::Result<Vec<PathBuf>> {
  let mut files = Vec::new();

  for entry in fs::read_dir(path)
    .with_context(|| format!("failed to read key directory {}", path.display()))?
  {
    let entry = entry.with_context(|| format!("failed to inspect {}", path.display()))?;
    let entry_path = entry.path();
    if entry.file_type()?.is_file() {
      files.push(entry_path);
    }
  }

  files.sort();
  Ok(files)
}

fn parse_certs(data: &[u8]) -> anyhow::Result<Vec<Cert>> {
  let packet_parser = PacketParser::from_bytes(&data)?;
  let mut certs = Vec::new();

  for result in CertParser::from(packet_parser) {
    certs.push(result.context("invalid certificate encountered in key source")?);
  }

  Ok(certs)
}

fn filter_certs_for_email(certs: Vec<Cert>, recipient: &str) -> Vec<Cert> {
  certs
    .into_iter()
    .filter(|cert| cert_matches_email(cert, recipient))
    .collect()
}

fn cert_matches_email(cert: &Cert, recipient: &str) -> bool {
  cert_userids(cert)
    .into_iter()
    .any(|email| email == recipient)
}

fn cert_userids(cert: &Cert) -> Vec<String> {
  cert
    .userids()
    .filter_map(|userid| userid.userid().email_normalized().ok().flatten())
    .collect()
}

fn deduplicate_certs(certs: Vec<Cert>) -> Vec<Cert> {
  let mut seen = HashSet::new();
  let mut deduped = Vec::new();

  for cert in certs {
    let fingerprint = cert.fingerprint().to_string();
    if seen.insert(fingerprint) {
      deduped.push(cert);
    }
  }

  deduped
}

fn encrypt_to_armored_message(plaintext: &[u8], certs: &[Cert]) -> anyhow::Result<Vec<u8>> {
  let policy = StandardPolicy::new();
  let mut output = Vec::new();
  let mut recipients = Vec::new();

  for cert in certs {
    let mut found = false;
    for key in cert
      .keys()
      .with_policy(&policy, None)
      .supported()
      .alive()
      .revoked(false)
      .for_transport_encryption()
    {
      recipients.push(key);
      found = true;
    }

    if !found {
      bail!(
        "certificate {} has no suitable transport encryption key",
        cert.fingerprint()
      );
    }
  }

  let message = Message::new(&mut output);
  let message = Armorer::new(message)
    .kind(Kind::Message)
    .build()
    .context("failed to initialize ASCII armor")?;
  let message = Encryptor::for_recipients(message, recipients)
    .build()
    .context("failed to initialize OpenPGP encryptor")?;
  let mut writer = LiteralWriter::new(message)
    .build()
    .context("failed to initialize OpenPGP literal data writer")?;
  writer
    .write_all(plaintext)
    .context("failed to write OpenPGP plaintext")?;
  writer
    .finalize()
    .context("failed to finalize OpenPGP message")?;

  Ok(output)
}

fn split_email(email: &str) -> anyhow::Result<(&str, &str)> {
  let Some((local, domain)) = email.rsplit_once('@') else {
    bail!("invalid recipient email address");
  };

  if local.is_empty() || domain.is_empty() {
    bail!("invalid recipient email address");
  }

  Ok((local, domain))
}

fn normalize_lookup_email(email: &str) -> anyhow::Result<String> {
  let email = email.trim().trim_matches('<').trim_matches('>');
  let (local, domain) = split_email(email)?;
  Ok(format!(
    "{}@{}",
    local.to_ascii_lowercase(),
    domain.to_ascii_lowercase()
  ))
}

fn zbase32_sha1(value: &str) -> String {
  let digest = Sha1::digest(value.as_bytes());
  encode_zbase32(&digest)
}

fn encode_zbase32(bytes: &[u8]) -> String {
  let mut buffer: u16 = 0;
  let mut bits_left = 0usize;
  let mut output = String::new();

  for byte in bytes {
    buffer = (buffer << 8) | u16::from(*byte);
    bits_left += 8;

    while bits_left >= 5 {
      bits_left -= 5;
      let index = ((buffer >> bits_left) & 0x1f) as usize;
      output.push(ZBASE32[index] as char);
    }
  }

  if bits_left > 0 {
    let index = ((buffer << (5 - bits_left)) & 0x1f) as usize;
    output.push(ZBASE32[index] as char);
  }

  output
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn zbase32_hash_matches_known_value_shape() {
    let hash = zbase32_sha1("alice");
    assert_eq!(hash.len(), 32);
    assert!(
      hash
        .chars()
        .all(|c| "ybndrfg8ejkmcpqxot1uwisza345h769".contains(c))
    );
  }

  #[test]
  fn normalizes_lookup_email() {
    let email = normalize_lookup_email("Alice@Example.COM").unwrap();
    assert_eq!(email, "alice@example.com");
  }

  #[test]
  fn invalid_lookup_errors_hide_recipient_values() {
    let sentinel = "sentinel-recipient-without-at";
    let error = normalize_lookup_email(sentinel).unwrap_err();
    let rendered = format!("{error:#}");

    assert!(rendered.contains("invalid recipient email address"));
    assert!(!rendered.contains(sentinel));
  }

  #[test]
  fn prepares_unencrypted_delivery_without_transforming_data() {
    let raw = b"Subject: passthrough\n\nbody\n";
    let delivery = prepare_unencrypted_delivery(
      RecipientGroup {
        envelope: Envelope {
          mail_from: "sender@example.com".to_string(),
          rcpt_to: vec!["archive@example.com".to_string()],
        },
        normalized_recipients: vec!["archive@example.com".to_string()],
      },
      raw,
    );

    assert_eq!(delivery.kind, DeliveryKind::Unencrypted);
    assert_eq!(delivery.message.data, raw);
    assert_eq!(delivery.message.envelope.rcpt_to, ["archive@example.com"]);
  }
}
