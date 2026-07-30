use std::collections::{HashMap, HashSet};

use anyhow::{Context, bail};
use mailparse::{MailAddr, addrparse_header, parse_headers};
use uuid::Uuid;

use crate::config::{EncryptionMode, UnencryptedRecipientConfig};

const OUTER_HEADER_ALLOWLIST: &[&str] = &[
  "date",
  "from",
  "to",
  "cc",
  "subject",
  "reply-to",
  "sender",
  "message-id",
  "in-reply-to",
  "references",
  "resent-date",
  "resent-from",
  "resent-to",
  "resent-cc",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Envelope {
  pub mail_from: String,
  pub rcpt_to: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct RelayMessage {
  pub envelope: Envelope,
  pub data: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliveryKind {
  Encrypted,
  Unencrypted,
}

#[derive(Debug, Clone)]
pub struct PreparedDelivery {
  pub kind: DeliveryKind,
  pub message: RelayMessage,
  pub normalized_recipients: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecipientGroup {
  pub envelope: Envelope,
  pub normalized_recipients: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecipientDeliveryPlan {
  Encrypted(RecipientGroup),
  Unencrypted(RecipientGroup),
  Split {
    encrypted: RecipientGroup,
    unencrypted: RecipientGroup,
  },
}

pub fn plan_recipient_deliveries(
  envelope: &Envelope,
  rules: &[UnencryptedRecipientConfig],
) -> anyhow::Result<RecipientDeliveryPlan> {
  let policy = rules
    .iter()
    .map(|rule| (rule.address.as_str(), rule.allow_split_delivery))
    .collect::<HashMap<_, _>>();
  let mut encrypted_recipients = Vec::new();
  let mut encrypted_normalized = Vec::new();
  let mut unencrypted_recipients = Vec::new();
  let mut unencrypted_normalized = Vec::new();
  let mut every_unencrypted_recipient_allows_split = true;

  for recipient in &envelope.rcpt_to {
    let normalized = normalize_email(recipient);
    if let Some(allow_split_delivery) = policy.get(normalized.as_str()) {
      unencrypted_recipients.push(recipient.clone());
      push_unique(&mut unencrypted_normalized, normalized);
      every_unencrypted_recipient_allows_split &= *allow_split_delivery;
    } else {
      encrypted_recipients.push(recipient.clone());
      push_unique(&mut encrypted_normalized, normalized);
    }
  }

  let encrypted = RecipientGroup {
    envelope: Envelope {
      mail_from: envelope.mail_from.clone(),
      rcpt_to: encrypted_recipients,
    },
    normalized_recipients: encrypted_normalized,
  };
  let unencrypted = RecipientGroup {
    envelope: Envelope {
      mail_from: envelope.mail_from.clone(),
      rcpt_to: unencrypted_recipients,
    },
    normalized_recipients: unencrypted_normalized,
  };

  if unencrypted.envelope.rcpt_to.is_empty() {
    return Ok(RecipientDeliveryPlan::Encrypted(encrypted));
  }
  if encrypted.envelope.rcpt_to.is_empty() {
    return Ok(RecipientDeliveryPlan::Unencrypted(unencrypted));
  }
  if !every_unencrypted_recipient_allows_split {
    bail!("mixed encrypted and unencrypted recipients require explicit split-delivery permission");
  }

  Ok(RecipientDeliveryPlan::Split {
    encrypted,
    unencrypted,
  })
}

pub fn collect_encryption_recipients(
  raw_message: &[u8],
  envelope: &Envelope,
  excluded_recipients: &HashSet<String>,
) -> anyhow::Result<Vec<String>> {
  let mut recipients = extract_recipients_from_headers(raw_message)?;
  recipients.retain(|recipient| !excluded_recipients.contains(recipient));

  for recipient in &envelope.rcpt_to {
    let normalized = normalize_email(recipient);
    if !excluded_recipients.contains(&normalized) {
      push_unique(&mut recipients, normalized);
    }
  }

  if recipients.is_empty() {
    bail!("could not determine any recipient addresses for OpenPGP encryption");
  }

  Ok(recipients)
}

pub fn plaintext_for_encryption(
  raw_message: &[u8],
  mode: EncryptionMode,
) -> anyhow::Result<Vec<u8>> {
  let normalized = normalize_crlf(raw_message);

  match mode {
    EncryptionMode::FullMessage => Ok(normalized),
    EncryptionMode::PgpMimeBody => {
      let (headers, body) = split_message(&normalized);
      let header_blocks = split_header_blocks(headers)?;
      let mut inner = Vec::new();
      let mut has_content_headers = false;

      for header in header_blocks {
        if is_content_header(&header.name_lower) {
          has_content_headers = true;
          inner.extend_from_slice(&header.raw);
        }
      }

      if has_content_headers {
        inner.extend_from_slice(b"\r\n");
      }

      inner.extend_from_slice(body);
      Ok(inner)
    }
  }
}

pub fn build_encrypted_message(
  raw_message: &[u8],
  armored_ciphertext: &[u8],
) -> anyhow::Result<Vec<u8>> {
  let normalized = normalize_crlf(raw_message);
  let (headers, _) = split_message(&normalized);
  let header_blocks = split_header_blocks(headers)?;
  let boundary = format!("sendmail-sec-{}", Uuid::new_v4().simple());
  let mut output = Vec::new();

  for header in header_blocks {
    if OUTER_HEADER_ALLOWLIST.contains(&header.name_lower.as_str()) {
      output.extend_from_slice(&header.raw);
    }
  }

  output.extend_from_slice(b"MIME-Version: 1.0\r\n");
  output.extend_from_slice(
        format!(
            "Content-Type: multipart/encrypted; protocol=\"application/pgp-encrypted\"; boundary=\"{}\"\r\n",
            boundary
        )
        .as_bytes(),
    );
  output.extend_from_slice(b"\r\n");

  let armored_ciphertext = normalize_crlf(armored_ciphertext);

  output.extend_from_slice(format!("--{}\r\n", boundary).as_bytes());
  output.extend_from_slice(b"Content-Type: application/pgp-encrypted\r\n");
  output.extend_from_slice(b"Content-Description: PGP/MIME version identification\r\n");
  output.extend_from_slice(b"\r\n");
  output.extend_from_slice(b"Version: 1\r\n");
  output.extend_from_slice(b"\r\n");

  output.extend_from_slice(format!("--{}\r\n", boundary).as_bytes());
  output.extend_from_slice(b"Content-Type: application/octet-stream; name=\"encrypted.asc\"\r\n");
  output.extend_from_slice(b"Content-Description: OpenPGP encrypted message\r\n");
  output.extend_from_slice(b"Content-Disposition: inline; filename=\"encrypted.asc\"\r\n");
  output.extend_from_slice(b"Content-Transfer-Encoding: 7bit\r\n");
  output.extend_from_slice(b"\r\n");
  output.extend_from_slice(&armored_ciphertext);
  if !armored_ciphertext.ends_with(b"\r\n") {
    output.extend_from_slice(b"\r\n");
  }
  output.extend_from_slice(b"\r\n");
  output.extend_from_slice(format!("--{}--\r\n", boundary).as_bytes());

  Ok(output)
}

pub fn extract_recipients_from_headers(raw_message: &[u8]) -> anyhow::Result<Vec<String>> {
  let normalized = normalize_crlf(raw_message);
  let (headers, _) = parse_headers(&normalized).context("failed to parse message headers")?;
  let mut recipients = Vec::new();

  for header in headers {
    let key = header.get_key_ref();
    if !matches_ignore_ascii_case(&key, "to")
      && !matches_ignore_ascii_case(&key, "cc")
      && !matches_ignore_ascii_case(&key, "bcc")
    {
      continue;
    }

    let parsed = addrparse_header(&header)
      .with_context(|| format!("failed to parse recipient header {}", header.get_key()))?;
    flatten_mail_addrs(&parsed, &mut recipients);
  }

  Ok(recipients)
}

pub fn normalize_email(value: &str) -> String {
  value
    .trim()
    .trim_matches('<')
    .trim_matches('>')
    .to_ascii_lowercase()
}

fn flatten_mail_addrs(addrs: &mailparse::MailAddrList, recipients: &mut Vec<String>) {
  for addr in addrs.iter() {
    match addr {
      MailAddr::Single(single) => push_unique(recipients, normalize_email(&single.addr)),
      MailAddr::Group(group) => {
        for single in &group.addrs {
          push_unique(recipients, normalize_email(&single.addr));
        }
      }
    }
  }
}

fn push_unique(values: &mut Vec<String>, value: String) {
  if value.is_empty() || values.iter().any(|existing| existing == &value) {
    return;
  }

  values.push(value);
}

fn split_message(raw_message: &[u8]) -> (&[u8], &[u8]) {
  match raw_message
    .windows(4)
    .position(|window| window == b"\r\n\r\n")
  {
    Some(position) => (&raw_message[..position], &raw_message[position + 4..]),
    None => (raw_message, &[]),
  }
}

#[derive(Debug, Clone)]
struct HeaderBlock {
  name_lower: String,
  raw: Vec<u8>,
}

fn split_header_blocks(headers: &[u8]) -> anyhow::Result<Vec<HeaderBlock>> {
  let mut blocks = Vec::new();
  let mut current = Vec::new();

  for line in headers.split_inclusive(|byte| *byte == b'\n') {
    if line.starts_with(b" ") || line.starts_with(b"\t") {
      if current.is_empty() {
        bail!("encountered folded header line without a preceding header");
      }
      current.extend_from_slice(line);
      continue;
    }

    if !current.is_empty() {
      blocks.push(build_header_block(&current)?);
    }

    current.clear();
    current.extend_from_slice(line);
  }

  if !current.is_empty() {
    blocks.push(build_header_block(&current)?);
  }

  Ok(blocks)
}

fn build_header_block(raw: &[u8]) -> anyhow::Result<HeaderBlock> {
  let Some(separator) = raw.iter().position(|byte| *byte == b':') else {
    bail!("invalid header line without ':'");
  };

  let name_lower = String::from_utf8_lossy(&raw[..separator]).to_ascii_lowercase();
  let mut raw = raw.to_vec();
  if !raw.ends_with(b"\r\n") {
    raw.extend_from_slice(b"\r\n");
  }
  Ok(HeaderBlock { name_lower, raw })
}

fn is_content_header(name_lower: &str) -> bool {
  name_lower == "mime-version" || name_lower.starts_with("content-")
}

fn matches_ignore_ascii_case(value: &str, expected: &str) -> bool {
  value.eq_ignore_ascii_case(expected)
}

pub fn normalize_crlf(data: &[u8]) -> Vec<u8> {
  let mut normalized = Vec::with_capacity(data.len() + 16);
  let mut index = 0;

  while index < data.len() {
    match data[index] {
      b'\r' => {
        normalized.push(b'\r');
        if data.get(index + 1) == Some(&b'\n') {
          normalized.push(b'\n');
          index += 2;
        } else {
          normalized.push(b'\n');
          index += 1;
        }
      }
      b'\n' => {
        normalized.extend_from_slice(b"\r\n");
        index += 1;
      }
      byte => {
        normalized.push(byte);
        index += 1;
      }
    }
  }

  normalized
}

pub fn dot_stuff(data: &[u8]) -> Vec<u8> {
  let normalized = normalize_crlf(data);
  let mut output = Vec::with_capacity(normalized.len() + 32);

  for line in normalized.split_inclusive(|byte| *byte == b'\n') {
    if line.starts_with(b".") {
      output.push(b'.');
    }
    output.extend_from_slice(line);
  }

  if !output.ends_with(b"\r\n") {
    output.extend_from_slice(b"\r\n");
  }

  output
}

#[cfg(test)]
mod tests {
  use super::*;

  fn rule(address: &str, allow_split_delivery: bool) -> UnencryptedRecipientConfig {
    UnencryptedRecipientConfig {
      address: address.to_string(),
      allow_split_delivery,
    }
  }

  fn envelope(recipients: &[&str]) -> Envelope {
    Envelope {
      mail_from: "sender@example.com".to_string(),
      rcpt_to: recipients
        .iter()
        .map(|recipient| recipient.to_string())
        .collect(),
    }
  }

  #[test]
  fn extracts_header_recipients() {
    let raw = b"From: sender@example.com\r\nTo: Alice <alice@example.com>\r\nCc: team@example.com\r\n\r\nhello\r\n";
    let recipients = extract_recipients_from_headers(raw).unwrap();
    assert_eq!(recipients, vec!["alice@example.com", "team@example.com"]);
  }

  #[test]
  fn builds_pgp_mime_body_from_content_headers_only() {
    let raw = b"From: sender@example.com\r\nSubject: hi\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nhello\r\n";
    let inner = plaintext_for_encryption(raw, EncryptionMode::PgpMimeBody).unwrap();
    assert_eq!(
      String::from_utf8(inner).unwrap(),
      "MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nhello\r\n"
    );
  }

  #[test]
  fn builds_full_message_plaintext_with_normalized_line_endings() {
    let raw = b"From: sender@example.com\nSubject: hi\n\nhello\n";
    let plaintext = plaintext_for_encryption(raw, EncryptionMode::FullMessage).unwrap();

    assert_eq!(
      plaintext,
      b"From: sender@example.com\r\nSubject: hi\r\n\r\nhello\r\n"
    );
  }

  #[test]
  fn dot_stuffs_lines_starting_with_period() {
    let stuffed = dot_stuff(b".hello\r\nworld\r\n");
    assert_eq!(stuffed, b"..hello\r\nworld\r\n");
  }

  #[test]
  fn plans_encrypted_delivery_without_an_envelope_match() {
    let plan = plan_recipient_deliveries(
      &envelope(&["encrypted@example.com"]),
      &[rule("header-only@example.com", false)],
    )
    .unwrap();

    assert_eq!(
      plan,
      RecipientDeliveryPlan::Encrypted(RecipientGroup {
        envelope: envelope(&["encrypted@example.com"]),
        normalized_recipients: vec!["encrypted@example.com".to_string()],
      })
    );
  }

  #[test]
  fn plans_unencrypted_delivery_with_case_insensitive_exact_matching() {
    let plan = plan_recipient_deliveries(
      &envelope(&["Archive@Example.COM"]),
      &[rule("archive@example.com", false)],
    )
    .unwrap();

    assert_eq!(
      plan,
      RecipientDeliveryPlan::Unencrypted(RecipientGroup {
        envelope: envelope(&["Archive@Example.COM"]),
        normalized_recipients: vec!["archive@example.com".to_string()],
      })
    );
  }

  #[test]
  fn does_not_canonicalize_plus_addresses() {
    let plan = plan_recipient_deliveries(
      &envelope(&["archive+tag@example.com"]),
      &[rule("archive@example.com", false)],
    )
    .unwrap();

    assert!(matches!(plan, RecipientDeliveryPlan::Encrypted(_)));
  }

  #[test]
  fn rejects_mixed_delivery_without_permission_from_every_match() {
    let error = plan_recipient_deliveries(
      &envelope(&[
        "encrypted@example.com",
        "split@example.com",
        "strict@example.com",
      ]),
      &[
        rule("split@example.com", true),
        rule("strict@example.com", false),
      ],
    )
    .unwrap_err();

    assert!(
      error
        .to_string()
        .contains("require explicit split-delivery permission")
    );
  }

  #[test]
  fn plans_encrypted_first_split_when_every_match_allows_it() {
    let plan = plan_recipient_deliveries(
      &envelope(&["encrypted@example.com", "passthrough@example.com"]),
      &[rule("passthrough@example.com", true)],
    )
    .unwrap();

    assert_eq!(
      plan,
      RecipientDeliveryPlan::Split {
        encrypted: RecipientGroup {
          envelope: envelope(&["encrypted@example.com"]),
          normalized_recipients: vec!["encrypted@example.com".to_string()],
        },
        unencrypted: RecipientGroup {
          envelope: envelope(&["passthrough@example.com"]),
          normalized_recipients: vec!["passthrough@example.com".to_string()],
        },
      }
    );
  }

  #[test]
  fn excludes_only_matched_unencrypted_recipients_from_key_lookup() {
    let raw = b"To: passthrough@example.com\r\nCc: header-only@example.com\r\n\r\nbody\r\n";
    let excluded = HashSet::from(["passthrough@example.com".to_string()]);
    let recipients =
      collect_encryption_recipients(raw, &envelope(&["encrypted@example.com"]), &excluded).unwrap();

    assert_eq!(
      recipients,
      vec!["header-only@example.com", "encrypted@example.com"]
    );
  }
}
