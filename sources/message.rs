use anyhow::{Context, bail};
use mailparse::{MailAddr, addrparse_header, parse_headers};
use uuid::Uuid;

use crate::config::EncryptionMode;

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

#[derive(Debug, Clone)]
pub struct Envelope {
    pub mail_from: String,
    pub rcpt_to: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct RelayMessage {
    pub envelope: Envelope,
    pub data: Vec<u8>,
}

pub fn collect_encryption_recipients(
    raw_message: &[u8],
    envelope: &Envelope,
) -> anyhow::Result<Vec<String>> {
    let mut recipients = extract_recipients_from_headers(raw_message)?;
    for recipient in &envelope.rcpt_to {
        push_unique(&mut recipients, normalize_email(recipient));
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
    fn dot_stuffs_lines_starting_with_period() {
        let stuffed = dot_stuff(b".hello\r\nworld\r\n");
        assert_eq!(stuffed, b"..hello\r\nworld\r\n");
    }
}
