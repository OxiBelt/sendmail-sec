use std::{net::SocketAddr, sync::Arc};

use anyhow::{Context, bail};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream},
};
use tracing::{error, info, warn};

use crate::{
    config::ListenConfig, message::Envelope, openpgp::OpenPgpService, remote_smtp::RemoteSmtpClient,
};

#[derive(Clone)]
pub struct SmtpListener {
    listen: ListenConfig,
    openpgp: Arc<OpenPgpService>,
    remote: Arc<RemoteSmtpClient>,
}

impl SmtpListener {
    pub fn new(
        listen: ListenConfig,
        openpgp: Arc<OpenPgpService>,
        remote: Arc<RemoteSmtpClient>,
    ) -> Self {
        Self {
            listen,
            openpgp,
            remote,
        }
    }

    pub async fn run(self) -> anyhow::Result<()> {
        let listener: TcpListener = TcpListener::bind(self.listen.bind)
            .await
            .with_context(|| format!("failed to bind SMTP listener on {}", self.listen.bind))?;
        let shared: Arc<SmtpListener> = Arc::new(self);

        info!(bind = %shared.listen.bind, "SMTP listener ready");

        loop {
            tokio::select! {
                result = listener.accept() => {
                    let (stream, peer) = result.context("failed to accept SMTP connection")?;
                    let shared = shared.clone();
                    tokio::spawn(async move {
                        if let Err(error) = shared.handle_connection(stream, peer).await {
                            warn!(peer = %peer, error = %error, "SMTP session ended with error");
                        }
                    });
                }
                result = tokio::signal::ctrl_c() => {
                    result.context("failed to wait for Ctrl+C")?;
                    info!("shutdown signal received");
                    break;
                }
            }
        }

        Ok(())
    }

    async fn handle_connection(
        self: Arc<Self>,
        stream: TcpStream,
        peer: SocketAddr,
    ) -> anyhow::Result<()> {
        if !self.is_allowed_peer(peer) {
            let mut stream: TcpStream = stream;
            let _ = stream.write_all(b"554 access denied\r\n").await;
            bail!("connection from {peer} is outside the allowed networks");
        }

        let mut reader: BufReader<TcpStream> = BufReader::new(stream);
        self.write_response(
            &mut reader,
            220,
            &format!("{} ESMTP ready", self.listen.banner),
        )
        .await?;

        let mut state: SessionState = SessionState::default();

        loop {
            let line: Vec<u8> = match read_smtp_line(&mut reader, 4096).await? {
                Some(line) => line,
                None => return Ok(()),
            };

            let line: String = trim_crlf(&line);
            if line.is_empty() {
                continue;
            }

            let (command, argument) = split_command(&line);
            match command.as_str() {
                "EHLO" => {
                    state.helo = true;
                    state.reset_transaction();
                    self.write_multiline_response(
                        &mut reader,
                        250,
                        &[
                            self.listen.banner.clone(),
                            "AUTH PLAIN".to_string(),
                            "8BITMIME".to_string(),
                            format!("SIZE {}", self.listen.message_size_limit_bytes),
                        ],
                    )
                    .await?;
                }
                "HELO" => {
                    state.helo = true;
                    state.reset_transaction();
                    self.write_response(&mut reader, 250, &self.listen.banner)
                        .await?;
                }
                "AUTH" => {
                    if !state.helo {
                        self.write_response(&mut reader, 503, "send EHLO/HELO first")
                            .await?;
                        continue;
                    }
                    if state.authenticated {
                        self.write_response(&mut reader, 503, "already authenticated")
                            .await?;
                        continue;
                    }
                    self.handle_auth(&mut reader, &mut state, &argument).await?;
                }
                "MAIL" => {
                    if !state.helo {
                        self.write_response(&mut reader, 503, "send EHLO/HELO first")
                            .await?;
                        continue;
                    }
                    if !state.authenticated {
                        self.write_response(&mut reader, 530, "authentication required")
                            .await?;
                        continue;
                    }

                    let sender: String = match parse_path_argument(&argument, "FROM:") {
                        Ok(sender) => sender,
                        Err(error) => {
                            self.write_response(&mut reader, 501, &error.to_string())
                                .await?;
                            continue;
                        }
                    };

                    state.reset_transaction();
                    state.mail_from = Some(sender);
                    self.write_response(&mut reader, 250, "sender ok").await?;
                }
                "RCPT" => {
                    if state.mail_from.is_none() {
                        self.write_response(&mut reader, 503, "need MAIL before RCPT")
                            .await?;
                        continue;
                    }

                    let recipient: String = match parse_path_argument(&argument, "TO:") {
                        Ok(recipient) => recipient,
                        Err(error) => {
                            self.write_response(&mut reader, 501, &error.to_string())
                                .await?;
                            continue;
                        }
                    };

                    state.rcpt_to.push(recipient);
                    self.write_response(&mut reader, 250, "recipient ok")
                        .await?;
                }
                "DATA" => {
                    if state.mail_from.is_none() || state.rcpt_to.is_empty() {
                        self.write_response(&mut reader, 503, "need MAIL and RCPT before DATA")
                            .await?;
                        continue;
                    }

                    self.write_response(&mut reader, 354, "end data with <CRLF>.<CRLF>")
                        .await?;
                    let raw_message: Vec<u8> =
                        read_message_data(&mut reader, self.listen.message_size_limit_bytes)
                            .await?;

                    let envelope: Envelope = Envelope {
                        mail_from: state.mail_from.clone().unwrap_or_default(),
                        rcpt_to: state.rcpt_to.clone(),
                    };

                    match self.openpgp.encrypt_message(&envelope, &raw_message).await {
                        Ok(relay_message) => match self.remote.send_message(&relay_message).await {
                            Ok(()) => {
                                state.reset_transaction();
                                self.write_response(&mut reader, 250, "message relayed")
                                    .await?;
                            }
                            Err(error) => {
                                error!(peer = %peer, error = %error, "failed to relay message");
                                state.reset_transaction();
                                self.write_response(&mut reader, 554, "failed to relay message")
                                    .await?;
                            }
                        },
                        Err(error) => {
                            error!(peer = %peer, error = %error, "failed to encrypt message");
                            state.reset_transaction();
                            self.write_response(&mut reader, 554, "failed to encrypt message")
                                .await?;
                        }
                    }
                }
                "RSET" => {
                    state.reset_transaction();
                    self.write_response(&mut reader, 250, "state reset").await?;
                }
                "NOOP" => {
                    self.write_response(&mut reader, 250, "ok").await?;
                }
                "QUIT" => {
                    self.write_response(&mut reader, 221, "bye").await?;
                    return Ok(());
                }
                _ => {
                    self.write_response(&mut reader, 502, "command not implemented")
                        .await?;
                }
            }
        }
    }

    async fn handle_auth(
        &self,
        reader: &mut BufReader<TcpStream>,
        state: &mut SessionState,
        argument: &str,
    ) -> anyhow::Result<()> {
        let mut parts: std::str::SplitWhitespace<'_> = argument.split_whitespace();
        let Some(mechanism) = parts.next() else {
            self.write_response(reader, 501, "missing AUTH mechanism")
                .await?;
            return Ok(());
        };

        if !mechanism.eq_ignore_ascii_case("PLAIN") {
            self.write_response(reader, 504, "only AUTH PLAIN is supported")
                .await?;
            return Ok(());
        }

        let response: String = if let Some(initial) = parts.next() {
            initial.to_string()
        } else {
            self.write_response(reader, 334, "").await?;
            match read_smtp_line(reader, 4096).await? {
                Some(line) => trim_crlf(&line),
                None => return Ok(()),
            }
        };

        match decode_auth_plain(&response) {
            Ok((username, password)) => {
                if username == self.listen.auth.username && password == self.listen.auth.password {
                    state.authenticated = true;
                    self.write_response(reader, 235, "authentication successful")
                        .await?;
                } else {
                    self.write_response(reader, 535, "authentication failed")
                        .await?;
                }
            }
            Err(error) => {
                self.write_response(reader, 501, &error.to_string()).await?;
            }
        }

        Ok(())
    }

    fn is_allowed_peer(&self, peer: SocketAddr) -> bool {
        self.listen
            .allowed_networks
            .iter()
            .any(|network| network.contains(&peer.ip()))
    }

    async fn write_response(
        &self,
        reader: &mut BufReader<TcpStream>,
        code: u16,
        text: &str,
    ) -> anyhow::Result<()> {
        reader
            .get_mut()
            .write_all(format!("{code} {text}\r\n").as_bytes())
            .await
            .context("failed to write SMTP response")
    }

    async fn write_multiline_response(
        &self,
        reader: &mut BufReader<TcpStream>,
        code: u16,
        lines: &[String],
    ) -> anyhow::Result<()> {
        for (index, line) in lines.iter().enumerate() {
            let separator = if index + 1 == lines.len() { ' ' } else { '-' };
            reader
                .get_mut()
                .write_all(format!("{code}{separator}{line}\r\n").as_bytes())
                .await
                .context("failed to write multiline SMTP response")?;
        }
        Ok(())
    }
}

#[derive(Debug, Default)]
struct SessionState {
    helo: bool,
    authenticated: bool,
    mail_from: Option<String>,
    rcpt_to: Vec<String>,
}

impl SessionState {
    fn reset_transaction(&mut self) {
        self.mail_from = None;
        self.rcpt_to.clear();
    }
}

async fn read_smtp_line(
    reader: &mut BufReader<TcpStream>,
    max_bytes: usize,
) -> anyhow::Result<Option<Vec<u8>>> {
    let mut line = Vec::new();
    let read = reader
        .read_until(b'\n', &mut line)
        .await
        .context("failed to read SMTP line")?;

    if read == 0 {
        return Ok(None);
    }

    if line.len() > max_bytes {
        bail!("SMTP line exceeded {max_bytes} bytes");
    }

    Ok(Some(line))
}

async fn read_message_data(
    reader: &mut BufReader<TcpStream>,
    limit: usize,
) -> anyhow::Result<Vec<u8>> {
    let mut message: Vec<u8> = Vec::new();

    loop {
        let Some(line) = read_smtp_line(reader, limit.saturating_add(5)).await? else {
            bail!("SMTP client closed connection during DATA");
        };

        let trimmed = trim_crlf_bytes(&line);
        if trimmed == b"." {
            break;
        }

        let body_line = if trimmed.starts_with(b"..") {
            &trimmed[1..]
        } else {
            trimmed
        };

        message.extend_from_slice(body_line);
        message.extend_from_slice(b"\r\n");

        if message.len() > limit {
            bail!("message exceeds configured size limit of {limit} bytes");
        }
    }

    Ok(message)
}

fn decode_auth_plain(value: &str) -> anyhow::Result<(String, String)> {
    let decoded: Vec<u8> = STANDARD
        .decode(value.as_bytes())
        .context("invalid base64 payload for AUTH PLAIN")?;
    let parts: Vec<&[u8]> = decoded.split(|byte| *byte == 0).collect();
    if parts.len() < 3 {
        bail!("AUTH PLAIN payload is malformed");
    }

    let username: String = String::from_utf8(parts[1].to_vec()).context("AUTH username is not UTF-8")?;
    let password: String = String::from_utf8(parts[2].to_vec()).context("AUTH password is not UTF-8")?;
    Ok((username, password))
}

fn parse_path_argument(argument: &str, prefix: &str) -> anyhow::Result<String> {
    let Some(rest) = strip_prefix_ignore_ascii_case(argument.trim_start(), prefix) else {
        bail!("expected {prefix}");
    };

    let rest = rest.trim_start();
    if let Some(rest) = rest.strip_prefix('<') {
        let Some(end) = rest.find('>') else {
            bail!("unterminated address path");
        };
        return Ok(rest[..end].trim().to_string());
    }

    let value = rest.split_whitespace().next().unwrap_or_default();
    Ok(value.trim().to_string())
}

fn strip_prefix_ignore_ascii_case<'a>(value: &'a str, prefix: &str) -> Option<&'a str> {
    let prefix_len = prefix.len();
    if value.len() < prefix_len || !value[..prefix_len].eq_ignore_ascii_case(prefix) {
        return None;
    }
    Some(&value[prefix_len..])
}

fn split_command(line: &str) -> (String, String) {
    let mut parts = line.splitn(2, char::is_whitespace);
    let command = parts.next().unwrap_or_default().to_ascii_uppercase();
    let argument = parts.next().unwrap_or_default().trim().to_string();
    (command, argument)
}

fn trim_crlf(line: &[u8]) -> String {
    String::from_utf8_lossy(trim_crlf_bytes(line)).to_string()
}

fn trim_crlf_bytes(line: &[u8]) -> &[u8] {
    let mut end = line.len();
    while end > 0 && matches!(line[end - 1], b'\r' | b'\n') {
        end -= 1;
    }
    &line[..end]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_auth_plain_payload() {
        let payload: String = STANDARD.encode(b"\0relay\0secret");
        let (username, password) = decode_auth_plain(&payload).unwrap();
        assert_eq!(username, "relay");
        assert_eq!(password, "secret");
    }

    #[test]
    fn parses_smtp_path() {
        let sender: String = parse_path_argument("FROM:<sender@example.com> SIZE=42", "FROM:").unwrap();
        assert_eq!(sender, "sender@example.com");
    }
}
