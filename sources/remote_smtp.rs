use std::{collections::HashSet, sync::Arc, time::Duration};

use anyhow::{Context, bail};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use rustls::pki_types::ServerName;
use tokio::{
    io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader},
    net::TcpStream,
    time::timeout,
};

use crate::{
    config::{RemoteAuthConfig, RemoteSmtpConfig, RemoteTlsMode},
    message::{RelayMessage, dot_stuff},
    tls::OutboundTls,
};

pub struct RemoteSmtpClient {
    config: RemoteSmtpConfig,
    tls: Arc<OutboundTls>,
}

impl RemoteSmtpClient {
    pub fn new(config: RemoteSmtpConfig, tls: Arc<OutboundTls>) -> Self {
        Self { config, tls }
    }

    pub async fn send_message(&self, message: &RelayMessage) -> anyhow::Result<()> {
        let address = format!("{}:{}", self.config.host, self.config.port);
        let connect_timeout = Duration::from_secs(self.config.connect_timeout_secs);
        let command_timeout = Duration::from_secs(self.config.command_timeout_secs);

        let stream = timeout(connect_timeout, TcpStream::connect(&address))
            .await
            .context("timed out connecting to remote SMTP server")?
            .with_context(|| format!("failed to connect to remote SMTP server {address}"))?;
        stream
            .set_nodelay(true)
            .context("failed to configure TCP_NODELAY")?;

        match self.config.tls_mode {
            RemoteTlsMode::Wrapper => {
                let server_name = server_name(&self.config.host)?;
                let tls_stream = timeout(
                    connect_timeout,
                    self.tls.connector().connect(server_name, stream),
                )
                .await
                .context("timed out during SMTPS TLS handshake")?
                .context("failed to establish SMTPS TLS connection")?;

                let mut connection = SmtpConnection::new(tls_stream, command_timeout);
                connection.expect_greeting().await?;
                let capabilities = connection.ehlo(&self.config.hello_name).await?;
                self.authenticate(&mut connection, &capabilities).await?;
                self.send_transaction(&mut connection, message).await?;
                let _ = connection.quit().await;
            }
            RemoteTlsMode::Starttls => {
                let mut plain = SmtpConnection::new(stream, command_timeout);
                plain.expect_greeting().await?;
                let capabilities = plain.ehlo(&self.config.hello_name).await?;
                if !capabilities.starttls {
                    bail!("remote SMTP server did not advertise STARTTLS");
                }

                plain
                    .command_expect("STARTTLS", &[220])
                    .await
                    .context("remote SMTP server rejected STARTTLS")?;

                let stream = plain.into_inner();
                let server_name = server_name(&self.config.host)?;
                let tls_stream = timeout(
                    connect_timeout,
                    self.tls.connector().connect(server_name, stream),
                )
                .await
                .context("timed out during STARTTLS handshake")?
                .context("failed to upgrade SMTP connection to TLS")?;

                let mut tls = SmtpConnection::new(tls_stream, command_timeout);
                let capabilities = tls.ehlo(&self.config.hello_name).await?;
                self.authenticate(&mut tls, &capabilities).await?;
                self.send_transaction(&mut tls, message).await?;
                let _ = tls.quit().await;
            }
        }

        Ok(())
    }

    async fn authenticate<S>(
        &self,
        connection: &mut SmtpConnection<S>,
        capabilities: &ServerCapabilities,
    ) -> anyhow::Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        match &self.config.auth {
            RemoteAuthConfig::Plain { username, password } => {
                capabilities.require_mechanism("PLAIN")?;
                connection.command_expect("AUTH PLAIN", &[334]).await?;
                let payload = STANDARD.encode(format!("\u{0}{username}\u{0}{password}"));
                connection
                    .command_expect(&payload, &[235])
                    .await
                    .context("remote SMTP AUTH PLAIN failed")?;
            }
            RemoteAuthConfig::Oauthbearer {
                username,
                access_token,
                authzid,
            } => {
                capabilities.require_mechanism("OAUTHBEARER")?;
                connection
                    .command_expect("AUTH OAUTHBEARER", &[334])
                    .await?;
                let payload = STANDARD.encode(format!(
                    "n,a={},\u{1}host={}\u{1}port={}\u{1}auth=Bearer {}\u{1}\u{1}",
                    authzid.as_deref().unwrap_or(username),
                    self.config.host,
                    self.config.port,
                    access_token
                ));
                let response = connection.command(&payload).await?;
                if response.code == 235 {
                    return Ok(());
                }
                if response.code == 334 {
                    let _ = connection.command("AQ==").await;
                }
                bail!(
                    "remote SMTP AUTH OAUTHBEARER failed: {}",
                    response.summary()
                );
            }
            RemoteAuthConfig::Xoauth2 {
                username,
                access_token,
            } => {
                capabilities.require_mechanism("XOAUTH2")?;
                connection.command_expect("AUTH XOAUTH2", &[334]).await?;
                let payload = STANDARD.encode(format!(
                    "user={username}\u{1}auth=Bearer {access_token}\u{1}\u{1}"
                ));
                let response = connection.command(&payload).await?;
                if response.code == 235 {
                    return Ok(());
                }
                if response.code == 334 {
                    let _ = connection.command("").await;
                }
                bail!("remote SMTP AUTH XOAUTH2 failed: {}", response.summary());
            }
        }

        Ok(())
    }

    async fn send_transaction<S>(
        &self,
        connection: &mut SmtpConnection<S>,
        message: &RelayMessage,
    ) -> anyhow::Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let sender = if message.envelope.mail_from.is_empty() {
            "<>".to_string()
        } else {
            format!("<{}>", message.envelope.mail_from)
        };

        connection
            .command_expect(&format!("MAIL FROM:{sender}"), &[250])
            .await
            .context("remote SMTP MAIL FROM rejected")?;

        for recipient in &message.envelope.rcpt_to {
            connection
                .command_expect(&format!("RCPT TO:<{recipient}>"), &[250, 251])
                .await
                .with_context(|| format!("remote SMTP RCPT TO rejected for {recipient}"))?;
        }

        connection.command_expect("DATA", &[354]).await?;
        connection
            .write_message_data(&message.data)
            .await
            .context("remote SMTP DATA transfer failed")?;

        Ok(())
    }
}

#[derive(Debug, Default)]
struct ServerCapabilities {
    starttls: bool,
    auth_mechanisms: HashSet<String>,
}

impl ServerCapabilities {
    fn from_ehlo(response: &SmtpResponse) -> Self {
        let mut capabilities = Self::default();

        for line in &response.lines {
            let upper = line.to_ascii_uppercase();
            if upper == "STARTTLS" {
                capabilities.starttls = true;
            } else if let Some(rest) = upper.strip_prefix("AUTH ") {
                for mechanism in rest.split_whitespace() {
                    capabilities.auth_mechanisms.insert(mechanism.to_string());
                }
            } else if let Some(rest) = upper.strip_prefix("AUTH=") {
                capabilities.auth_mechanisms.insert(rest.trim().to_string());
            }
        }

        capabilities
    }

    fn require_mechanism(&self, mechanism: &str) -> anyhow::Result<()> {
        if self.auth_mechanisms.contains(mechanism) {
            return Ok(());
        }

        bail!("remote SMTP server did not advertise AUTH {mechanism}")
    }
}

struct SmtpConnection<S> {
    stream: BufReader<S>,
    timeout: Duration,
}

impl<S> SmtpConnection<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn new(stream: S, timeout: Duration) -> Self {
        Self {
            stream: BufReader::new(stream),
            timeout,
        }
    }

    fn into_inner(self) -> S {
        self.stream.into_inner()
    }

    async fn expect_greeting(&mut self) -> anyhow::Result<SmtpResponse> {
        self.expect_response(&[220]).await
    }

    async fn ehlo(&mut self, hello_name: &str) -> anyhow::Result<ServerCapabilities> {
        let response = self
            .command_expect(&format!("EHLO {hello_name}"), &[250])
            .await
            .context("remote SMTP EHLO failed")?;
        Ok(ServerCapabilities::from_ehlo(&response))
    }

    async fn quit(&mut self) -> anyhow::Result<()> {
        let _ = self.command("QUIT").await?;
        Ok(())
    }

    async fn write_message_data(&mut self, data: &[u8]) -> anyhow::Result<()> {
        let stuffed = dot_stuff(data);
        self.write_all(&stuffed).await?;
        self.write_all(b".\r\n").await?;
        self.expect_response(&[250]).await?;
        Ok(())
    }

    async fn command_expect(
        &mut self,
        line: &str,
        expected_codes: &[u16],
    ) -> anyhow::Result<SmtpResponse> {
        let response = self.command(line).await?;
        if expected_codes.contains(&response.code) {
            return Ok(response);
        }

        bail!(
            "unexpected SMTP response to `{line}`: expected {:?}, got {} ({})",
            expected_codes,
            response.code,
            response.summary()
        )
    }

    async fn command(&mut self, line: &str) -> anyhow::Result<SmtpResponse> {
        self.write_all(line.as_bytes()).await?;
        self.write_all(b"\r\n").await?;
        self.read_response().await
    }

    async fn expect_response(&mut self, expected_codes: &[u16]) -> anyhow::Result<SmtpResponse> {
        let response = self.read_response().await?;
        if expected_codes.contains(&response.code) {
            return Ok(response);
        }

        bail!(
            "unexpected SMTP response: expected {:?}, got {} ({})",
            expected_codes,
            response.code,
            response.summary()
        )
    }

    async fn read_response(&mut self) -> anyhow::Result<SmtpResponse> {
        let mut code = None;
        let mut lines = Vec::new();

        loop {
            let line = self.read_line().await?;
            if line.len() < 3 {
                bail!("short SMTP response from remote server");
            }

            let parsed_code: u16 = line[..3]
                .parse()
                .with_context(|| format!("invalid SMTP response code in `{line}`"))?;
            let separator = line.as_bytes().get(3).copied().unwrap_or(b' ');
            let text = line.get(4..).unwrap_or("").trim().to_string();

            if let Some(existing) = code {
                if existing != parsed_code {
                    bail!("mixed SMTP response codes in multiline response");
                }
            } else {
                code = Some(parsed_code);
            }

            lines.push(text);

            match separator {
                b'-' => continue,
                b' ' => break,
                _ => bail!("malformed SMTP response separator"),
            }
        }

        Ok(SmtpResponse {
            code: code.expect("response code must be set"),
            lines,
        })
    }

    async fn read_line(&mut self) -> anyhow::Result<String> {
        let mut buffer = Vec::new();
        let read = timeout(self.timeout, self.stream.read_until(b'\n', &mut buffer))
            .await
            .context("timed out waiting for SMTP response")?
            .context("failed to read SMTP response")?;

        if read == 0 {
            bail!("remote SMTP server closed the connection");
        }

        Ok(String::from_utf8_lossy(&buffer)
            .trim_end_matches(['\r', '\n'])
            .to_string())
    }

    async fn write_all(&mut self, bytes: &[u8]) -> anyhow::Result<()> {
        timeout(self.timeout, self.stream.get_mut().write_all(bytes))
            .await
            .context("timed out writing to remote SMTP server")?
            .context("failed to write to remote SMTP server")
    }
}

#[derive(Debug)]
struct SmtpResponse {
    code: u16,
    lines: Vec<String>,
}

impl SmtpResponse {
    fn summary(&self) -> String {
        self.lines.join(" | ")
    }
}

fn server_name(host: &str) -> anyhow::Result<ServerName<'static>> {
    ServerName::try_from(host.to_string())
        .with_context(|| format!("invalid TLS server name {host}"))
}
