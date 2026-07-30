use std::{
  fmt,
  fs::OpenOptions,
  io::Read,
  os::unix::fs::OpenOptionsExt,
  path::{Path, PathBuf},
};

use anyhow::{Context, bail};

const MAX_SECRET_BYTES: usize = 64 * 1024;

#[derive(Clone)]
pub struct SecretString {
  source: SecretSource,
}

#[derive(Clone)]
enum SecretSource {
  Value(String),
  File(PathBuf),
}

impl SecretString {
  pub fn from_sources(
    value: Option<String>,
    file: Option<PathBuf>,
    value_field: &str,
    file_field: &str,
  ) -> Result<Self, String> {
    let source = match (value, file) {
      (Some(value), None) => SecretSource::Value(value),
      (None, Some(path)) => SecretSource::File(path),
      (Some(_), Some(_)) => {
        return Err(format!(
          "exactly one of {value_field} or {file_field} must be configured, not both"
        ));
      }
      (None, None) => {
        return Err(format!(
          "exactly one of {value_field} or {file_field} must be configured"
        ));
      }
    };

    Ok(Self { source })
  }

  pub fn inline(value: String) -> Self {
    Self {
      source: SecretSource::Value(value),
    }
  }

  pub fn resolve_relative_path(&mut self, base_dir: &Path) {
    let SecretSource::File(path) = &mut self.source else {
      return;
    };

    if !path.as_os_str().is_empty() && path.is_relative() {
      *path = base_dir.join(&path);
    }
  }

  pub fn resolve_file(&mut self, field: &str) -> anyhow::Result<()> {
    let SecretSource::File(path) = &self.source else {
      return Ok(());
    };

    if path.as_os_str().is_empty() {
      bail!("{field} must not be an empty path");
    }

    let mut file = OpenOptions::new()
      .read(true)
      .custom_flags(libc::O_NONBLOCK)
      .open(path)
      .with_context(|| format!("failed to read {field} file {}", path.display()))?;
    let opened_metadata = file
      .metadata()
      .with_context(|| format!("failed to inspect opened {field} file {}", path.display()))?;
    if !opened_metadata.is_file() {
      bail!("{field} must reference a regular file: {}", path.display());
    }

    let mut bytes = Vec::new();
    (&mut file)
      .take((MAX_SECRET_BYTES + 1) as u64)
      .read_to_end(&mut bytes)
      .with_context(|| format!("failed to read {field} file {}", path.display()))?;

    if bytes.len() > MAX_SECRET_BYTES {
      bail!(
        "{field} file exceeds the {MAX_SECRET_BYTES}-byte limit: {}",
        path.display()
      );
    }

    if bytes.ends_with(b"\r\n") {
      bytes.truncate(bytes.len() - 2);
    } else if bytes.ends_with(b"\n") {
      bytes.truncate(bytes.len() - 1);
    }

    let value = String::from_utf8(bytes)
      .map_err(|_| anyhow::anyhow!("{field} file is not valid UTF-8: {}", path.display()))?;
    if value.is_empty() {
      bail!("{field} must not be empty");
    }

    self.source = SecretSource::Value(value);
    Ok(())
  }

  pub fn expose(&self) -> anyhow::Result<&str> {
    match &self.source {
      SecretSource::Value(value) => Ok(value),
      SecretSource::File(_) => bail!("secret file source was not resolved during config loading"),
    }
  }
}

impl fmt::Debug for SecretString {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter.write_str("SecretString([REDACTED])")
  }
}

#[cfg(test)]
mod tests {
  use std::{
    fs,
    path::{Path, PathBuf},
  };

  use super::*;

  struct TestPath {
    path: PathBuf,
  }

  impl TestPath {
    fn file(contents: &[u8]) -> Self {
      let path = std::env::temp_dir().join(format!("sendmail-sec-secret-{}", uuid::Uuid::new_v4()));
      fs::write(&path, contents).unwrap();
      Self { path }
    }

    fn directory() -> Self {
      let path = std::env::temp_dir().join(format!("sendmail-sec-secret-{}", uuid::Uuid::new_v4()));
      fs::create_dir(&path).unwrap();
      Self { path }
    }

    fn path(&self) -> &Path {
      &self.path
    }
  }

  impl Drop for TestPath {
    fn drop(&mut self) {
      if self.path.is_dir() {
        let _ = fs::remove_dir_all(&self.path);
      } else {
        let _ = fs::remove_file(&self.path);
      }
    }
  }

  fn file_secret(path: &Path) -> SecretString {
    SecretString::from_sources(None, Some(path.to_path_buf()), "password", "password_file").unwrap()
  }

  #[test]
  fn strips_one_terminal_line_ending() {
    for (contents, expected) in [
      (&b"secret\n"[..], "secret"),
      (&b"secret\r\n"[..], "secret"),
      (&b"secret\n\n"[..], "secret\n"),
      (&b" secret \n"[..], " secret "),
      (&b"secret\r"[..], "secret\r"),
    ] {
      let file = TestPath::file(contents);
      let mut secret = file_secret(file.path());
      secret.resolve_file("listen.auth.password_file").unwrap();
      assert_eq!(secret.expose().unwrap(), expected);
    }
  }

  #[test]
  fn accepts_exactly_the_maximum_secret_size() {
    let file = TestPath::file(&vec![b'x'; MAX_SECRET_BYTES]);
    let mut secret = file_secret(file.path());

    secret.resolve_file("listen.auth.password_file").unwrap();

    assert_eq!(secret.expose().unwrap().len(), MAX_SECRET_BYTES);
  }

  #[test]
  fn rejects_invalid_secret_files_without_exposing_content() {
    let cases = [
      TestPath::file(b""),
      TestPath::file(b"\n"),
      TestPath::file(&[0xff, 0xfe]),
      TestPath::file(&vec![b'x'; MAX_SECRET_BYTES + 1]),
      TestPath::directory(),
    ];

    for path in &cases {
      let mut secret = file_secret(path.path());
      let error = secret
        .resolve_file("listen.auth.password_file")
        .unwrap_err();
      let rendered = format!("{error:#}");
      assert!(!rendered.contains("[REDACTED]"));
      assert!(!rendered.contains(&"x".repeat(256)));
    }
  }

  #[cfg(unix)]
  #[test]
  fn follows_symlinks_to_regular_files() {
    use std::os::unix::fs::symlink;

    let target = TestPath::file(b"secret\n");
    let link = TestPath {
      path: std::env::temp_dir().join(format!(
        "sendmail-sec-secret-symlink-{}",
        uuid::Uuid::new_v4()
      )),
    };
    symlink(target.path(), link.path()).unwrap();

    let mut secret = file_secret(link.path());
    secret.resolve_file("listen.auth.password_file").unwrap();

    assert_eq!(secret.expose().unwrap(), "secret");
  }

  #[test]
  fn debug_output_is_redacted() {
    let secret = SecretString::inline("sentinel-secret".to_string());
    let rendered = format!("{secret:?}");
    assert_eq!(rendered, "SecretString([REDACTED])");
    assert!(!rendered.contains("sentinel-secret"));
  }

  #[test]
  fn resolved_secrets_do_not_change_when_files_are_replaced() {
    let file = TestPath::file(b"initial-secret\n");
    let mut secret = file_secret(file.path());
    secret.resolve_file("listen.auth.password_file").unwrap();

    fs::write(file.path(), b"rotated-secret\n").unwrap();

    assert_eq!(secret.expose().unwrap(), "initial-secret");
  }
}
