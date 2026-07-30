use std::{
  fs,
  path::{Path, PathBuf},
};

use super::*;

const MINIMAL_YAML: &str = r#"
listen:
  auth:
    username: inbound
    password: secret
remote_smtp:
  host: smtp.example.com
  auth:
    mechanism: PLAIN
    username: relay
    password: secret
"#;

const MINIMAL_JSON: &str = r#"{
  "listen": {
    "auth": {
      "username": "inbound",
      "password": "secret"
    }
  },
  "remote_smtp": {
    "host": "smtp.example.com",
    "auth": {
      "mechanism": "PLAIN",
      "username": "relay",
      "password": "secret"
    }
  }
}"#;

struct TestConfigFile {
  path: PathBuf,
}

impl TestConfigFile {
  fn new(extension: Option<&str>, contents: &str) -> Self {
    let mut path = std::env::temp_dir().join(format!("sendmail-sec-{}", uuid::Uuid::new_v4()));
    if let Some(extension) = extension {
      path.set_extension(extension);
    }
    fs::write(&path, contents).unwrap();
    Self { path }
  }

  fn path(&self) -> &Path {
    &self.path
  }
}

impl Drop for TestConfigFile {
  fn drop(&mut self) {
    let _ = fs::remove_file(&self.path);
  }
}

struct TestSecretFile {
  path: PathBuf,
}

impl TestSecretFile {
  fn new(contents: &[u8]) -> Self {
    let path = std::env::temp_dir().join(format!("sendmail-sec-secret-{}", uuid::Uuid::new_v4()));
    fs::write(&path, contents).unwrap();
    Self { path }
  }

  fn path(&self) -> &Path {
    &self.path
  }

  fn relative_name(&self) -> &str {
    self.path.file_name().unwrap().to_str().unwrap()
  }
}

impl Drop for TestSecretFile {
  fn drop(&mut self) {
    let _ = fs::remove_file(&self.path);
  }
}

#[test]
fn loads_yaml_extensions_with_defaults_and_enum_aliases() {
  for extension in ["yaml", "yml"] {
    let file = TestConfigFile::new(Some(extension), MINIMAL_YAML);
    let config = AppConfig::load(file.path()).unwrap();

    assert_eq!(config.listen.bind, "0.0.0.0:2525".parse().unwrap());
    assert_eq!(config.remote_smtp.port, 587);
    assert!(matches!(
      config.remote_smtp.auth,
      RemoteAuthConfig::Plain { .. }
    ));
  }
}

#[test]
fn loads_yaml_anchor_aliases() {
  let file = TestConfigFile::new(
    Some("yaml"),
    r#"
relay_auth: &relay_auth
  mechanism: plain
  username: relay
  password: secret
listen:
  auth:
    username: inbound
    password: secret
remote_smtp:
  host: smtp.example.com
  auth: *relay_auth
"#,
  );

  let config = AppConfig::load(file.path()).unwrap();
  assert!(matches!(
    config.remote_smtp.auth,
    RemoteAuthConfig::Plain { .. }
  ));
}

#[test]
fn extensionless_files_fall_back_between_yaml_and_json() {
  for contents in [MINIMAL_YAML, MINIMAL_JSON] {
    let file = TestConfigFile::new(None, contents);
    let config = AppConfig::load(file.path()).unwrap();
    assert_eq!(config.remote_smtp.host, "smtp.example.com");
  }
}

#[test]
fn parses_checked_in_config_examples() {
  let _: ParsedAppConfig =
    serde_norway::from_str(include_str!("../examples/config-secrets.yaml")).unwrap();
  let _: ParsedAppConfig =
    serde_json::from_str(include_str!("../examples/config-secrets.json")).unwrap();

  let examples_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples");
  let inline_yaml = AppConfig::load(&examples_dir.join("config.yaml")).unwrap();
  let inline_json = AppConfig::load(&examples_dir.join("config.json")).unwrap();

  for config in [inline_yaml, inline_json] {
    let rendered = format!("{config:?}");
    assert!(!rendered.contains("change-me"));
    assert!(!rendered.contains("relay-password"));
  }
}

#[test]
fn resolves_relative_paths_against_the_config_directory() {
  let contents = format!(
    "{MINIMAL_YAML}\ntls:\n  extra_root_certificates:\n    - roots/ca.pem\nopenpgp:\n  local_key_files:\n    - keys/public.asc\n  local_key_directories:\n    - keys\n"
  );
  let file = TestConfigFile::new(Some("yaml"), &contents);
  let base = file.path().parent().unwrap();
  let config = AppConfig::load(file.path()).unwrap();

  assert_eq!(
    config.tls.extra_root_certificates,
    [base.join("roots/ca.pem")]
  );
  assert_eq!(
    config.openpgp.local_key_files,
    [base.join("keys/public.asc")]
  );
  assert_eq!(config.openpgp.local_key_directories, [base.join("keys")]);
}

#[test]
fn loads_relative_yaml_password_files() {
  let inbound = TestSecretFile::new(b"inbound-file-secret\r\n");
  let remote = TestSecretFile::new(b"remote-file-secret\n");
  let file = TestConfigFile::new(
    Some("yaml"),
    &format!(
      r#"
listen:
  auth:
    username: inbound
    password_file: {}
remote_smtp:
  host: smtp.example.com
  auth:
    mechanism: PLAIN
    username: relay
    password_file: {}
"#,
      inbound.relative_name(),
      remote.relative_name()
    ),
  );

  let config = AppConfig::load(file.path()).unwrap();
  assert_eq!(
    config.listen.auth.password.expose().unwrap(),
    "inbound-file-secret"
  );
  match config.remote_smtp.auth {
    RemoteAuthConfig::Plain { password, .. } => {
      assert_eq!(password.expose().unwrap(), "remote-file-secret");
    }
    _ => panic!("expected PLAIN auth"),
  }
}

#[test]
fn loads_json_access_token_files_for_oauth_mechanisms() {
  for mechanism in ["OAUTHBEARER", "XOAUTH2"] {
    let token = TestSecretFile::new(format!("{mechanism}-file-token\n").as_bytes());
    let contents = serde_json::json!({
      "listen": {
        "auth": {
          "username": "inbound",
          "password": "secret"
        }
      },
      "remote_smtp": {
        "host": "smtp.example.com",
        "auth": {
          "mechanism": mechanism,
          "username": "relay",
          "access_token_file": token.path()
        }
      }
    })
    .to_string();
    let file = TestConfigFile::new(Some("json"), &contents);

    let config = AppConfig::load(file.path()).unwrap();
    let access_token = match config.remote_smtp.auth {
      RemoteAuthConfig::Oauthbearer { access_token, .. }
      | RemoteAuthConfig::Xoauth2 { access_token, .. } => access_token,
      _ => panic!("expected OAuth auth"),
    };
    assert_eq!(
      access_token.expose().unwrap(),
      format!("{mechanism}-file-token")
    );
  }
}

#[test]
fn rejects_ambiguous_or_missing_secret_sources() {
  let cases = [
    (
      r#"
listen:
  auth:
    username: inbound
    password: inline
    password_file: ignored
remote_smtp:
  host: smtp.example.com
  auth:
    mechanism: plain
    username: relay
    password: secret
"#,
      "exactly one of listen.auth.password or listen.auth.password_file",
    ),
    (
      r#"
listen:
  auth:
    username: inbound
    password: secret
remote_smtp:
  host: smtp.example.com
  auth:
    mechanism: plain
    username: relay
    password: inline
    password_file: ignored
"#,
      "exactly one of remote_smtp.auth.password or remote_smtp.auth.password_file",
    ),
    (
      r#"
listen:
  auth:
    username: inbound
    password: secret
remote_smtp:
  host: smtp.example.com
  auth:
    mechanism: xoauth2
    username: relay
"#,
      "exactly one of remote_smtp.auth.access_token or remote_smtp.auth.access_token_file",
    ),
    (
      r#"
listen:
  auth:
    username: inbound
remote_smtp:
  host: smtp.example.com
  auth:
    mechanism: plain
    username: relay
    password: secret
"#,
      "exactly one of listen.auth.password or listen.auth.password_file",
    ),
    (
      r#"
listen:
  auth:
    username: inbound
    password: secret
remote_smtp:
  host: smtp.example.com
  auth:
    mechanism: plain
    username: relay
"#,
      "exactly one of remote_smtp.auth.password or remote_smtp.auth.password_file",
    ),
    (
      r#"
listen:
  auth:
    username: inbound
    password: secret
remote_smtp:
  host: smtp.example.com
  auth:
    mechanism: oauthbearer
    username: relay
    access_token: inline
    access_token_file: ignored
"#,
      "exactly one of remote_smtp.auth.access_token or remote_smtp.auth.access_token_file",
    ),
  ];

  for (contents, expected) in cases {
    let file = TestConfigFile::new(Some("yaml"), contents);
    let error = AppConfig::load(file.path()).unwrap_err();
    assert!(format!("{error:#}").contains(expected));
  }
}

#[test]
fn rejects_empty_secret_file_paths_before_resolving_them() {
  let file = TestConfigFile::new(
    Some("yaml"),
    r#"
listen:
  auth:
    username: inbound
    password_file: ""
remote_smtp:
  host: smtp.example.com
  auth:
    mechanism: plain
    username: relay
    password: secret
"#,
  );

  let error = AppConfig::load(file.path()).unwrap_err();
  assert!(format!("{error:#}").contains("listen.auth.password_file must not be an empty path"));
}

#[test]
fn rejects_missing_secret_files_with_field_context() {
  let missing_name = format!("sendmail-sec-missing-{}", uuid::Uuid::new_v4());
  let file = TestConfigFile::new(
    Some("yaml"),
    &format!(
      r#"
listen:
  auth:
    username: inbound
    password_file: {missing_name}
remote_smtp:
  host: smtp.example.com
  auth:
    mechanism: plain
    username: relay
    password: secret
"#
    ),
  );

  let error = AppConfig::load(file.path()).unwrap_err();
  let rendered = format!("{error:#}");
  assert!(rendered.contains("listen.auth.password_file"));
  assert!(rendered.contains(&missing_name));
}

#[test]
fn rejects_malformed_yaml() {
  let file = TestConfigFile::new(Some("yaml"), "listen: [");
  let error = AppConfig::load(file.path()).unwrap_err();
  assert!(error.to_string().contains("failed to parse YAML config"));
}

#[test]
fn rejects_recursive_yaml_aliases() {
  let file = TestConfigFile::new(
    Some("yaml"),
    r#"
listen:
  auth:
    username: inbound
    password: secret
remote_smtp: &remote
  host: smtp.example.com
  auth: *remote
"#,
  );

  assert!(AppConfig::load(file.path()).is_err());
}
