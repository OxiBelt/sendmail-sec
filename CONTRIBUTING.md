# Contributing to `sendmail-sec`

Thanks for helping improve `sendmail-sec`. This project accepts authenticated
local SMTP submissions, encrypts mail with OpenPGP, and relays the encrypted
message to a remote SMTP server over mandatory TLS. Treat changes to SMTP
parsing, authentication, CIDR access control, OpenPGP key discovery,
encryption, remote SMTP delivery, TLS validation, and configuration as
security-sensitive unless there is a clear reason they are not.

Use root-relative paths in root-level documentation, scripts, issues, and pull
request notes. For example, prefer `sources/config.rs` over `config.rs` unless
the text explicitly says the command is being run from `sources/`.

## Repository Layout

Generated and local-only directories such as `target/`, `node_modules/`, and
temporary Docker or test output are not source contributions and should not be
committed.

| Path | Purpose | Change here when |
| --- | --- | --- |
| `sources/` | Main Rust binary crate source. | You are changing CLI, runtime, SMTP listener, OpenPGP, TLS, config, message, or relay behavior. |
| `sources/main.rs` | Binary entry point. | Startup, logging, process exit, or top-level wiring changes. |
| `sources/app.rs` and `sources/cli.rs` | Application orchestration and command-line parsing. | CLI flags, config checking, or high-level application flow changes. |
| `sources/config.rs` | Configuration types, defaults, loading, and validation. | YAML or JSON syntax, defaults, validation, or compatibility changes. |
| `sources/listener.rs` | Inbound SMTP listener, client restrictions, and local authentication. | Local SMTP command handling, allowed networks, inbound auth, or message acceptance changes. |
| `sources/message.rs` | Mail parsing and recipient/message handling helpers. | Header parsing, envelope/header recipient handling, or MIME/message transformations change. |
| `sources/openpgp.rs` | OpenPGP key loading, discovery, caching, and encryption. | Local key files, key directories, WKD, `keys.openpgp.org`, encryption mode, or PGP/MIME behavior changes. |
| `sources/remote_smtp.rs` | Remote SMTP relay behavior. | STARTTLS/wrapper TLS flow, remote auth, SMTP command flow, delivery, timeouts, or relay errors change. |
| `sources/tls.rs` | Rustls root store and certificate handling. | TLS root loading, certificate parsing, or outbound TLS validation changes. |
| `examples/` | Example YAML and JSON configuration. | User-visible configuration keys, defaults, or examples change. |
| `Dockerfile` | Release container image. | Runtime image, build targets, package dependencies, entrypoint, user, or container layout changes. |
| `scripts/docker-integration-test.sh` | End-to-end Docker integration test. | Containerized SMTP relay behavior, Docker fixtures, generated OpenPGP/TLS materials, or cleanup flow changes. |
| `scripts/build-docker-image-artifact.sh` | Release-style Docker image tarball builder. | CI image artifacts, OCI labels, architecture matrix, or release image layout changes. |
| `devops/` | TypeScript release versioning and Docker image plan tooling. | Release tag validation, Cargo release metadata, GHCR tag planning, or DevOps tests change. |
| `.github/workflows/` | GitHub Actions workflows. | CI checks, release image publishing, build matrix, or required workflow behavior changes. |
| `README.md` | User-facing overview, build, configuration, container, and release notes. | Setup, usage, high-level behavior, configuration, or release documentation changes. |

## Contribution Workflow

1. Identify the affected area before editing: Rust runtime, inbound SMTP,
   remote SMTP, OpenPGP, TLS, configuration, Docker image, Docker integration
   test, GitHub Actions, examples, or documentation.
2. Make the smallest reasonable change for the behavior being changed.
3. Add or update tests when SMTP, authentication, CIDR filtering, OpenPGP,
   TLS, configuration, Docker, workflow, or user-visible runtime behavior
   changes.
4. Update `README.md` and `examples/` when behavior, configuration syntax,
   defaults, commands, supported platforms, or container usage changes.
5. Run the relevant checks and mention any checks that could not be run.
6. Verify that generated key material, TLS material, Docker resources, and
   temporary captures are cleaned up.

For Rust changes, prefer commands from the repository root:

```sh
cargo fmt --all --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked
cargo build --locked
```

Run Docker checks when the change affects the container image, release image
matrix, SMTP relay behavior, TLS behavior, OpenPGP encryption behavior, or the
Docker test fixture:

```sh
docker build -t sendmail-sec .
scripts/docker-integration-test.sh
```

Run DevOps checks when release versioning, GHCR image publishing, workflow
metadata, or TypeScript automation changes:

```sh
pnpm install --frozen-lockfile
pnpm run lint
pnpm run typecheck
pnpm run test
pnpm run versioning:check
```

Validate configuration examples after changing config syntax or defaults. At a
minimum, run `sendmail-sec --config <path> --check-config` against the affected
example format after building the binary.

## Commit Messages

Use Conventional Commits for commit messages:

```text
<type>(<scope>): <subject>
```

- `type` must be one of `feat`, `fix`, `chore`, `docs`, `ci`, `refactor`,
  `security`, `tests`, or `perf`.
- `scope` is the field, area, or responsibility touched by the code, such as
  `smtp`, `auth`, `openpgp`, `tls`, `config`, `docker`, `workflows`, or `docs`.
- `subject` is a short imperative summary. Use a present-tense verb. Do not use
  past tense or past-perfect wording.
- In the commit title and detailed description, wrap code keywords, paths,
  commands, configuration keys, function names, variable names, type names,
  module names, and literal values in Markdown inline code spans with
  backticks.

Valid examples:

```text
feat(openpgp): add `full_message` encryption coverage
fix(smtp): reject unauthenticated `MAIL FROM` commands
security(tls): fail closed on invalid relay certificates
ci(workflows): test Docker image on `linux/arm64`
```

Avoid examples like `fixed SMTP auth`, `added TLS tests`, or `has updated
docs` because the subject is not imperative present tense. Also avoid leaving
identifiers unformatted, such as `update encryption_mode`; write
`update \`encryption_mode\`` instead.

## Rust Module Organization

Do not force unrelated functionality into an existing Rust source file just
because the file already exists.

If new code belongs to a different responsibility or feature category, add a
new Rust module under `sources/` and wire it through `sources/main.rs` as
needed. Keep module boundaries explicit:

- Inbound SMTP command handling and client policy should remain in
  `sources/listener.rs` or a focused listener module.
- Remote SMTP delivery, advertised capabilities, and remote authentication
  should remain in `sources/remote_smtp.rs` or a focused relay module.
- OpenPGP key discovery and encryption should remain in `sources/openpgp.rs` or
  a focused OpenPGP module.
- TLS root loading and certificate handling should remain in `sources/tls.rs`
  or a focused TLS module.
- Configuration parsing, defaults, and validation should remain in
  `sources/config.rs` or a focused config module.
- Mail parsing and recipient extraction should remain in `sources/message.rs`
  or a focused message module.

When adding a new Rust file or module, choose a responsibility-focused name,
add tests for new behavior, update user-facing documentation when behavior is
visible to operators, and avoid generic utility modules unless the shared
responsibility is clear.

Treat roughly 750 lines as a review threshold for Rust source files under
`sources/`. Existing larger files should shrink over time rather than absorb
unrelated behavior.

## Area Guidelines

Be especially careful when modifying:

- `sources/listener.rs`
- `sources/remote_smtp.rs`
- `sources/openpgp.rs`
- `sources/config.rs`
- `sources/tls.rs`
- `sources/message.rs`
- `scripts/docker-integration-test.sh`
- `Dockerfile`

Do not silently change SMTP, OpenPGP, or TLS behavior. Changes should
explicitly consider authentication requirements, allowed client networks,
message size limits, envelope and header recipient handling, key lookup
sources, encryption mode, outbound TLS validation, remote SMTP authentication,
timeout behavior, error handling, and logging behavior.

Configuration changes must update `sources/config.rs`, update `examples/` and
`README.md` when syntax or semantics change, add or update tests when
practical, and keep both YAML and JSON examples valid.

Detailed operational behavior belongs in `README.md` unless a future `docs/`
directory is introduced. Do not leave user-visible configuration or security
behavior documented only in code comments or pull request text.

## Tests and Temporary Data

Rust unit tests live in the relevant `sources/*.rs` modules. Docker-based
end-to-end coverage lives in `scripts/docker-integration-test.sh`.

When modifying SMTP, authentication, CIDR filtering, OpenPGP, TLS,
configuration, runtime, or Docker behavior, update or add tests in the relevant
area. Do not remove tests just to make CI pass, and do not disable TLS,
OpenPGP, SMTP, configuration, or Docker integration coverage without
documenting the reason.

Tests may need short-lived generated files, such as OpenPGP keypairs,
self-signed TLS certificates, private keys, temporary configuration files,
generated CA roots, SMTP fixture scripts, or captured relay messages. Treat
these as disposable test data:

- Generate temporary data at test startup or test-suite setup time.
- Use each generated data set only for the relevant test run.
- Delete generated files when the test or test suite finishes.
- Prefer temporary directories over fixed paths inside the repository.
- Avoid committing generated certificates, private keys, keyrings, runtime
  configs, logs, captures, or decrypted test output.
- Ensure cleanup also runs when tests fail, where practical.
- Do not reuse stale TLS certificates, keys, OpenPGP keys, or generated configs
  across independent test runs unless the reuse is explicit, safe, and
  documented.

## Docker and Integration Tests

Docker-based tests should be reproducible locally and in GitHub Actions.

Prefer `scripts/docker-integration-test.sh` for end-to-end Docker validation.
It builds or accepts an application image, starts an isolated Docker network,
runs a TLS-enabled SMTP fixture container, starts the application container,
submits a message through the local SMTP listener, and verifies that the
captured relay message is PGP/MIME encrypted and decryptable with an ephemeral
test key.

The script intentionally uses `docker cp` to place generated configs, OpenPGP
material, TLS certificates, and fixture scripts into containers. Some
developers work inside a Dev Container while Docker is exposed through Docker
outside of Docker, where bind mounts and host paths can behave differently from
a normal local shell. Do not rewrite Docker tests to depend on bind mounts or
volume mounts unless there is a strong reason.

When changing Docker behavior:

- Avoid depending on host-installed services.
- Keep Docker builds reproducible.
- Prefer explicit package versions when practical.
- Make Docker-based tests work in CI.
- Do not assume local-only paths outside the repository.
- Clean up Docker resources created by tests.
- Keep generated OpenPGP keys, TLS material, configs, and captures out of the
  repository.

Docker tests must remove related test containers, test networks, test-only
images, and temporary files. Prefer explicit container, image, network, volume,
or label names so cleanup does not remove unrelated developer resources.

## Security Requirements

Do not hard-code:

- secrets
- tokens
- credentials
- private URLs
- cookies
- certificates or private keys
- OpenPGP private keys

Be careful with:

- inbound SMTP `AUTH PLAIN` credentials
- remote SMTP credentials and OAuth bearer tokens
- `From`, `To`, `Cc`, `Bcc`, `Date`, and `Subject` headers
- SMTP envelope sender and recipient values
- generated OpenPGP and TLS test material
- `tls.extra_root_certificates`
- `openpgp.local_key_files` and `openpgp.local_key_directories`
- WKD and `keys.openpgp.org` key discovery

Treat all SMTP client input, message content, envelope values, headers,
configuration files, local key material paths, remote SMTP server responses,
and OpenPGP key discovery responses as untrusted.

Do not weaken TLS behavior, certificate validation, inbound authentication,
allowed-network checks, OpenPGP encryption defaults, or security-sensitive
configuration validation without tests and documentation.

When modifying inbound SMTP behavior, explicitly consider:

- unauthenticated commands before `AUTH PLAIN`
- malformed or invalid base64 auth payloads
- CIDR allow-list enforcement
- message size limit enforcement
- command sequencing before `MAIL`, `RCPT`, and `DATA`
- envelope recipient handling, including Bcc-style recipients
- header recipient parsing for key lookup
- dot-stuffed message bodies
- timeout and connection error behavior
- logging without leaking credentials or message secrets

When modifying remote SMTP behavior, explicitly consider:

- mandatory TLS enforcement
- `starttls` versus wrapper TLS behavior
- remote certificate validation and extra trust roots
- advertised auth mechanism parsing
- `PLAIN`, `OAUTHBEARER`, and `XOAUTH2` failure behavior
- envelope sender and recipient delivery semantics
- timeout behavior and partial delivery errors
- logging without leaking credentials, bearer tokens, or message content

When modifying OpenPGP behavior, explicitly consider:

- local key file and directory parsing
- invalid, expired, revoked, or non-encryption-capable keys
- key lookup precedence and caching behavior
- WKD and `keys.openpgp.org` network failures
- recipient coverage for envelope and header recipients
- `pgp_mime_body` versus `full_message` semantics
- failure behavior when a recipient key cannot be found

For security-related changes:

1. Identify the affected trust boundary.
2. Identify attacker-controlled inputs.
3. Describe the vulnerability class or suspected vulnerability class.
4. Add or update regression tests whenever practical.
5. Prefer fail-closed behavior for security-sensitive decisions.
6. Avoid introducing `unwrap`, `expect`, `panic!`, `todo!`, or `unreachable!`
   on externally reachable input paths.
7. Avoid silently ignoring errors in SMTP handling, TLS validation, OpenPGP key
   lookup, encryption, remote relay, or configuration validation.
8. Run the relevant tests or clearly state why they could not be run.
9. Summarize remaining risks and compatibility concerns.

If a security-sensitive operation fails, the default should be reject, deny,
abort delivery, or return a safe error unless there is a documented and tested
reason to continue.

## Do Not

- Do not remove tests just to make CI pass.
- Do not disable TLS, SMTP, OpenPGP, configuration, or Docker integration tests
  without a documented reason.
- Do not commit `target/`, generated build artifacts, `node_modules/`,
  generated certificates, private keys, OpenPGP private keys, temporary
  configs, logs, captures, or decrypted test output unless explicitly required.
- Do not make CI depend on local-only files or absolute host paths.
- Do not silently change public SMTP, TLS, OpenPGP, or configuration behavior.
- Do not change configuration syntax without updating examples, docs, and tests
  where practical.
- Do not leave Docker test containers, networks, images, temporary volumes, or
  generated key material behind after Docker-based tests finish.
- Do not rely on Dev Container bind-mount paths being visible to the Docker
  daemon in the same way as inside the container.

## Pull Request Checklist

Before opening or marking a pull request ready:

- The commit messages use the documented Conventional Commits format.
- The affected area is clear in the pull request description.
- User-visible behavior changes are covered in `README.md` and `examples/` as
  appropriate.
- Configuration changes update tests, docs, and example configuration when
  needed.
- SMTP, TLS, OpenPGP, authentication, CIDR, runtime, or security-sensitive
  changes include regression tests whenever practical.
- Relevant local checks were run, or any skipped checks are explained.
- Temporary test data was removed.
- Docker-based tests clean up containers, networks, test-only images, and
  temporary files.
- Security-sensitive changes describe trust boundaries, attacker-controlled
  inputs, failure behavior, remaining risks, and compatibility concerns.
