# sendmail-sec

`sendmail-sec` is a Rust CLI that accepts authenticated SMTP submissions from localhost or private networks, encrypts the submitted mail with OpenPGP by default, and relays it to a remote SMTP server over mandatory TLS using Rustls. Operators can explicitly allow selected envelope recipients to receive an unencrypted message.

## What It Does

- Listens for SMTP on a configurable local address.
- Restricts clients to configured local/private CIDR ranges.
- Requires `AUTH PLAIN` for inbound SMTP before `MAIL` / `RCPT` / `DATA`.
- Resolves OpenPGP public keys for recipients from:
  - operator-provided key files
  - operator-provided key directories
  - WKD
  - `keys.openpgp.org`
- Encrypts the message and wraps it as `multipart/encrypted` PGP/MIME.
- Supports exact, explicitly configured envelope-recipient exceptions that bypass OpenPGP encryption.
- Relays the encrypted message to a remote SMTP server using:
  - `PLAIN`
  - `OAUTHBEARER`
  - `XOAUTH2`
- Refuses outbound SMTP delivery unless the connection is protected with TLS.
- Uses Rustls for all TLS connections, including SMTP and HTTPS key fetches.

## Assumptions

- Inbound SMTP is plaintext by design and is expected to be exposed only on localhost or trusted private networks.
- The default OpenPGP `encryption_mode` is `pgp_mime_body`, which preserves common outer mail headers such as `From`, `To`, `Cc`, `Date`, and `Subject`, and encrypts the MIME body.
- If you want the entire raw message encrypted instead, set `openpgp.encryption_mode` to `full_message`.
- Envelope recipients from SMTP are always used for remote relay delivery. Header recipients are also used for key lookup so that normal `To`/`Cc` delivery works, and Bcc-style envelope recipients can still be encrypted for.
- Only SMTP envelope recipients can trigger an unencrypted-recipient exception. Sender-controlled `To`, `Cc`, and `Bcc` headers cannot downgrade encryption.

## Build

```bash
cargo build --release
```

Build a musl binary explicitly:

```bash
cargo build --release --target x86_64-unknown-linux-musl
```

For a local musl build outside Docker, install a musl cross toolchain that provides `x86_64-linux-musl-gcc` first.

Supported Linux release targets:

- `x86_64-unknown-linux-gnu`
- `aarch64-unknown-linux-gnu`
- `riscv64gc-unknown-linux-gnu`
- `x86_64-unknown-linux-musl`
- `aarch64-unknown-linux-musl`
- `riscv64gc-unknown-linux-musl`

Validate a config file without starting the listener:

```bash
./target/release/sendmail-sec --config /path/to/sendmail-sec.yaml --check-config
```

For a musl build, the binary path is:

```bash
./target/x86_64-unknown-linux-musl/release/sendmail-sec --config /path/to/sendmail-sec.yaml --check-config
```

Start the service:

```bash
./target/release/sendmail-sec --config /path/to/sendmail-sec.yaml
```

## Configuration

YAML and JSON are both supported. Example files:

- [`examples/config.yaml`](examples/config.yaml)
- [`examples/config.json`](examples/config.json)
- [`examples/config-secrets.yaml`](examples/config-secrets.yaml)
- [`examples/config-secrets.json`](examples/config-secrets.json)

Important fields:

- `listen.bind`: local SMTP bind address, default `0.0.0.0:2525`
- `listen.allowed_networks`: CIDRs allowed to connect
- `listen.auth`: inbound SMTP `AUTH PLAIN` credentials
- `listen.auth.password_file`: file alternative to `listen.auth.password`
- `remote_smtp.tls_mode`: `starttls` or `wrapper`
- `remote_smtp.auth.mechanism`: `plain`, `oauthbearer`, or `xoauth2`
- `remote_smtp.auth.password_file`: file alternative to `password` for `plain`
- `remote_smtp.auth.access_token_file`: file alternative to `access_token` for OAuth
- `tls.extra_root_certificates`: extra PEM roots for all outbound TLS connections
- `openpgp.local_key_files`: mounted public key files or keyrings
- `openpgp.local_key_directories`: directories scanned for public key files
- `openpgp.encryption_mode`: `pgp_mime_body` or `full_message`
- `openpgp.unencrypted_recipients`: exact envelope addresses allowed to bypass OpenPGP
- `logging.log_recipient_addresses`: allow recipient details in debug-level logs

### Unencrypted recipients

OpenPGP encryption remains the default. To relay a message without OpenPGP for
an exact SMTP envelope recipient, add an explicit exception:

```yaml
openpgp:
  unencrypted_recipients:
    - address: archive@example.com
      allow_split_delivery: false
```

Addresses must be bare ASCII `local@domain` values. Matching is
case-insensitive across the full address and does not apply wildcard, domain,
or plus-address canonicalization. Invalid or duplicate normalized entries stop
configuration loading. At least one OpenPGP key source is still required.

If every envelope recipient matches the list, the listener-normalized original
message is relayed without an OpenPGP wrapper. Inbound authentication, allowed
networks, remote SMTP authentication, and mandatory TLS remain enforced. The
message is plaintext at the message layer, however, and downstream delivery
after the configured SMTP relay is outside `sendmail-sec`'s control. The raw
message headers are not rewritten, including any submitted `Bcc` header.

A message containing both encrypted and unencrypted recipients is rejected
with SMTP status `554` unless every matching exception sets
`allow_split_delivery: true`. An allowed split creates two outbound SMTP
transactions: the encrypted group is delivered first, followed by the
unencrypted group. Both deliveries are prepared before either is sent. The two
remote transactions cannot be atomic; if the second fails after the first is
accepted, the client receives `554`, and retrying can duplicate the accepted
encrypted delivery.

Unencrypted-delivery warnings and partial-delivery errors include counts but
not recipient values. To make normalized recipient details available for
troubleshooting, both enable debug logging and explicitly opt in:

```yaml
logging:
  filter: debug
  log_recipient_addresses: true
```

The recipient logging flag also governs OpenPGP lookup and remote `RCPT TO`
details. Recipient addresses and address-bearing key lookup URLs are never
included in higher-level logs.

### File-backed credentials

Credential values can remain inline for backward compatibility, or be read
from files mounted by Docker Compose or another secret manager. Configure
exactly one member of each applicable pair:

- `listen.auth.password` or `listen.auth.password_file`
- `remote_smtp.auth.password` or `remote_smtp.auth.password_file` for `plain`
- `remote_smtp.auth.access_token` or
  `remote_smtp.auth.access_token_file` for `oauthbearer` and `xoauth2`

Relative secret paths are resolved against the directory containing the
configuration file. Secret files must be regular UTF-8 files no larger than
64 KiB. One final LF or CRLF is removed so files produced by common
line-oriented tools work as expected; all other content and whitespace is
preserved. Missing, unreadable, invalid, oversized, or empty secret files stop
configuration loading without logging the secret value.

Secrets are loaded once during startup, including `--check-config`. Restart the
process or recreate the container after rotating a secret.

## Container

Build the image:

```bash
docker build -t sendmail-sec .
```

Build a multi-arch image with Buildx:

```bash
docker buildx build \
  --platform linux/amd64,linux/arm64,linux/riscv64 \
  -t sendmail-sec .
```

Build a release-style Docker image tarball for one architecture:

```bash
scripts/build-docker-image-artifact.sh linux/amd64 amd64 /tmp/sendmail-sec-image
docker load --input /tmp/sendmail-sec-image/sendmail-sec-alpine-musl-amd64.tar
scripts/verify-docker-image.sh sendmail-sec:alpine-musl-amd64 amd64
```

The Dockerfile builds `amd64` and `arm64` natively on their matching runners.
It cross-compiles `riscv64` on the Buildx host with a pinned
`cargo-zigbuild`/Zig tool image, so the RISC-V build does not execute compiler
processes through QEMU. The final Alpine image is assembled without
target-architecture `RUN` instructions.

Run with a read-only root filesystem and no Linux capabilities:

```bash
docker run --rm \
  --read-only \
  --cap-drop=ALL \
  --tmpfs /tmp:rw,noexec,nosuid,size=64m \
  -p 2525:2525 \
  -v /path/to/sendmail-sec.yaml:/config/sendmail-sec.yaml:ro \
  -v /path/to/public-keys:/config/keys:ro \
  sendmail-sec \
  --config /config/sendmail-sec.yaml
```

Use the checked-in Docker Compose example with host secret files that are kept
outside the repository:

```bash
install -d -m 0700 "$HOME/.local/share/sendmail-sec/secrets"
install -m 0444 /path/to/listen-password \
  "$HOME/.local/share/sendmail-sec/secrets/listen-password"
install -m 0444 /path/to/remote-password \
  "$HOME/.local/share/sendmail-sec/secrets/remote-password"
export SENDMAIL_SEC_LISTEN_PASSWORD_FILE="$HOME/.local/share/sendmail-sec/secrets/listen-password"
export SENDMAIL_SEC_REMOTE_PASSWORD_FILE="$HOME/.local/share/sendmail-sec/secrets/remote-password"
docker compose -f examples/compose.yaml up -d
```

The example grants only the required runtime secrets to the service. Compose
mounts them as read-only files named `/run/secrets/listen_auth_password` and
`/run/secrets/remote_smtp_password`. To use OAuth instead, select
`oauthbearer` or `xoauth2`, configure `access_token_file`, and grant a
corresponding token secret.

For Compose secrets sourced with `file:`, Docker Compose uses bind mounts and
does not apply the service secret's `uid`, `gid`, or `mode` settings. Protect
the source directory on the rootless Docker daemon host with mode `0700`, and
make each secret file readable by the image's non-root `app:app` user (mode
`0444` in the example). The exported paths must be visible to that daemon.
When Docker is accessed from a Dev Container or another Docker-outside-of-
Docker setup, both the Compose configuration and secret source paths are
daemon-side bind mounts; run Compose on the daemon host or use paths that exist
identically from the daemon's point of view. See Docker's
[Compose secrets guide](https://docs.docker.com/compose/how-tos/use-secrets/)
and [service secrets reference](https://docs.docker.com/reference/compose-file/services/#secrets).

Run the Docker integration test:

```bash
scripts/docker-integration-test.sh
```

Wrapper TLS is the default. Exercise the explicit STARTTLS path with:

```bash
REMOTE_TLS_MODE=starttls scripts/docker-integration-test.sh
```

The integration test builds a temporary image, generates temporary OpenPGP and TLS material, copies test files into containers with `docker cp`, verifies encrypted, unencrypted, rejected-mixed, split, and partial-delivery SMTP behavior through either wrapper TLS or STARTTLS, and removes the containers, network, image tag, and temporary files before exiting.

## Notes

- The process does not require write access beyond optional `/tmp`.
- Logs are written to stdout/stderr.
- Local key files are loaded at startup. Restart the container after changing mounted key material.
- Credential files are loaded at startup. Restart the container after rotating a mounted secret.
- The Docker image contains a static musl binary for `amd64`, `arm64`, and `riscv64`.
- The Rust crate entry point now lives under `sources/` rather than `src/`.

## Release Automation

- Docker releases publish to `ghcr.io/oxibelt/sendmail-sec` from the canonical `OxiBelt/sendmail-sec` repository.
- Strict tags are required: `2.1.2`, `1.1.0-beta.1`, or `1.1.0-build.4f43abcd`. `v`-prefixed tags and unsupported prerelease names are rejected.
- Stable releases publish `latest`, `<major>-alpine-musl`, and per-architecture `<major>-alpine-musl-<arch>` aliases. Beta and build releases publish only versioned tags.
- Release CI validates the tag, updates Cargo release metadata in the CI worktree, builds and structurally verifies per-architecture Docker image tar artifacts, runs an isolated QEMU smoke test against the completed `riscv64` image, runs Trivy image scans, and only then pushes arch tags and multi-arch manifests.
- The Docker workflow publishes Alpine musl images for `linux/amd64`, `linux/arm64`, and `linux/riscv64`.

Run DevOps validation locally after changing release automation:

```bash
pnpm install --frozen-lockfile
pnpm run lint
pnpm run typecheck
pnpm run test
pnpm run versioning:check
```
