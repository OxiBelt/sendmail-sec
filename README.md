# sendmail-sec

`sendmail-sec` is a Rust CLI that accepts authenticated SMTP submissions from localhost or private networks, encrypts the submitted mail with OpenPGP, and relays the encrypted message to a remote SMTP server over mandatory TLS using Rustls.

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

- [`examples/config.yaml`](/workspaces/mail/sendmail-sec/examples/config.yaml)
- [`examples/config.json`](/workspaces/mail/sendmail-sec/examples/config.json)

Important fields:

- `listen.bind`: local SMTP bind address, default `0.0.0.0:2525`
- `listen.allowed_networks`: CIDRs allowed to connect
- `listen.auth`: inbound SMTP `AUTH PLAIN` credentials
- `remote_smtp.tls_mode`: `starttls` or `wrapper`
- `remote_smtp.auth.mechanism`: `plain`, `oauthbearer`, or `xoauth2`
- `tls.extra_root_certificates`: extra PEM roots for all outbound TLS connections
- `openpgp.local_key_files`: mounted public key files or keyrings
- `openpgp.local_key_directories`: directories scanned for public key files
- `openpgp.encryption_mode`: `pgp_mime_body` or `full_message`

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

Run the Docker integration test:

```bash
scripts/docker-integration-test.sh
```

The integration test builds a temporary image, generates temporary OpenPGP and TLS material, copies test files into containers with `docker cp`, verifies encrypted SMTP relay through a TLS fixture, and removes the containers, network, image tag, and temporary files before exiting.

## Notes

- The process does not require write access beyond optional `/tmp`.
- Logs are written to stdout/stderr.
- Local key files are loaded at startup. Restart the container after changing mounted key material.
- The Docker image builds a static musl binary on Alpine for `amd64`, `arm64`, and `riscv64`.
- The Rust crate entry point now lives under `sources/` rather than `src/`.

## Release Automation

- A semver tag such as `2.1.2` or `1.1.0-beta.1` triggers GitHub Actions to build release binaries for all supported GNU and musl targets.
- Those binary builds are uploaded as workflow artifacts immediately after the tag push so they exist before an immutable GitHub Release is published.
- Docker images are built and published only when a GitHub Release is published.
- The Docker workflow publishes a multi-arch Alpine image for `linux/amd64`, `linux/arm64`, and `linux/riscv64`.
