# AGENTS.md

## Project Overview

`sendmail-sec` is a Rust CLI and container image for accepting authenticated
local SMTP submissions, encrypting messages with OpenPGP, and relaying them to
a remote SMTP server over mandatory TLS.

The Rust binary entry point is `sources/main.rs`. The Docker image builds a
static musl binary and runs `sendmail-sec --config /config/sendmail-sec.yaml`
by default.

## Repository Structure

- `sources/`
  - Main Rust binary crate source.
- `sources/main.rs`
  - Binary entry point and top-level module wiring.
- `sources/app.rs`
  - Application startup and config-check flow.
- `sources/cli.rs`
  - Command-line argument parsing.
- `sources/config.rs`
  - YAML/JSON configuration types, defaults, loading, and validation.
- `sources/listener.rs`
  - Inbound SMTP listener, allowed networks, and `AUTH PLAIN` handling.
- `sources/message.rs`
  - Mail parsing, envelope/header recipient extraction, and message helpers.
- `sources/openpgp.rs`
  - OpenPGP key loading, key discovery, caching, and encryption.
- `sources/remote_smtp.rs`
  - Remote SMTP relay, TLS mode handling, and remote authentication.
- `sources/tls.rs`
  - Rustls root store and certificate handling.
- `examples/`
  - YAML and JSON example configuration.
- `Dockerfile`
  - Static musl release image build and runtime layout.
- `scripts/docker-integration-test.sh`
  - End-to-end Docker SMTP, TLS, and OpenPGP integration test.
- `devops/`
  - TypeScript release versioning and Docker image plan tooling.
- `.github/workflows/`
  - GitHub Actions checks, CodeQL analysis, and Docker release workflow.

## Common Commands

- Format check: `cargo fmt --all --check`
- Lint: `cargo clippy --locked --all-targets --all-features -- -D warnings`
- Run unit tests: `cargo test --locked`
- Build locally: `cargo build --locked`
- Build the Docker image: `docker build -t sendmail-sec .`
- Run the Docker integration test: `scripts/docker-integration-test.sh`
- DevOps checks: `pnpm install --frozen-lockfile && pnpm run lint && pnpm run typecheck && pnpm run test && pnpm run versioning:check`

## Contributor Guidance

`CONTRIBUTING.md` is the source of truth for contributor workflow, security
requirements, pull request checks, and commit-message format. Use these
sections before making or reviewing changes:

- [Contribution Workflow](CONTRIBUTING.md#contribution-workflow)
- [Commit Messages](CONTRIBUTING.md#commit-messages)
- [Security Requirements](CONTRIBUTING.md#security-requirements)
- [Pull Request Checklist](CONTRIBUTING.md#pull-request-checklist)

If this file and `CONTRIBUTING.md` diverge on workflow, security, testing,
documentation, or Conventional Commits requirements, follow `CONTRIBUTING.md`
and update this pointer file only when agent-specific orientation changes.

## Docker Integration Testing

Prefer the repository script `scripts/docker-integration-test.sh` for
end-to-end Docker validation. It builds or accepts an application image, starts
an isolated Docker network, runs a TLS-enabled SMTP fixture container, starts
the application container, submits a message through the application, and
verifies that the captured relay message is PGP/MIME encrypted and decryptable
with the ephemeral test key.

The script intentionally uses `docker cp` to place generated configs, OpenPGP
material, TLS certificates, and fixture scripts into containers. Do not rewrite
Docker tests to depend on bind mounts or volume mounts unless there is a strong
reason.

## Required Test Hygiene

- Development may happen inside a Dev Container that uses Docker outside of
  Docker. Prefer `docker cp ...` over Docker bind mounts or volume mounts so
  tests work across host and Dev Container setups.
- Generate temporary OpenPGP keypairs and TLS certificates for each test run.
  Delete and discard those materials when the test exits.
- After Docker tests complete, remove all Docker resources created by the test,
  including built application images, Docker networks, and Docker containers.
- Keep test fixtures isolated from external services. Use local containers and
  generated local trust roots rather than public keyservers or real SMTP
  providers.

## Release DevOps

Docker release automation uses TypeScript tooling under `devops/` to validate
strict release tags, update Cargo release metadata during CI, and emit the
image plan consumed by `.github/workflows/release-docker.yml`. Release images
publish to `ghcr.io/digitalbelt/sendmail-sec` only from the canonical
`digitalBelt/sendmail-sec` repository.

## Editing Notes

- Keep changes scoped to the requested behavior and follow the existing Rust
  style.
- Use config examples under `examples/` as references for new settings or docs.
- Do not commit generated key material, generated TLS material, Docker test
  captures, or build outputs.
