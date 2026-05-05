# AGENTS.md

## Project Overview

`sendmail-sec` is a Rust CLI and container image for accepting authenticated local SMTP submissions, encrypting messages with OpenPGP, and relaying them to a remote SMTP server over mandatory TLS.

The Rust binary entry point is `sources/main.rs`. The Docker image builds a static musl binary and runs `sendmail-sec --config /config/sendmail-sec.yaml` by default.

## Common Commands

- Run unit tests: `cargo test --locked`
- Build locally: `cargo build --locked`
- Build the Docker image: `docker build -t sendmail-sec .`
- Run the Docker integration test: `scripts/docker-integration-test.sh`

## Docker Integration Testing

Prefer the repository script `scripts/docker-integration-test.sh` for end-to-end Docker validation. It builds a temporary application image, starts an isolated Docker network, runs a TLS-enabled SMTP fixture container, starts the application container, submits a message through the application, and verifies that the captured relay message is PGP/MIME encrypted and decryptable with the ephemeral test key.

The script intentionally uses `docker cp` to place generated configs, OpenPGP material, TLS certificates, and fixture scripts into containers. Do not rewrite Docker tests to depend on bind mounts or volume mounts unless there is a strong reason.

## Required Test Hygiene

- Development may happen inside a Dev Container that uses Docker outside of Docker. Prefer `docker cp ...` over Docker bind mounts or volume mounts so tests work across host and Dev Container setups.
- Generate temporary OpenPGP keypairs and TLS certificates for each test run. Delete and discard those materials when the test exits.
- After Docker tests complete, remove all Docker resources created by the test, including built application images, Docker networks, and Docker containers.
- Keep test fixtures isolated from external services. Use local containers and generated local trust roots rather than public keyservers or real SMTP providers.

## Editing Notes

- Keep changes scoped to the requested behavior and follow the existing Rust style.
- Use config examples under `examples/` as references for new settings or docs.
- Do not commit generated key material, generated TLS material, Docker test captures, or build outputs.
