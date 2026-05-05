#!/usr/bin/env bash
set -Eeuo pipefail

APP_IMAGE_PREFIX="${APP_IMAGE_PREFIX:-sendmail-sec}"
HELPER_IMAGE="${HELPER_IMAGE:-python:3.12-alpine}"
PGP_EMAIL="${PGP_EMAIL:-recipient@example.test}"
INBOUND_USERNAME="${INBOUND_USERNAME:-inbound-relay}"
INBOUND_PASSWORD="${INBOUND_PASSWORD:-change-me}"
REMOTE_USERNAME="${REMOTE_USERNAME:-relay-user}"
REMOTE_PASSWORD="${REMOTE_PASSWORD:-relay-password}"
SMTP_HOST="smtp-fixture"
SMTP_PORT="8465"

log() {
  printf '[integration] %s\n' "$*"
}

die() {
  printf '[integration] error: %s\n' "$*" >&2
  exit 1
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"
}

wait_for_log() {
  local container="$1"
  local needle="$2"
  local timeout_secs="$3"
  local deadline=$((SECONDS + timeout_secs))

  while ((SECONDS < deadline)); do
    if docker logs "$container" 2>&1 | grep -Fq "$needle"; then
      return 0
    fi

    if [ "$(docker inspect -f '{{.State.Running}}' "$container" 2>/dev/null || true)" = "false" ]; then
      docker logs "$container" >&2 || true
      die "container $container exited before logging: $needle"
    fi

    sleep 1
  done

  docker logs "$container" >&2 || true
  die "timed out waiting for $container to log: $needle"
}

wait_for_container_exit() {
  local container="$1"
  local timeout_secs="$2"
  local deadline=$((SECONDS + timeout_secs))
  local status
  local exit_code

  while ((SECONDS < deadline)); do
    status="$(docker inspect -f '{{.State.Status}}' "$container")"
    if [ "$status" = "exited" ]; then
      exit_code="$(docker inspect -f '{{.State.ExitCode}}' "$container")"
      [ "$exit_code" = "0" ] || {
        docker logs "$container" >&2 || true
        die "container $container exited with status $exit_code"
      }
      return 0
    fi
    sleep 1
  done

  docker logs "$container" >&2 || true
  die "timed out waiting for $container to exit"
}

containers=()
images=()
network=""
tmpdir=""

cleanup() {
  local status=$?
  set +e

  if [ "$status" -ne 0 ]; then
    for container in "${containers[@]:-}"; do
      if docker inspect "$container" >/dev/null 2>&1; then
        printf '\n[integration] logs from %s\n' "$container" >&2
        docker logs "$container" >&2 || true
      fi
    done
  fi

  for container in "${containers[@]:-}"; do
    docker rm -f "$container" >/dev/null 2>&1 || true
  done

  if [ -n "${network:-}" ]; then
    docker network rm "$network" >/dev/null 2>&1 || true
  fi

  for image in "${images[@]:-}"; do
    docker image rm -f "$image" >/dev/null 2>&1 || true
  done

  if [ -n "${tmpdir:-}" ]; then
    rm -rf "$tmpdir"
  fi
}
trap cleanup EXIT

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

require_command docker
require_command gpg
require_command openssl
require_command grep
require_command sed

docker info >/dev/null 2>&1 || die "Docker is not available to this shell"

run_id="$(date +%Y%m%d%H%M%S)-$$-$(openssl rand -hex 4)"
app_image="${APP_IMAGE_PREFIX}:integration-${run_id}"
network="sendmail-sec-it-${run_id}"
smtp_container="sendmail-sec-smtp-${run_id}"
app_container="sendmail-sec-app-${run_id}"
client_container="sendmail-sec-client-${run_id}"
tmpdir="$(mktemp -d)"
gnupghome="${tmpdir}/gnupg"
config_dir="${tmpdir}/config"

containers+=("$client_container" "$app_container" "$smtp_container")
images+=("$app_image")

mkdir -p "$config_dir"
chmod 755 "$config_dir"
mkdir -m 700 "$gnupghome"

log "generating ephemeral OpenPGP keypair"
cat >"${tmpdir}/gpg-key.batch" <<GPG
%no-protection
Key-Type: RSA
Key-Length: 2048
Key-Usage: cert
Subkey-Type: RSA
Subkey-Length: 2048
Subkey-Usage: encrypt
Name-Real: Sendmail Sec Integration
Name-Email: ${PGP_EMAIL}
Expire-Date: 1d
%commit
GPG

gpg --batch --homedir "$gnupghome" --generate-key "${tmpdir}/gpg-key.batch" >/dev/null 2>&1
gpg --batch --homedir "$gnupghome" --armor --export "$PGP_EMAIL" >"${config_dir}/public-keys.asc"

log "generating ephemeral TLS CA and server certificate"
openssl req \
  -x509 \
  -newkey rsa:2048 \
  -sha256 \
  -days 1 \
  -nodes \
  -subj "/CN=sendmail-sec integration CA" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -keyout "${tmpdir}/ca.key" \
  -out "${config_dir}/ca.crt" >/dev/null 2>&1

openssl req \
  -newkey rsa:2048 \
  -sha256 \
  -nodes \
  -subj "/CN=${SMTP_HOST}" \
  -addext "subjectAltName=DNS:${SMTP_HOST}" \
  -keyout "${tmpdir}/server.key" \
  -out "${tmpdir}/server.csr" >/dev/null 2>&1

cat >"${tmpdir}/server.ext" <<TLS_EXT
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:${SMTP_HOST}
TLS_EXT

openssl x509 \
  -req \
  -in "${tmpdir}/server.csr" \
  -CA "${config_dir}/ca.crt" \
  -CAkey "${tmpdir}/ca.key" \
  -CAcreateserial \
  -sha256 \
  -days 1 \
  -out "${tmpdir}/server.crt" \
  -extfile "${tmpdir}/server.ext" >/dev/null 2>&1

chmod 644 "${config_dir}/ca.crt" "${config_dir}/public-keys.asc"

cat >"${config_dir}/sendmail-sec.yaml" <<YAML
listen:
  bind: 0.0.0.0:2525
  banner: sendmail-sec-integration
  auth:
    username: ${INBOUND_USERNAME}
    password: ${INBOUND_PASSWORD}
  allowed_networks:
    - 0.0.0.0/0
  message_size_limit_bytes: 1048576

remote_smtp:
  host: ${SMTP_HOST}
  port: ${SMTP_PORT}
  tls_mode: wrapper
  hello_name: relay.local
  auth:
    mechanism: plain
    username: ${REMOTE_USERNAME}
    password: ${REMOTE_PASSWORD}
  connect_timeout_secs: 10
  command_timeout_secs: 10

tls:
  extra_root_certificates:
    - /config/ca.crt

openpgp:
  local_key_files:
    - /config/public-keys.asc
  local_key_directories: []
  enable_wkd: false
  enable_keys_openpgp_org: false
  key_cache_ttl_secs: 30
  http_timeout_secs: 5
  encryption_mode: pgp_mime_body

logging:
  filter: info
YAML
chmod 644 "${config_dir}/sendmail-sec.yaml"

cat >"${tmpdir}/smtp_server.py" <<'PY'
import base64
import os
import socket
import ssl
import sys

host = "0.0.0.0"
port = int(os.environ["SMTP_PORT"])
cert_path = "/tmp/server.crt"
key_path = "/tmp/server.key"
capture_path = "/tmp/captured.eml"
expected_user = os.environ["REMOTE_USERNAME"]
expected_password = os.environ["REMOTE_PASSWORD"]


def send(file, line):
    file.write(line.encode("utf-8") + b"\r\n")
    file.flush()


def read_line(file):
    line = file.readline()
    if not line:
        raise RuntimeError("client closed the connection")
    return line.decode("utf-8", errors="replace").rstrip("\r\n")


def read_data(file):
    chunks = []
    while True:
        raw = file.readline()
        if not raw:
            raise RuntimeError("client closed the connection during DATA")
        line = raw.rstrip(b"\r\n")
        if line == b".":
            break
        if line.startswith(b".."):
            line = line[1:]
        chunks.append(line)
    return b"\r\n".join(chunks) + b"\r\n"


context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(certfile=cert_path, keyfile=key_path)

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((host, port))
    server.listen(1)
    print("SMTP fixture ready", flush=True)

    with context.wrap_socket(server.accept()[0], server_side=True) as conn:
        file = conn.makefile("rwb", buffering=0)
        send(file, "220 smtp-fixture ESMTP ready")

        while True:
            line = read_line(file)
            upper = line.upper()

            if upper.startswith("EHLO ") or upper.startswith("HELO "):
                send(file, "250-smtp-fixture")
                send(file, "250-AUTH PLAIN")
                send(file, "250 SIZE 1048576")
            elif upper == "AUTH PLAIN":
                send(file, "334 ")
                payload = base64.b64decode(read_line(file)).decode("utf-8", errors="replace")
                parts = payload.split("\x00")
                username = parts[1] if len(parts) > 1 else ""
                password = parts[2] if len(parts) > 2 else ""
                if username != expected_user or password != expected_password:
                    send(file, "535 authentication failed")
                    sys.exit(2)
                send(file, "235 authentication successful")
            elif upper.startswith("MAIL FROM:"):
                send(file, "250 sender ok")
            elif upper.startswith("RCPT TO:"):
                send(file, "250 recipient ok")
            elif upper == "DATA":
                send(file, "354 end data with <CRLF>.<CRLF>")
                data = read_data(file)
                with open(capture_path, "wb") as output:
                    output.write(data)
                send(file, "250 message accepted")
            elif upper == "QUIT":
                send(file, "221 bye")
                break
            else:
                send(file, "502 command not implemented")
PY

marker="sendmail-sec integration marker ${run_id}"
cat >"${tmpdir}/send_message.py" <<'PY'
import base64
import os
import socket

host = os.environ["SMTP_HOST"]
port = int(os.environ["SMTP_PORT"])
username = os.environ["INBOUND_USERNAME"]
password = os.environ["INBOUND_PASSWORD"]
recipient = os.environ["PGP_EMAIL"]
marker = os.environ["MARKER"]


def read_response(sock):
    lines = []
    while True:
        data = b""
        while not data.endswith(b"\n"):
            chunk = sock.recv(1)
            if not chunk:
                raise RuntimeError("server closed the connection")
            data += chunk
        line = data.decode("utf-8", errors="replace").rstrip("\r\n")
        lines.append(line)
        if len(line) < 4 or line[3] != "-":
            return lines


def expect(sock, prefix):
    lines = read_response(sock)
    if not lines[-1].startswith(prefix):
        raise RuntimeError(f"expected {prefix}, got {lines!r}")


def command(sock, line, expected):
    sock.sendall(line.encode("utf-8") + b"\r\n")
    expect(sock, expected)


message = (
    "From: Sender <sender@example.test>\r\n"
    f"To: Recipient <{recipient}>\r\n"
    "Subject: Docker integration test\r\n"
    "Content-Type: text/plain; charset=utf-8\r\n"
    "\r\n"
    f"{marker}\r\n"
)

with socket.create_connection((host, port), timeout=10) as sock:
    expect(sock, "220")
    command(sock, "EHLO integration-client", "250")
    auth = base64.b64encode(f"\0{username}\0{password}".encode("utf-8")).decode("ascii")
    command(sock, f"AUTH PLAIN {auth}", "235")
    command(sock, "MAIL FROM:<sender@example.test>", "250")
    command(sock, f"RCPT TO:<{recipient}>", "250")
    command(sock, "DATA", "354")
    sock.sendall(message.encode("utf-8") + b".\r\n")
    expect(sock, "250")
    command(sock, "QUIT", "221")
PY

log "building application image ${app_image}"
docker build -t "$app_image" "$repo_root"

log "creating isolated Docker network ${network}"
docker network create "$network" >/dev/null

log "starting TLS SMTP fixture"
docker create \
  --name "$smtp_container" \
  --network "$network" \
  --network-alias "$SMTP_HOST" \
  --env "SMTP_PORT=${SMTP_PORT}" \
  --env "REMOTE_USERNAME=${REMOTE_USERNAME}" \
  --env "REMOTE_PASSWORD=${REMOTE_PASSWORD}" \
  "$HELPER_IMAGE" \
  python /tmp/smtp_server.py >/dev/null
docker cp "${tmpdir}/smtp_server.py" "${smtp_container}:/tmp/smtp_server.py"
docker cp "${tmpdir}/server.crt" "${smtp_container}:/tmp/server.crt"
docker cp "${tmpdir}/server.key" "${smtp_container}:/tmp/server.key"
docker start "$smtp_container" >/dev/null
wait_for_log "$smtp_container" "SMTP fixture ready" 30

log "starting sendmail-sec container"
docker create \
  --name "$app_container" \
  --network "$network" \
  --network-alias sendmail-sec \
  "$app_image" \
  --config /config/sendmail-sec.yaml >/dev/null
docker cp "$config_dir" "${app_container}:/config"
docker start "$app_container" >/dev/null
wait_for_log "$app_container" "SMTP listener ready" 30

log "submitting message through containerized SMTP listener"
docker create \
  --name "$client_container" \
  --network "$network" \
  --env "SMTP_HOST=sendmail-sec" \
  --env "SMTP_PORT=2525" \
  --env "INBOUND_USERNAME=${INBOUND_USERNAME}" \
  --env "INBOUND_PASSWORD=${INBOUND_PASSWORD}" \
  --env "PGP_EMAIL=${PGP_EMAIL}" \
  --env "MARKER=${marker}" \
  "$HELPER_IMAGE" \
  python /tmp/send_message.py >/dev/null
docker cp "${tmpdir}/send_message.py" "${client_container}:/tmp/send_message.py"
docker start -a "$client_container"

wait_for_container_exit "$smtp_container" 30
docker cp "${smtp_container}:/tmp/captured.eml" "${tmpdir}/captured.eml"

log "verifying captured relay message"
grep -Fq "Content-Type: multipart/encrypted" "${tmpdir}/captured.eml"
grep -Fq -- "-----BEGIN PGP MESSAGE-----" "${tmpdir}/captured.eml"
sed -n '/-----BEGIN PGP MESSAGE-----/,/-----END PGP MESSAGE-----/p' \
  "${tmpdir}/captured.eml" >"${tmpdir}/encrypted.asc"
gpg --batch --homedir "$gnupghome" --decrypt "${tmpdir}/encrypted.asc" \
  >"${tmpdir}/decrypted.txt" 2>/dev/null
grep -Fq "$marker" "${tmpdir}/decrypted.txt"

log "docker integration test passed"
