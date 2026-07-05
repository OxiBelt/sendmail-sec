#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: $0 <docker-platform> <artifact-arch> <output-dir>" >&2
  echo "artifact-arch: amd64, arm64, or riscv64" >&2
}

default_source="https://github.com/digitalBelt/sendmail-sec"

sanitize_source_url() {
  local source_url="$1"
  source_url="${source_url%%#*}"
  source_url="${source_url%%\?*}"
  sed -E 's#^([A-Za-z][A-Za-z0-9+.-]*://)[^/@]+@#\1#' <<<"${source_url}"
}

detect_source() {
  if [[ -n "${GITHUB_SERVER_URL:-}" && -n "${GITHUB_REPOSITORY:-}" ]]; then
    sanitize_source_url "${GITHUB_SERVER_URL%/}/${GITHUB_REPOSITORY}"
    return
  fi

  local remote_url
  remote_url="$(git -C "${repo_root}" config --get remote.origin.url 2>/dev/null || true)"
  if [[ -n "${remote_url}" ]]; then
    sanitize_source_url "${remote_url}"
    return
  fi

  echo "${default_source}"
}

platform="${1:-}"
artifact_arch="${2:-}"
output_dir="${3:-}"

if [[ -z "${platform}" || -z "${artifact_arch}" || -z "${output_dir}" ]]; then
  usage
  exit 2
fi

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/.." && pwd)"
image_tag="sendmail-sec:alpine-musl-${artifact_arch}"
image_tar="${output_dir%/}/sendmail-sec-alpine-musl-${artifact_arch}.tar"
rust_builder_image="rust:1.94-alpine"
sendmail_sec_version="$(
  sed -n 's/^version = "\(.*\)"/\1/p' "${repo_root}/Cargo.toml" | head -n 1
)"
sendmail_sec_version="${SENDMAIL_SEC_DOCKER_IMAGE_VERSION:-${sendmail_sec_version}}"
sendmail_sec_revision="${SENDMAIL_SEC_DOCKER_IMAGE_REVISION:-$(git -C "${repo_root}" rev-parse HEAD 2>/dev/null || true)}"
sendmail_sec_created="${SENDMAIL_SEC_DOCKER_IMAGE_CREATED:-$(date -u '+%Y-%m-%dT%H:%M:%SZ')}"
sendmail_sec_source="${SENDMAIL_SEC_DOCKER_IMAGE_SOURCE:-$(detect_source)}"
sendmail_sec_ref_name="${SENDMAIL_SEC_DOCKER_IMAGE_REF_NAME:-${sendmail_sec_version}}"

case "${artifact_arch}" in
  amd64)
    [[ "${platform}" == "linux/amd64" ]] || {
      usage
      exit 2
    }
    ;;
  arm64)
    [[ "${platform}" == "linux/arm64" ]] || {
      usage
      exit 2
    }
    ;;
  riscv64)
    [[ "${platform}" == "linux/riscv64" ]] || {
      usage
      exit 2
    }
    rust_builder_image="rust:1.94-trixie"
    ;;
  *)
    usage
    exit 2
    ;;
esac

if [[ -z "${sendmail_sec_version}" ]]; then
  sendmail_sec_version="dev"
fi

if [[ -z "${sendmail_sec_revision}" ]]; then
  sendmail_sec_revision="unknown"
fi

if [[ -z "${sendmail_sec_source}" ]]; then
  sendmail_sec_source="${default_source}"
fi

mkdir -p "${output_dir}"

docker buildx build \
  --platform "${platform}" \
  --file "${repo_root}/Dockerfile" \
  --build-arg "RUST_BUILDER_IMAGE=${rust_builder_image}" \
  --build-arg "SENDMAIL_SEC_VERSION=${sendmail_sec_version}" \
  --build-arg "SENDMAIL_SEC_REVISION=${sendmail_sec_revision}" \
  --build-arg "SENDMAIL_SEC_CREATED=${sendmail_sec_created}" \
  --build-arg "SENDMAIL_SEC_SOURCE=${sendmail_sec_source}" \
  --build-arg "SENDMAIL_SEC_REF_NAME=${sendmail_sec_ref_name}" \
  --tag "${image_tag}" \
  --output "type=docker,dest=${image_tar}" \
  "${repo_root}"

echo "Wrote ${image_tar}"
