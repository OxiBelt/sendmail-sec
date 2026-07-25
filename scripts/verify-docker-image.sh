#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
  echo "usage: $0 <image-tag> <artifact-arch>" >&2
  echo "artifact-arch: amd64, arm64, or riscv64" >&2
}

if [[ "$#" -ne 2 || "$1" == -* ]]; then
  usage
  exit 2
fi

image_tag="$1"
artifact_arch="$2"

case "${artifact_arch}" in
  amd64)
    expected_machine="Advanced Micro Devices X86-64"
    ;;
  arm64)
    expected_machine="AArch64"
    ;;
  riscv64)
    expected_machine="RISC-V"
    ;;
  *)
    usage
    exit 2
    ;;
esac

for command_name in docker readelf; do
  if ! command -v "${command_name}" >/dev/null 2>&1; then
    echo "required command not found: ${command_name}" >&2
    exit 1
  fi
done

temporary_directory="$(mktemp -d)"
container_id=""

cleanup() {
  if [[ -n "${container_id}" ]]; then
    docker rm -f "${container_id}" >/dev/null 2>&1 || true
  fi
  rm -rf -- "${temporary_directory}"
}

trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

inspect_value() {
  local template="$1"
  docker image inspect --format "${template}" "${image_tag}"
}

assert_equal() {
  local description="$1"
  local actual="$2"
  local expected="$3"

  if [[ "${actual}" != "${expected}" ]]; then
    echo "${description} was ${actual@Q}, expected ${expected@Q}" >&2
    exit 1
  fi
}

assert_equal "image operating system" "$(inspect_value '{{.Os}}')" "linux"
assert_equal "image architecture" "$(inspect_value '{{.Architecture}}')" "${artifact_arch}"
assert_equal "image user" "$(inspect_value '{{.Config.User}}')" "app:app"
assert_equal \
  "image entrypoint" \
  "$(inspect_value '{{json .Config.Entrypoint}}')" \
  '["/usr/local/bin/sendmail-sec"]'
assert_equal \
  "image command" \
  "$(inspect_value '{{json .Config.Cmd}}')" \
  '["--config","/config/sendmail-sec.yaml"]'

container_id="$(docker create --platform "linux/${artifact_arch}" "${image_tag}")"
binary_path="${temporary_directory}/sendmail-sec"
docker cp "${container_id}:/usr/local/bin/sendmail-sec" "${binary_path}"

if [[ ! -x "${binary_path}" ]]; then
  echo "image binary is missing or is not executable: /usr/local/bin/sendmail-sec" >&2
  exit 1
fi

elf_header="$(LC_ALL=C readelf -h "${binary_path}")"

if ! grep -Fq "Class:                             ELF64" <<<"${elf_header}"; then
  echo "image binary is not ELF64" >&2
  exit 1
fi

if ! grep -Fq "Data:                              2's complement, little endian" <<<"${elf_header}"; then
  echo "image binary is not little-endian" >&2
  exit 1
fi

if ! grep -Fq "Machine:                           ${expected_machine}" <<<"${elf_header}"; then
  echo "image binary has the wrong ELF machine; expected ${expected_machine}" >&2
  exit 1
fi

if LC_ALL=C readelf -l "${binary_path}" | grep -Fq "INTERP"; then
  echo "image binary contains a dynamic program interpreter" >&2
  exit 1
fi

if LC_ALL=C readelf -d "${binary_path}" | grep -Fq "(NEEDED)"; then
  echo "image binary contains dynamic library dependencies" >&2
  exit 1
fi

echo "Verified ${image_tag}: linux/${artifact_arch}, static ELF64 ${expected_machine}"
