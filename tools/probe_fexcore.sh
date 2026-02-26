#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${1:-build-fex}"
TARGET_EXE="${2:-pvz/main.exe}"

if [[ ! -f "${ROOT_DIR}/CMakeLists.txt" ]]; then
  echo "[!] project root not found: ${ROOT_DIR}" >&2
  exit 1
fi

echo "[*] Building ${BUILD_DIR}..."
cmake --build "${ROOT_DIR}/${BUILD_DIR}" -j8 >/tmp/pvz_build_fex_probe.log 2>&1 || {
  echo "[!] build failed. tail -n 80 /tmp/pvz_build_fex_probe.log"
  tail -n 80 /tmp/pvz_build_fex_probe.log || true
  exit 1
}

RUNNER="${ROOT_DIR}/${BUILD_DIR}/runner"
if [[ ! -x "${RUNNER}" ]]; then
  echo "[!] runner not found: ${RUNNER}" >&2
  exit 1
fi

LOG_PATH="/tmp/pvz_fex_strict_probe_$(date +%Y%m%d_%H%M%S).log"
echo "[*] Running strict probe: ${RUNNER} ${TARGET_EXE}"
(
  cd "${ROOT_DIR}"
  PVZ_CPU_BACKEND=fexcore PVZ_FEXCORE_STRICT=1 "${RUNNER}" "${TARGET_EXE}" >"${LOG_PATH}" 2>&1
) || true

echo "[*] Strict probe log: ${LOG_PATH}"
echo "[*] Key lines:"
rg -n "CPU backend|FEX bridge|STRICT|backend implementation|failed|unavailable|falling back|Error|EXIT" "${LOG_PATH}" || true

echo
echo "[*] Host libFEXCore candidate scan:"
found=0
for base in /opt/homebrew/lib /usr/local/lib; do
  if [[ -d "${base}" ]]; then
    hits="$(find "${base}" -maxdepth 2 -iname 'libFEX*.dylib' -print 2>/dev/null || true)"
    if [[ -n "${hits}" ]]; then
      found=1
      echo "${hits}"
    fi
  fi
done
if [[ "${found}" -eq 0 ]]; then
  echo "  (none found in /opt/homebrew/lib or /usr/local/lib)"
fi

