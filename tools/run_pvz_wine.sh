#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WINE_BIN="${WINE_BIN:-wine}"
PREFIX_DIR="${WINEPREFIX:-${ROOT_DIR}/artifacts/wine/prefix-pvz}"
GAME_DIR="${ROOT_DIR}/pvz"
GAME_EXE="${1:-main.exe}"
INIT_SENTINEL="${PREFIX_DIR}/.pvz_wine_initialized"

mkdir -p "${PREFIX_DIR}" "${ROOT_DIR}/logs_wine"

if ! command -v "${WINE_BIN}" >/dev/null 2>&1; then
  echo "[!] wine binary not found: ${WINE_BIN}" >&2
  exit 1
fi

if [[ ! -f "${GAME_DIR}/${GAME_EXE}" ]]; then
  echo "[!] game executable not found: ${GAME_DIR}/${GAME_EXE}" >&2
  exit 1
fi

if [[ ! -f "${INIT_SENTINEL}" ]]; then
  echo "[*] Initializing Wine prefix: ${PREFIX_DIR}"
  if WINEPREFIX="${PREFIX_DIR}" WINEDEBUG=-all "${WINE_BIN}" wineboot -u; then
    touch "${INIT_SENTINEL}"
  else
    echo "[!] wineboot returned non-zero. continuing with existing prefix state."
  fi
fi

RUN_LOG="${ROOT_DIR}/logs_wine/pvz_wine_$(date +%Y%m%d_%H%M%S).log"
echo "[*] Launching PvZ via Wine"
echo "[*] Wine: ${WINE_BIN}"
echo "[*] Prefix: ${PREFIX_DIR}"
echo "[*] Log: ${RUN_LOG}"

(
  cd "${GAME_DIR}"
  WINEPREFIX="${PREFIX_DIR}" WINEDEBUG="${WINEDEBUG:--all}" "${WINE_BIN}" "./${GAME_EXE}"
) | tee "${RUN_LOG}"
