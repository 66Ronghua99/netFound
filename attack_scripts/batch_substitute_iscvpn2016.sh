#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="/home/ronghua/codes/netFound"
TOOL="${ROOT_DIR}/attack_scripts/build/substitute_flow_headers"

SUBS_PCAP="${ROOT_DIR}/data/ISCVPN2016/raw/p2p/vpn_bittorrent.pcap"

CHAT_IN_DIR="${ROOT_DIR}/data/ISCVPN2016/raw/chat"
EMAIL_IN_DIR="${ROOT_DIR}/data/ISCVPN2016/raw/email"

OUT_CHAT_DIR="${ROOT_DIR}/data/ISCVPN2016/attack_exp/chat"
OUT_EMAIL_DIR="${ROOT_DIR}/data/ISCVPN2016/attack_exp/email"

mkdir -p "${OUT_CHAT_DIR}" "${OUT_EMAIL_DIR}"

if [[ ! -x "${TOOL}" ]]; then
  echo "Error: tool not found or not executable: ${TOOL}" >&2
  echo "Please build it: cmake -S ${ROOT_DIR}/attack_scripts -B ${ROOT_DIR}/attack_scripts/build && cmake --build ${ROOT_DIR}/attack_scripts/build -j" >&2
  exit 1
fi

if [[ ! -f "${SUBS_PCAP}" ]]; then
  echo "Error: substitution pcap not found: ${SUBS_PCAP}" >&2
  exit 1
fi

process_dir() {
  local in_dir="$1"
  local out_dir="$2"
  local subs="$3"

  shopt -s nullglob
  for tgt in "${in_dir}"/*.pcap "${in_dir}"/*.pcapng; do
    [[ -e "$tgt" ]] || continue
    local base
    base=$(basename "$tgt")
    local out="${out_dir}/${base%.pcap}.attack.pcapng"
    out="${out%.pcapng}.attack.pcapng" # ensure extension
    echo "[+] Processing: $tgt -> $out"
    "${TOOL}" "${subs}" "$tgt" "$out"
  done
}

echo "=== Processing CHAT pcaps ==="
process_dir "${CHAT_IN_DIR}" "${OUT_CHAT_DIR}" "${SUBS_PCAP}"

echo "=== Processing EMAIL pcaps ==="
process_dir "${EMAIL_IN_DIR}" "${OUT_EMAIL_DIR}" "${SUBS_PCAP}"

echo "Done. Outputs in:"
echo "  - ${OUT_CHAT_DIR}"
echo "  - ${OUT_EMAIL_DIR}"


