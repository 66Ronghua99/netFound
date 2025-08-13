#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="/home/ronghua/codes/netFound"
TOOL="${ROOT_DIR}/attack_scripts/build/remove_first_packet"

CHAT_IN_DIR="${ROOT_DIR}/data/ISCVPN2016/split/chat"
EMAIL_IN_DIR="${ROOT_DIR}/data/ISCVPN2016/split/email"

OUT_CHAT_DIR="${ROOT_DIR}/data/ISCVPN2016/attack_remove/split/chat"
OUT_EMAIL_DIR="${ROOT_DIR}/data/ISCVPN2016/attack_remove/split/email"

mkdir -p "${OUT_CHAT_DIR}" "${OUT_EMAIL_DIR}"

if [[ ! -x "${TOOL}" ]]; then
  echo "Error: tool not found or not executable: ${TOOL}" >&2
  echo "Please build it: cmake -S ${ROOT_DIR}/attack_scripts -B ${ROOT_DIR}/attack_scripts/build && cmake --build ${ROOT_DIR}/attack_scripts/build -j" >&2
  exit 1
fi

process_dir() {
  local in_dir="$1"
  local out_dir="$2"

  # Create output directory
  mkdir -p "${out_dir}"

  # Process files in current directory
  shopt -s nullglob
  for tgt in "${in_dir}"/*.pcap "${in_dir}"/*.pcapng; do
    [[ -e "$tgt" ]] || continue
    local base
    base=$(basename "$tgt")
    local out="${out_dir}/${base%.pcap}.remove_first.pcapng"
    out="${out%.pcapng}.remove_first.pcapng" # ensure extension
    echo "[+] Processing: $tgt -> $out"
    "${TOOL}" "$tgt" "$out"
  done

  # Process subdirectories recursively
  for subdir in "${in_dir}"/*/; do
    [[ -d "$subdir" ]] || continue
    local subdir_name
    subdir_name=$(basename "$subdir")
    local sub_out_dir="${out_dir}/${subdir_name}"
    echo "[+] Processing subdirectory: $subdir -> $sub_out_dir"
    process_dir "$subdir" "$sub_out_dir"
  done
}

echo "=== Processing CHAT pcaps (removing first packet) ==="
process_dir "${CHAT_IN_DIR}" "${OUT_CHAT_DIR}"

echo "=== Processing EMAIL pcaps (removing first packet) ==="
process_dir "${EMAIL_IN_DIR}" "${OUT_EMAIL_DIR}"

echo "Done. Outputs in:"
echo "  - ${OUT_CHAT_DIR}"
echo "  - ${OUT_EMAIL_DIR}"
