#!/usr/bin/env bash
set -euo pipefail

# WPA-PSK bake-off test suite
# Tests all 50 modules (90001-90050) for correctness and performance.
# Outputs a TSV file with benchmark speeds, crack results per type,
# and mixed-workload throughput.
#
# Usage: ./tools/bakeoff_test.sh [output.tsv]
# Default output: bakeoff-results.tsv in the current directory

HASHCAT="./hashcat"
HASHFILE="specs/wpawolf_all.txt"
PASSWORD="hashcat!"
OUTFILE="${1:-bakeoff-results.tsv}"
TMPDIR="$(mktemp -d)"
trap 'rm -rf "${TMPDIR}"' EXIT

echo "${PASSWORD}" > "${TMPDIR}/dict.txt"

# --- extract one test hash per type ---
for t in 01 02 03 04 05 06 07 08 09 10 11; do
  grep "^WPA\*${t}\*" "${HASHFILE}" | head -1 > "${TMPDIR}/type_${t}.hash" || true
done

# --- header ---
printf "mode\tname\tbench_hs\t" > "${OUTFILE}"
for t in 01 02 03 04 05 06 07 08 09 10 11; do
  printf "t%s\t" "${t}" >> "${OUTFILE}"
done
printf "types_pass\ttypes_total\tmixed_hs\tmixed_recovered\tjit_ms\n" >> "${OUTFILE}"

total_modes=0
total_pass=0
total_fail=0

for m in $(seq 90001 90050); do
  total_modes=$((total_modes + 1))
  echo "========== MODE ${m} =========="

  # --- benchmark ---
  bench_out=$("${HASHCAT}" -m "${m}" -b --force 2>&1 || true)
  bench_speed=$(echo "${bench_out}" | grep -oP '[\d.]+(?= [kMG]?H/s)' | head -1)
  bench_unit=$(echo "${bench_out}" | grep -oP '[\d.]+ \K[kMG]?H/s' | head -1)
  mode_name=$(echo "${bench_out}" | grep -oP 'Hash-Mode.*\(\K[^)]+' | head -1)

  # normalize to H/s
  case "${bench_unit}" in
    kH/s) bench_hs=$(echo "${bench_speed} * 1000" | bc -l 2> /dev/null | cut -d. -f1) ;;
    MH/s) bench_hs=$(echo "${bench_speed} * 1000000" | bc -l 2> /dev/null | cut -d. -f1) ;;
    GH/s) bench_hs=$(echo "${bench_speed} * 1000000000" | bc -l 2> /dev/null | cut -d. -f1) ;;
    H/s) bench_hs=$(echo "${bench_speed}" | cut -d. -f1) ;;
    *) bench_hs="0" ;;
  esac

  echo "  Benchmark: ${bench_speed} ${bench_unit} (${bench_hs} H/s)"

  # --- per-type crack test ---
  types_pass=0
  types_total=0
  type_results=""

  for t in 01 02 03 04 05 06 07 08 09 10 11; do
    hf="${TMPDIR}/type_${t}.hash"
    if [[ ! -s "${hf}" ]]; then
      type_results="${type_results}SKIP	"
      continue
    fi
    types_total=$((types_total + 1))

    crack_out=$("${HASHCAT}" -m "${m}" "${hf}" "${TMPDIR}/dict.txt" --force --potfile-disable 2>&1 || true)
    if echo "${crack_out}" | grep -q 'Status.*Cracked'; then
      type_results="${type_results}PASS	"
      types_pass=$((types_pass + 1))
    else
      type_results="${type_results}FAIL	"
    fi
  done

  echo "  Types: ${types_pass}/${types_total} cracked"

  # --- mixed-type workload ---
  mixed_out=$("${HASHCAT}" -m "${m}" "${HASHFILE}" "${TMPDIR}/dict.txt" --force --potfile-disable 2>&1 || true)
  mixed_speed=$(echo "${mixed_out}" | grep -oP '[\d.]+(?= [kMG]?H/s)' | tail -1)
  mixed_unit=$(echo "${mixed_out}" | grep -oP '[\d.]+ \K[kMG]?H/s' | tail -1)
  mixed_recovered=$(echo "${mixed_out}" | grep -oP 'Recovered.*?(\d+/\d+)' | grep -oP '\d+/\d+' | head -1)

  case "${mixed_unit}" in
    kH/s) mixed_hs=$(echo "${mixed_speed} * 1000" | bc -l 2> /dev/null | cut -d. -f1) ;;
    MH/s) mixed_hs=$(echo "${mixed_speed} * 1000000" | bc -l 2> /dev/null | cut -d. -f1) ;;
    GH/s) mixed_hs=$(echo "${mixed_speed} * 1000000000" | bc -l 2> /dev/null | cut -d. -f1) ;;
    H/s) mixed_hs=$(echo "${mixed_speed}" | cut -d. -f1) ;;
    *) mixed_hs="0" ;;
  esac

  echo "  Mixed: ${mixed_speed} ${mixed_unit}, recovered ${mixed_recovered}"

  # --- wall-clock time from benchmark start/stop ---
  started=$(echo "${bench_out}" | grep -oP 'Started: \K.*' | head -1)
  stopped=$(echo "${bench_out}" | grep -oP 'Stopped: \K.*' | head -1)
  if [[ -n "${started}" ]] && [[ -n "${stopped}" ]]; then
    start_epoch=$(date -d "${started}" +%s 2> /dev/null || echo 0)
    stop_epoch=$(date -d "${stopped}" +%s 2> /dev/null || echo 0)
    jit_ms=$(((stop_epoch - start_epoch) * 1000))
  else
    jit_ms=""
  fi

  # --- write row ---
  {
    printf "%s\t%s\t%s\t" "${m}" "${mode_name}" "${bench_hs}"
    printf "%s" "${type_results}"
    printf "%s\t%s\t%s\t%s\t%s\n" "${types_pass}" "${types_total}" "${mixed_hs}" "${mixed_recovered}" "${jit_ms:-}"
  } >> "${OUTFILE}"

  if [[ "${types_pass}" -eq "${types_total}" ]] && [[ "${types_total}" -gt 0 ]]; then
    total_pass=$((total_pass + 1))
    echo "  RESULT: PASS"
  else
    total_fail=$((total_fail + 1))
    echo "  RESULT: FAIL (${types_pass}/${types_total})"
  fi

  echo ""
done

echo "========================================"
echo "SUMMARY: ${total_pass} pass, ${total_fail} fail out of ${total_modes} modules"
echo "Results written to: ${OUTFILE}"
echo "========================================"
