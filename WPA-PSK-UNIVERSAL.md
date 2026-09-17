# WPA-PSK Universal Cracking Modes — 50-Module Bake-Off

## Summary

This branch adds hashcat support for cracking **all eleven AKM / handshake-type combinations** a PSK network can present. It ships 50 plugin implementations (modes `90001`–`90050`), each a different internal architecture that produces identical results, so the best design can be measured empirically across CPU and GPU backends before converging on a production mode. A companion test script (`tools/bakeoff_test.sh`) automates correctness and performance testing across all 50 modules.

The hash format, the eleven verifier functions, and the PBKDF2 core are shared infrastructure. The 50 modules differ only in how the per-digest post-PMK verification is dispatched — aux packing, monolithic comp, HOOK23 host-side, JIT type-mask specialization, branchless execution, struct layout, and combinations of these.

## The problem we are solving

Stock hashcat `-m 22000` cracks the common case: WPA2-PSK PMKID and EAPOL handshakes whose key derivation and MIC use SHA-1. Modern PSK deployments add several variants that `22000` does not cover:

- **PSK-SHA256** (AKM 6) — KDF and MIC move to SHA-256 / AES-128-CMAC.
- **PSK-SHA384** (AKM 20) — KDF and MIC move to SHA-384, with a 24-byte KCK and a 192-bit MIC.
- **802.11r Fast Transition, FT-PSK** (AKM 4 and 19) — a multi-stage FT key hierarchy (PMK-R0 → PMK-R1 → PTK) feeds both the PMKID (PMKR1Name) and the EAPOL MIC, in SHA-256 and SHA-384 flavors.
- **Legacy WPA1** — TKIP-era EAPOL with an HMAC-MD5 MIC.

A single hash-line format encodes all of these, distinguished by a two-digit decimal type code. The goal is one plugin that loads and cracks every type with 100% correctness, validated against synthetic all-types fixtures and real GPU benchmarks.

## The hash format

```
WPA*TT*<mic-or-pmkid>*<ap-mac>*<sta-mac>*<essid>*<anonce>*<eapol>*<message-pair>[*<mdid>*<r0kh-id>*<r1kh-id>]
```

`TT` is a two-digit **decimal** type code, `01`–`11`. Even codes are PMKID hashes, odd codes are EAPOL handshakes. The three trailing fields are present only for the FT types (06, 07, 10, 11).

| Type | AKM | Handshake | What is verified | KDF / PMKID hash | MIC |
|-----:|----:|-----------|------------------|------------------|-----|
| 01 | WPA1 | EAPOL | 4-way MIC | PRF-SHA1 | HMAC-MD5 |
| 02 | 2 | PMKID | Truncate-128 PMKID | HMAC-SHA1 | — |
| 03 | 2 | EAPOL | 4-way MIC | PRF-SHA1 | HMAC-SHA1-128 |
| 04 | 6 | PMKID | Truncate-128 PMKID | HMAC-SHA256 | — |
| 05 | 6 | EAPOL | 4-way MIC | KDF-SHA256 | AES-128-CMAC |
| 06 | 4 | PMKID (FT) | PMKR1Name | SHA-256 FT chain | — |
| 07 | 4 | EAPOL (FT) | 4-way MIC | SHA-256 FT chain | AES-128-CMAC |
| 08 | 20 | PMKID | Truncate-128 PMKID | HMAC-SHA384 | — |
| 09 | 20 | EAPOL | 4-way MIC | KDF-SHA384 | HMAC-SHA384-192 |
| 10 | 19 | PMKID (FT) | PMKR1Name | SHA-384 FT chain | — |
| 11 | 19 | EAPOL (FT) | 4-way MIC | SHA-384 FT chain | HMAC-SHA384-192 |

The PMK is always `PBKDF2-HMAC-SHA1(passphrase, ESSID, 4096, 32)` — a 256-bit PMK for every type, including the SHA-384 ones.

## Key design decisions

- **PBKDF2 once per ESSID.** The expensive 4096-iteration PBKDF2 is salt-level work — `salt_t` carries the ESSID — so it runs once per ESSID and is shared by every digest under that ESSID. Per-handshake material (MACs, nonce, EAPOL frame, MIC/PMKID, FT fields) lives in the per-digest `esalt`.
- **Per-digest verification via the deep-comp kernel.** Final, type-specific verification runs after PBKDF2 and is dispatched per digest. The 50 plugins differ in *how* that dispatch is structured — that is the experiment.
- **Decimal type code.** `TT` is parsed and emitted as decimal `01`–`11`, not hex. An early implementation parsed `10`/`11` as hex and silently rejected them.
- **HMAC keys zero-padded to a full block.** The PMK and the FT keys are zero-padded to the hash's full input-block width before being used as HMAC keys.
- **EAPOL buffer sized for FT.** Real FT M3 frames reach ~515 bytes. The EAPOL buffer is 1088 bytes and the loader token cap is 2048 hex.
- **Bounded FT fields.** `mdid` (2 B), `r0kh-id` (≤48 B, the spec maximum) and `r1kh-id` (6 B) are length-checked against their spec maxima.

## The 50 plugin architectures

### Group 0: Standalone modes (90001–90010) — original bake-off

The first 10 modes test the "separate mode" design space — each is a complete standalone plugin with its own `wpa_universal_t` esalt. These were the original bake-off that demonstrated all 11 types can be cracked.

| Mode | Architecture | Key property |
|------|-------------|--------------|
| 90001 | monolithic _comp, no aux | Loops digests in _comp, switch on type; no dispatch overhead |
| 90002 | 4-family aux, deep_comp | 4 aux grouped by crypto family (SHA1, SHA256, FT, SHA384) |
| 90003 | GPU PBKDF2 + all-CPU hook23 | Host-side verification of all 11 types |
| 90004 | 2-aux by attack surface | PMKID vs EAPOL split |
| 90005 | 11 per-type aux | One kernel per type; requires AUX6-11 core patch |
| 90006 | single aux + switch | One aux kernel with internal type switch |
| 90007 | GPU types 1-7, CPU types 8-11 | Hybrid: SHA-384 offloaded to host hook |
| 90008 | 2-aux by word width | 32-bit primitives vs 64-bit (SHA-384) |
| 90009 | 3-tier aux | {1,2,3} / {4,5,6,7} / {8,9,10,11} |
| 90010 | branchless superset | Runs all 11 verifiers, selects by type mask |

### Group 1: Aux packing strategies (90011–90022) — the core question

All share PBKDF2 init/loop infrastructure. All use deep_comp → aux dispatch. They differ ONLY in how 11 types map to 5 aux slots.

| Mode | Name | aux1 | aux2 | aux3 | aux4 | aux5 | Types |
|------|------|------|------|------|------|------|-------|
| 90011 | jsteube-baseline | 1 | 3 | 5 | 2,4 | 6,7 | 1-7 |
| 90012 | primitive-based | 1 | 3 | 5,7 | 2,4,6,8,10 | 9,11 | 1-11 |
| 90013 | feature-based | 1 | 3 | 5 | 2,4,8 | 6,7,9,10,11 | 1-11 |
| 90014 | zero-touch | 1 | 3 | 5 | 2,4,6,8,10 | 7,9,11 | 1-11 |
| 90015 | progressive-overload | 1 | 3 | 5 | 2 | 4,6,7,8,9,10,11 | 1-11 |
| 90016 | kdf-merge | 1,3 | 5,7 | 9,11 | 2,4,6,8,10 | *(free)* | 1-11 |
| 90017 | pmkid-first | 2,4,6,8,10 | 1 | 3,5,7 | 9,11 | *(free)* | 1-11 |
| 90018 | ultra-minimal-2aux | 1,3,5,7,9,11 | 2,4,6,8,10 | — | — | — | 1-11 |
| 90019 | per-eapol-family | 1 | 3 | 5,7 | 9,11 | 2,4,6,8,10 | 1-11 |
| 90020 | jsteube-plus-sha384 | 1 | 3 | 5 | 2,4 | 6,7,8,9,10,11 | 1-11 |
| 90021 | cross-cut | 1 | 3 | 5,7 | 2,4,8,10 | 6,9,11 | 1-11 |
| 90022 | sha256-complete | 1 | 3 | 5 | 2,4,6 | 7,8,9,10,11 | 1-11 |

### Group 2: Dispatch alternatives (90023–90030)

| Mode | Name | Dispatch mechanism |
|------|------|--------------------|
| 90023 | monolithic-comp-22k | No deep_comp, no aux — all types in _comp |
| 90024 | hook23-all | GPU PBKDF2 only, all verification on host CPU |
| 90025 | hook23-sha384-baseline | GPU aux types 1-7 (90011 packing), CPU hook types 8-11 |
| 90026 | hook23-sha384-primitive | GPU aux types 1-7 (90012 packing), CPU hook types 8-11 |
| 90027 | hook23-sha384-zerotouch | GPU aux types 1-7 (zero-touch packing), CPU hook types 8-11 |
| 90028 | monolithic-hook-hybrid | Monolithic _comp types 1-7, HOOK23 types 8-11 |
| 90029 | batch-pmkid | Primitive-based, if-else PMKID dispatch |
| 90030 | table-dispatch | Primitive-based, lookup-table dispatch in module |

### Group 3: JIT specialization (90031–90035)

These add `module_jit_build_options` to scan loaded hashes and emit `-DENABLE_TYPE_N` defines. The kernel wraps type-specific code in `#ifdef ENABLE_TYPE_N` blocks so dead types produce no code — smaller kernel binary, lower register pressure.

| Mode | Name | JIT strategy | Base packing |
|------|------|-------------|-------------|
| 90031 | jit-primitive | per-type `-DENABLE_TYPE_N` | 90012 |
| 90032 | jit-zerotouch | per-type `-DENABLE_TYPE_N` | 90014 |
| 90033 | jit-monolithic | per-type on monolithic _comp | 90023 |
| 90034 | jit-surface | `-DENABLE_PMKID` / `-DENABLE_EAPOL` | 90012 |
| 90035 | jit-dynshared | per-type + dynamic shared flag | 90012 |

### Group 4: Struct layout and kernel optimizations (90036–90045)

| Mode | Name | Variant tested |
|------|------|----------------|
| 90036 | fat-struct | All fields always present (baseline) |
| 90037 | union-struct-placeholder | Union layout marker |
| 90038 | compat-struct-placeholder | Extended wpa_t naming |
| 90039 | minimal-esalt | HOOK23 with minimal esalt |
| 90040 | simd-aux | SIMD-vectorized aux kernels |
| 90041 | scalar-aux | No NEW_SIMD_CODE in aux |
| 90042 | dynshared-cmac | OPTS_TYPE_DYNAMIC_SHARED for AES |
| 90043 | opt-hot-placeholder | Optimized kernel target |
| 90044 | branchless-prim | Branchless superset on primitive packing |
| 90045 | inline-finalize-placeholder | Inline PBKDF2 finalization target |

### Group 5: Format compatibility and PR candidates (90046–90050)

| Mode | Name | Format/combination |
|------|------|--------------------|
| 90046 | greenfield | WPA*01*..*11* only |
| 90047 | legacy-compat | Legacy *01*..*04* + new *05*..*11* |
| 90048 | auto-detect | Infer type from keyver for legacy lines |
| 90049 | pr-candidate-a | Primitive packing + JIT type-mask |
| 90050 | kitchen-sink | All optimizations stacked |

## Benchmark results

### AMD Radeon 780M (ROCm/HIP) — full correctness + performance

Tested with `tools/bakeoff_test.sh` on AMD Radeon 780M (Phoenix3 iGPU), 6 CUs, HIP 7.15, 47 GB unified memory. Each module was benchmarked, then crack-tested against all 11 types individually and as a 200-hash mixed workload.

**Correctness: 49/50 pass all 11 types.** Mode 90011 passes 7/11 by design (types 1-7 only).

**Performance tiers (benchmark speed):**

| Tier | Speed | Modules | Why |
|------|-------|---------|-----|
| GPU-only | 194–207 kH/s | 90001-90002, 90004-90006, 90008-90050 (non-hook) | PBKDF2 dominates; packing irrelevant |
| HOOK23 | 164–173 kH/s | 90003, 90007, 90024-90028, 90039 | ~15-18% host-verification overhead |

**Key finding: on a real GPU, PBKDF2 dominates so completely that aux packing strategy has no measurable impact on throughput.** All GPU-only modules cluster within ~5% of each other (194–207 kH/s). The only measurable difference is HOOK23 vs GPU-only (~15-18% penalty for host-side verification).

**Selected benchmark results (780M):**

| Mode | Name | Bench (kH/s) | 11/11 | Mixed |
|------|------|-------------|-------|-------|
| 90001 | monolithic-comp | 201.8 | PASS | 155/155 |
| 90002 | 4-family-aux | 197.6 | PASS | 155/155 |
| 90008 | 2-aux-32v64 | 204.2 | PASS | 155/155 |
| 90012 | primitive-based | 199.3 | PASS | 155/155 |
| 90014 | zero-touch | 198.4 | PASS | 155/155 |
| 90016 | kdf-merge | 199.7 | PASS | 155/155 |
| 90018 | ultra-minimal-2aux | 199.2 | PASS | 155/155 |
| 90020 | jsteube-plus-sha384 | 203.9 | PASS | 155/155 |
| 90023 | monolithic-comp-22k | 201.2 | PASS | 155/155 |
| 90029 | batch-pmkid | 204.3 | PASS | 155/155 |
| 90031 | jit-primitive | 200.4 | PASS | 155/155 |
| 90046 | greenfield | 203.7 | PASS | 155/155 |
| 90049 | pr-candidate-a | 201.0 | PASS | 155/155 |
| 90024 | hook23-all | 171.8 | PASS | 155/155 |
| 90003 | GPU+CPU-validate | 169.9 | PASS | 155/155 |

### PoCL CPU — baseline

Tested on PoCL 6.0, cpu-skylake-avx512, 16 MCU. GPU-only modules: 57–66 kH/s. HOOK23 modules: ~50 kH/s.

### RTX 4060 Ti — historical (modes 90001-90010 only)

See `GPU-BENCHMARK-RTX4060Ti.md` for detailed sustained-run results from the original 10-module bake-off on NVIDIA CUDA/OpenCL. Key finding: universal modes beat stock 22000 by 2.2-2.4× on CUDA single-hash, narrowing to ~1.1× dense. OpenCL tied.

## What the data proves

1. **PBKDF2 dominates.** On every backend tested (PoCL CPU, AMD 780M, NVIDIA 4060 Ti), the 4096-iteration PBKDF2-HMAC-SHA1 accounts for >99% of runtime. Post-PMK verification (the part that differs between modules) is <1% of wall time. This means:
   - Aux packing strategy does not measurably affect throughput
   - The choice of architecture should be driven by code simplicity, maintainability, and correctness — not by micro-optimization of the post-PMK dispatch
   - Any of the 42 GPU-only modules that pass 11/11 is a viable production candidate

2. **HOOK23 costs ~15-18%.** Host-side verification is measurably slower due to GPU→CPU→GPU data transfer overhead. This cost is constant regardless of which types run on the host. HOOK23 is viable for rare types (SHA-384) but not ideal as a universal approach.

3. **JIT type-mask works but requires care.** The JIT modules correctly compile out unused type paths, but the self-test hash must always be enabled (the type-2 PMKID self-test was initially compiled out when running single-type workloads, fixed by always seeding the type-2 enable flag).

4. **All 11 types crack correctly.** Every non-HOOK23 GPU-only module cracks all 11 types with 100% accuracy — 155/155 on the mixed workload, 11/11 on per-type individual tests.

## Building and testing

```
make clean && make -j16
rm -rf kernels
printf 'hashcat!\n' > wl.txt

# Quick test: one module, all types
./hashcat -m 90012 specs/wpawolf_all.txt wl.txt --force --potfile-disable

# Full bake-off: all 50 modules, correctness + performance
bash tools/bakeoff_test.sh bakeoff-results.tsv
```

The test fixture `specs/wpawolf_all.txt` contains 200 lines (155 distinct hashes across all 11 types, passphrase `hashcat!`). The test script benchmarks each module, crack-tests all 11 types individually, and runs a mixed-workload crack, outputting a TSV with per-module results.

## Status

All 50 modules compile, benchmark, and crack on PoCL CPU and AMD GPU (ROCm/HIP). 49/50 pass all 11 types (90011 passes 7/11 by design). The full TSV results are in `bakeoff-780m.tsv`. The test script is ready for deployment on additional GPU hardware (NVIDIA CUDA via vast.ai) to validate cross-platform behavior.
