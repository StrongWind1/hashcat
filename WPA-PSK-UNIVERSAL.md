# WPA-PSK Universal Cracking Modes (90001–90010 → 22002/22003)

## Summary

This branch adds hashcat support for cracking an extended WPA/WPA2/WPA3-PSK hash format that covers **all eleven AKM / handshake-type combinations** a PSK network can present — not just the WPA2 PMKID/EAPOL pair that stock `-m 22000` handles. It ships ten interchangeable plugin implementations (modes `90001`–`90010`), each a different internal architecture that produces identical results, so the fastest and cleanest design can be measured and then flattened into a single production mode (`22002`, with a PMK-direct sibling `22003` planned).

## The problem we are solving

Stock hashcat `-m 22000` cracks the common case: WPA2-PSK PMKID and EAPOL handshakes whose key derivation and MIC use SHA-1. Modern PSK deployments add several variants that `22000` does not cover:

- **PSK-SHA256** (AKM 6) — KDF and MIC move to SHA-256 / AES-128-CMAC.
- **PSK-SHA384** (AKM 20) — KDF and MIC move to SHA-384, with a 24-byte KCK and a 192-bit MIC.
- **802.11r Fast Transition, FT-PSK** (AKM 4 and 19) — a multi-stage FT key hierarchy (PMK-R0 → PMK-R1 → PTK) feeds both the PMKID (PMKR1Name) and the EAPOL MIC, in SHA-256 and SHA-384 flavors.
- **Legacy WPA1** — TKIP-era EAPOL with an HMAC-MD5 MIC.

A single hash-line format encodes all of these, distinguished by a two-digit decimal type code. The goal of this branch is one plugin that loads and cracks every type with 100% correctness, validated against a synthetic all-types fixture and a large benchmark corpus, then to pick the best-performing architecture to ship as a clean production mode.

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

The PMK is always `PBKDF2-HMAC-SHA1(passphrase, ESSID, 4096, 32)` — a 256-bit PMK for every type, including the SHA-384 ones (the passphrase PSK is used directly as the PMK; a 384-bit PMK is not derivable from a passphrase, and that case is documented as a real-radio deviation rather than something the passphrase path can crack).

## Key design decisions

- **PBKDF2 once per ESSID.** The expensive 4096-iteration PBKDF2 is salt-level work — `salt_t` carries the ESSID — so it runs once per ESSID and is shared by every digest under that ESSID. Per-handshake material (MACs, nonce, EAPOL frame, MIC/PMKID, FT fields) lives in the per-digest `esalt`. This is what makes the many-handshakes-per-network case cheap.
- **Per-digest verification via the deep-comp kernel.** Final, type-specific verification runs after PBKDF2 and is dispatched per digest. The ten plugins differ almost entirely in *how* that dispatch is structured — that is the whole experiment.
- **Decimal type code.** `TT` is parsed and emitted as decimal `01`–`11`, not hex. An early implementation parsed `10`/`11` as hex and silently rejected them.
- **HMAC keys zero-padded to a full block.** The PMK and the FT keys are zero-padded to the hash's full input-block width before being used as HMAC keys; otherwise the upper key block holds stale data on some types and the MIC is wrong.
- **EAPOL buffer sized for FT.** Real FT M3 frames reach ~515 bytes — they carry the MDE/FTE/GTK/IGTK key-data elements — far past the ~256-byte truncated frame stock `22000` stores. The EAPOL buffer is 1088 bytes and the loader token cap is 2048 hex, so every real frame parses (an earlier 512-hex cap silently dropped the long FT handshakes).
- **Bounded FT fields.** `mdid` (2 B), `r0kh-id` (≤48 B, the spec maximum) and `r1kh-id` (6 B) are length-checked against their spec maxima.

## The ten plugin architectures

All ten load the same format, share the same PBKDF2 core and the same eleven verifiers, and each cracks 100% of the all-types fixture. They differ only in how the per-digest verification is split across kernels.

- **90001 — Monolithic comp.** All eleven verifiers live in a single `_comp` kernel that loops over a salt's digests (`MULTIHASH_DESPITE_ESALT`).
  - Pros: no per-digest deep-comp kernel launches, so it is fastest when there are many handshakes per ESSID; no core patch; simple control flow.
  - Cons: one large kernel carrying every primitive (high register/instruction footprint); all type branches compiled together; does not isolate cheap from expensive types.

- **90002 — Four family-aux (baseline).** Four aux kernels split by hash family: MD5/SHA-1, SHA-256, SHA-384, and FT.
  - Pros: highest raw `-b` throughput in testing; clean separation by crypto family; moderate kernel sizes; no core patch.
  - Cons: still switches PMKID-vs-EAPOL inside each family; the family split is not the same as the attack-surface split.

- **90003 — PBKDF2 on GPU + CPU validate (HOOK23).** The GPU runs PBKDF2 only; all eleven verifiers run on the host hook.
  - Pros: tiny, simple GPU kernel; verifier logic is portable C that is trivial to read, debug and extend; no GPU divergence at all.
  - Cons: reliably the slowest — the host round-trip and the device↔host PMK copies dominate; the CPU becomes the bottleneck and it does not scale with the GPU.

- **90004 — Two aux by attack surface (the winner).** Two aux kernels split by surface: one handles all PMKID types, the other all EAPOL types.
  - Pros: the fewest kernels that still isolate the two genuinely different code paths; the most consistent design across every workload; core-clean (no aux5–11 patch) and structurally simple. Selected to be flattened into mode `22002`.
  - Cons: each aux still switches across families internally; not the single fastest on any one metric, though never far off the lead.

- **90005 — Eleven per-type aux.** One dedicated aux kernel per type, which requires a small hashcat core patch to add the extra aux dispatch slots.
  - Pros: zero per-kernel branching — each kernel does exactly one type — which is the theoretically best layout on a divergence-heavy GPU mix; cleanest possible separation.
  - Cons: requires patching the core (`backend.c` + `types.h`), a real maintenance cost; eleven kernel objects; and on CPU it shows no advantage because there are no SIMT lanes to keep convergent.

- **90006 — One aux + deep-comp switch.** A single aux kernel with a `switch` over all eleven types.
  - Pros: the simplest aux design — one kernel plus a switch; no core patch; minimal surface.
  - Cons: maximal in-kernel branching, so the worst-case divergence on a GPU; one kernel again carries every primitive.

- **90007 — GPU types 1–7 + CPU types 8–11 (hybrid HOOK23).** SHA-1/SHA-256 types run on the GPU; the SHA-384 types are offloaded to the host hook.
  - Pros: keeps the heavy, rarer SHA-384 paths out of the GPU kernel (smaller kernel); a useful model for partial offload.
  - Cons: hybrid hook overhead; clearly worst on SHA-384-heavy mixes — exactly the types it offloads — which confirms the host round-trip cost lands where the design puts it; the most complex wiring.

- **90008 — Two aux split by word width (32/64-bit).** One aux for the 32-bit primitives (MD5/SHA-1/SHA-256), one for the 64-bit primitive (SHA-384).
  - Pros: groups by the underlying integer width, giving each kernel coherent register usage; solid raw throughput.
  - Cons: the 32-bit group still mixes PMKID/EAPOL/FT; the split is by primitive width rather than by attack surface.

- **90009 — Three aux by cost tier.** Tiers grouped by crypto cost: {1,2,3} MD5/SHA-1, {4,5,6,7} SHA-256 plus FT and AES-CMAC, {8,9,10,11} SHA-384.
  - Pros: a middle ground between kernel count and separation; tiers roughly track cost; no core patch.
  - Cons: the middle tier is the busiest (four types including FT and AES-CMAC) and still switches within the tier.

- **90010 — Branchless superset.** Computes all eleven verifier leaves for every digest, then selects the matching result branchlessly.
  - Pros: zero data-dependent branching, so fully uniform execution by construction — no divergence is even possible.
  - Cons: does roughly eleven times the necessary crypto per digest, so it wastes most of its work and is reliably among the slowest; useful only as a divergence-free reference point.

## Benchmark — CPU impressions (PoCL)

These were measured on a CPU OpenCL backend (PoCL, `cpu-skylake-avx512`), so treat them as indicative rather than a GPU verdict. On a CPU the 4096-iteration PBKDF2 dominates wall time, which compresses the architectures together. The GPU verdict that follows supersedes these where they disagree.

- **The top tier is effectively a tie.** 90004, 90002, 90001, 90008, 90009, 90005 and 90006 land within roughly ~1.5% of each other on every workload — that spread is statistical noise, because PBKDF2 dominates and a CPU has no SIMT divergence for the divergence-elimination designs to recover.
- **Per-metric leaders.** 90002 tends to post the highest raw `-b` number; 90001 leads when a hash list has many handshakes per ESSID, because its comp-loop avoids the per-digest deep-comp kernel-launch dispatch the aux designs pay there; 90004 is the most consistent, never more than ~1% off the lead on any workload.
- **The clear losers** are 90003 (all-CPU validate), 90007 (hybrid) and 90010 (branchless superset). Each pays a structural cost — host round-trips, or redundant crypto — that no device can hide. 90007 is worst precisely on the SHA-384 slice it offloads.
- **90005 buys nothing on CPU**, but the GPU verdict below shows the picture is backend-split: its eleven lean per-type kernels top the OpenCL dense workload yet land near the bottom on CUDA, so the per-type isolation pays off on one backend only — and it still costs a core patch to get there.
- **No generality penalty.** On identical WPA2 inputs, the universal plugins match or edge stock `-m 22000` — the eleven-type loader and dispatch cost essentially nothing over the single-purpose stock kernel.

## Benchmark — GPU verdict (RTX 4060 Ti)

The GPU re-run is done on clean, equal-dataset corpora generated from scratch by `WPAWolf/tools/corpusgen` (no data reused). A first pass used hashcat `--speed-only`, but a sustained-run confirmation showed `--speed-only` is unreliable for this comparison — it over-states OpenCL single-hash and under-states dense CUDA — so the verdict below is from **real, sustained runs** (`--runtime`), comparing only within a single corpus where the ratio is trustworthy; full tables and the methodology note are in `GPU-BENCHMARK-RTX4060Ti.md`. The bring-up first required fixing a `REAL_SHM` AES T-table address-space bug; with it fixed, all eleven types build, crack and benchmark on both the CUDA and OpenCL backends.

- **Universal beats stock 22000 on CUDA and ties it on OpenCL, on identical handshakes.** On CUDA the universal modes are ~2.2–2.4× faster than 22000 at a single hash, narrowing to ~1.1× on a dense list (NVRTC produces a much slower kernel for stock 22000; the gap shrinks when a dense salt structure lets 22000 amortize it). On OpenCL the two are tied (~1.00×) at every density. The PMKID and EAPOL surfaces behave the same. 22000 is never favored — the earlier "22000 dominates the dense workload" claim was an unequal digest count, and the earlier "~2× on CUDA across all densities" overstated a single-hash effect.
- **OpenCL is roughly tied with CUDA (≤ ~1.14×), not 2×.** The apparent 2× backend advantage was a `--speed-only` artifact; on real runs OpenCL is at most ~14% ahead and essentially tied on dense lists.
- **No design wins everywhere — the differences are real and workload-dependent.** Run-to-run noise is ~1–2% (measured over five repeats), so the ~10–15% spreads between designs are genuine, not noise. 90001 (monolithic-comp) leads WPA2-dense on CUDA but is a register-heavy monolith and only fourth on OpenCL; on a realistic all-types mixed list the top is a 90009/90004/90002 cluster on CUDA and 90005/90002 on OpenCL. 90002 (4-family) is the most consistent across backends; 90004 is mid on WPA2-only but top-cluster on mixed. 90003/90007/90010 are clearly slowest everywhere and collapse on SHA-384.
- **All eleven types run on both backends**, including the AES-128-CMAC types (05/07) that exercise the `REAL_SHM` path and the SHA-384 / FT families 22000 cannot represent at all — which is the whole reason these modes exist.

## Recommendation

The design differences are real (run-to-run noise is ~1–2%) but modest and workload-dependent, so no single mode wins everywhere. For the representative production workload — mixed all-types traffic — **90004 (two aux by attack surface) sits in the top cluster (CUDA second) while staying core-clean (no `backend.c`/`types.h` patch) and the structurally simplest fast design, so it remains a defensible default for `22002`**. If a single data-driven pick is preferred, **90002 (4-family) or 90009 (3-tier)** are marginally more consistent across both backends and also core-clean; **90001** is the WPA2-dense CUDA peak (register-heavy monolith); **90005** leads OpenCL but needs the core patch. The backend-independent constant: all ten universal modes beat (CUDA) or tie (OpenCL) stock 22000 on equal data, so shipping any of them is a net win. All ten plugins are kept in-tree as the bake-off record.

## Building and testing

```
make clean && make -j16                            # full build (the Makefile does not track header deps, so clean first)
rm -rf kernels                                     # clear the JIT cache before a run after any kernel change
printf 'hashcat!\n' > wl.txt                       # the fixture passphrase
./hashcat -m 90004 specs/wpawolf_all.txt wl.txt    # expect 155/155 cracked, 0 parse errors
```

The repository ships a synthetic all-types test fixture, `specs/wpawolf_all.txt` (200 lines = 155 distinct hashes spanning all eleven types, passphrase `hashcat!`) — the command above should crack every line, and the same fixture drives the built-in self-test that runs at startup for each mode. Substitute any other mode number (`90001`–`90010`) to compare. For at-scale throughput numbers, run any mode against a larger hash list and wordlist of your own.

## Status

All ten modes load every type and crack the all-types fixture 100% — on CPU (PoCL) and on a real GPU (RTX 4060 Ti) across both the CUDA and OpenCL backends — with no parse errors and zero false positives. The GPU bring-up required the `REAL_SHM` AES T-table fix; without it, nine of ten modes failed to compile on a GPU while building cleanly on CPU. The GPU re-benchmark is done on clean equal-dataset corpora with sustained real runs (an initial `--speed-only` pass was found unreliable and discarded); it shows all ten modes beat 22000 on CUDA and tie it on OpenCL, with real but modest, workload-dependent design differences (90001 leads WPA2-dense CUDA; a 90009/90004/90002 cluster leads mixed traffic). 90004 remains a defensible production base — top-cluster on mixed traffic and the simplest core-clean design. See the GPU verdict above and `GPU-BENCHMARK-RTX4060Ti.md`. The remaining work is flattening 90004 into the self-contained production mode `22002` (and implementing the PMK-direct `22003`).
