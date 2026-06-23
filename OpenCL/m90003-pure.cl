/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 *
 * Bake-off plugin 90003 (config C): the GPU runs PBKDF2 only; ALL post-PMK
 * validation happens on the host CPU in the hook23 host callback.
 * The hashcat hook API doesn't expose esalts to host hook code, so the hook23
 * kernel (which does have esalt access) stages the PMK + a snapshot of every
 * digest of the salt into the per-workitem hook buffer; the host runs the
 * verifiers over that snapshot and records a match bitmask; this comp kernel
 * marks the bits the host set. Tests the GPU/CPU boundary / all-CPU floor.
 */

#define NEW_SIMD_CODE                                  // opt into the vectorised SIMD code paths used by the loop kernel

#ifdef KERNEL_STATIC                                   // device build: pull headers via the wrapped include path
#include M2S(INCLUDE_PATH/inc_vendor.h)                // vendor/platform feature macros (vector width, address spaces)
#include M2S(INCLUDE_PATH/inc_types.h)                 // u32/u64 and the kernel parameter struct types
#include M2S(INCLUDE_PATH/inc_platform.cl)             // get_global_id, atomics and other platform shims
#include M2S(INCLUDE_PATH/inc_common.cl)               // mark_hash and shared crack-bookkeeping helpers
#include M2S(INCLUDE_PATH/inc_simd.cl)                 // SIMD pack/unpack helpers for the vectorised loop
#include M2S(INCLUDE_PATH/inc_hash_md5.cl)             // MD5 (WPA1 MIC); little-endian, no word swap
#include M2S(INCLUDE_PATH/inc_hash_sha1.cl)            // SHA-1 (PBKDF2 PMK, WPA2 PMKID/MIC); big-endian words
#include M2S(INCLUDE_PATH/inc_hash_sha256.cl)          // SHA-256 (SHA256/FT families); big-endian words
#include M2S(INCLUDE_PATH/inc_hash_sha384.cl)          // SHA-384 (SHA384/FT-384 families); 64-bit big-endian words
#include M2S(INCLUDE_PATH/inc_cipher_aes.cl)           // AES-128 primitives backing the AES-CMAC MICs
#include M2S(INCLUDE_PATH/inc_wpa_psk_universal.cl)    // shared WPA helpers: PBKDF2 init/loop + per-AKM verifiers
#else                                                  // host build: include the same headers by plain path for CPU validation
#include "inc_vendor.h"
#include "inc_types.h"
#include "inc_platform.h"
#include "inc_common.h"
#include "inc_simd.h"
#include "inc_hash_md5.h"
#include "inc_hash_sha1.h"
#include "inc_hash_sha256.h"
#include "inc_hash_sha384.h"
#include "inc_cipher_aes.h"
#include "inc_wpa_psk_universal.cl"
#endif

// _init: seed the per-workitem PBKDF2 state (counts as the first of 4096 iterations).
KERNEL_FQ KERNEL_FA void m90003_init (KERN_ATTR_TMPS_HOOKS_ESALT (wpa_pbkdf2_tmp_t, wpa_hook_t, wpa_universal_t))
{
  const u64 gid = get_global_id (0);                   // this work item's index = which password candidate to process
  if (gid >= GID_CNT) return;                          // skip padding work items past the real candidate count

  // Run the first PBKDF2-HMAC-SHA1 transform for both output blocks and stash state in tmps.
  wpa_pbkdf2_init (pws, tmps, esalt_bufs, gid, DIGESTS_OFFSET_HOST);
}

// _loop: the slow inner PBKDF2 iterations; called repeatedly until 4096 total are done.
KERNEL_FQ KERNEL_FA void m90003_loop (KERN_ATTR_TMPS_HOOKS_ESALT (wpa_pbkdf2_tmp_t, wpa_hook_t, wpa_universal_t))
{
  const u64 gid = get_global_id (0);                   // work-item index; here each item covers VECT_SIZE candidates
  if ((gid * VECT_SIZE) >= GID_CNT) return;            // bounds-check accounting for the SIMD vector width

  // Fold LOOP_CNT more HMAC-SHA1 iterations into the running PBKDF2 accumulators.
  wpa_pbkdf2_loop (tmps, gid, LOOP_CNT);
}

// hook23 kernel: stage the PMK + a snapshot of the salt's digests for the host to validate.
KERNEL_FQ KERNEL_FA void m90003_hook23 (KERN_ATTR_TMPS_HOOKS_ESALT (wpa_pbkdf2_tmp_t, wpa_hook_t, wpa_universal_t))
{
  const u64 gid = get_global_id (0);                   // work-item index = the candidate whose PMK we hand to the host
  if (gid >= GID_CNT) return;                          // skip padding work items

  // Copy the 32-byte PMK (8 big-endian u32) out of tmps into the host-readable hook buffer.
  for (int i = 0; i < 8; i++) hooks[gid].pmk[i] = tmps[gid].out[i];

  u32 nd = DIGESTS_CNT;                                // number of digests sharing this salt the host should check
  if (nd > WPA_HOOK_MAXD) nd = WPA_HOOK_MAXD;          // clamp to the fixed hook-buffer capacity (and the ok-bitmask width)
  hooks[gid].ndig = nd;                                // tell the host how many digest snapshots are valid
  hooks[gid].ok   = 0;                                 // clear the match bitmask; host sets a bit per cracked digest

  // Snapshot each esalt (handshake data) so the host validator can read it without esalt access.
  for (u32 dp = 0; dp < nd; dp++)
  {
    hooks[gid].dig[dp] = esalt_bufs[DIGESTS_OFFSET_HOST + dp];   // copy this digest's esalt into the hook buffer slot
  }
}

// _comp: mark the digests the host validated (bit dp of hooks[gid].ok).
KERNEL_FQ KERNEL_FA void m90003_comp (KERN_ATTR_TMPS_HOOKS_ESALT (wpa_pbkdf2_tmp_t, wpa_hook_t, wpa_universal_t))
{
  const u64 gid = get_global_id (0);                   // work-item index = the candidate whose results we report
  if (gid >= GID_CNT) return;                          // skip padding work items

  // Walk the salt's digests, bounded by the same cap used when staging the bitmask.
  for (u32 digest_pos = 0; (digest_pos < DIGESTS_CNT) && (digest_pos < WPA_HOOK_MAXD); digest_pos++)
  {
    if (((hooks[gid].ok >> digest_pos) & 1) == 0) continue;   // bit clear -> host found no match for this digest, skip

    const u32 digest_cur = DIGESTS_OFFSET_HOST + digest_pos;   // absolute digest index within the global hash list
    if (hc_atomic_inc (&hashes_shown[digest_cur]) == 0)        // claim this crack exactly once across all work items
    {
      // Record the cracked candidate/digest pair so hashcat reports it.
      mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, digest_pos, digest_cur, gid, 0, 0, 0);
    }
  }
}
