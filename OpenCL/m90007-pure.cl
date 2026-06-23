/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 *
 * Bake-off plugin 90007 (config G): hybrid. The GPU validates the 32-bit
 * family {1..7} directly in the comp kernel; the SHA-384 family {8..11} is
 * validated on the host CPU in module_hook23. The hook23 kernel stages the
 * PMK + the salt's digests; the host validates only the SHA-384 rows and
 * records a bitmask the comp reads back for those types.
 */

#define NEW_SIMD_CODE                          // enable the vectorised (SIMD) code paths in the shared headers

#ifdef KERNEL_STATIC                            // device build: pull headers via the indirected INCLUDE_PATH macro
#include M2S(INCLUDE_PATH/inc_vendor.h)         // vendor/platform tunables (VECT_SIZE, address-space macros)
#include M2S(INCLUDE_PATH/inc_types.h)          // base scalar/vector typedefs (u32, u32x, ...)
#include M2S(INCLUDE_PATH/inc_platform.cl)      // platform shims (get_global_id, atomics, etc.)
#include M2S(INCLUDE_PATH/inc_common.cl)        // common helpers (byte swaps, mark_hash, ...)
#include M2S(INCLUDE_PATH/inc_simd.cl)          // SIMD pack/unpack helpers across lanes
#include M2S(INCLUDE_PATH/inc_hash_md5.cl)      // MD5 primitive: little-endian, used for the type-1 MIC
#include M2S(INCLUDE_PATH/inc_hash_sha1.cl)     // SHA-1 primitive: PBKDF2/PMK + SHA-1 PMKID/MIC
#include M2S(INCLUDE_PATH/inc_hash_sha256.cl)   // SHA-256 primitive: SHA-256 KDF/PMKID/CMAC families
#include M2S(INCLUDE_PATH/inc_hash_sha384.cl)   // SHA-384 primitive: needed so host C build can compile; GPU uses 1..7
#include M2S(INCLUDE_PATH/inc_cipher_aes.cl)    // AES core for AES-128-CMAC MIC (types 5,7)
#include M2S(INCLUDE_PATH/inc_wpa_psk_universal.cl)  // shared WPA verifiers + PBKDF2 init/loop for all 11 types
#else                                           // host C build: include the plain headers from the local dir
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
#include "inc_wpa_psk_universal.cl"             // verifier source compiled as host C for the CPU-validation path
#endif

// _init: seed the per-workitem PBKDF2 state so _loop can grind the 4096 iterations.
KERNEL_FQ KERNEL_FA void m90007_init (KERN_ATTR_TMPS_HOOKS_ESALT (wpa_pbkdf2_tmp_t, wpa_hook_t, wpa_universal_t))
{
  const u64 gid = get_global_id (0);           // this work item's global index
  if (gid >= GID_CNT) return;                   // skip padding items beyond the candidate count
  wpa_pbkdf2_init (pws, tmps, esalt_bufs, gid, DIGESTS_OFFSET_HOST);  // load passphrase+ESSID, run first PBKDF2 transform into tmps
}

// _loop: the slow inner PBKDF2 loop (HMAC-SHA1 iterated toward 4096), vectorised over SIMD lanes.
KERNEL_FQ KERNEL_FA void m90007_loop (KERN_ATTR_TMPS_HOOKS_ESALT (wpa_pbkdf2_tmp_t, wpa_hook_t, wpa_universal_t))
{
  const u64 gid = get_global_id (0);           // this work item's global index
  if ((gid * VECT_SIZE) >= GID_CNT) return;     // each item covers VECT_SIZE candidates; bound the highest one
  wpa_pbkdf2_loop (tmps, gid, LOOP_CNT);        // advance the PBKDF2 chain by LOOP_CNT iterations this call
}

// hook23: stage the finished PMK + the salt's digests so module_hook23 can validate the SHA-384 rows on CPU.
KERNEL_FQ KERNEL_FA void m90007_hook23 (KERN_ATTR_TMPS_HOOKS_ESALT (wpa_pbkdf2_tmp_t, wpa_hook_t, wpa_universal_t))
{
  const u64 gid = get_global_id (0);           // this work item's global index
  if (gid >= GID_CNT) return;                   // skip padding items beyond the candidate count

  for (int i = 0; i < 8; i++) hooks[gid].pmk[i] = tmps[gid].out[i];  // copy the 32-byte PMK (8 big-endian words) out for the host

  u32 nd = DIGESTS_CNT;                          // number of digests sharing this salt (handshakes to test)
  if (nd > WPA_HOOK_MAXD) nd = WPA_HOOK_MAXD;     // clamp to the fixed-size hook digest array capacity
  hooks[gid].ndig = nd;                          // tell the host how many digests it staged
  hooks[gid].ok   = 0;                           // clear the result bitmask; host sets a bit per matching SHA-384 row

  // Snapshot each digest's handshake data into the hook buffer for the CPU verifier to read.
  for (u32 dp = 0; dp < nd; dp++)
  {
    hooks[gid].dig[dp] = esalt_bufs[DIGESTS_OFFSET_HOST + dp];  // copy the whole esalt record (nonces, MACs, eapol, expected MIC/PMKID)
  }
}

// _comp: GPU-verify types {1..7} inline; for SHA-384 types {8..11} read the host-set bitmask. Report any crack.
KERNEL_FQ KERNEL_FA void m90007_comp (KERN_ATTR_TMPS_HOOKS_ESALT (wpa_pbkdf2_tmp_t, wpa_hook_t, wpa_universal_t))
{
  WPA_AES_SHARED                                 // alias the read-only constant-memory AES T-tables (s_te0..s_te4) for the AES-128-CMAC verifiers (types 5,7)

  const u64 gid = get_global_id (0);           // this work item's global index
  if (gid >= GID_CNT) return;                   // skip padding items beyond the candidate count

  u32 pmk[32];                                   // PMK buffer padded to the full SHA-384 HMAC block width (32 words)
  for (int i = 0; i < 32; i++) pmk[i] = 0;       // zero-pad so *_hmac_init can safely read the whole key block
  for (int i = 0; i <  8; i++) pmk[i] = tmps[gid].out[i];  // fill the real 32-byte PMK (8 big-endian words) from PBKDF2 output

  // Walk every digest under this salt; each may be a different one of the 11 types.
  for (u32 digest_pos = 0; digest_pos < DIGESTS_CNT; digest_pos++)
  {
    const u32 digest_cur = DIGESTS_OFFSET_HOST + digest_pos;  // absolute index into esalt_bufs / hashes_shown
    GLOBAL_AS const wpa_universal_t *wpa = &esalt_bufs[digest_cur];  // this digest's handshake/PMKID record

    int matched = 0;                             // per-digest verdict for this candidate
    switch (wpa->type)                           // dispatch by the 2-digit type code stored in the esalt
    {
      case 1: matched = wpa_check_eapol_md5        (pmk, wpa); break;  // WPA1 EAPOL: SHA-1 PTK KCK, MIC = HMAC-MD5
      case 2: matched = wpa_check_pmkid_sha1       (pmk, wpa); break;  // WPA2 PMKID: first 16 bytes of HMAC-SHA1(PMK,...)
      case 3: matched = wpa_check_eapol_sha1       (pmk, wpa); break;  // WPA2 EAPOL: SHA-1 PTK KCK, MIC = HMAC-SHA1-128
      case 4: matched = wpa_check_pmkid_sha256     (pmk, wpa); break;  // SHA-256 PMKID: first 16 bytes of HMAC-SHA256(PMK,...)
      case 5: matched = wpa_check_eapol_cmac256    (pmk, wpa, s_te0, s_te1, s_te2, s_te3, s_te4); break;  // SHA-256 KDF KCK, MIC = AES-128-CMAC
      case 6: matched = wpa_check_ft_pmkid_sha256  (pmk, wpa); break;  // FT PMKID = PMKR1Name via the SHA-256 FT key hierarchy
      case 7: matched = wpa_check_ft_eapol_cmac256 (pmk, wpa, s_te0, s_te1, s_te2, s_te3, s_te4); break;  // FT SHA-256 chain -> KCK, MIC = AES-128-CMAC
      default: // SHA-384 family {8..11}: not verified on GPU; result was computed on the host
        matched = (digest_pos < WPA_HOOK_MAXD) ? (int) ((hooks[gid].ok >> digest_pos) & 1) : 0;  // read this row's bit from the host bitmask (0 if beyond staged range)
        break;
    }

    if (matched)                                 // candidate cracks this digest
    {
      if (hc_atomic_inc (&hashes_shown[digest_cur]) == 0)  // claim it atomically; first claimer (was 0) reports it
      {
        mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, digest_pos, digest_cur, gid, 0, 0, 0);  // record the crack for output exactly once
      }
    }
  }
}
