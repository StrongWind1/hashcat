/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 *
 * Plugin 90001 (config A): one monolithic _comp kernel does all verification.
 * It loops every digest under the salt and switch()es on the per-digest type,
 * dispatching to the matching WPA-PSK verifier -- no separate aux kernels.
 * Trades minimal kernel count for higher register/branch pressure in _comp.
 */

#define NEW_SIMD_CODE                                       // opt into the vectorised SIMD code paths in the shared headers

// Two include flavours: device builds (KERNEL_STATIC) pull the .cl sources via
// the INCLUDE_PATH macro; host/CPU builds pull the plain .h declarations so the
// same kernel compiles as ordinary C for the CPU-validation modes.
#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)                     // vendor/arch detection macros
#include M2S(INCLUDE_PATH/inc_types.h)                      // u32/u64 and core hashcat types
#include M2S(INCLUDE_PATH/inc_platform.cl)                  // atomics, global-id, platform shims
#include M2S(INCLUDE_PATH/inc_common.cl)                    // mark_hash and shared helpers
#include M2S(INCLUDE_PATH/inc_simd.cl)                      // SIMD vector helpers (packv/unpackv etc.)
#include M2S(INCLUDE_PATH/inc_hash_md5.cl)                  // MD5 (type 1 MIC)
#include M2S(INCLUDE_PATH/inc_hash_sha1.cl)                 // SHA-1 (PBKDF2, type 2/3 paths)
#include M2S(INCLUDE_PATH/inc_hash_sha256.cl)               // SHA-256 (type 4/5/6/7 paths)
#include M2S(INCLUDE_PATH/inc_hash_sha384.cl)               // SHA-384 (type 8/9/10/11 paths)
#include M2S(INCLUDE_PATH/inc_cipher_aes.cl)                // AES for the CMAC MIC (types 5,7)
#include M2S(INCLUDE_PATH/inc_wpa_psk_universal.cl)         // shared PBKDF2 + all 11 verifiers + dispatch macros
#else
#include "inc_vendor.h"                                     // host-build counterparts: declarations only
#include "inc_types.h"
#include "inc_platform.h"
#include "inc_common.h"
#include "inc_simd.h"
#include "inc_hash_md5.h"
#include "inc_hash_sha1.h"
#include "inc_hash_sha256.h"
#include "inc_hash_sha384.h"
#include "inc_cipher_aes.h"
#include "inc_wpa_psk_universal.cl"                         // verifier bodies are .cl even on host (header-only)
#endif

// _init: seed the PBKDF2 state. Runs the first of the 4096 HMAC-SHA1 iterations
// for both PBKDF2 output blocks so _loop only has to grind the remaining 4095.
KERNEL_FQ KERNEL_FA void m90001_init (KERN_ATTR_TMPS_ESALT (wpa_pbkdf2_tmp_t, wpa_universal_t))
{
  const u64 gid = get_global_id (0);                        // this work item = one password candidate
  if (gid >= GID_CNT) return;                               // drop the over-launched tail items
  wpa_pbkdf2_init (pws, tmps, esalt_bufs, gid, DIGESTS_OFFSET_HOST); // build PBKDF2 inner/outer state, ESSID salt -> tmps
}

// _loop: the slow inner loop. Each call grinds LOOP_CNT of the PBKDF2 iterations;
// hashcat invokes it repeatedly until 4096 total are done, then the PMK is in tmps.
KERNEL_FQ KERNEL_FA void m90001_loop (KERN_ATTR_TMPS_ESALT (wpa_pbkdf2_tmp_t, wpa_universal_t))
{
  const u64 gid = get_global_id (0);                        // this SIMD work item
  if ((gid * VECT_SIZE) >= GID_CNT) return;                 // scale guard by vector width since each item covers VECT_SIZE candidates
  wpa_pbkdf2_loop (tmps, gid, LOOP_CNT);                    // advance the PBKDF2 state by LOOP_CNT iterations
}

// _comp: the entire verifier. With the PMK derived, test it against every digest
// under this salt, dispatching by type, and report any crack.
KERNEL_FQ KERNEL_FA void m90001_comp (KERN_ATTR_TMPS_ESALT (wpa_pbkdf2_tmp_t, wpa_universal_t))
{
  WPA_AES_SHARED                                            // expose AES T-tables (s_te0..s_te4) for the CMAC verifiers (types 5,7)

  const u64 gid = get_global_id (0);                        // this work item = one candidate's finished PMK
  if (gid >= GID_CNT) return;                               // drop the over-launched tail items

  u32 pmk[32];                                              // PMK buffer sized to a full SHA-384 HMAC block (32 u32)
  for (int wi = 0; wi < 32; wi++) pmk[wi] = 0;              // zero-pad: HMAC init reads the whole key block, so unused words must be 0
  pmk[0] = tmps[gid].out[0]; pmk[1] = tmps[gid].out[1];     // copy the 32-byte PMK (8 u32 words) out of PBKDF2 scratch
  pmk[2] = tmps[gid].out[2]; pmk[3] = tmps[gid].out[3];
  pmk[4] = tmps[gid].out[4]; pmk[5] = tmps[gid].out[5];
  pmk[6] = tmps[gid].out[6]; pmk[7] = tmps[gid].out[7];

  // The same PMK can satisfy many digests, so test it against each one in turn.
  for (u32 digest_pos = 0; digest_pos < DIGESTS_CNT; digest_pos++)
  {
    const u32 digest_cur = DIGESTS_OFFSET_HOST + digest_pos; // absolute digest index = salt's first digest + offset
    GLOBAL_AS const wpa_universal_t *wpa = &esalt_bufs[digest_cur]; // this digest's handshake data (MACs, nonces, type, target)

    int matched = 0;                                        // per-digest verdict flag
    WPA_DISPATCH_ONE (matched)                              // switch on wpa->type, run the right verifier, set matched
    WPA_MARK_IF (matched)                                   // on a hit, atomically report the crack exactly once
  }
}
