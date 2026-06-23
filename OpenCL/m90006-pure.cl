/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 *
 * Bake-off plugin 90006 (config F): a single aux kernel holding one switch over
 * all 11 WPA-PSK types, run once per digest by the deep-comp dispatch path. This
 * isolates the cost of deep-comp dispatch (one kernel, one switch) versus the
 * sibling config that instead loops over digests inside _comp.
 */

#define NEW_SIMD_CODE                                  // opt into the vectorised SIMD code path for this kernel

#ifdef KERNEL_STATIC                                   // device build: pull headers through the include-path macro
#include M2S(INCLUDE_PATH/inc_vendor.h)                // vendor/arch detection (warp size, address-space qualifiers)
#include M2S(INCLUDE_PATH/inc_types.h)                 // u32/u64/u32x and the pw_t/salt_t/digest scratch types
#include M2S(INCLUDE_PATH/inc_platform.cl)             // platform shims (get_global_id, atomics, address spaces)
#include M2S(INCLUDE_PATH/inc_common.cl)               // shared helpers: byte swaps, mark_hash, packv/unpackv
#include M2S(INCLUDE_PATH/inc_simd.cl)                 // SIMD vector helpers for the vectorised PBKDF2 loop
#include M2S(INCLUDE_PATH/inc_hash_md5.cl)             // MD5 (little-endian) for the WPA1 EAPOL MIC
#include M2S(INCLUDE_PATH/inc_hash_sha1.cl)            // SHA-1 (big-endian) for PBKDF2/PMK, PMKID, WPA2 MIC
#include M2S(INCLUDE_PATH/inc_hash_sha256.cl)          // SHA-256 (big-endian) for SHA-256 PMKID/KDF and FT chain
#include M2S(INCLUDE_PATH/inc_hash_sha384.cl)          // SHA-384 (64-bit words) for SHA-384 PMKID/KDF and FT chain
#include M2S(INCLUDE_PATH/inc_cipher_aes.cl)           // AES-128 + T-tables for the AES-CMAC EAPOL MICs
#include M2S(INCLUDE_PATH/inc_wpa_psk_universal.cl)    // shared PBKDF2 init/loop + the 11 per-type verifiers and macros
#else                                                  // host (CPU-validation) build: include the plain header forms
#include "inc_vendor.h"                                // same headers as above, resolved as local C includes
#include "inc_types.h"
#include "inc_platform.h"
#include "inc_common.h"
#include "inc_simd.h"
#include "inc_hash_md5.h"
#include "inc_hash_sha1.h"
#include "inc_hash_sha256.h"
#include "inc_hash_sha384.h"
#include "inc_cipher_aes.h"
#include "inc_wpa_psk_universal.cl"                    // verifiers/macros are source-only, so include the .cl even on host
#endif

// _init: seed PBKDF2-HMAC-SHA1 state and run the very first of the 4096 iterations.
KERNEL_FQ KERNEL_FA void m90006_init (KERN_ATTR_TMPS_ESALT (wpa_pbkdf2_tmp_t, wpa_universal_t))
{
  const u64 gid = get_global_id (0);                   // this work item's global index = which password candidate
  if (gid >= GID_CNT) return;                          // skip padding work items past the real candidate count
  wpa_pbkdf2_init (pws, tmps, esalt_bufs, gid, DIGESTS_OFFSET_HOST); // hash pw+ESSID into tmps, doing iteration 1
}

// _loop: the slow part -- the remaining 4095 PBKDF2 SHA-1 iterations, vectorised.
KERNEL_FQ KERNEL_FA void m90006_loop (KERN_ATTR_TMPS_ESALT (wpa_pbkdf2_tmp_t, wpa_universal_t))
{
  const u64 gid = get_global_id (0);                   // global index; here it addresses a SIMD group of candidates
  if ((gid * VECT_SIZE) >= GID_CNT) return;            // bound by VECT_SIZE since each item processes a vector of pws
  wpa_pbkdf2_loop (tmps, gid, LOOP_CNT);               // advance the PBKDF2 inner loop by LOOP_CNT iterations
}

// _comp: empty -- the per-type comparison is done entirely by the aux kernel below.
KERNEL_FQ KERNEL_FA void m90006_comp (KERN_ATTR_TMPS_ESALT (wpa_pbkdf2_tmp_t, wpa_universal_t)) { }

// _aux1: deep-comp verifier -- invoked once per digest, derives keys from the PMK and matches.
KERNEL_FQ KERNEL_FA void m90006_aux1 (KERN_ATTR_TMPS_ESALT (wpa_pbkdf2_tmp_t, wpa_universal_t))
{
  WPA_AES_SHARED                                       // bind the AES T-tables (s_te0..s_te4) for the CMAC types 5 and 7
  WPA_AUX_PROLOGUE                                     // resolve gid/digest cursor and load the PMK zero-padded into pmk[32]

  int matched = 0;                                     // crack flag for this digest, set by the dispatched verifier
  WPA_DISPATCH_ONE (matched)                           // switch on wpa->type and run the one matching verifier
  WPA_MARK_IF (matched)                                // if it matched, report the crack exactly once via mark_hash
}
