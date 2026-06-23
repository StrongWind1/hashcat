/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 *
 * Bake-off plugin 90008 (config H): two aux kernels split on the 32-/64-bit
 * primitive boundary -- {1..7} (MD5/SHA1/SHA256/AES) vs {8..11} (SHA-384).
 * Isolates the occupancy cost of mixing SHA-384 with 32-bit primitives.
 */

#define NEW_SIMD_CODE                                   // opt into hashcat's vectorised SIMD code path

#ifdef KERNEL_STATIC                                    // device build: pull headers via the include-path macro
#include M2S(INCLUDE_PATH/inc_vendor.h)                 // vendor/arch detection and tuning knobs
#include M2S(INCLUDE_PATH/inc_types.h)                  // u32/u64/u32x and the kernel parameter structs
#include M2S(INCLUDE_PATH/inc_platform.cl)              // address-space + intrinsic shims per backend
#include M2S(INCLUDE_PATH/inc_common.cl)                // shared helpers (byte-swap, mark_hash, etc.)
#include M2S(INCLUDE_PATH/inc_simd.cl)                  // SIMD pack/unpack across vector lanes
#include M2S(INCLUDE_PATH/inc_hash_md5.cl)              // MD5 primitive (type 1 EAPOL MIC)
#include M2S(INCLUDE_PATH/inc_hash_sha1.cl)             // SHA-1 primitive (PBKDF2/PMK, types 2/3)
#include M2S(INCLUDE_PATH/inc_hash_sha256.cl)           // SHA-256 primitive (types 4..7)
#include M2S(INCLUDE_PATH/inc_hash_sha384.cl)           // SHA-384 primitive (types 8..11)
#include M2S(INCLUDE_PATH/inc_cipher_aes.cl)            // AES core for AES-128-CMAC MICs (types 5/7)
#include M2S(INCLUDE_PATH/inc_wpa_psk_universal.cl)     // the per-type WPA verifier library this kernel dispatches into
#else                                                   // host build (CPU validation): include plain headers
#include "inc_vendor.h"                                 // same vendor defs, host variant
#include "inc_types.h"                                  // same type defs, host variant
#include "inc_platform.h"                               // host stubs for the platform shims
#include "inc_common.h"                                 // host shared helpers
#include "inc_simd.h"                                   // host SIMD helpers (scalar lanes)
#include "inc_hash_md5.h"                               // MD5 declarations
#include "inc_hash_sha1.h"                              // SHA-1 declarations
#include "inc_hash_sha256.h"                            // SHA-256 declarations
#include "inc_hash_sha384.h"                            // SHA-384 declarations
#include "inc_cipher_aes.h"                             // AES declarations
#include "inc_wpa_psk_universal.cl"                     // WPA verifier library (shared source for host + device)
#endif

// _init: seed the per-workitem PBKDF2 state and run its first SHA-1 transform.
KERNEL_FQ KERNEL_FA void m90008_init (KERN_ATTR_TMPS_ESALT (wpa_pbkdf2_tmp_t, wpa_universal_t))
{
  const u64 gid = get_global_id (0);                    // this work item's global index
  if (gid >= GID_CNT) return;                           // skip padding items past the candidate count
  wpa_pbkdf2_init (pws, tmps, esalt_bufs, gid, DIGESTS_OFFSET_HOST); // load passphrase+ESSID, do PBKDF2 setup + first iteration
}

// _loop: the slow PBKDF2 inner loop; runs LOOP_CNT of the remaining 4095 iterations, vectorised.
KERNEL_FQ KERNEL_FA void m90008_loop (KERN_ATTR_TMPS_ESALT (wpa_pbkdf2_tmp_t, wpa_universal_t))
{
  const u64 gid = get_global_id (0);                    // this work item's global index
  if ((gid * VECT_SIZE) >= GID_CNT) return;             // bound by vector width since each item handles VECT_SIZE candidates
  wpa_pbkdf2_loop (tmps, gid, LOOP_CNT);                // advance the PBKDF2 state by LOOP_CNT iterations
}

// _comp: empty; the actual digest verification is done entirely by the aux kernels below.
KERNEL_FQ KERNEL_FA void m90008_comp (KERN_ATTR_TMPS_ESALT (wpa_pbkdf2_tmp_t, wpa_universal_t)) { }

// 32-bit-primitive family {1..7}: MD5 / SHA-1 / SHA-256 / AES-CMAC.
KERNEL_FQ KERNEL_FA void m90008_aux1 (KERN_ATTR_TMPS_ESALT (wpa_pbkdf2_tmp_t, wpa_universal_t))
{
  WPA_AES_SHARED                                        // alias the read-only constant-memory AES T-tables (s_te0..s_te4) for the AES-128-CMAC types (5,7)
  WPA_AUX_PROLOGUE                                      // gather gid, the finished PMK, the esalt handshake, and bail on padding

  int matched = 0;                                      // verdict: nonzero once a verifier confirms this candidate
  switch (wpa->type)                                    // dispatch on the per-AKM type code carried in the esalt
  {
    case 1: matched = wpa_check_eapol_md5        (pmk, wpa); break;                                  // WPA1: SHA-1 PTK, MIC = HMAC-MD5(KCK)
    case 2: matched = wpa_check_pmkid_sha1       (pmk, wpa); break;                                  // WPA2 PMKID: first 16B of HMAC-SHA1(PMK, "PMK Name"||AP||STA)
    case 3: matched = wpa_check_eapol_sha1       (pmk, wpa); break;                                  // WPA2: SHA-1 PTK, MIC = HMAC-SHA1 truncated to 128 bits
    case 4: matched = wpa_check_pmkid_sha256     (pmk, wpa); break;                                  // SHA-256 PMKID: first 16B of HMAC-SHA256(PMK, ...)
    case 5: matched = wpa_check_eapol_cmac256    (pmk, wpa, s_te0, s_te1, s_te2, s_te3, s_te4); break; // SHA-256 KDF PTK, MIC = AES-128-CMAC(KCK) over staged tables
    case 6: matched = wpa_check_ft_pmkid_sha256  (pmk, wpa); break;                                  // 802.11r SHA-256 PMKR1Name used as the PMKID
    case 7: matched = wpa_check_ft_eapol_cmac256 (pmk, wpa, s_te0, s_te1, s_te2, s_te3, s_te4); break; // FT SHA-256 PTK, MIC = AES-128-CMAC(KCK)
  }
  WPA_MARK_IF (matched)                                 // report the crack once if matched, via mark_hash + atomic bookkeeping
}

// SHA-384 family {8..11} (flat + FT).
KERNEL_FQ KERNEL_FA void m90008_aux2 (KERN_ATTR_TMPS_ESALT (wpa_pbkdf2_tmp_t, wpa_universal_t))
{
  WPA_AUX_PROLOGUE                                      // gather gid, PMK, esalt and bail on padding (no AES tables needed here)

  int matched = 0;                                      // verdict flag for the SHA-384 verifiers
  switch (wpa->type)                                    // dispatch on the per-AKM type code
  {
    case  8: matched = wpa_check_pmkid_sha384    (pmk, wpa); break;                                  // SHA-384 PMKID: first 16B of HMAC-SHA384(PMK, ...)
    case  9: matched = wpa_check_eapol_sha384    (pmk, wpa); break;                                  // SHA-384 KDF -> 24B KCK, MIC = HMAC-SHA384 truncated to 192 bits
    case 10: matched = wpa_check_ft_pmkid_sha384 (pmk, wpa); break;                                  // FT SHA-384 PMKR1Name used as the PMKID
    case 11: matched = wpa_check_ft_eapol_sha384 (pmk, wpa); break;                                  // FT SHA-384 PTK -> 24B KCK, MIC = HMAC-SHA384-192
  }
  WPA_MARK_IF (matched)                                 // report the crack once if matched
}
