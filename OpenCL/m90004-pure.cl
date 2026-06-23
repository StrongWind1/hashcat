/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 *
 * Bake-off plugin 90004 (config D): the two verifier kernels are split by attack
 * surface -- one handles the PMKID hash types {2,4,6,8,10}, the other the EAPOL/MIC
 * hash types {1,3,5,7,9,11}, so only the EAPOL kernel pays for the AES tables.
 */

#define NEW_SIMD_CODE                                 // opt into the vectorised SIMD code path for _loop

#ifdef KERNEL_STATIC                                  // device build: pull headers via the include-path macro
#include M2S(INCLUDE_PATH/inc_vendor.h)               // vendor/arch tunables (vector width, etc.)
#include M2S(INCLUDE_PATH/inc_types.h)                // u32/u64/u32x and core kernel typedefs
#include M2S(INCLUDE_PATH/inc_platform.cl)            // address-space + atomic shims across OpenCL/CUDA
#include M2S(INCLUDE_PATH/inc_common.cl)              // shared helpers (byte swap, mark_hash, ...)
#include M2S(INCLUDE_PATH/inc_simd.cl)                // SIMD pack/unpack across lanes
#include M2S(INCLUDE_PATH/inc_hash_md5.cl)            // MD5 (type 1 EAPOL MIC)
#include M2S(INCLUDE_PATH/inc_hash_sha1.cl)           // SHA-1 (PBKDF2 PMK, type 2/3)
#include M2S(INCLUDE_PATH/inc_hash_sha256.cl)         // SHA-256 (types 4/5/6/7)
#include M2S(INCLUDE_PATH/inc_hash_sha384.cl)         // SHA-384 (types 8/9/10/11)
#include M2S(INCLUDE_PATH/inc_cipher_aes.cl)          // AES core for the AES-128-CMAC MIC (types 5/7)
#include M2S(INCLUDE_PATH/inc_wpa_psk_universal.cl)   // the shared verifiers and aux-kernel wiring macros
#else                                                 // host build: same headers by plain relative name
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

// _init: seed the PBKDF2-HMAC-SHA1 state that derives the 32-byte WPA PMK.
KERNEL_FQ KERNEL_FA void m90004_init (KERN_ATTR_TMPS_ESALT (wpa_pbkdf2_tmp_t, wpa_universal_t))
{
  const u64 gid = get_global_id (0);                  // this work item's global index
  if (gid >= GID_CNT) return;                         // drop padding items past the candidate count
  wpa_pbkdf2_init (pws, tmps, esalt_bufs, gid, DIGESTS_OFFSET_HOST); // run the first PBKDF2 transform, store state in tmps
}

// _loop: the slow part -- the remaining 4096-1 PBKDF2 iterations, vectorised over SIMD lanes.
KERNEL_FQ KERNEL_FA void m90004_loop (KERN_ATTR_TMPS_ESALT (wpa_pbkdf2_tmp_t, wpa_universal_t))
{
  const u64 gid = get_global_id (0);                  // this work item's global index
  if ((gid * VECT_SIZE) >= GID_CNT) return;           // each item covers VECT_SIZE candidates; bound the last group
  wpa_pbkdf2_loop (tmps, gid, LOOP_CNT);              // advance the PBKDF2 inner loop by LOOP_CNT iterations
}

// _comp: nothing to do -- the aux kernels below perform the actual verification.
KERNEL_FQ KERNEL_FA void m90004_comp (KERN_ATTR_TMPS_ESALT (wpa_pbkdf2_tmp_t, wpa_universal_t)) { }

// aux1: PMKID surface (even types). PMKID = first 16 bytes of an HMAC over "PMK Name"||AP||STA; no AES needed.
KERNEL_FQ KERNEL_FA void m90004_aux1 (KERN_ATTR_TMPS_ESALT (wpa_pbkdf2_tmp_t, wpa_universal_t))
{
  WPA_AUX_PROLOGUE                                     // bind gid/digest cursor + load PMK zero-padded to a full HMAC block

  int matched = 0;                                     // becomes nonzero when this digest's PMKID matches
  switch (wpa->type)                                   // dispatch by the per-digest WPA hash-type code
  {
    case  2: matched = wpa_check_pmkid_sha1      (pmk, wpa); break; // WPA2 PMKID via HMAC-SHA1
    case  4: matched = wpa_check_pmkid_sha256    (pmk, wpa); break; // PMKID via HMAC-SHA256
    case  6: matched = wpa_check_ft_pmkid_sha256 (pmk, wpa); break; // 802.11r PMKR1Name via SHA-256 FT hierarchy
    case  8: matched = wpa_check_pmkid_sha384    (pmk, wpa); break; // PMKID via HMAC-SHA384
    case 10: matched = wpa_check_ft_pmkid_sha384 (pmk, wpa); break; // PMKR1Name via SHA-384 FT hierarchy
  }
  WPA_MARK_IF (matched)                                // report the crack exactly once if matched
}

// aux2: EAPOL/MIC surface (odd types). Verifies the keyed MIC over the EAPOL-Key frame; types 5/7 need AES.
KERNEL_FQ KERNEL_FA void m90004_aux2 (KERN_ATTR_TMPS_ESALT (wpa_pbkdf2_tmp_t, wpa_universal_t))
{
  WPA_AES_SHARED                                       // expose the AES T-tables required by the AES-128-CMAC types
  WPA_AUX_PROLOGUE                                     // bind gid/digest cursor + load PMK zero-padded to a full HMAC block

  int matched = 0;                                     // becomes nonzero when this digest's EAPOL MIC matches
  switch (wpa->type)                                   // dispatch by the per-digest WPA hash-type code
  {
    case  1: matched = wpa_check_eapol_md5        (pmk, wpa); break; // WPA1: SHA1-PRF PTK, MIC = HMAC-MD5
    case  3: matched = wpa_check_eapol_sha1       (pmk, wpa); break; // WPA2: SHA1-PRF PTK, MIC = HMAC-SHA1-128
    case  5: matched = wpa_check_eapol_cmac256    (pmk, wpa, s_te0, s_te1, s_te2, s_te3, s_te4); break; // SHA-256 KDF PTK, MIC = AES-128-CMAC
    case  7: matched = wpa_check_ft_eapol_cmac256 (pmk, wpa, s_te0, s_te1, s_te2, s_te3, s_te4); break; // SHA-256 FT chain PTK, MIC = AES-128-CMAC
    case  9: matched = wpa_check_eapol_sha384     (pmk, wpa); break; // SHA-384 KDF PTK, MIC = HMAC-SHA384-192
    case 11: matched = wpa_check_ft_eapol_sha384  (pmk, wpa); break; // SHA-384 FT chain PTK, MIC = HMAC-SHA384-192
  }
  WPA_MARK_IF (matched)                                // report the crack exactly once if matched
}
