/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 *
 * Bake-off plugin 90009 (config I): three aux kernels grouped by crypto cost tier --
 * {1,2,3} use MD5/SHA-1, {4,5,6,7} use SHA-256 (flat PMKID/EAPOL plus the FT key
 * hierarchy and AES-CMAC), {8,9,10,11} use SHA-384. This grouping sits midway between
 * coarse single-dispatch variants and fully per-type-split variants.
 */

#define NEW_SIMD_CODE                               // opt in to the vectorised SIMD kernel macros

#ifdef KERNEL_STATIC                                // device build: pull headers via the include-path macro
#include M2S(INCLUDE_PATH/inc_vendor.h)             // vendor/arch detection and qualifier defines
#include M2S(INCLUDE_PATH/inc_types.h)              // core scalar/vector type aliases (u32, u32x, ...)
#include M2S(INCLUDE_PATH/inc_platform.cl)          // platform shims (atomics, address-space helpers)
#include M2S(INCLUDE_PATH/inc_common.cl)            // shared helpers (byte swaps, packv/unpackv, mark_hash)
#include M2S(INCLUDE_PATH/inc_simd.cl)              // SIMD lane gather/scatter machinery
#include M2S(INCLUDE_PATH/inc_hash_md5.cl)          // MD5 primitive: needed for type 1 EAPOL MIC
#include M2S(INCLUDE_PATH/inc_hash_sha1.cl)         // SHA-1 primitive: PBKDF2 PMK + types 2/3
#include M2S(INCLUDE_PATH/inc_hash_sha256.cl)       // SHA-256 primitive: types 4/5/6/7
#include M2S(INCLUDE_PATH/inc_hash_sha384.cl)       // SHA-384 primitive: types 8/9/10/11
#include M2S(INCLUDE_PATH/inc_cipher_aes.cl)        // AES core: backs the AES-128-CMAC MIC for types 5/7
#include M2S(INCLUDE_PATH/inc_wpa_psk_universal.cl) // all the wpa_check_* verifiers and shared macros
#else                                               // host build: include the same headers by plain name
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
#include "inc_wpa_psk_universal.cl"                 // verifiers compiled as host C for CPU validation
#endif

// _init: seed PBKDF2-HMAC-SHA1 state per password candidate (one PMK derivation begins here).
KERNEL_FQ KERNEL_FA void m90009_init (KERN_ATTR_TMPS_ESALT (wpa_pbkdf2_tmp_t, wpa_universal_t))
{
  const u64 gid = get_global_id (0);               // this work item's global index
  if (gid >= GID_CNT) return;                       // skip padding items past the real candidate count
  wpa_pbkdf2_init (pws, tmps, esalt_bufs, gid, DIGESTS_OFFSET_HOST); // run the first of 4096 PBKDF2 iterations and store state in tmps
}

// _loop: the heavy 4096-iteration PBKDF2 inner loop; vectorised, the slow part of cracking.
KERNEL_FQ KERNEL_FA void m90009_loop (KERN_ATTR_TMPS_ESALT (wpa_pbkdf2_tmp_t, wpa_universal_t))
{
  const u64 gid = get_global_id (0);               // global index of this SIMD work item
  if ((gid * VECT_SIZE) >= GID_CNT) return;         // bounds check across all VECT_SIZE lanes this item owns
  wpa_pbkdf2_loop (tmps, gid, LOOP_CNT);            // perform LOOP_CNT more PBKDF2 iterations, updating tmps in place
}

// _comp: empty -- final verification is done entirely by the aux kernels below.
KERNEL_FQ KERNEL_FA void m90009_comp (KERN_ATTR_TMPS_ESALT (wpa_pbkdf2_tmp_t, wpa_universal_t)) { }

// tier 1 aux: lowest-cost crypto -- WPA1 (MD5 MIC) and WPA2 (SHA-1 PMKID/MIC).
KERNEL_FQ KERNEL_FA void m90009_aux1 (KERN_ATTR_TMPS_ESALT (wpa_pbkdf2_tmp_t, wpa_universal_t))
{
  WPA_AUX_PROLOGUE                                  // bounds-check gid, load the finished PMK and the per-digest handshake (wpa)

  int matched = 0;                                  // accumulates whether this candidate cracked the digest
  switch (wpa->type)                                // dispatch on the per-digest type code (PMKID vs EAPOL, family)
  {
    case 1: matched = wpa_check_eapol_md5  (pmk, wpa); break; // WPA1: PRF-SHA1 PTK -> KCK, MIC = HMAC-MD5(KCK, eapol)
    case 2: matched = wpa_check_pmkid_sha1 (pmk, wpa); break; // WPA2 PMKID: first 16 bytes of HMAC-SHA1(PMK, "PMK Name"||AP||STA)
    case 3: matched = wpa_check_eapol_sha1 (pmk, wpa); break; // WPA2: PRF-SHA1 PTK -> KCK, MIC = HMAC-SHA1 truncated to 128 bits
  }
  WPA_MARK_IF (matched)                             // report the crack once via mark_hash if matched
}

// tier 2 aux: SHA-256 family -- flat PMKID/EAPOL plus the FT roaming hierarchy; uses AES-CMAC.
KERNEL_FQ KERNEL_FA void m90009_aux2 (KERN_ATTR_TMPS_ESALT (wpa_pbkdf2_tmp_t, wpa_universal_t))
{
  WPA_AES_SHARED                                    // alias the read-only constant-memory AES T-tables (s_te0..s_te4) for the AES-128-CMAC path
  WPA_AUX_PROLOGUE                                  // bounds-check gid, load the finished PMK and this digest's handshake/esalt

  int matched = 0;                                  // crack flag for this candidate/digest
  switch (wpa->type)                                // dispatch within the SHA-256 tier
  {
    case 4: matched = wpa_check_pmkid_sha256     (pmk, wpa); break;                          // first 16 bytes of HMAC-SHA256(PMK, "PMK Name"||AP||STA)
    case 5: matched = wpa_check_eapol_cmac256    (pmk, wpa, s_te0, s_te1, s_te2, s_te3, s_te4); break; // KDF-SHA256 PTK -> KCK, MIC = AES-128-CMAC(KCK, eapol)
    case 6: matched = wpa_check_ft_pmkid_sha256  (pmk, wpa); break;                          // 802.11r fast-roaming PMKR1Name via the SHA-256 FT chain
    case 7: matched = wpa_check_ft_eapol_cmac256 (pmk, wpa, s_te0, s_te1, s_te2, s_te3, s_te4); break; // FT SHA-256 chain -> FT-PTK -> KCK, MIC = AES-128-CMAC
  }
  WPA_MARK_IF (matched)                             // report the crack once if matched
}

// tier 3 aux: SHA-384 family -- flat PMKID/EAPOL plus the SHA-384 FT hierarchy; 24-byte KCK.
KERNEL_FQ KERNEL_FA void m90009_aux3 (KERN_ATTR_TMPS_ESALT (wpa_pbkdf2_tmp_t, wpa_universal_t))
{
  WPA_AUX_PROLOGUE                                  // bounds-check gid, load PMK and handshake (no AES table needed for this tier)

  int matched = 0;                                  // crack flag for this candidate/digest
  switch (wpa->type)                                // dispatch within the SHA-384 tier
  {
    case  8: matched = wpa_check_pmkid_sha384    (pmk, wpa); break; // first 16 bytes of HMAC-SHA384(PMK, "PMK Name"||AP||STA)
    case  9: matched = wpa_check_eapol_sha384    (pmk, wpa); break; // KDF-SHA384 PTK -> 24-byte KCK, MIC = HMAC-SHA384 truncated to 192 bits
    case 10: matched = wpa_check_ft_pmkid_sha384 (pmk, wpa); break; // FT PMKR1Name via the SHA-384 FT hierarchy (FT name hashes use SHA-384)
    case 11: matched = wpa_check_ft_eapol_sha384 (pmk, wpa); break; // FT SHA-384 chain -> FT-PTK -> 24-byte KCK, MIC = HMAC-SHA384-192
  }
  WPA_MARK_IF (matched)                             // report the crack once if matched
}
