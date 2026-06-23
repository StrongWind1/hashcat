/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 *
 * Plugin 90002: four AKM-family aux kernels, each with an internal switch(type)
 * dispatch. Splitting by family lets each aux kernel pull in only the hash/cipher
 * code it actually needs, keeping register/constant-memory pressure down.
 *   aux1: types 1,2,3   (MD5 / SHA-1)
 *   aux2: types 4,5     (SHA-256 / AES-CMAC)
 *   aux3: types 6,7     (FT SHA-256 / AES-CMAC)
 *   aux4: types 8,9,10,11 (SHA-384 flat + FT)
 * All crypto lives in inc_wpa_psk_universal.cl; this file is pure wiring.
 */

#define NEW_SIMD_CODE                                            // opt into hashcat's vectorised SIMD code path

#ifdef KERNEL_STATIC                                             // KERNEL_STATIC = building as a GPU/CPU device kernel
#include M2S(INCLUDE_PATH/inc_vendor.h)                          // vendor/arch detection macros (M2S resolves the include path token)
#include M2S(INCLUDE_PATH/inc_types.h)                           // core scalar/vector typedefs (u32, u32x, etc.)
#include M2S(INCLUDE_PATH/inc_platform.cl)                       // platform shims (atomics, address-space helpers)
#include M2S(INCLUDE_PATH/inc_common.cl)                         // shared helpers (mark_hash, byte-swap, etc.)
#include M2S(INCLUDE_PATH/inc_simd.cl)                           // SIMD pack/unpack across vector lanes
#include M2S(INCLUDE_PATH/inc_hash_md5.cl)                       // MD5 primitives (type 1 EAPOL MIC = HMAC-MD5)
#include M2S(INCLUDE_PATH/inc_hash_sha1.cl)                      // SHA-1 primitives (PBKDF2 PMK + type 2/3)
#include M2S(INCLUDE_PATH/inc_hash_sha256.cl)                    // SHA-256 primitives (types 4-7)
#include M2S(INCLUDE_PATH/inc_hash_sha384.cl)                    // SHA-384 primitives (types 8-11)
#include M2S(INCLUDE_PATH/inc_cipher_aes.cl)                     // AES (AES-128-CMAC EAPOL MIC for types 5,7)
#include M2S(INCLUDE_PATH/inc_wpa_psk_universal.cl)              // all WPA-PSK crypto + the WPA_* wiring macros
#else                                                            // else: compiling the same source as plain host C for CPU validation
#include "inc_vendor.h"                                          // same headers, plain relative include form for the host build
#include "inc_types.h"
#include "inc_platform.h"
#include "inc_common.h"
#include "inc_simd.h"
#include "inc_hash_md5.h"
#include "inc_hash_sha1.h"
#include "inc_hash_sha256.h"
#include "inc_hash_sha384.h"
#include "inc_cipher_aes.h"
#include "inc_wpa_psk_universal.cl"                              // crypto/wiring body is shared verbatim between device and host builds
#endif

// _init: seed the PBKDF2 state and run the first of the 4096 iterations.
KERNEL_FQ KERNEL_FA void m90002_init (KERN_ATTR_TMPS_ESALT (wpa_pbkdf2_tmp_t, wpa_universal_t))
{
  const u64 gid = get_global_id (0);                            // this work item's global index = which password candidate
  if (gid >= GID_CNT) return;                                   // skip padding work items past the real candidate count

  wpa_pbkdf2_init (pws, tmps, esalt_bufs, gid, DIGESTS_OFFSET_HOST); // load passphrase+ESSID, do iteration 1, store state in tmps[gid]
}

// _loop: the slow PBKDF2 inner loop, run LOOP_CNT iterations per invocation.
KERNEL_FQ KERNEL_FA void m90002_loop (KERN_ATTR_TMPS_ESALT (wpa_pbkdf2_tmp_t, wpa_universal_t))
{
  const u64 gid = get_global_id (0);                            // global index; here it addresses a vector of VECT_SIZE candidates
  if ((gid * VECT_SIZE) >= GID_CNT) return;                     // vectorised guard: skip if this whole SIMD group is past the end

  wpa_pbkdf2_loop (tmps, gid, LOOP_CNT);                        // crank LOOP_CNT more HMAC-SHA1 rounds; total 4096 across all calls
}

// _comp: deliberately empty -- all post-PMK verification is done by the aux kernels.
KERNEL_FQ KERNEL_FA void m90002_comp (KERN_ATTR_TMPS_ESALT (wpa_pbkdf2_tmp_t, wpa_universal_t))
{
  // empty: post-PMK work is in the aux kernels
}

// aux1: verify the MD5/SHA-1 family (types 1,2,3). No AES needed, so no T-tables loaded.
KERNEL_FQ KERNEL_FA void m90002_aux1 (KERN_ATTR_TMPS_ESALT (wpa_pbkdf2_tmp_t, wpa_universal_t))
{
  WPA_AUX_PROLOGUE                                              // resolve this digest, copy the finished PMK into a zero-padded register buffer

  int matched = 0;                                             // 0 = no crack yet for this candidate/digest pair

  switch (wpa->type)                                           // branch on the per-digest AKM type code from the esalt
  {
    case 1: matched = wpa_check_eapol_md5  (pmk, wpa); break;  // WPA1 EAPOL: SHA-1 PTK, MIC = HMAC-MD5(KCK, frame)
    case 2: matched = wpa_check_pmkid_sha1 (pmk, wpa); break;  // WPA2 PMKID: first 16 bytes of HMAC-SHA1(PMK, "PMK Name"||AP||STA)
    case 3: matched = wpa_check_eapol_sha1 (pmk, wpa); break;  // WPA2 EAPOL: SHA-1 PTK, MIC = HMAC-SHA1 truncated to 128 bits
  }

  WPA_MARK_IF (matched)                                        // if matched, report the crack to hashcat exactly once
}

// aux2: SHA-256 family (types 4,5). Type 5 uses AES-128-CMAC, so AES T-tables must be in scope.
KERNEL_FQ KERNEL_FA void m90002_aux2 (KERN_ATTR_TMPS_ESALT (wpa_pbkdf2_tmp_t, wpa_universal_t))
{
  WPA_AES_SHARED                                               // bring the AES encrypt T-tables (s_te0..s_te4) into scope for CMAC
  WPA_AUX_PROLOGUE                                             // resolve this digest and load the PMK into registers

  int matched = 0;                                            // crack flag for this candidate/digest pair

  switch (wpa->type)                                          // branch on the per-digest AKM type code
  {
    case 4: matched = wpa_check_pmkid_sha256 (pmk, wpa); break;                              // PMKID: first 16 bytes of HMAC-SHA256(PMK, ...)
    case 5: matched = wpa_check_eapol_cmac256 (pmk, wpa, s_te0, s_te1, s_te2, s_te3, s_te4); break; // EAPOL: SHA-256 KDF PTK, MIC = AES-128-CMAC(KCK, frame)
  }

  WPA_MARK_IF (matched)                                       // report the crack once if matched
}

// aux3: 802.11r SHA-256 FT family (types 6,7). Type 7 uses AES-128-CMAC, so AES T-tables are loaded.
KERNEL_FQ KERNEL_FA void m90002_aux3 (KERN_ATTR_TMPS_ESALT (wpa_pbkdf2_tmp_t, wpa_universal_t))
{
  WPA_AES_SHARED                                               // AES encrypt T-tables for the FT CMAC verifier
  WPA_AUX_PROLOGUE                                             // resolve this digest and load the PMK into registers

  int matched = 0;                                            // crack flag

  switch (wpa->type)                                          // branch on the per-digest AKM type code
  {
    case 6: matched = wpa_check_ft_pmkid_sha256 (pmk, wpa); break;                              // FT PMKID = PMKR1Name via the SHA-256 FT key hierarchy
    case 7: matched = wpa_check_ft_eapol_cmac256 (pmk, wpa, s_te0, s_te1, s_te2, s_te3, s_te4); break; // FT EAPOL: SHA-256 FT chain PTK, MIC = AES-128-CMAC
  }

  WPA_MARK_IF (matched)                                       // report the crack once if matched
}

// aux4: SHA-384 family (types 8-11, flat + FT). MIC here is HMAC-SHA384-192, not CMAC, so no AES T-tables.
KERNEL_FQ KERNEL_FA void m90002_aux4 (KERN_ATTR_TMPS_ESALT (wpa_pbkdf2_tmp_t, wpa_universal_t))
{
  WPA_AUX_PROLOGUE                                             // resolve this digest and load the PMK into registers

  int matched = 0;                                            // crack flag

  switch (wpa->type)                                          // branch on the per-digest AKM type code
  {
    case  8: matched = wpa_check_pmkid_sha384    (pmk, wpa); break; // PMKID: first 16 bytes of HMAC-SHA384(PMK, ...)
    case  9: matched = wpa_check_eapol_sha384    (pmk, wpa); break; // EAPOL: SHA-384 KDF PTK (24-byte KCK), MIC = HMAC-SHA384 truncated to 192 bits
    case 10: matched = wpa_check_ft_pmkid_sha384 (pmk, wpa); break; // FT PMKID = PMKR1Name via the SHA-384 FT key hierarchy
    case 11: matched = wpa_check_ft_eapol_sha384 (pmk, wpa); break; // FT EAPOL: SHA-384 FT chain PTK (24-byte KCK), MIC = HMAC-SHA384-192
  }

  WPA_MARK_IF (matched)                                       // report the crack once if matched
}
