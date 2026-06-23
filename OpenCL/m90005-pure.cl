/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 *
 * Bake-off plugin 90005 (config E): eleven per-type aux kernels, one verifier
 * each, zero internal branch -- the divergence-elimination design. Each work
 * item runs exactly one straight-line check with no type switch, so all lanes
 * follow the same path. This needs extra aux slots (aux5..aux11) wired into the
 * core dispatcher; other configs reuse only the standard aux1..aux4 slots.
 */

#define NEW_SIMD_CODE                                  // opt into the vectorised SIMD code paths in the shared headers

#ifdef KERNEL_STATIC                                   // device build: pull headers through the include-path macro
#include M2S(INCLUDE_PATH/inc_vendor.h)                // vendor/arch quirks and feature switches
#include M2S(INCLUDE_PATH/inc_types.h)                 // u32/u64/vector typedefs and the kernel attribute structs
#include M2S(INCLUDE_PATH/inc_platform.cl)             // platform shims (atomics, get_global_id, address spaces)
#include M2S(INCLUDE_PATH/inc_common.cl)               // common helpers (mark_hash, packv/unpackv, byte-swap)
#include M2S(INCLUDE_PATH/inc_simd.cl)                 // SIMD vector load/store helpers
#include M2S(INCLUDE_PATH/inc_hash_md5.cl)             // MD5 (little-endian) for the WPA1 EAPOL MIC
#include M2S(INCLUDE_PATH/inc_hash_sha1.cl)            // SHA-1 for PBKDF2/PMK, PMKID, and WPA2 PTK/MIC
#include M2S(INCLUDE_PATH/inc_hash_sha256.cl)          // SHA-256 for the 256-bit KDF, PMKID, and FT hierarchy
#include M2S(INCLUDE_PATH/inc_hash_sha384.cl)          // SHA-384 for the 384-bit KDF, PMKID, and FT hierarchy
#include M2S(INCLUDE_PATH/inc_cipher_aes.cl)           // AES primitives backing AES-128-CMAC for types 5/7
#include M2S(INCLUDE_PATH/inc_wpa_psk_universal.cl)    // the shared WPA verifier library this plugin dispatches into
#else                                                  // host (CPU-validation) build: include the plain headers
#include "inc_vendor.h"                                // same headers as above, resolved as ordinary C includes
#include "inc_types.h"
#include "inc_platform.h"
#include "inc_common.h"
#include "inc_simd.h"
#include "inc_hash_md5.h"
#include "inc_hash_sha1.h"
#include "inc_hash_sha256.h"
#include "inc_hash_sha384.h"
#include "inc_cipher_aes.h"
#include "inc_wpa_psk_universal.cl"                    // verifier library is shared verbatim between device and host
#endif

// _init: seed the per-work-item PBKDF2 state and run the first of the 4096 SHA-1 iterations.
KERNEL_FQ KERNEL_FA void m90005_init (KERN_ATTR_TMPS_ESALT (wpa_pbkdf2_tmp_t, wpa_universal_t))
{
  const u64 gid = get_global_id (0);                   // index of this candidate among all work items
  if (gid >= GID_CNT) return;                          // drop the padding lanes past the real candidate count
  wpa_pbkdf2_init (pws, tmps, esalt_bufs, gid, DIGESTS_OFFSET_HOST);  // set up PBKDF2(passphrase,ESSID); does iteration 1
}

// _loop: the slow part -- the remaining PBKDF2-HMAC-SHA1 iterations, run vectorised across SIMD lanes.
KERNEL_FQ KERNEL_FA void m90005_loop (KERN_ATTR_TMPS_ESALT (wpa_pbkdf2_tmp_t, wpa_universal_t))
{
  const u64 gid = get_global_id (0);                   // SIMD-group index for this work item
  if ((gid * VECT_SIZE) >= GID_CNT) return;            // guard: scale by vector width since each lane is one candidate
  wpa_pbkdf2_loop (tmps, gid, LOOP_CNT);               // advance LOOP_CNT iterations of the 4095 remaining; PMK lands in tmps.out
}

// _comp: empty -- the per-type aux kernels do all verification, so there is no final compare here.
KERNEL_FQ KERNEL_FA void m90005_comp (KERN_ATTR_TMPS_ESALT (wpa_pbkdf2_tmp_t, wpa_universal_t)) { }

// aux1 / type 1 WPA1-PSK-EAPOL: legacy SHA-1 PRF PTK, MIC = HMAC-MD5(KCK, eapol).
KERNEL_FQ KERNEL_FA void m90005_aux1 (KERN_ATTR_TMPS_ESALT (wpa_pbkdf2_tmp_t, wpa_universal_t))   // type 1
{
  WPA_AUX_PROLOGUE                                      // load gid/PMK/esalt and bail on padding lanes
  int matched = wpa_check_eapol_md5 (pmk, wpa);         // derive PTK, recompute the MD5 MIC, compare to the captured one
  WPA_MARK_IF (matched)                                 // report the crack exactly once if the MIC matched
}

// aux2 / type 2 WPA2-PSK-PMKID: PMKID = first 16 bytes of HMAC-SHA1(PMK, "PMK Name"||AP||STA).
KERNEL_FQ KERNEL_FA void m90005_aux2 (KERN_ATTR_TMPS_ESALT (wpa_pbkdf2_tmp_t, wpa_universal_t))   // type 2
{
  WPA_AUX_PROLOGUE                                      // load gid/PMK/esalt and bail on padding lanes
  int matched = wpa_check_pmkid_sha1 (pmk, wpa);        // recompute the SHA-1 PMKID and compare to the captured one
  WPA_MARK_IF (matched)                                 // report the crack if the PMKID matched
}

// aux3 / type 3 WPA2-PSK-EAPOL: SHA-1 PRF PTK, MIC = HMAC-SHA1 truncated to 128 bits.
KERNEL_FQ KERNEL_FA void m90005_aux3 (KERN_ATTR_TMPS_ESALT (wpa_pbkdf2_tmp_t, wpa_universal_t))   // type 3
{
  WPA_AUX_PROLOGUE                                      // load gid/PMK/esalt and bail on padding lanes
  int matched = wpa_check_eapol_sha1 (pmk, wpa);        // derive PTK, recompute the truncated SHA-1 MIC, compare
  WPA_MARK_IF (matched)                                 // report the crack if the MIC matched
}

// aux4 / type 4 PSK-SHA256-PMKID: PMKID = first 16 bytes of HMAC-SHA256(PMK, "PMK Name"||AP||STA).
KERNEL_FQ KERNEL_FA void m90005_aux4 (KERN_ATTR_TMPS_ESALT (wpa_pbkdf2_tmp_t, wpa_universal_t))   // type 4
{
  WPA_AUX_PROLOGUE                                      // load gid/PMK/esalt and bail on padding lanes
  int matched = wpa_check_pmkid_sha256 (pmk, wpa);      // recompute the SHA-256 PMKID and compare to the captured one
  WPA_MARK_IF (matched)                                 // report the crack if the PMKID matched
}

// aux5 / type 5 PSK-SHA256-EAPOL: SHA-256 KDF PTK, MIC = AES-128-CMAC(KCK, eapol) -- needs the AES tables.
KERNEL_FQ KERNEL_FA void m90005_aux5 (KERN_ATTR_TMPS_ESALT (wpa_pbkdf2_tmp_t, wpa_universal_t))   // type 5
{
  WPA_AES_SHARED                                        // alias the read-only constant-memory AES T-tables (s_te0..s_te4) for the AES-128-CMAC verifier
  WPA_AUX_PROLOGUE                                      // load gid/PMK/esalt and bail on padding lanes
  int matched = wpa_check_eapol_cmac256 (pmk, wpa, s_te0, s_te1, s_te2, s_te3, s_te4);  // SHA-256 PTK, AES-CMAC MIC, compare
  WPA_MARK_IF (matched)                                 // report the crack if the MIC matched
}

// aux6 / type 6 FT-PSK-PMKID: 802.11r PMKR1Name through the SHA-256 FT key hierarchy.
KERNEL_FQ KERNEL_FA void m90005_aux6 (KERN_ATTR_TMPS_ESALT (wpa_pbkdf2_tmp_t, wpa_universal_t))   // type 6
{
  WPA_AUX_PROLOGUE                                      // load gid/PMK/esalt and bail on padding lanes
  int matched = wpa_check_ft_pmkid_sha256 (pmk, wpa);   // walk PMK->PMK-R0->PMK-R1, recompute PMKR1Name, compare
  WPA_MARK_IF (matched)                                 // report the crack if the FT PMKID matched
}

// aux7 / type 7 FT-PSK-EAPOL: SHA-256 FT chain -> FT-PTK, MIC = AES-128-CMAC -- needs the AES tables.
KERNEL_FQ KERNEL_FA void m90005_aux7 (KERN_ATTR_TMPS_ESALT (wpa_pbkdf2_tmp_t, wpa_universal_t))   // type 7
{
  WPA_AES_SHARED                                        // alias the read-only constant-memory AES T-tables (s_te0..s_te4) for the AES-128-CMAC verifier
  WPA_AUX_PROLOGUE                                      // load gid/PMK/esalt and bail on padding lanes
  int matched = wpa_check_ft_eapol_cmac256 (pmk, wpa, s_te0, s_te1, s_te2, s_te3, s_te4);  // FT-PTK, AES-CMAC MIC, compare
  WPA_MARK_IF (matched)                                 // report the crack if the MIC matched
}

// aux8 / type 8 PSK-SHA384-PMKID: PMKID = first 16 bytes of HMAC-SHA384(PMK, "PMK Name"||AP||STA).
KERNEL_FQ KERNEL_FA void m90005_aux8 (KERN_ATTR_TMPS_ESALT (wpa_pbkdf2_tmp_t, wpa_universal_t))   // type 8
{
  WPA_AUX_PROLOGUE                                      // load gid/PMK/esalt and bail on padding lanes
  int matched = wpa_check_pmkid_sha384 (pmk, wpa);      // recompute the SHA-384 PMKID and compare to the captured one
  WPA_MARK_IF (matched)                                 // report the crack if the PMKID matched
}

// aux9 / type 9 PSK-SHA384-EAPOL: SHA-384 KDF PTK (24-byte KCK), MIC = HMAC-SHA384 truncated to 192 bits.
KERNEL_FQ KERNEL_FA void m90005_aux9 (KERN_ATTR_TMPS_ESALT (wpa_pbkdf2_tmp_t, wpa_universal_t))   // type 9
{
  WPA_AUX_PROLOGUE                                      // load gid/PMK/esalt and bail on padding lanes
  int matched = wpa_check_eapol_sha384 (pmk, wpa);      // derive PTK, recompute the truncated SHA-384 MIC, compare
  WPA_MARK_IF (matched)                                 // report the crack if the MIC matched
}

// aux10 / type 10 FT-PSK-SHA384-PMKID: PMKR1Name through the SHA-384 FT key hierarchy.
KERNEL_FQ KERNEL_FA void m90005_aux10 (KERN_ATTR_TMPS_ESALT (wpa_pbkdf2_tmp_t, wpa_universal_t))  // type 10
{
  WPA_AUX_PROLOGUE                                      // load gid/PMK/esalt and bail on padding lanes
  int matched = wpa_check_ft_pmkid_sha384 (pmk, wpa);   // walk the SHA-384 FT chain, recompute PMKR1Name, compare
  WPA_MARK_IF (matched)                                 // report the crack if the FT PMKID matched
}

// aux11 / type 11 FT-PSK-SHA384-EAPOL: SHA-384 FT chain -> FT-PTK (24-byte KCK), MIC = HMAC-SHA384-192.
KERNEL_FQ KERNEL_FA void m90005_aux11 (KERN_ATTR_TMPS_ESALT (wpa_pbkdf2_tmp_t, wpa_universal_t))  // type 11
{
  WPA_AUX_PROLOGUE                                      // load gid/PMK/esalt and bail on padding lanes
  int matched = wpa_check_ft_eapol_sha384 (pmk, wpa);   // FT-PTK, recompute the truncated SHA-384 MIC, compare
  WPA_MARK_IF (matched)                                 // report the crack if the MIC matched
}
