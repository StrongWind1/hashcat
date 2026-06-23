/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 *
 * Bake-off plugin 90010 (config J): branchless "compute-all-leaves" aux.
 * Per digest it runs the full superset of verifiers straight-line (no type
 * switch) and selects the matching one by type at the end -- trades wasted
 * work for zero divergence; every SIMD lane executes the identical sequence
 * of all eleven verifiers so there is no verifier-selection branch to diverge.
 *
 * Verifiers run against a digest of the "wrong" type read zeroed esalt fields
 * (eapol_len = 0, keymic/pmkid = 0); they cannot fault and their result is
 * masked out by the type select, so this stays correct -- just slower.
 */

#define NEW_SIMD_CODE                                       // enable hashcat's vectorised (SIMD) kernel code path

#ifdef KERNEL_STATIC                                        // device build: pull headers via the indirection-macro include path
#include M2S(INCLUDE_PATH/inc_vendor.h)                     // vendor/arch detection (warp size, byte order, intrinsics)
#include M2S(INCLUDE_PATH/inc_types.h)                      // base typedefs (u32/u64, u32x SIMD vectors, kernel structs)
#include M2S(INCLUDE_PATH/inc_platform.cl)                  // platform shims so the same source runs on GPU/CPU/host
#include M2S(INCLUDE_PATH/inc_common.cl)                    // shared helpers (mark_hash, hc_swap32_S, atomics, packv/unpackv)
#include M2S(INCLUDE_PATH/inc_simd.cl)                      // SIMD vector macros used by NEW_SIMD_CODE
#include M2S(INCLUDE_PATH/inc_hash_md5.cl)                  // MD5 (little-endian) for the WPA1 EAPOL MIC, type 1
#include M2S(INCLUDE_PATH/inc_hash_sha1.cl)                 // SHA-1 (big-endian) for PBKDF2, SHA1 PMKID/EAPOL/FT
#include M2S(INCLUDE_PATH/inc_hash_sha256.cl)               // SHA-256 for PMKID/KDF/CMAC and SHA-256 FT hierarchy
#include M2S(INCLUDE_PATH/inc_hash_sha384.cl)               // SHA-384 (64-bit words) for the SHA-384 families
#include M2S(INCLUDE_PATH/inc_cipher_aes.cl)                // AES core + T-tables backing the AES-128-CMAC MIC (types 5,7)
#include M2S(INCLUDE_PATH/inc_wpa_psk_universal.cl)         // the eleven per-AKM WPA-PSK verifiers and their wiring macros
#else                                                       // host build (CPU-validation modes compile this .cl as plain C)
#include "inc_vendor.h"                                     // same headers, plain-path filenames for the host compiler
#include "inc_types.h"
#include "inc_platform.h"
#include "inc_common.h"
#include "inc_simd.h"
#include "inc_hash_md5.h"
#include "inc_hash_sha1.h"
#include "inc_hash_sha256.h"
#include "inc_hash_sha384.h"
#include "inc_cipher_aes.h"
#include "inc_wpa_psk_universal.cl"                          // verifiers shared verbatim between device and host builds
#endif

// _init: seed the per-workitem PBKDF2 state and run the first SHA-1 transform.
KERNEL_FQ KERNEL_FA void m90010_init (KERN_ATTR_TMPS_ESALT (wpa_pbkdf2_tmp_t, wpa_universal_t))
{
  const u64 gid = get_global_id (0);                        // this work item's global index
  if (gid >= GID_CNT) return;                               // drop padding items past the real candidate count
  wpa_pbkdf2_init (pws, tmps, esalt_bufs, gid, DIGESTS_OFFSET_HOST); // build PBKDF2-HMAC-SHA1(pass, ESSID) state; first iter done here
}

// _loop: the slow inner PBKDF2 stretch; called repeatedly until 4096 iters total.
KERNEL_FQ KERNEL_FA void m90010_loop (KERN_ATTR_TMPS_ESALT (wpa_pbkdf2_tmp_t, wpa_universal_t))
{
  const u64 gid = get_global_id (0);                        // this work item's global index
  if ((gid * VECT_SIZE) >= GID_CNT) return;                 // each item covers VECT_SIZE candidates; bound the vector base
  wpa_pbkdf2_loop (tmps, gid, LOOP_CNT);                    // run LOOP_CNT more HMAC-SHA1 iterations; the heavy work
}

// _comp: empty -- all comparison/marking happens in the aux verifier kernel below.
KERNEL_FQ KERNEL_FA void m90010_comp (KERN_ATTR_TMPS_ESALT (wpa_pbkdf2_tmp_t, wpa_universal_t)) { }

// _aux1: the single verifier kernel; runs every type's check then masks by type.
KERNEL_FQ KERNEL_FA void m90010_aux1 (KERN_ATTR_TMPS_ESALT (wpa_pbkdf2_tmp_t, wpa_universal_t))
{
  WPA_AES_SHARED                                            // expose AES T-tables s_te0..s_te4 needed by the CMAC checks (5,7)
  WPA_AUX_PROLOGUE                                          // resolve gid/digest cursor and load the PMK into zero-padded pmk[32]

  const u32 type = wpa->type;                               // this digest's per-AKM type code (01..11)

  // Compute every leaf unconditionally (all lanes do the same work -> no
  // verifier-selection divergence), then select the matching one by type.
  const int r1  = wpa_check_eapol_md5        (pmk, wpa);    // 1: WPA1 EAPOL, MIC = HMAC-MD5(KCK, eapol)
  const int r2  = wpa_check_pmkid_sha1       (pmk, wpa);    // 2: WPA2 PMKID = Truncate-128 HMAC-SHA1(PMK, "PMK Name"||AP||STA)
  const int r3  = wpa_check_eapol_sha1       (pmk, wpa);    // 3: WPA2 EAPOL, MIC = HMAC-SHA1 truncated to 128 bits
  const int r4  = wpa_check_pmkid_sha256     (pmk, wpa);    // 4: PMKID via HMAC-SHA256
  const int r5  = wpa_check_eapol_cmac256    (pmk, wpa, s_te0, s_te1, s_te2, s_te3, s_te4); // 5: SHA-256 KDF PTK, MIC = AES-128-CMAC(KCK)
  const int r6  = wpa_check_ft_pmkid_sha256  (pmk, wpa);    // 6: 802.11r PMKR1Name via the SHA-256 FT key hierarchy
  const int r7  = wpa_check_ft_eapol_cmac256 (pmk, wpa, s_te0, s_te1, s_te2, s_te3, s_te4); // 7: SHA-256 FT PTK, MIC = AES-128-CMAC
  const int r8  = wpa_check_pmkid_sha384     (pmk, wpa);    // 8: PMKID via HMAC-SHA384
  const int r9  = wpa_check_eapol_sha384     (pmk, wpa);    // 9: SHA-384 KDF PTK (24-byte KCK), MIC = HMAC-SHA384 truncated to 192 bits
  const int r10 = wpa_check_ft_pmkid_sha384  (pmk, wpa);    // 10: PMKR1Name via the SHA-384 FT hierarchy
  const int r11 = wpa_check_ft_eapol_sha384  (pmk, wpa);    // 11: SHA-384 FT PTK, MIC = HMAC-SHA384-192 (24 bytes)

  // Branchless select: zero out every result whose type tag doesn't equal this
  // digest's type, then OR -- only the one matching verifier can contribute.
  const int matched = ((type ==  1) & r1) | ((type ==  2) & r2) | ((type ==  3) & r3)  // types 1-3 lane
                    | ((type ==  4) & r4) | ((type ==  5) & r5) | ((type ==  6) & r6)  // types 4-6 lane
                    | ((type ==  7) & r7) | ((type ==  8) & r8) | ((type ==  9) & r9)  // types 7-9 lane
                    | ((type == 10) & r10) | ((type == 11) & r11);                     // types 10-11 lane
  WPA_MARK_IF (matched)                                     // report a crack exactly once if the selected verifier matched
}
