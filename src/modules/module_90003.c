/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 *
 * Plugin 90003 (config C): the GPU computes ONLY the PBKDF2 PMK; every per-AKM
 * post-PMK validation (PMKID + EAPOL MIC for all eleven wpawolf types) runs on
 * the host CPU inside module_hook23, reusing the very same device verifier
 * functions but compiled for the host. The hook23 kernel (which, unlike host
 * code, can read the esalts) copies the PMK and a snapshot of the salt's digests
 * into a per-workitem hook buffer; module_hook23 then verifies each on the CPU
 * and sets a per-digest match bitmask that the comp kernel later reads back.
 *
 * Why the .cl is included before everything else: the device source defines the
 * shared structs and the verifier functions under its own include guard, so
 * pulling it in FIRST both arms that guard (the module header then skips the
 * duplicate struct definitions) and gives us host-compiled copies of the
 * verifiers to call directly from module_hook23.
 */

#include "common.h"
#include "types.h"
#include "modules.h"
#include "bitops.h"
#include "convert.h"
#include "shared.h"
#include "memory.h"
#include "emu_general.h"            // host shims for device builtins (get_global_id, etc.)
#include "emu_inc_cipher_aes.h"     // host AES tables/definitions for the CMAC verifiers
#include "emu_inc_hash_md5.h"       // host MD5 definitions for the type-1 MIC verifier

// These headers only DECLARE the crypto routines the host verifiers call; the
// actual machine code is linked in from the emulated-crypto (emu_*) objects in
// the static archive, so the .cl no longer needs to self-include them.
#include "inc_vendor.h"
#include "inc_types.h"
#include "inc_platform.h"
#include "inc_common.h"
#include "inc_simd.h"
#include "inc_hash_md5.h"           // HMAC-MD5 (type 1 MIC)
#include "inc_hash_sha1.h"          // HMAC-SHA1 (PMKID type 2, EAPOL type 3, FT names)
#include "inc_hash_sha256.h"        // HMAC/KDF-SHA256 (types 4,5,6,7)
#include "inc_hash_sha384.h"        // HMAC/KDF-SHA384 (types 8,9,10,11)
#include "inc_cipher_aes.h"         // AES-128-CMAC (types 5,7 MIC)

#include "inc_wpa_psk_universal.cl"          // included FIRST: defines shared structs + host verifiers and arms the struct guard
#include "inc_wpa_psk_universal_module.h"    // loader/encoder/boilerplate; its struct copies are guarded out by the line above

// Human-readable mode name shown in --help / status output.
static const char *HASH_NAME = "WPA-PBKDF2-Universal (90003 / PBKDF2-GPU+CPU-validate)";
// Kernel/mode number; selects the .cl entry points hashcat launches for this plugin.
static const u64   KERN_TYPE = 90003;
// Option flags controlling how the core engine drives this slow hash.
static const u64   OPTS_TYPE = OPTS_TYPE_STOCK_MODULE         // ships as a stock hashcat module
                             | OPTS_TYPE_PT_GENERATE_LE       // generate password candidates little-endian
                             | OPTS_TYPE_HOOK23               // run a CPU hook (module_hook23) between the _loop and _comp kernels
                             | OPTS_TYPE_MULTIHASH_DESPITE_ESALT;  // allow many digests under one ESSID salt; the comp kernel just reads the match bits the host set

// Trivial accessors hashcat calls to read the three constants above.
const char *module_hash_name (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return HASH_NAME; }
u64         module_kern_type (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return KERN_TYPE; }
u64         module_opts_type (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return OPTS_TYPE; }

// Size of the per-workitem hook buffer hashcat must allocate: one wpa_hook_t
// (PMK + match bitmask + the staged digest snapshots) for every candidate.
u64 module_hook_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  return (u64) sizeof (wpa_hook_t);
}

// CPU validation hook: for one password slot, run every staged digest through
// the matching host verifier and flag the ones that match. Runs after the GPU
// has produced the PMK and the hook23 kernel staged the data into hooks_buf.
void module_hook23 (hc_device_param_t *device_param, MAYBE_UNUSED const void *hook_extra_param, MAYBE_UNUSED const void *hook_salts_buf, MAYBE_UNUSED const u32 salt_pos, const u64 pw_pos)
{
  // Base of the hook buffer (one entry per in-flight password candidate)...
  wpa_hook_t *hooks = (wpa_hook_t *) device_param->hooks_buf;
  // ...and the entry for the candidate this call is handling.
  wpa_hook_t *h     = &hooks[pw_pos];

  // PMK expanded into a full HMAC input block: the verifiers HMAC the PMK as the
  // key, so it must be zero-padded out to the block width before use.
  u32 pmk[32];
  for (int i = 0; i < 32; i++) pmk[i] = 0;          // zero the whole padded block first
  for (int i = 0; i <  8; i++) pmk[i] = h->pmk[i];  // then copy in the 32-byte (8x u32) PMK the GPU staged

  // Walk each staged digest snapshot (bounded by the buffer's capacity).
  for (u32 dp = 0; (dp < h->ndig) && (dp < WPA_HOOK_MAXD); dp++)
  {
    // The per-digest esalt snapshot: carries type, MACs, nonce, EAPOL/PMKID, FT IDs.
    const wpa_universal_t *wpa = &h->dig[dp];

    int ok = 0;  // 1 if this digest validates against the current PMK
    // Dispatch on the 2-digit decimal wpawolf type to the right host verifier.
    switch (wpa->type)
    {
      case  1: ok = wpa_check_eapol_md5        (pmk, wpa); break;                          // WPA1-PSK EAPOL: MIC = HMAC-MD5(KCK, eapol)
      case  2: ok = wpa_check_pmkid_sha1       (pmk, wpa); break;                          // WPA2-PSK PMKID: HMAC-SHA1(PMK,"PMK Name"||AP||STA), first 16 bytes
      case  3: ok = wpa_check_eapol_sha1       (pmk, wpa); break;                          // WPA2-PSK EAPOL: MIC = HMAC-SHA1 truncated to 128 bits
      case  4: ok = wpa_check_pmkid_sha256     (pmk, wpa); break;                          // SHA-256 PMKID: HMAC-SHA256(...) first 16 bytes
      case  5: ok = wpa_check_eapol_cmac256    (pmk, wpa, te0, te1, te2, te3, te4); break; // SHA-256 EAPOL: MIC = AES-128-CMAC (te0..te4 are the AES tables)
      case  6: ok = wpa_check_ft_pmkid_sha256  (pmk, wpa); break;                          // FT PMKID (PMKR1Name) via the SHA-256 FT key hierarchy
      case  7: ok = wpa_check_ft_eapol_cmac256 (pmk, wpa, te0, te1, te2, te3, te4); break; // FT EAPOL: SHA-256 FT chain -> KCK; MIC = AES-128-CMAC
      case  8: ok = wpa_check_pmkid_sha384     (pmk, wpa); break;                          // SHA-384 PMKID: HMAC-SHA384(...) first 16 bytes
      case  9: ok = wpa_check_eapol_sha384     (pmk, wpa); break;                          // SHA-384 EAPOL: MIC = HMAC-SHA384 truncated to 192 bits (24 bytes)
      case 10: ok = wpa_check_ft_pmkid_sha384  (pmk, wpa); break;                          // FT PMKID (PMKR1Name) via the SHA-384 FT key hierarchy
      case 11: ok = wpa_check_ft_eapol_sha384  (pmk, wpa); break;                          // FT EAPOL: SHA-384 FT chain -> KCK; MIC = HMAC-SHA384-192
    }

    if (ok) h->ok |= (1u << dp);  // record the match: set bit dp the comp kernel reads back
  }
}

// Register the plugin's function pointers with the core engine.
void module_init (module_ctx_t *module_ctx)
{
  // Shared setup for every wpawolf universal plugin (loader/encoder, salt/esalt
  // sizes, digest layout, PBKDF2 iteration count, etc.).
  WPA_MODULE_CTX_COMMON (module_ctx);

  // This config's two extras: the CPU validation hook and its buffer size.
  module_ctx->module_hook23    = module_hook23;
  module_ctx->module_hook_size = module_hook_size;
}
