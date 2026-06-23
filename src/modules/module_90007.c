/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 *
 * Plugin 90007 (config G): hybrid verifier. The GPU comp kernel validates the
 * 32-bit-MAC family (hash types 1..7) directly on the device, while the SHA-384
 * family (types 8..11) is validated on the host CPU inside module_hook23. The
 * hook23 staging buffer carries the PMK plus this salt's digests up to the host;
 * the host checks only the SHA-384 rows and sets a per-digest bitmask the comp
 * kernel reads back for those types.
 */

// hashcat core headers: option/type constants, module ctx API, helpers.
#include "common.h"
#include "types.h"
#include "modules.h"
#include "bitops.h"
#include "convert.h"
#include "shared.h"
#include "memory.h"
#include "emu_general.h"
// CPU emulation of the AES and MD5 crypto primitives the host verifiers call.
#include "emu_inc_cipher_aes.h"
#include "emu_inc_hash_md5.h"

// Crypto-library declarations the host verifiers need; the actual code is linked
// from the emu_* objects, so the .cl included below does not pull these itself.
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

// The shared universal WPA logic: esalt struct, per-type verifiers, and tokenizer.
#include "inc_wpa_psk_universal.cl"
// The shared host-side decode/encode/init code reused across the bake-off plugins.
#include "inc_wpa_psk_universal_module.h"

// Human-readable name shown in --help / status, flagged with this config's split.
static const char *HASH_NAME = "WPA-PBKDF2-Universal (90007 / GPU1-7+CPU8-11)";
// Kernel/mode number; selects the OpenCL kernel file for this plugin.
static const u64   KERN_TYPE = 90007;
// Behavior flags hashcat applies to this mode.
static const u64   OPTS_TYPE = OPTS_TYPE_STOCK_MODULE          // ships as a stock hashcat module
                             | OPTS_TYPE_PT_GENERATE_LE        // generate password candidates little-endian
                             | OPTS_TYPE_HOOK23                // run a CPU hook between the _loop and _comp kernels
                             | OPTS_TYPE_MULTIHASH_DESPITE_ESALT; // allow many digests per salt; comp iterates them (no DEEP_COMP dispatch)

// Trivial getters hashcat calls to read this mode's name / kernel number / flags.
const char *module_hash_name (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return HASH_NAME; }
u64         module_kern_type (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return KERN_TYPE; }
u64         module_opts_type (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return OPTS_TYPE; }

// Size of the per-password hook staging record hashcat allocates between kernels.
u64 module_hook_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  return (u64) sizeof (wpa_hook_t); // one wpa_hook_t per candidate (PMK + this salt's digests)
}

// CPU hook running between _loop and _comp: validate only the SHA-384 family {8..11}; 1..7 are GPU-verified.
void module_hook23 (hc_device_param_t *device_param, MAYBE_UNUSED const void *hook_extra_param, MAYBE_UNUSED const void *hook_salts_buf, MAYBE_UNUSED const u32 salt_pos, const u64 pw_pos)
{
  wpa_hook_t *hooks = (wpa_hook_t *) device_param->hooks_buf; // base of the hook staging array
  wpa_hook_t *h     = &hooks[pw_pos];                         // the record for this password candidate

  u32 pmk[32];                                  // local PMK buffer sized for the widest verifier scratch use
  for (int i = 0; i < 32; i++) pmk[i] = 0;      // zero the tail so unused words never leak into a hash
  for (int i = 0; i <  8; i++) pmk[i] = h->pmk[i]; // copy the 32-byte (8 word) PMK the GPU staged for us

  // Walk every digest this salt staged, bounded by the staging buffer capacity.
  for (u32 dp = 0; (dp < h->ndig) && (dp < WPA_HOOK_MAXD); dp++)
  {
    const wpa_universal_t *wpa = &h->dig[dp]; // the per-handshake esalt for digest dp

    int ok = 0;                  // does this candidate's PMK satisfy this digest?
    switch (wpa->type)           // dispatch on the 2-digit decimal hash type
    {
      // PMKID = first 16 bytes of HMAC-SHA384(PMK, "PMK Name" || AP || STA).
      case  8: ok = wpa_check_pmkid_sha384     (pmk, wpa); break;
      // KDF-HMAC-SHA384 PTK -> 24-byte KCK; MIC = HMAC-SHA384 truncated to 192 bits.
      case  9: ok = wpa_check_eapol_sha384     (pmk, wpa); break;
      // 802.11r fast-roaming PMKR1Name via the SHA-384 FT key hierarchy, used as the PMKID.
      case 10: ok = wpa_check_ft_pmkid_sha384  (pmk, wpa); break;
      // SHA-384 FT chain -> FT-PTK -> 24-byte KCK; MIC = HMAC-SHA384-192.
      case 11: ok = wpa_check_ft_eapol_sha384  (pmk, wpa); break;
      default: continue; // types 1-7 are validated on the GPU, so skip them here
    }

    if (ok) h->ok |= (1u << dp); // set bit dp so the comp kernel learns digest dp matched
  }
}

// Register this mode's function pointers with hashcat.
void module_init (module_ctx_t *module_ctx)
{
  WPA_MODULE_CTX_COMMON (module_ctx); // install the shared decode/encode/salt/digest handlers

  module_ctx->module_hook23    = module_hook23;    // our SHA-384 host verifier
  module_ctx->module_hook_size = module_hook_size; // size of the per-candidate hook record
}
