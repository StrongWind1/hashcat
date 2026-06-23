/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 *
 * Plugin 90008: a WPA-PSK "universal" mode that cracks all eleven per-AKM
 * hash types but splits the per-digest verification across two aux kernels
 * along the 32-bit/64-bit primitive boundary. Types 1..7 use only the
 * 32-bit-word primitives (MD5, SHA-1, SHA-256, AES) and go to aux kernel 1;
 * the SHA-384 family (types 8..11) uses 64-bit-word arithmetic and goes to
 * aux kernel 2. Keeping SHA-384 in its own kernel isolates the register and
 * compile cost of the 64-bit datapath so it does not slow the 32-bit types.
 */

// Pull in the shared host core: struct layouts, the loader/encoder, and the
// mandatory module getters every WPA-PSK universal plugin reuses.
#include "inc_wpa_psk_universal_module.h"

// Human-readable name shown in --help / status; tags this as the 2-aux 32-vs-64 variant.
static const char *HASH_NAME = "WPA-PBKDF2-Universal (90008 / 2-aux-32v64)";
// Mode number; also selects the matching .cl kernel set (kernel type 90008).
static const u64   KERN_TYPE = 90008;
// Option flags controlling how hashcat drives this mode.
static const u64   OPTS_TYPE = OPTS_TYPE_STOCK_MODULE          // ships as a built-in mode
                             | OPTS_TYPE_PT_GENERATE_LE        // generate password candidates little-endian
                             | OPTS_TYPE_AUX1                  // enable aux kernel 1 (32-bit primitive types)
                             | OPTS_TYPE_AUX2                  // enable aux kernel 2 (SHA-384 family)
                             | OPTS_TYPE_DEEP_COMP_KERNEL      // dispatch a per-digest comp kernel chosen below
                             | OPTS_TYPE_COPY_TMPS;            // copy the PMK (tmps) back to host on a crack

// Return the display name (signature ignores the unused config args).
const char *module_hash_name (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return HASH_NAME; }
// Return the kernel/mode number so hashcat loads the 90008 kernels.
u64         module_kern_type (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return KERN_TYPE; }
// Return the option flag set defined above.
u64         module_opts_type (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return OPTS_TYPE; }

// Per-digest aux-kernel selector: hashcat calls this for each digest under a salt
// because DEEP_COMP_KERNEL is set, and we route by hash type.
u32 module_deep_comp_kernel (MAYBE_UNUSED const hashes_t *hashes, MAYBE_UNUSED const u32 salt_pos, MAYBE_UNUSED const u32 digest_pos)
{
  // Locate where this salt's digests begin in the global digest/esalt arrays.
  const u32 digests_offset = hashes->salts_buf[salt_pos].digests_offset;
  // Grab the esalt for this specific digest; it carries the per-handshake type.
  const wpa_universal_t *wpa = &((const wpa_universal_t *) hashes->esalts_buf)[digests_offset + digest_pos];

  // Types 1..7 (MD5/SHA1/SHA256/AES, all 32-bit) -> aux1; SHA-384 family 8..11 -> aux2.
  return (wpa->type <= 7) ? KERN_RUN_AUX1 : KERN_RUN_AUX2;
}

// Register this module's function pointers with hashcat at load time.
void module_init (module_ctx_t *module_ctx)
{
  // Wire up every shared getter/loader/encoder; fields not used are set to MODULE_DEFAULT.
  WPA_MODULE_CTX_COMMON (module_ctx);

  // Override the per-digest dispatcher so the type-based aux split above takes effect.
  module_ctx->module_deep_comp_kernel = module_deep_comp_kernel;
}
