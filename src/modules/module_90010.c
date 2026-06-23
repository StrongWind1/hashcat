/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 *
 * hashcat plugin mode 90010: one aux kernel plus per-digest dispatch. A single
 * "compute-all-leaves" verifier kernel runs every WPA-PSK type's check and picks
 * the result by the digest's type, so this module just routes everything to it.
 */

// Pull in the shared WPA-PSK loader/encoder, salt/esalt layout, and ctx wiring.
#include "inc_wpa_psk_universal_module.h"

// Human-readable mode label shown in --help and status output.
static const char *HASH_NAME = "WPA-PBKDF2-Universal (90010 / branchless-superset)";
// Kernel/mode number; selects the GPU kernel sources built for this plugin.
static const u64   KERN_TYPE = 90010;
// Behaviour flags OR'd together to describe how hashcat drives this slow hash.
static const u64   OPTS_TYPE = OPTS_TYPE_STOCK_MODULE       // ships as a built-in stock module
                             | OPTS_TYPE_PT_GENERATE_LE      // generate password candidates little-endian
                             | OPTS_TYPE_AUX1                // enable exactly one auxiliary verifier kernel
                             | OPTS_TYPE_DEEP_COMP_KERNEL    // iterate each digest and dispatch its comp via module_deep_comp_kernel
                             | OPTS_TYPE_COPY_TMPS;          // copy tmps (the derived PMK) back to host on a crack

// Return the mode label; args unused because the name is constant for this mode.
const char *module_hash_name (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return HASH_NAME; }
// Return the kernel/mode number that selects this plugin's GPU kernels.
u64         module_kern_type (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return KERN_TYPE; }
// Return the behaviour flag set defined above.
u64         module_opts_type (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return OPTS_TYPE; }

// Pick which aux kernel verifies a given digest; this mode always uses the one
// superset kernel, which internally computes every type and selects by digest type.
u32 module_deep_comp_kernel (MAYBE_UNUSED const hashes_t *hashes, MAYBE_UNUSED const u32 salt_pos, MAYBE_UNUSED const u32 digest_pos)
{
  return KERN_RUN_AUX1; // always route to aux kernel #1 regardless of salt/digest
}

// Register this module's function pointers with hashcat at load time.
void module_init (module_ctx_t *module_ctx)
{
  WPA_MODULE_CTX_COMMON (module_ctx); // wire up all the shared WPA-PSK loader/encoder/salt callbacks

  module_ctx->module_deep_comp_kernel = module_deep_comp_kernel; // override the default no-op with our aux1 router
}
