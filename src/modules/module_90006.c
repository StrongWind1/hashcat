/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 *
 * Bake-off plugin 90006 (config F): a single aux kernel holding one switch over
 * all 11 WPA-PSK types, with hashcat dispatching it per digest via DEEP_COMP.
 * (Config A instead loops over the types inside the comp kernel.)
 */

// Pull in the shared host core: salt/esalt structs, the line loader/encoder,
// and every mandatory module getter common to all WPA universal plugins.
#include "inc_wpa_psk_universal_module.h"

// Human-readable name shown in --help and the status screen for this mode.
static const char *HASH_NAME = "WPA-PBKDF2-Universal (90006 / 1-aux-switch)";
// Mode number; also the kernel file/identifier hashcat loads for the GPU code.
static const u64   KERN_TYPE = 90006;
// Behaviour flags wiring this plugin's slow-hash + aux-kernel mechanics.
static const u64   OPTS_TYPE = OPTS_TYPE_STOCK_MODULE       // ships as a standard hashcat mode
                             | OPTS_TYPE_PT_GENERATE_LE     // generate password candidates little-endian
                             | OPTS_TYPE_AUX1               // enable exactly one auxiliary kernel
                             | OPTS_TYPE_DEEP_COMP_KERNEL   // dispatch a per-digest comp/aux kernel
                             | OPTS_TYPE_COPY_TMPS;         // copy tmps (the PMK) back to host on a crack

// Report this plugin's display name to hashcat.
const char *module_hash_name (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return HASH_NAME; }
// Report the kernel/mode number so hashcat loads the matching GPU kernels.
u64         module_kern_type (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return KERN_TYPE; }
// Report the OPTS_TYPE flag set that drives this plugin's execution model.
u64         module_opts_type (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return OPTS_TYPE; }

// Pick which aux kernel verifies a given digest. Config F has just one aux
// kernel (an internal switch over all 11 types), so always select aux1.
u32 module_deep_comp_kernel (MAYBE_UNUSED const hashes_t *hashes, MAYBE_UNUSED const u32 salt_pos, MAYBE_UNUSED const u32 digest_pos)
{
  return KERN_RUN_AUX1;   // route every digest to the single all-types aux kernel
}

// Register this plugin's function pointers with hashcat at load time.
void module_init (module_ctx_t *module_ctx)
{
  // Install all the shared WPA getters/loader/encoder (defaults plus common impls).
  WPA_MODULE_CTX_COMMON (module_ctx);

  // Override the per-digest dispatch hook with this config's always-aux1 chooser.
  module_ctx->module_deep_comp_kernel = module_deep_comp_kernel;
}
