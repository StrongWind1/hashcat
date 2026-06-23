/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 *
 * WPA-PSK universal cracking plugin, mode 90009 (config I).
 * This config groups the eleven per-AKM WPA-PSK types into three complexity tiers,
 * each handled by its own auxiliary verifier kernel:
 *   tier 1 = types {1,2,3} (WPA1/WPA2, MD5/SHA1 MICs + PMKID)        -> aux kernel 1
 *   tier 2 = types {4,5,6,7} (SHA-256 flat PMKID/EAPOL + FT + CMAC)  -> aux kernel 2
 *   tier 3 = types {8,9,10,11} (SHA-384 flat + FT)                   -> aux kernel 3
 * module_deep_comp_kernel routes each digest to the aux kernel for its tier.
 */

#include "inc_wpa_psk_universal_module.h"  // shared salt/esalt structs, tokenizer, and the WPA_MODULE_CTX_COMMON setup

static const char *HASH_NAME = "WPA-PBKDF2-Universal (90009 / 3-aux-tier)";  // human-readable name shown in hashcat listings
static const u64   KERN_TYPE = 90009;  // kernel/mode number; selects the .cl kernels for this plugin
static const u64   OPTS_TYPE = OPTS_TYPE_STOCK_MODULE      // ships as a standard in-tree module
                             | OPTS_TYPE_PT_GENERATE_LE    // generate password candidates in little-endian word order
                             | OPTS_TYPE_AUX1              // enable auxiliary verifier kernel 1 (tier 1 types)
                             | OPTS_TYPE_AUX2              // enable auxiliary verifier kernel 2 (tier 2 types)
                             | OPTS_TYPE_AUX3              // enable auxiliary verifier kernel 3 (tier 3 types)
                             | OPTS_TYPE_DEEP_COMP_KERNEL  // iterate each digest under a salt and dispatch per-digest comp kernels
                             | OPTS_TYPE_COPY_TMPS;        // copy the tmps (the derived PMK) back to the host when a hash cracks

// Report the display name for this mode.
const char *module_hash_name (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return HASH_NAME; }
// Report the kernel/mode number so hashcat loads the matching kernels.
u64         module_kern_type (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return KERN_TYPE; }
// Report the OPTS_TYPE feature bitmask above so the engine knows which kernels/behaviors to enable.
u64         module_opts_type (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return OPTS_TYPE; }

// Per-digest dispatch: pick which aux verifier kernel runs for a given digest, based on its WPA type tier.
u32 module_deep_comp_kernel (MAYBE_UNUSED const hashes_t *hashes, MAYBE_UNUSED const u32 salt_pos, MAYBE_UNUSED const u32 digest_pos)
{
  // Digests for this salt start at this offset in the global digest/esalt arrays.
  const u32 digests_offset = hashes->salts_buf[salt_pos].digests_offset;
  // Locate this digest's esalt, which carries the per-handshake data including the WPA type byte.
  const wpa_universal_t *wpa = &((const wpa_universal_t *) hashes->esalts_buf)[digests_offset + digest_pos];

  if (wpa->type <= 3) return KERN_RUN_AUX1;  // tier 1: types 1,2,3 (WPA1/WPA2 MD5/SHA1 MIC + PMKID)
  if (wpa->type <= 7) return KERN_RUN_AUX2;  // tier 2: types 4,5,6,7 (SHA-256 flat + FT + AES-CMAC)
  return KERN_RUN_AUX3;                      // tier 3: types 8,9,10,11 (SHA-384 flat + FT)
}

// Register all of this module's function pointers with the engine.
void module_init (module_ctx_t *module_ctx)
{
  WPA_MODULE_CTX_COMMON (module_ctx);  // wire up the shared WPA-PSK handlers (decode/encode/salt/esalt/etc.) common to all configs

  module_ctx->module_deep_comp_kernel = module_deep_comp_kernel;  // override with this config's 3-tier per-digest dispatch
}
