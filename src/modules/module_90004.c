/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 *
 * Universal WPA-PSK plugin 90004 (config D, the bake-off winner). It cracks all
 * eleven per-AKM WPA-PSK types from one module by splitting the work across two
 * aux verifier kernels keyed on the attack surface: PMKID attacks (the even type
 * codes) run on aux kernel 1, EAPOL handshake attacks (the odd type codes) run
 * on aux kernel 2. Even/odd is the dispatch axis because even types are the
 * keyless PMKID captures while odd types carry a 4-way-handshake MIC to verify.
 */

// Shared host core: structs, the line loader/encoder, and every module getter
// except the aux wiring this file defines (KERN_TYPE, OPTS_TYPE, deep-comp).
#include "inc_wpa_psk_universal_module.h"

// Human-readable name shown in --help / status, tagged with the routing scheme.
static const char *HASH_NAME = "WPA-PBKDF2-Universal (90004 / 2-aux-by-surface)";
// Mode number; selects the matching .cl kernel set on the device.
static const u64   KERN_TYPE = 90004;
// Behaviour flags OR'd into one mask, telling hashcat how to drive this mode.
static const u64   OPTS_TYPE = OPTS_TYPE_STOCK_MODULE         // ships as a built-in hashcat mode
                             | OPTS_TYPE_PT_GENERATE_LE        // emit password candidates little-endian
                             | OPTS_TYPE_AUX1                  // enable aux kernel 1 (PMKID verifier)
                             | OPTS_TYPE_AUX2                  // enable aux kernel 2 (EAPOL verifier)
                             | OPTS_TYPE_DEEP_COMP_KERNEL      // iterate each digest and pick its aux kernel per type
                             | OPTS_TYPE_COPY_TMPS;            // copy tmps (the cracked PMK) back to host on a hit

// Return the display name; the MAYBE_UNUSED context args are part of the fixed module ABI.
const char *module_hash_name (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return HASH_NAME; }
// Return the kernel/mode number so hashcat loads the 90004 device kernels.
u64         module_kern_type (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return KERN_TYPE; }
// Return the assembled options mask defined above.
u64         module_opts_type (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return OPTS_TYPE; }

// Per-digest aux-kernel selector: with DEEP_COMP set, hashcat calls this for each
// digest to choose which aux verifier kernel runs for that digest's type.
u32 module_deep_comp_kernel (MAYBE_UNUSED const hashes_t *hashes, MAYBE_UNUSED const u32 salt_pos, MAYBE_UNUSED const u32 digest_pos)
{
  // Find where this salt's digests start in the flat esalt array.
  const u32 digests_offset = hashes->salts_buf[salt_pos].digests_offset;
  // Point at this specific digest's esalt so we can read its WPA type code.
  const wpa_universal_t *wpa = &((const wpa_universal_t *) hashes->esalts_buf)[digests_offset + digest_pos];

  // Even type -> PMKID attack -> aux1; odd type -> EAPOL handshake -> aux2.
  return ((wpa->type % 2) == 0) ? KERN_RUN_AUX1 : KERN_RUN_AUX2;
}

// Register this mode's function pointers; called once at module load time.
void module_init (module_ctx_t *module_ctx)
{
  // Wire up all the shared WPA getters/loaders/encoders from the common header.
  WPA_MODULE_CTX_COMMON (module_ctx);

  // Override the per-digest dispatcher with this file's even/odd surface router.
  module_ctx->module_deep_comp_kernel = module_deep_comp_kernel;
}
