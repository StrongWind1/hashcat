/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 *
 * Bake-off plugin 90002 (config B): four AKM-family aux kernels, each running an
 * internal switch(type) to pick the right crypto. This is one of several
 * candidate layouts that crack the same eleven per-AKM WPA-PSK types; it differs
 * from the others only in how many aux kernels exist and how the type-to-kernel
 * grouping is drawn. All the real loader/encoder/crypto logic is shared and
 * lives in the included header; this file only wires the kernel number, the aux
 * kernel set, and the per-digest family dispatch.
 */

// Pull in the shared host core (structs, tokenizer/loader, encoder, the common
// module_* getters) used by every WPA-PSK universal/bake-off plugin.
#include "inc_wpa_psk_universal_module.h"

// Human-readable mode name shown in --help / status output.
static const char *HASH_NAME = "WPA-PBKDF2-Universal (90002 / 4-family-aux)";
// Kernel/mode number; selects the .cl kernel file and identifies this plugin.
static const u64   KERN_TYPE = 90002;
// Option flags that describe this plugin's runtime shape to hashcat.
static const u64   OPTS_TYPE = OPTS_TYPE_STOCK_MODULE        // ships as a built-in stock module
                             | OPTS_TYPE_PT_GENERATE_LE      // generate password candidates little-endian
                             | OPTS_TYPE_AUX1                // enable a 1st auxiliary verifier kernel
                             | OPTS_TYPE_AUX2                // enable a 2nd auxiliary verifier kernel
                             | OPTS_TYPE_AUX3                // enable a 3rd auxiliary verifier kernel
                             | OPTS_TYPE_AUX4                // enable a 4th auxiliary verifier kernel
                             | OPTS_TYPE_DEEP_COMP_KERNEL    // per-digest comp dispatch (chooses an aux kernel per hash)
                             | OPTS_TYPE_COPY_TMPS;          // copy tmps (the derived PMK) back to host on a crack

// Report the display name for this mode.
const char *module_hash_name (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return HASH_NAME; }
// Report the kernel/mode number so hashcat loads the matching kernel.
u64         module_kern_type (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return KERN_TYPE; }
// Report the option flags above so hashcat sets up aux kernels / deep-comp / tmp copy.
u64         module_opts_type (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return OPTS_TYPE; }

// Per-digest deep-comp dispatch: given one hash, return which aux kernel verifies
// it. The eleven types are grouped into four aux kernels by shared crypto family
// so each kernel only has to handle a small set of related primitives.
u32 module_deep_comp_kernel (MAYBE_UNUSED const hashes_t *hashes, MAYBE_UNUSED const u32 salt_pos, MAYBE_UNUSED const u32 digest_pos)
{
  // Where this salt's digests begin in the global esalt array.
  const u32 digests_offset = hashes->salts_buf[salt_pos].digests_offset;
  // The esalt for the specific digest under examination (carries its type field).
  const wpa_universal_t *wpa = &((const wpa_universal_t *) hashes->esalts_buf)[digests_offset + digest_pos];

  // Route by the 2-digit type code; each case is a family sharing a hash/MAC primitive.
  switch (wpa->type)
  {
    case 1: case 2: case 3:           return KERN_RUN_AUX1;  // WPA1/WPA2 legacy family: SHA-1 PRF, MD5/SHA-1 MIC, SHA-1 PMKID
    case 4: case 5:                   return KERN_RUN_AUX2;  // SHA-256 family: SHA-256 PMKID and SHA-256 KDF + AES-CMAC MIC
    case 6: case 7:                   return KERN_RUN_AUX3;  // SHA-256 FT (802.11r) family: SHA-256 FT key hierarchy + AES-CMAC
    case 8: case 9: case 10: case 11: return KERN_RUN_AUX4;  // SHA-384 family: SHA-384 PMKID/KDF and SHA-384 FT hierarchy
  }

  // Unknown/unset type: 0 means "no aux kernel" (should not happen for valid hashes).
  return 0;
}

// Register this plugin's function pointers with hashcat.
void module_init (module_ctx_t *module_ctx)
{
  // Install all the shared getters/loader/encoder common to the WPA universal plugins.
  WPA_MODULE_CTX_COMMON (module_ctx);

  // Override with this config's per-digest family dispatch defined above.
  module_ctx->module_deep_comp_kernel = module_deep_comp_kernel;
}
