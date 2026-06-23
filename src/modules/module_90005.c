/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 *
 * Bake-off plugin 90005 (config E): one dedicated aux (verifier) kernel per
 * hash type, so the device code for each of the eleven WPA-PSK variants is a
 * straight-line verifier with zero "switch (type)" branching inside the kernel.
 * The cost of that branch-free design is that hashcat's stock core only exposes
 * four aux-kernel slots (AUX1..AUX4); supporting eleven types needs the core
 * itself extended with AUX5..AUX11 slots plus a kernel-load path that pulls them
 * in when DEEP_COMP is set. So this is the cleanest per-kernel layout but the
 * only plugin in the set that requires a patch to hashcat's core, not just a
 * new module file.
 */

// Shared host core: structs, tokenizer, encoder, and the WPA_MODULE_CTX_COMMON wiring macro.
#include "inc_wpa_psk_universal_module.h"

static const char *HASH_NAME = "WPA-PBKDF2-Universal (90005 / 11-per-type-aux)"; // shown in --help / status
static const u64   KERN_TYPE = 90005;                                            // the kernel/mode number for this plugin
// Option flags that tell the core how to drive this slow hash.
static const u64   OPTS_TYPE = OPTS_TYPE_STOCK_MODULE       // ships as a built-in hashcat module
                             | OPTS_TYPE_PT_GENERATE_LE     // generate password candidates little-endian
                             | OPTS_TYPE_AUX1               // enable base aux slot 1 (loaded by the normal path)
                             | OPTS_TYPE_AUX2               // enable base aux slot 2
                             | OPTS_TYPE_AUX3               // enable base aux slot 3
                             | OPTS_TYPE_AUX4               // enable base aux slot 4 (AUX5..11 come from the extended DEEP_COMP load path)
                             | OPTS_TYPE_DEEP_COMP_KERNEL   // iterate each digest and dispatch a per-digest aux kernel
                             | OPTS_TYPE_COPY_TMPS;         // copy tmps (the PMK) back to the host when a hash cracks

const char *module_hash_name (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return HASH_NAME; } // report the display name
u64         module_kern_type (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return KERN_TYPE; } // report the mode number
u64         module_opts_type (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return OPTS_TYPE; } // report the option flags

// Flat 11-arm map from the 2-digit type code to the aux kernel that verifies it.
// No conditional crypto here -- each type's whole verify routine is its own kernel.
u32 module_deep_comp_kernel (MAYBE_UNUSED const hashes_t *hashes, MAYBE_UNUSED const u32 salt_pos, MAYBE_UNUSED const u32 digest_pos)
{
  const u32 digests_offset = hashes->salts_buf[salt_pos].digests_offset;                                    // first digest index for this salt (one PBKDF2 salt = one ESSID)
  const wpa_universal_t *wpa = &((const wpa_universal_t *) hashes->esalts_buf)[digests_offset + digest_pos]; // the esalt (per-handshake data, incl. type) for this exact digest

  switch (wpa->type) // the 2-digit type code is the sole dispatch axis
  {
    case  1: return KERN_RUN_AUX1;  // 1  WPA1-PSK-EAPOL    : SHA1-PRF PTK; MIC = HMAC-MD5
    case  2: return KERN_RUN_AUX2;  // 2  WPA2-PSK-PMKID    : PMKID = HMAC-SHA1(PMK, "PMK Name"||AP||STA)[:16]
    case  3: return KERN_RUN_AUX3;  // 3  WPA2-PSK-EAPOL    : SHA1-PRF PTK; MIC = HMAC-SHA1-128
    case  4: return KERN_RUN_AUX4;  // 4  PSK-SHA256-PMKID  : PMKID = HMAC-SHA256(...)[:16]
    case  5: return KERN_RUN_AUX5;  // 5  PSK-SHA256-EAPOL  : SHA256-KDF PTK; MIC = AES-128-CMAC
    case  6: return KERN_RUN_AUX6;  // 6  FT-PSK-PMKID      : 802.11r PMKR1Name via the SHA-256 FT hierarchy
    case  7: return KERN_RUN_AUX7;  // 7  FT-PSK-EAPOL      : SHA-256 FT chain -> FT-PTK; MIC = AES-128-CMAC
    case  8: return KERN_RUN_AUX8;  // 8  PSK-SHA384-PMKID  : PMKID = HMAC-SHA384(...)[:16]
    case  9: return KERN_RUN_AUX9;  // 9  PSK-SHA384-EAPOL  : SHA384-KDF PTK; MIC = HMAC-SHA384-192 (24 B)
    case 10: return KERN_RUN_AUX10; // 10 FT-PSK-SHA384-PMKID : PMKR1Name via the SHA-384 FT hierarchy
    case 11: return KERN_RUN_AUX11; // 11 FT-PSK-SHA384-EAPOL : SHA-384 FT chain -> FT-PTK; MIC = HMAC-SHA384-192
  }
  return 0; // unreachable: the loader rejects any type outside 1..11
}

// Register the function pointers; the shared macro fills the defaults, then we override deep_comp.
void module_init (module_ctx_t *module_ctx)
{
  WPA_MODULE_CTX_COMMON (module_ctx); // wire all the shared getters/loader/encoder and leave deep_comp as MODULE_DEFAULT

  module_ctx->module_deep_comp_kernel = module_deep_comp_kernel; // override with our per-type aux dispatch
}
