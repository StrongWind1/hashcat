/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 *
 * Plugin 90001 (config A): one monolithic _comp kernel does the per-digest
 * verification. The _comp kernel walks every digest hung under a salt and
 * branches on each digest's WPA type internally, so there are no auxiliary
 * kernels and no per-digest deep-comp dispatch. This file is just the mode's
 * identity + option flags; all the heavy parsing/encoding lives in the shared
 * header pulled in below.
 */

// Shared WPA-PSK module code: token parser, salt/esalt layout, hash decode/
// encode, postprocess, and the WPA_MODULE_CTX_COMMON registration macro.
#include "inc_wpa_psk_universal_module.h"

// Human-readable mode name shown in --help and status output.
static const char *HASH_NAME = "WPA-PBKDF2-Universal (90001 / monolithic-comp)";
// Kernel/mode number; selects the .cl kernel set and the -m number.
static const u64   KERN_TYPE = 90001;
// Option bitmask describing how the host engine should drive this slow hash.
static const u64   OPTS_TYPE = OPTS_TYPE_STOCK_MODULE              // ships as part of stock hashcat
                             | OPTS_TYPE_PT_GENERATE_LE            // emit password candidates little-endian (WPA PBKDF2 expects LE words)
                             | OPTS_TYPE_MULTIHASH_DESPITE_ESALT   // allow many digests under one salt even though each digest has its own esalt: the single comp kernel iterates them itself rather than relying on per-digest dispatch
                             | OPTS_TYPE_COPY_TMPS;                // copy tmps (the derived PMK) back to host on a crack so the potfile line can be rebuilt
// Note the flags deliberately NOT set here: no OPTS_TYPE_DEEP_COMP_KERNEL and
// no AUX1..4, because config A uses a single comp kernel that loops the salt's
// digests and switches on type, so there is no per-digest comp dispatch and no
// separate aux kernels to enable. (ATTACK_EXEC_OUTSIDE_KERNEL / slow-hash split
// and HOOK23 are likewise unused by this config.)

// Return the display name; args unused, this mode has no per-run variation.
const char *module_hash_name (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return HASH_NAME; }
// Return the kernel/mode number so the engine loads the matching kernels.
u64         module_kern_type (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return KERN_TYPE; }
// Return the option bitmask defined above; constant for this mode.
u64         module_opts_type (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return OPTS_TYPE; }

// Register every module function pointer the engine calls.
void module_init (module_ctx_t *module_ctx)
{
  // Wire up the shared WPA implementation (decode/encode/postprocess/salt/
  // esalt/digest sizes, etc.). This macro also sets module_deep_comp_kernel to
  // MODULE_DEFAULT, i.e. unused — config A has no per-digest deep-comp kernel.
  WPA_MODULE_CTX_COMMON (module_ctx);
}
