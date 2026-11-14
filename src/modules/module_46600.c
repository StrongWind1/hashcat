/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "modules.h"
#include "bitops.h"
#include "convert.h"
#include "shared.h"
#include "parser.h"
#include "memory.h"
#include "module_options.h"

static const u32   ATTACK_EXEC    = ATTACK_EXEC_OUTSIDE_KERNEL;
static const u32   DGST_POS0      = 0;
static const u32   DGST_POS1      = 1;
static const u32   DGST_POS2      = 2;
static const u32   DGST_POS3      = 3;
static const u32   DGST_SIZE      = DGST_SIZE_4_4;
static const u32   HASH_CATEGORY  = HASH_CATEGORY_ARCHIVE;
static const char *HASH_NAME      = "RAR 2.0 (Feistel block cipher)";
static const u64   KERN_TYPE      = 46600;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "password";
static const char *ST_HASH        = "$rar$20$*967e05a2*57*60*30*2d422ae3e5206e813239c637f0aeff180d6266bb652bfbeb7f4618b0ec235a4422a85cf9e49b0bff424a2e84cf02d0d4949dbcbc3c853b3fee4e1b2e870b01182774639daa9dc66bde1ad320111db098cd8091f1da0d28062aa8843d65a2ce9d$/rar$";

static const char *SIGNATURE_RAR_LEGACY = "$rar$20$";
static const u32   RAR_LEGACY_TYPE      = 20;

static u64 module_kern_bits (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  return KERN_BIT_HOOK12 | KERN_BIT_HOOK23;
}

#include "hooks_common.c"

// The decompressor, the host side of the cipher and everything else this module shares with its
// sibling.

#include "rar_legacy.c"

static const char *module_usage_notice (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  return "You can use https://github.com/hashcat/hashcat/blob/master/tools/rar2hashcat.py or ArchiveWolf to extract the hashes. A line carries the whole encrypted entry. The password is used as raw bytes, in the code page of the system that created the archive.";
}

static u64 module_esalt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  return (u64) sizeof (rar_legacy_t);
}

static u64 module_hook_salt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  return (u64) sizeof (rar_legacy_hook_salt_t);
}

static u64 module_hook_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  return (u64) sizeof (rar20_hook_t);
}

static u64 module_hook_extra_param_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  return (u64) sizeof (rar_legacy_hook_extra_t);
}

static bool module_hook_extra_param_init (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, MAYBE_UNUSED const hashconfig_t *hashconfig, const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra, MAYBE_UNUSED const folder_config_t *folder_config, MAYBE_UNUSED const backend_ctx_t *backend_ctx, void *hook_extra_param)
{
  memset (hook_extra_param, 0, sizeof (rar_legacy_hook_extra_t));

  rar_legacy_hook_extra_t *extra = (rar_legacy_hook_extra_t *) hook_extra_param;

  extra->key_setup = module_option_u32 (user_options, OPTION_RAR20_KEY_SETUP);

  return true;
}

static bool module_hook_extra_param_term (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra, MAYBE_UNUSED const folder_config_t *folder_config, MAYBE_UNUSED const backend_ctx_t *backend_ctx, void *hook_extra_param)
{
  return rarl_hook_extra_param_term (hook_extra_param);
}

static u64 module_tmp_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  return (u64) sizeof (rar20_tmp_t);
}

// A batch is held for as long as its key setup takes, and that is long for this cipher. Small
// batches keep the status and a found password timely.

static u32 module_kernel_accel_max (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u32 kernel_accel_max = 64;

  return kernel_accel_max;
}

// The kernel keeps one 256 byte table for each thread of a work group in shared memory, and has
// room for this many.

static u32 module_kernel_threads_max (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u32 kernel_threads_max = 64;

  return kernel_threads_max;
}

static u32 module_kernel_loops_min (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return 1; }
static u32 module_kernel_loops_max (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return 1; }

// RAR 1.5 and 2.0 take at most 127 password bytes.

static u32 module_pw_max (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return 127; }

static const module_option_t *module_register_options (void)
{
  return rarl_register_options ();
}

static void module_hook12 (hc_device_param_t *device_param, const void *hook_extra_param, const void *hook_salts_buf, const u32 salt_pos, const u64 pw_pos)
{
  rarl_hook12 (device_param, hook_extra_param, hook_salts_buf, salt_pos, pw_pos);
}

static char *module_jit_build_options (MAYBE_UNUSED const hashconfig_t *hashconfig, const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra, MAYBE_UNUSED const hashes_t *hashes, const hc_device_param_t *device_param)
{
  char *jit_build_options = NULL;

  if (rarl_host_key (device_param, module_option_u32 (user_options, OPTION_RAR20_KEY_SETUP)) == true) hc_asprintf (&jit_build_options, "-D RARL_HOST_KEY");

  return jit_build_options;
}

static char *module_extra_tuningdb_block (MAYBE_UNUSED const hashconfig_t *hashconfig, const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra, const backend_ctx_t *backend_ctx, const hashes_t *hashes, const u32 device_id, MAYBE_UNUSED const u32 kernel_accel_user)
{
  return rarl_extra_tuningdb_block (user_options, backend_ctx, hashes, device_id, 64);
}

static void module_hook23 (hc_device_param_t *device_param, const void *hook_extra_param, const void *hook_salts_buf, const u32 salt_pos, const u64 pw_pos)
{
  rarl_hook23 (device_param, hook_extra_param, hook_salts_buf, salt_pos, pw_pos);
}

static int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  return rarl_hash_decode (SIGNATURE_RAR_LEGACY, RAR_LEGACY_TYPE, (u32 *) digest_buf, salt, (rar_legacy_t *) esalt_buf, (rar_legacy_hook_salt_t *) hook_salt_buf, line_buf, line_len);
}

static int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  return rarl_hash_encode (SIGNATURE_RAR_LEGACY, (const rar_legacy_hook_salt_t *) hook_salt_buf, line_buf, line_size);
}

void module_init (module_ctx_t *module_ctx)
{
  module_init_common (module_ctx);

  module_ctx->module_esalt_size                = module_esalt_size;
  module_ctx->module_extra_tuningdb_block      = module_extra_tuningdb_block;
  module_ctx->module_hash_decode               = module_hash_decode;
  module_ctx->module_hash_encode               = module_hash_encode;
  module_ctx->module_hook12                    = module_hook12;
  module_ctx->module_hook23                    = module_hook23;
  module_ctx->module_hook_extra_param_size     = module_hook_extra_param_size;
  module_ctx->module_hook_extra_param_init     = module_hook_extra_param_init;
  module_ctx->module_hook_extra_param_term     = module_hook_extra_param_term;
  module_ctx->module_hook_salt_size            = module_hook_salt_size;
  module_ctx->module_hook_size                 = module_hook_size;
  module_ctx->module_jit_build_options         = module_jit_build_options;
  module_ctx->module_kern_bits                 = module_kern_bits;
  module_ctx->module_kernel_accel_max          = module_kernel_accel_max;
  module_ctx->module_kernel_threads_max        = module_kernel_threads_max;
  module_ctx->module_kernel_loops_max          = module_kernel_loops_max;
  module_ctx->module_kernel_loops_min          = module_kernel_loops_min;
  module_ctx->module_pw_max                    = module_pw_max;
  module_ctx->module_register_options          = module_register_options;
  module_ctx->module_tmp_size                  = module_tmp_size;
  module_ctx->module_usage_notice              = module_usage_notice;
}
