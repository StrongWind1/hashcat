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

#include <inttypes.h>

static const u32   ATTACK_EXEC    = ATTACK_EXEC_INSIDE_KERNEL;
static const u32   DGST_POS0      = 0;
static const u32   DGST_POS1      = 1;
static const u32   DGST_POS2      = 2;
static const u32   DGST_POS3      = 3;
static const u32   DGST_SIZE      = DGST_SIZE_4_4;
static const u32   HASH_CATEGORY  = HASH_CATEGORY_ARCHIVE;
static const char *HASH_NAME      = "ZIP traditional encryption (ZipCrypto)";
static const u64   KERN_TYPE      = 46100;
static const u32   OPTI_TYPE      = 0;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_NATIVE_THREADS;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "$zip$1$*1*a8eedebcb5ef1b88b056e6ac/74*0*742eada9*36*36*4a5ff13279fbcab3e05f8bb2e5f2a1541a0726c2068d8425d89256ac7bfefa7dd3066c882bc9e0b05913e9e72ae1aa88beb741ea820c$/zip$";

#include "zip_traditional.c"

#include "hooks_common.c"

static bool module_unstable_warning (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra, MAYBE_UNUSED const hc_device_param_t *device_param)
{
  if ((device_param->opencl_platform_vendor_id == VENDOR_ID_APPLE) && (device_param->opencl_device_vendor_id == VENDOR_ID_AMD) && (device_param->opencl_device_type & CL_DEVICE_TYPE_GPU))
  {
    // Apple, OpenCL, AMD GPU: abort on the first kernel launch, signal 6, no output

    return true;
  }

  if ((device_param->opencl_platform_vendor_id == VENDOR_ID_APPLE) && (device_param->opencl_device_vendor_id == VENDOR_ID_INTEL_SDK) && (device_param->opencl_device_type & CL_DEVICE_TYPE_GPU))
  {
    // Apple, OpenCL, Intel GPU: the shader compiler does not come back from register allocation

    return true;
  }

  return false;
}

static u64 module_esalt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 esalt_size = (const u64) sizeof (zip1_t);

  return esalt_size;
}

// The decoder costs every candidate several times what the rest of the kernel does, so it is
// compiled in only when a line that is loaded holds a deflate stream.

static char *module_jit_build_options (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra, MAYBE_UNUSED const hashes_t *hashes, MAYBE_UNUSED const hc_device_param_t *device_param)
{
  const zip1_t *zips = (const zip1_t *) hashes->esalts_buf;

  bool inflate = false;

  for (u32 i = 0; i < hashes->digests_cnt; i++)
  {
    if ((zips[i].verify == ZIP1_VERIFY_INFLATE) || (zips[i].verify == ZIP1_VERIFY_PREFIX)) inflate = true;
  }

  char *jit_build_options = NULL;

  if (inflate == true) hc_asprintf (&jit_build_options, "-D ZIP1_INFLATE");

  return jit_build_options;
}

static const char *module_usage_notice (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  return ZIP1_USAGE_NOTICE;
}

static int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  return zip1_hash_decode ((u32 *) digest_buf, salt, (zip1_t *) esalt_buf, line_buf, line_len);
}

static int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  return zip1_hash_encode ((const zip1_t *) esalt_buf, line_buf, line_size);
}

void module_init (module_ctx_t *module_ctx)
{
  module_init_common (module_ctx);

  module_ctx->module_esalt_size               = module_esalt_size;
  module_ctx->module_hash_decode              = module_hash_decode;
  module_ctx->module_hash_encode              = module_hash_encode;
  module_ctx->module_jit_build_options        = module_jit_build_options;
  module_ctx->module_unstable_warning         = module_unstable_warning;
  module_ctx->module_usage_notice             = module_usage_notice;
}
