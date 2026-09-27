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
#include "memory.h"
#include "parser.h"

static const u32   ATTACK_EXEC    = ATTACK_EXEC_OUTSIDE_KERNEL;
static const u32   DGST_POS0      = 0;
static const u32   DGST_POS1      = 2;
static const u32   DGST_POS2      = 4;
static const u32   DGST_POS3      = 6;
static const u32   DGST_SIZE      = DGST_SIZE_8_8;
static const u32   HASH_CATEGORY  = HASH_CATEGORY_DOCUMENTS;
static const char *HASH_NAME      = "MS Office Protection Verifier";
static const u64   KERN_TYPE      = 37141;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE
                                  | OPTS_TYPE_SELF_TEST_DISABLE;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = NULL;
static const char *ST_HASH        = NULL;

u32         module_attack_exec    (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return ATTACK_EXEC;     }
u32         module_dgst_pos0      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return DGST_POS0;       }
u32         module_dgst_pos1      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return DGST_POS1;       }
u32         module_dgst_pos2      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return DGST_POS2;       }
u32         module_dgst_pos3      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return DGST_POS3;       }
u32         module_dgst_size      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return DGST_SIZE;       }
u32         module_hash_category  (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return HASH_CATEGORY;   }
const char *module_hash_name      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return HASH_NAME;       }
u64         module_kern_type      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return KERN_TYPE;       }
u32         module_opti_type      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return OPTI_TYPE;       }
u64         module_opts_type      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return OPTS_TYPE;       }
u32         module_salt_type      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return SALT_TYPE;       }
const char *module_st_hash        (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return ST_HASH;         }
const char *module_st_pass        (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return ST_PASS;         }

typedef struct office_protect
{
  u32 hash_type; // 0=SHA-1, 1=SHA-256, 2=SHA-384, 3=SHA-512, 4=MD5, 5=MD4, 6=MD2
  u32 kdf_type;  // 0=iso, 1=crypt

} office_protect_t;

typedef struct office_protect_tmp
{
  u64 out[8];

} office_protect_tmp_t;

typedef enum kern_type_protect
{
  KERN_TYPE_PROTECT_SHA1   = 37111,
  KERN_TYPE_PROTECT_SHA256 = 37121,
  KERN_TYPE_PROTECT_SHA384 = 37131,
  KERN_TYPE_PROTECT_SHA512 = 37141,
  KERN_TYPE_PROTECT_MD5    = 37151,
  KERN_TYPE_PROTECT_MD4    = 37161,
  KERN_TYPE_PROTECT_MD2    = 37171,

} kern_type_protect_t;

static const char *SIGNATURE_OFFICE_PROTECT     = "$office-protect$";
static const char *SIGNATURE_OFFICE2016_COMPAT  = "$office$2016$0$";

// digest byte widths per hash_type, for validation and hex parsing
static const int DIGEST_BYTE_WIDTHS[] = { 20, 32, 48, 64, 16, 16, 16 };

// hash_type string tokens, ordered by hash_type enum value
static const char *HASH_TYPE_NAMES[] = { "sha1", "sha256", "sha384", "sha512", "md5", "md4", "md2" };

static int parse_hash_type (const u8 *buf, const int len)
{
  if ((len == 4) && (memcmp (buf, "sha1",   4) == 0)) return 0;
  if ((len == 6) && (memcmp (buf, "sha256", 6) == 0)) return 1;
  if ((len == 6) && (memcmp (buf, "sha384", 6) == 0)) return 2;
  if ((len == 6) && (memcmp (buf, "sha512", 6) == 0)) return 3;
  if ((len == 3) && (memcmp (buf, "md5",    3) == 0)) return 4;
  if ((len == 3) && (memcmp (buf, "md4",    3) == 0)) return 5;
  if ((len == 3) && (memcmp (buf, "md2",    3) == 0)) return 6;

  return -1;
}

static int parse_kdf_type (const u8 *buf, const int len)
{
  if ((len == 3) && (memcmp (buf, "iso",   3) == 0)) return 0;
  if ((len == 5) && (memcmp (buf, "crypt", 5) == 0)) return 1;

  return -1;
}

char *module_jit_build_options (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra, MAYBE_UNUSED const hashes_t *hashes, MAYBE_UNUSED const hc_device_param_t *device_param)
{
  char *jit_build_options = NULL;

  if (device_param->opencl_platform_vendor_id == VENDOR_ID_APPLE)
  {
    return jit_build_options;
  }

  if (device_param->opencl_device_vendor_id == VENDOR_ID_NV)
  {
    hc_asprintf (&jit_build_options, "-D _unroll");
  }

  if (device_param->opencl_device_vendor_id == VENDOR_ID_AMD_USE_HIP)
  {
    hc_asprintf (&jit_build_options, "-D _unroll");
  }

  if ((device_param->opencl_device_vendor_id == VENDOR_ID_AMD) && (device_param->has_vperm == true))
  {
    hc_asprintf (&jit_build_options, "-D _unroll");
  }

  return jit_build_options;
}

u64 module_esalt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 esalt_size = (const u64) sizeof (office_protect_t);

  return esalt_size;
}

u64 module_tmp_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 tmp_size = (const u64) sizeof (office_protect_tmp_t);

  return tmp_size;
}

u64 module_kern_type_dynamic (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info)
{
  const office_protect_t *office_protect = (const office_protect_t *) esalt_buf;

  switch (office_protect->hash_type)
  {
    case 0: return KERN_TYPE_PROTECT_SHA1;
    case 1: return KERN_TYPE_PROTECT_SHA256;
    case 2: return KERN_TYPE_PROTECT_SHA384;
    case 3: return KERN_TYPE_PROTECT_SHA512;
    case 4: return KERN_TYPE_PROTECT_MD5;
    case 5: return KERN_TYPE_PROTECT_MD4;
    case 6: return KERN_TYPE_PROTECT_MD2;
  }

  return (PARSER_HASH_LENGTH);
}

void *module_benchmark_esalt (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  office_protect_t *office_protect = (office_protect_t *) hcmalloc (sizeof (office_protect_t));

  office_protect->hash_type = 3; // SHA-512
  office_protect->kdf_type  = 0; // iso

  return office_protect;
}

salt_t *module_benchmark_salt (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  salt_t *salt = (salt_t *) hcmalloc (sizeof (salt_t));

  salt->salt_iter = 100000;
  salt->salt_len  = 16;

  return salt;
}

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u64 *digest = (u64 *) digest_buf;

  office_protect_t *office_protect = (office_protect_t *) esalt_buf;

  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  // --- Try new format first: $office-protect$*hash*kdf*iters*salt*hash ---

  token.token_cnt  = 6;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_OFFICE_PROTECT;

  // $office-protect$
  token.sep[0]     = '*';
  token.len[0]     = 16;
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  // hashfunc
  token.sep[1]     = '*';
  token.len_min[1] = 3;
  token.len_max[1] = 6;
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH;

  // kdf
  token.sep[2]     = '*';
  token.len_min[2] = 3;
  token.len_max[2] = 5;
  token.attr[2]    = TOKEN_ATTR_VERIFY_LENGTH;

  // iterations
  token.sep[3]     = '*';
  token.len_min[3] = 1;
  token.len_max[3] = 7;
  token.attr[3]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  // salt hex
  token.sep[4]     = '*';
  token.len_min[4] = 2;
  token.len_max[4] = 256;
  token.attr[4]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  // hash hex
  token.sep[5]     = '*';
  token.len_min[5] = 32;
  token.len_max[5] = 128;
  token.attr[5]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer == PARSER_OK)
  {
    // hashfunc
    const int ht = parse_hash_type (token.buf[1], token.len[1]);

    if (ht < 0) return (PARSER_SIGNATURE_UNMATCHED);

    office_protect->hash_type = (u32) ht;

    // kdf
    const int kt = parse_kdf_type (token.buf[2], token.len[2]);

    if (kt < 0) return (PARSER_SIGNATURE_UNMATCHED);

    office_protect->kdf_type = (u32) kt;

    // iterations
    const u32 iters = hc_strtoul ((const char *) token.buf[3], NULL, 10);

    salt->salt_iter = iters;

    // salt
    const u8 *salt_pos = token.buf[4];
    const int salt_len = token.len[4];

    const int salt_byte_len = salt_len / 2;

    if (salt_byte_len > 128) return (PARSER_SALT_LENGTH);

    for (int i = 0; i < salt_byte_len / 4; i++)
    {
      salt->salt_buf[i] = hex_to_u32 (salt_pos + (i * 8));
    }

    const int salt_rem = salt_byte_len % 4;

    if (salt_rem > 0)
    {
      u8 tmp_salt[4] = { 0 };

      for (int i = 0; i < salt_rem * 2; i++)
      {
        tmp_salt[i / 2] |= hex_convert (salt_pos[(salt_byte_len / 4) * 8 + i]) << (((i + 1) % 2) * 4);
      }

      memcpy (&salt->salt_buf[salt_byte_len / 4], tmp_salt, salt_rem);
    }

    salt->salt_len = salt_byte_len;

    // hash
    const u8 *hash_pos = token.buf[5];
    const int hash_len = token.len[5];
    const int hash_byte_len = hash_len / 2;

    const int expected_bytes = DIGEST_BYTE_WIDTHS[ht];

    if (hash_byte_len != expected_bytes) return (PARSER_HASH_LENGTH);

    memset (digest, 0, 64);

    if (ht == 2 || ht == 3)
    {
      // SHA-384 (6 words) or SHA-512 (8 words): u64 hash words
      const int n_words = (ht == 2) ? 6 : 8;

      for (int i = 0; i < n_words; i++)
      {
        digest[i] = byte_swap_64 (hex_to_u64 (hash_pos + (i * 16)));
      }
    }
    else if (ht == 4 || ht == 5 || ht == 6)
    {
      // MD5, MD4 or MD2: 4 u32 LE words, each stored in its own u64 slot
      for (int i = 0; i < 4; i++)
      {
        digest[i] = (u64) hex_to_u32 (hash_pos + (i * 8));
      }
    }
    else
    {
      // SHA-1 (5 words) or SHA-256 (8 words): u32 BE words in u64 slots
      const int n_words = (ht == 0) ? 5 : 8;

      for (int i = 0; i < n_words; i++)
      {
        digest[i] = (u64) byte_swap_32 (hex_to_u32 (hash_pos + (i * 8)));
      }
    }

    return (PARSER_OK);
  }

  // --- Try legacy format: $office$2016$0$<spin>$<saltb64>$<hashb64> ---

  memset (&token, 0, sizeof (hc_token_t));

  token.token_cnt  = 4;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_OFFICE2016_COMPAT;

  token.len[0]     = 15;
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.sep[1]     = '$';
  token.len_min[1] = 1;
  token.len_max[1] = 7;
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[2]     = '$';
  token.len_min[2] = 4;
  token.len_max[2] = 180;
  token.attr[2]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_BASE64A;

  token.sep[3]     = '$';
  token.len_min[3] = 4;
  token.len_max[3] = 180;
  token.attr[3]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_BASE64A;

  const int rc_legacy = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_legacy != PARSER_OK) return (rc_tokenizer);

  // legacy is always SHA-512 / iso
  office_protect->hash_type = 3;
  office_protect->kdf_type  = 0;

  // spinCount
  const u32 spinCount = hc_strtoul ((const char *) token.buf[1], NULL, 10);

  salt->salt_iter = spinCount;

  // salt (base64)
  const u8 *salt_b64_pos = token.buf[2];
  const int salt_b64_len = token.len[2];

  u8 tmp_buf[256];

  memset (tmp_buf, 0, sizeof (tmp_buf));

  int tmp_len = base64_decode (base64_to_int, salt_b64_pos, salt_b64_len, tmp_buf);

  if ((tmp_len < 1) || (tmp_len > 128)) return (PARSER_SALT_LENGTH);

  memcpy (salt->salt_buf, tmp_buf, tmp_len);

  salt->salt_len = tmp_len;

  // hash (base64)
  const u8 *hash_b64_pos = token.buf[3];
  const int hash_b64_len = token.len[3];

  memset (tmp_buf, 0, sizeof (tmp_buf));

  tmp_len = base64_decode (base64_to_int, hash_b64_pos, hash_b64_len, tmp_buf);

  if (tmp_len != 64) return (PARSER_HASH_LENGTH);

  memset (digest, 0, 64);
  memcpy (digest, tmp_buf, tmp_len);

  digest[0] = byte_swap_64 (digest[0]);
  digest[1] = byte_swap_64 (digest[1]);
  digest[2] = byte_swap_64 (digest[2]);
  digest[3] = byte_swap_64 (digest[3]);
  digest[4] = byte_swap_64 (digest[4]);
  digest[5] = byte_swap_64 (digest[5]);
  digest[6] = byte_swap_64 (digest[6]);
  digest[7] = byte_swap_64 (digest[7]);

  return (PARSER_OK);
}

int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const u64 *digest = (const u64 *) digest_buf;

  const office_protect_t *office_protect = (const office_protect_t *) esalt_buf;

  const u32 ht = office_protect->hash_type;
  const u32 kt = office_protect->kdf_type;

  const char *hash_name = (ht <= 6) ? HASH_TYPE_NAMES[ht] : "sha512";
  const char *kdf_name  = (kt == 1) ? "crypt" : "iso";
  const u32   iters     = salt->salt_iter;

  u8 *out_buf = (u8 *) line_buf;

  int out_len = snprintf ((char *) out_buf, line_size, "%s*%s*%s*%u*",
    SIGNATURE_OFFICE_PROTECT,
    hash_name,
    kdf_name,
    iters);

  // salt hex
  const u8 *salt_bytes = (const u8 *) salt->salt_buf;

  for (int i = 0; i < (int) salt->salt_len; i++)
  {
    out_len += snprintf ((char *) out_buf + out_len, line_size - out_len, "%02x", salt_bytes[i]);
  }

  out_buf[out_len++] = '*';

  // hash hex - per hash type
  if (ht == 2 || ht == 3)
  {
    // SHA-384 or SHA-512: u64 words stored as big-endian values
    const int n_words = (ht == 2) ? 6 : 8;

    for (int i = 0; i < n_words; i++)
    {
      u64 w = byte_swap_64 (digest[i]);
      const u8 *bytes = (const u8 *) &w;

      for (int j = 0; j < 8; j++)
      {
        out_len += snprintf ((char *) out_buf + out_len, line_size - out_len, "%02x", bytes[j]);
      }
    }
  }
  else if (ht == 4 || ht == 5 || ht == 6)
  {
    // MD5, MD4 or MD2: u32 LE words in u64 slots
    for (int i = 0; i < 4; i++)
    {
      u32 w = (u32) digest[i];
      const u8 *bytes = (const u8 *) &w;

      for (int j = 0; j < 4; j++)
      {
        out_len += snprintf ((char *) out_buf + out_len, line_size - out_len, "%02x", bytes[j]);
      }
    }
  }
  else
  {
    // SHA-1 or SHA-256: u32 BE words in u64 slots
    const int n_words = (ht == 0) ? 5 : 8;

    for (int i = 0; i < n_words; i++)
    {
      const u32 w = (u32) digest[i];

      out_len += snprintf ((char *) out_buf + out_len, line_size - out_len, "%02x%02x%02x%02x",
        (w >> 24) & 0xff, (w >> 16) & 0xff, (w >> 8) & 0xff, w & 0xff);
    }
  }

  return out_len;
}

void module_init (module_ctx_t *module_ctx)
{
  module_ctx->module_context_size             = MODULE_CONTEXT_SIZE_CURRENT;
  module_ctx->module_interface_version        = MODULE_INTERFACE_VERSION_CURRENT;

  module_ctx->module_advice_notice            = MODULE_DEFAULT;
  module_ctx->module_attack_exec              = module_attack_exec;
  module_ctx->module_benchmark_esalt          = module_benchmark_esalt;
  module_ctx->module_benchmark_hook_salt      = MODULE_DEFAULT;
  module_ctx->module_benchmark_mask           = MODULE_DEFAULT;
  module_ctx->module_benchmark_charset        = MODULE_DEFAULT;
  module_ctx->module_benchmark_salt           = module_benchmark_salt;
  module_ctx->module_bridge_name              = MODULE_DEFAULT;
  module_ctx->module_bridge_type              = MODULE_DEFAULT;
  module_ctx->module_build_plain_postprocess  = MODULE_DEFAULT;
  module_ctx->module_deep_comp_kernel         = MODULE_DEFAULT;
  module_ctx->module_deprecated_notice        = MODULE_DEFAULT;
  module_ctx->module_dgst_pos0                = module_dgst_pos0;
  module_ctx->module_dgst_pos1                = module_dgst_pos1;
  module_ctx->module_dgst_pos2                = module_dgst_pos2;
  module_ctx->module_dgst_pos3                = module_dgst_pos3;
  module_ctx->module_dgst_size                = module_dgst_size;
  module_ctx->module_esalt_size               = module_esalt_size;
  module_ctx->module_extra_buffer_size        = MODULE_DEFAULT;
  module_ctx->module_extra_tmp_size           = MODULE_DEFAULT;
  module_ctx->module_extra_tuningdb_block     = MODULE_DEFAULT;
  module_ctx->module_forced_outfile_format    = MODULE_DEFAULT;
  module_ctx->module_hash_binary_count        = MODULE_DEFAULT;
  module_ctx->module_hash_binary_parse        = MODULE_DEFAULT;
  module_ctx->module_hash_binary_save         = MODULE_DEFAULT;
  module_ctx->module_hash_decode_postprocess  = MODULE_DEFAULT;
  module_ctx->module_hash_decode_potfile      = MODULE_DEFAULT;
  module_ctx->module_hash_decode_zero_hash    = MODULE_DEFAULT;
  module_ctx->module_hash_decode              = module_hash_decode;
  module_ctx->module_hash_encode_status       = MODULE_DEFAULT;
  module_ctx->module_hash_encode_potfile      = MODULE_DEFAULT;
  module_ctx->module_hash_encode              = module_hash_encode;
  module_ctx->module_hash_hints               = MODULE_DEFAULT;
  module_ctx->module_hash_init_selftest       = MODULE_DEFAULT;
  module_ctx->module_hash_mode                = MODULE_DEFAULT;
  module_ctx->module_hash_category            = module_hash_category;
  module_ctx->module_hash_name                = module_hash_name;
  module_ctx->module_hashes_count_min         = MODULE_DEFAULT;
  module_ctx->module_hashes_count_max         = MODULE_DEFAULT;
  module_ctx->module_hlfmt_disable            = MODULE_DEFAULT;
  module_ctx->module_hook_extra_param_size    = MODULE_DEFAULT;
  module_ctx->module_hook_extra_param_init    = MODULE_DEFAULT;
  module_ctx->module_hook_extra_param_term    = MODULE_DEFAULT;
  module_ctx->module_hook12                   = MODULE_DEFAULT;
  module_ctx->module_hook23                   = MODULE_DEFAULT;
  module_ctx->module_hook_salt_size           = MODULE_DEFAULT;
  module_ctx->module_hook_size                = MODULE_DEFAULT;
  module_ctx->module_jit_build_options        = module_jit_build_options;
  module_ctx->module_jit_cache_disable        = MODULE_DEFAULT;
  module_ctx->module_kernel_accel_max         = MODULE_DEFAULT;
  module_ctx->module_kernel_accel_min         = MODULE_DEFAULT;
  module_ctx->module_kernel_loops_max         = MODULE_DEFAULT;
  module_ctx->module_kernel_loops_min         = MODULE_DEFAULT;
  module_ctx->module_kernel_threads_max       = MODULE_DEFAULT;
  module_ctx->module_kernel_threads_min       = MODULE_DEFAULT;
  module_ctx->module_kern_type                = module_kern_type;
  module_ctx->module_kern_type_dynamic        = module_kern_type_dynamic;
  module_ctx->module_opti_type                = module_opti_type;
  module_ctx->module_opts_type                = module_opts_type;
  module_ctx->module_outfile_check_disable    = MODULE_DEFAULT;
  module_ctx->module_outfile_check_nocomp     = MODULE_DEFAULT;
  module_ctx->module_potfile_custom_check     = MODULE_DEFAULT;
  module_ctx->module_potfile_disable          = MODULE_DEFAULT;
  module_ctx->module_potfile_keep_all_hashes  = MODULE_DEFAULT;
  module_ctx->module_pwdump_column            = MODULE_DEFAULT;
  module_ctx->module_pw_max                   = MODULE_DEFAULT;
  module_ctx->module_pw_min                   = MODULE_DEFAULT;
  module_ctx->module_salt_max                 = MODULE_DEFAULT;
  module_ctx->module_salt_min                 = MODULE_DEFAULT;
  module_ctx->module_salt_type                = module_salt_type;
  module_ctx->module_separator                = MODULE_DEFAULT;
  module_ctx->module_st_hash                  = module_st_hash;
  module_ctx->module_st_pass                  = module_st_pass;
  module_ctx->module_tmp_size                 = module_tmp_size;
  module_ctx->module_unstable_warning         = MODULE_DEFAULT;
  module_ctx->module_usage_notice             = MODULE_DEFAULT;
  module_ctx->module_warmup_disable           = MODULE_DEFAULT;
}
