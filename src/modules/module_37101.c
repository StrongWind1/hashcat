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

static const u32   ATTACK_EXEC    = ATTACK_EXEC_INSIDE_KERNEL;
static const u32   DGST_POS0      = 0;
static const u32   DGST_POS1      = 1;
static const u32   DGST_POS2      = 2;
static const u32   DGST_POS3      = 3;
static const u32   DGST_SIZE      = DGST_SIZE_4_4;
static const u32   HASH_CATEGORY  = HASH_CATEGORY_DOCUMENTS;
static const char *HASH_NAME      = "MS Office Document-Open (Legacy RC4), collider #1";
static const u64   KERN_TYPE      = 37041;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE
                                  | OPTI_TYPE_PRECOMPUTE_INIT
                                  | OPTI_TYPE_NOT_ITERATED;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE
                                  | OPTS_TYPE_PT_ADD80
                                  | OPTS_TYPE_PT_ALWAYS_HEXIFY
                                  | OPTS_TYPE_AUTODETECT_DISABLE
                                  | OPTS_TYPE_SELF_TEST_DISABLE;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *BENCHMARK_MASK = "?b?b?b?b?b";
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

typedef struct office_rc4
{
  u32 hash_type;
  u32 key_bits;
  u32 version;
  u32 encryptedVerifier[4];
  u32 encryptedVerifierHash[5];
  u32 secondBlockData[8];
  u32 secondBlockLen;
  u32 rc4key[2];

} office_rc4_t;

static const char *SIGNATURE_OFFICE_OPEN = "$office-open$";

enum
{
  KERN_TYPE_OFFICE_RC4_SHA1_COLL1 = 37041,
  KERN_TYPE_OFFICE_RC4_MD5_COLL1  = 37031,
};

u64 module_kern_type_dynamic (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info)
{
  const office_rc4_t *office_rc4 = (const office_rc4_t *) esalt_buf;

  if (office_rc4->hash_type == 0) return KERN_TYPE_OFFICE_RC4_MD5_COLL1;
  if (office_rc4->hash_type == 1) return KERN_TYPE_OFFICE_RC4_SHA1_COLL1;

  return (u64) -1;
}

char *module_jit_build_options (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra, MAYBE_UNUSED const hashes_t *hashes, MAYBE_UNUSED const hc_device_param_t *device_param)
{
  char *jit_build_options = NULL;

  u32 native_threads = (device_param->opencl_device_type & CL_DEVICE_TYPE_CPU) ? 1 : 32;

  hc_asprintf (&jit_build_options, "-D FIXED_LOCAL_SIZE=%u", native_threads);

  return jit_build_options;
}

u64 module_esalt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 esalt_size = (const u64) sizeof (office_rc4_t);

  return esalt_size;
}

u32 module_pw_min (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u32 pw_min = 5;

  return pw_min;
}

u32 module_pw_max (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u32 pw_max = 5;

  return pw_max;
}

const char *module_benchmark_mask (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  return BENCHMARK_MASK;
}

u32 module_forced_outfile_format (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u32 forced_outfile_format = OUTFILE_FMT_HASH | OUTFILE_FMT_HEXPLAIN;

  return forced_outfile_format;
}

void *module_benchmark_esalt (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  office_rc4_t *office_rc4 = (office_rc4_t *) hcmalloc (sizeof (office_rc4_t));

  office_rc4->hash_type = 0;
  office_rc4->key_bits  = 40;
  office_rc4->version   = 0;

  return office_rc4;
}

salt_t *module_benchmark_salt (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  salt_t *salt = (salt_t *) hcmalloc (sizeof (salt_t));

  salt->salt_len  = 16;
  salt->salt_iter = 0;

  return salt;
}

static int parse_oldoffice (const char *line_buf, const int line_len, u32 *digest, salt_t *salt, office_rc4_t *office_rc4)
{
  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  token.token_cnt  = 5;

  token.signatures_cnt    = 5;
  token.signatures_buf[0] = "$oldoffice$0";
  token.signatures_buf[1] = "$oldoffice$1";
  token.signatures_buf[2] = "$oldoffice$2";
  token.signatures_buf[3] = "$oldoffice$3";
  token.signatures_buf[4] = "$oldoffice$4";

  token.sep[0]     = '*';
  token.len[0]     = 11;
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.sep[1]     = '*';
  token.len[1]     = 1;
  token.attr[1]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[2]     = '*';
  token.len[2]     = 32;
  token.attr[2]    = TOKEN_ATTR_FIXED_LENGTH;

  token.sep[3]     = '*';
  token.len[3]     = 32;
  token.attr[3]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.sep[4]     = '*';
  token.len_min[4] = 32;
  token.len_max[4] = 40;
  token.attr[4]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  const u8 *version_pos               = token.buf[1];
  const u8 *osalt_pos                 = token.buf[2];
  const u8 *encryptedVerifier_pos     = token.buf[3];
  const u8 *encryptedVerifierHash_pos = token.buf[4];
  const int encryptedVerifierHash_len = token.len[4];

  const u32 version = *version_pos - 0x30;

  if (version <= 2)
  {
    office_rc4->hash_type = 0;
    office_rc4->key_bits  = (version == 2) ? 56 : 40;
    office_rc4->version   = version;
  }
  else if (version <= 4)
  {
    office_rc4->hash_type = 1;
    office_rc4->key_bits  = (version == 3) ? 40 : 128;
    office_rc4->version   = version;
  }
  else
  {
    return (PARSER_SALT_VALUE);
  }

  office_rc4->encryptedVerifier[0] = hex_to_u32 (encryptedVerifier_pos +  0);
  office_rc4->encryptedVerifier[1] = hex_to_u32 (encryptedVerifier_pos +  8);
  office_rc4->encryptedVerifier[2] = hex_to_u32 (encryptedVerifier_pos + 16);
  office_rc4->encryptedVerifier[3] = hex_to_u32 (encryptedVerifier_pos + 24);

  office_rc4->encryptedVerifierHash[0] = hex_to_u32 (encryptedVerifierHash_pos +  0);
  office_rc4->encryptedVerifierHash[1] = hex_to_u32 (encryptedVerifierHash_pos +  8);
  office_rc4->encryptedVerifierHash[2] = hex_to_u32 (encryptedVerifierHash_pos + 16);
  office_rc4->encryptedVerifierHash[3] = hex_to_u32 (encryptedVerifierHash_pos + 24);

  if (encryptedVerifierHash_len == 40)
  {
    office_rc4->encryptedVerifierHash[4] = hex_to_u32 (encryptedVerifierHash_pos + 32);
  }
  else
  {
    office_rc4->encryptedVerifierHash[4] = 0;
  }

  salt->salt_len = 16;

  salt->salt_buf[ 0] = hex_to_u32 (osalt_pos +  0);
  salt->salt_buf[ 1] = hex_to_u32 (osalt_pos +  8);
  salt->salt_buf[ 2] = hex_to_u32 (osalt_pos + 16);
  salt->salt_buf[ 3] = hex_to_u32 (osalt_pos + 24);

  salt->salt_buf[ 4] = office_rc4->encryptedVerifier[0];
  salt->salt_buf[ 5] = office_rc4->encryptedVerifier[1];
  salt->salt_buf[ 6] = office_rc4->encryptedVerifier[2];
  salt->salt_buf[ 7] = office_rc4->encryptedVerifier[3];
  salt->salt_buf[ 8] = office_rc4->encryptedVerifierHash[0];
  salt->salt_buf[ 9] = office_rc4->encryptedVerifierHash[1];
  salt->salt_buf[10] = office_rc4->encryptedVerifierHash[2];
  salt->salt_buf[11] = office_rc4->encryptedVerifierHash[3];

  salt->salt_len += 32;

  digest[0] = office_rc4->encryptedVerifierHash[0];
  digest[1] = office_rc4->encryptedVerifierHash[1];
  digest[2] = office_rc4->encryptedVerifierHash[2];
  digest[3] = office_rc4->encryptedVerifierHash[3];

  return (PARSER_OK);
}

static int parse_office_open_rc4 (const char *line_buf, const int line_len, u32 *digest, salt_t *salt, office_rc4_t *office_rc4)
{
  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  token.token_cnt  = 8;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = "$office-open$";

  token.sep[0]     = '*';
  token.len[0]     = 13;
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.sep[1]     = '*';
  token.len_min[1] = 3;
  token.len_max[1] = 6;
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH;

  token.sep[2]     = '*';
  token.len_min[2] = 6;
  token.len_max[2] = 7;
  token.attr[2]    = TOKEN_ATTR_VERIFY_LENGTH;

  token.sep[3]     = '*';
  token.len_min[3] = 3;
  token.len_max[3] = 6;
  token.attr[3]    = TOKEN_ATTR_VERIFY_LENGTH;

  token.sep[4]     = '*';
  token.len_min[4] = 1;
  token.len_max[4] = 7;
  token.attr[4]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[5]     = '*';
  token.len[5]     = 32;
  token.attr[5]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.sep[6]     = '*';
  token.len[6]     = 32;
  token.attr[6]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.sep[7]     = '*';
  token.len_min[7] = 32;
  token.len_max[7] = 40;
  token.attr[7]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  const u8 *hashfunc_pos = token.buf[1];
  const int hashfunc_len = token.len[1];
  const u8 *cipher_pos   = token.buf[2];
  const int cipher_len   = token.len[2];
  const u8 *salt_pos     = token.buf[5];
  const u8 *ev_pos       = token.buf[6];
  const u8 *evh_pos      = token.buf[7];
  const int evh_len      = token.len[7];

  if ((hashfunc_len == 3) && (memcmp (hashfunc_pos, "md5", 3) == 0))
  {
    office_rc4->hash_type = 0;
  }
  else if ((hashfunc_len == 4) && (memcmp (hashfunc_pos, "sha1", 4) == 0))
  {
    office_rc4->hash_type = 1;
  }
  else
  {
    return (PARSER_SIGNATURE_UNMATCHED);
  }

  if ((cipher_len >= 4) && (memcmp (cipher_pos, "rc4-", 4) == 0))
  {
    office_rc4->key_bits = (u32) strtoul ((const char *) cipher_pos + 4, NULL, 10);

    if ((office_rc4->key_bits < 40) || (office_rc4->key_bits > 128)) return (PARSER_SALT_VALUE);
    if (office_rc4->key_bits % 8 != 0) return (PARSER_SALT_VALUE);
  }
  else
  {
    return (PARSER_SIGNATURE_UNMATCHED);
  }

  if (office_rc4->hash_type == 0)
  {
    office_rc4->version = (office_rc4->key_bits == 40) ? 0 : 2;
  }
  else
  {
    office_rc4->version = (office_rc4->key_bits == 40) ? 3 : 4;
  }

  office_rc4->encryptedVerifier[0] = hex_to_u32 (ev_pos +  0);
  office_rc4->encryptedVerifier[1] = hex_to_u32 (ev_pos +  8);
  office_rc4->encryptedVerifier[2] = hex_to_u32 (ev_pos + 16);
  office_rc4->encryptedVerifier[3] = hex_to_u32 (ev_pos + 24);

  office_rc4->encryptedVerifierHash[0] = hex_to_u32 (evh_pos +  0);
  office_rc4->encryptedVerifierHash[1] = hex_to_u32 (evh_pos +  8);
  office_rc4->encryptedVerifierHash[2] = hex_to_u32 (evh_pos + 16);
  office_rc4->encryptedVerifierHash[3] = hex_to_u32 (evh_pos + 24);

  if (evh_len == 40)
  {
    office_rc4->encryptedVerifierHash[4] = hex_to_u32 (evh_pos + 32);
  }
  else
  {
    office_rc4->encryptedVerifierHash[4] = 0;
  }

  salt->salt_len = 16;

  salt->salt_buf[ 0] = hex_to_u32 (salt_pos +  0);
  salt->salt_buf[ 1] = hex_to_u32 (salt_pos +  8);
  salt->salt_buf[ 2] = hex_to_u32 (salt_pos + 16);
  salt->salt_buf[ 3] = hex_to_u32 (salt_pos + 24);

  salt->salt_buf[ 4] = office_rc4->encryptedVerifier[0];
  salt->salt_buf[ 5] = office_rc4->encryptedVerifier[1];
  salt->salt_buf[ 6] = office_rc4->encryptedVerifier[2];
  salt->salt_buf[ 7] = office_rc4->encryptedVerifier[3];
  salt->salt_buf[ 8] = office_rc4->encryptedVerifierHash[0];
  salt->salt_buf[ 9] = office_rc4->encryptedVerifierHash[1];
  salt->salt_buf[10] = office_rc4->encryptedVerifierHash[2];
  salt->salt_buf[11] = office_rc4->encryptedVerifierHash[3];

  salt->salt_len += 32;

  digest[0] = office_rc4->encryptedVerifierHash[0];
  digest[1] = office_rc4->encryptedVerifierHash[1];
  digest[2] = office_rc4->encryptedVerifierHash[2];
  digest[3] = office_rc4->encryptedVerifierHash[3];

  return (PARSER_OK);
}

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  office_rc4_t *office_rc4 = (office_rc4_t *) esalt_buf;

  memset (office_rc4, 0, sizeof (office_rc4_t));

  int rc = parse_office_open_rc4 (line_buf, line_len, digest, salt, office_rc4);

  if (rc != PARSER_OK)
  {
    rc = parse_oldoffice (line_buf, line_len, digest, salt, office_rc4);
  }

  return rc;
}

int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const office_rc4_t *office_rc4 = (const office_rc4_t *) esalt_buf;

  const char *hashfunc = (office_rc4->hash_type == 0) ? "md5" : "sha1";
  const int evh_words = (office_rc4->hash_type == 0) ? 4 : 5;

  char evh_hex[48];

  for (int i = 0; i < evh_words; i++)
  {
    u32_to_hex (byte_swap_32 (office_rc4->encryptedVerifierHash[i]), (u8 *) evh_hex + (i * 8));
  }

  evh_hex[evh_words * 8] = 0;

  const int line_len = snprintf (line_buf, line_size, "%s*%s*rc4-%u*stream*0*%08x%08x%08x%08x*%08x%08x%08x%08x*%s",
    SIGNATURE_OFFICE_OPEN,
    hashfunc,
    office_rc4->key_bits,
    byte_swap_32 (salt->salt_buf[0]),
    byte_swap_32 (salt->salt_buf[1]),
    byte_swap_32 (salt->salt_buf[2]),
    byte_swap_32 (salt->salt_buf[3]),
    byte_swap_32 (office_rc4->encryptedVerifier[0]),
    byte_swap_32 (office_rc4->encryptedVerifier[1]),
    byte_swap_32 (office_rc4->encryptedVerifier[2]),
    byte_swap_32 (office_rc4->encryptedVerifier[3]),
    evh_hex);

  return line_len;
}

void module_init (module_ctx_t *module_ctx)
{
  module_ctx->module_context_size             = MODULE_CONTEXT_SIZE_CURRENT;
  module_ctx->module_interface_version        = MODULE_INTERFACE_VERSION_CURRENT;

  module_ctx->module_advice_notice            = MODULE_DEFAULT;
  module_ctx->module_attack_exec              = module_attack_exec;
  module_ctx->module_benchmark_esalt          = module_benchmark_esalt;
  module_ctx->module_benchmark_hook_salt      = MODULE_DEFAULT;
  module_ctx->module_benchmark_mask           = module_benchmark_mask;
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
  module_ctx->module_forced_outfile_format    = module_forced_outfile_format;
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
  module_ctx->module_pw_max                   = module_pw_max;
  module_ctx->module_pw_min                   = module_pw_min;
  module_ctx->module_salt_max                 = MODULE_DEFAULT;
  module_ctx->module_salt_min                 = MODULE_DEFAULT;
  module_ctx->module_salt_type                = module_salt_type;
  module_ctx->module_separator                = MODULE_DEFAULT;
  module_ctx->module_st_hash                  = module_st_hash;
  module_ctx->module_st_pass                  = module_st_pass;
  module_ctx->module_tmp_size                 = MODULE_DEFAULT;
  module_ctx->module_unstable_warning         = MODULE_DEFAULT;
  module_ctx->module_usage_notice             = MODULE_DEFAULT;
  module_ctx->module_warmup_disable           = MODULE_DEFAULT;
}
