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
static const u32   DGST_POS1      = 1;
static const u32   DGST_POS2      = 2;
static const u32   DGST_POS3      = 3;
static const u32   DGST_SIZE      = DGST_SIZE_4_8;
static const u32   HASH_CATEGORY  = HASH_CATEGORY_DOCUMENTS;
static const char *HASH_NAME      = "Open Document Format (ODF) 1.1/1.2/1.3";
static const u64   KERN_TYPE      = 37321;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE
                                  | OPTI_TYPE_SLOW_HASH_SIMD_LOOP;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE
                                  | OPTS_TYPE_DYNAMIC_SHARED
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

typedef struct odf_tmp
{
  u32  ipad[5];
  u32  opad[5];

  u32  dgst[10];
  u32  out[10];

} odf_tmp_t;

typedef struct odf
{
  u32 start_key_type;
  u32 cipher_type;
  u32 key_size;
  u32 iv[4];
  u32 iv_len;
  u32 checksum[8];
  u32 encrypted_data[256];
  int encrypted_len;

} odf_t;

typedef enum kern_type_odf
{
  KERN_TYPE_ODF_SHA1_BLOWFISH = 37311,
  KERN_TYPE_ODF_SHA256_AES    = 37321,
  KERN_TYPE_ODF_SHA256_GCM    = 37322,

} kern_type_odf_t;

static const char *SIGNATURE_ODF = "$odf$";

u64 module_esalt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 esalt_size = (const u64) sizeof (odf_t);

  return esalt_size;
}

u64 module_tmp_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 tmp_size = (const u64) sizeof (odf_tmp_t);

  return tmp_size;
}

u32 module_pw_max (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u32 pw_max = 51;

  return pw_max;
}

u64 module_kern_type_dynamic (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info)
{
  const odf_t *odf = (const odf_t *) esalt_buf;

  if ((odf->start_key_type == 0) && (odf->cipher_type == 0))
  {
    return KERN_TYPE_ODF_SHA1_BLOWFISH;
  }
  else if ((odf->start_key_type == 1) && (odf->cipher_type == 1))
  {
    return KERN_TYPE_ODF_SHA256_AES;
  }
  else if ((odf->start_key_type == 1) && (odf->cipher_type == 2))
  {
    return KERN_TYPE_ODF_SHA256_GCM;
  }

  return KERN_TYPE_ODF_SHA256_AES;
}

void *module_benchmark_esalt (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  odf_t *odf = (odf_t *) hcmalloc (sizeof (odf_t));

  odf->start_key_type = 1;
  odf->cipher_type    = 1;
  odf->key_size       = 32;
  odf->iv_len         = 16;

  return odf;
}

salt_t *module_benchmark_salt (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  salt_t *salt = (salt_t *) hcmalloc (sizeof (salt_t));

  salt->salt_iter = 99999;
  salt->salt_len  = 16;

  return salt;
}

char *module_jit_build_options (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra, MAYBE_UNUSED const hashes_t *hashes, MAYBE_UNUSED const hc_device_param_t *device_param)
{
  // Always define FIXED_LOCAL_SIZE_COMP: m37311 (Blowfish) needs it and
  // m37321/m37322 (AES) ignore it.  In mixed-cipher runs the first esalt
  // may be AES, so checking only esalts_buf[0] would leave the macro
  // undefined and break Blowfish kernel compilation.

  char *jit_build_options = NULL;

  bool use_dynamic = false;

  if (device_param->is_cuda == true)
  {
    use_dynamic = true;
  }

  if (device_param->opencl_device_type & CL_DEVICE_TYPE_CPU)
  {
    hc_asprintf (&jit_build_options, "-D FIXED_LOCAL_SIZE_COMP=%u", 1);
  }
  else
  {
    u32 overhead = 0;

    if (device_param->opencl_device_vendor_id == VENDOR_ID_NV)
    {
      if (device_param->is_opencl == true)
      {
        overhead = 1;
      }
    }

    if (user_options->kernel_threads_chgd == true)
    {
      u32 fixed_local_size = user_options->kernel_threads;

      if (use_dynamic == true)
      {
        if ((fixed_local_size * 4096) > device_param->kernel_dynamic_local_mem_size[HC_DEV_KERN_MEMSET])
        {
          fixed_local_size = device_param->kernel_dynamic_local_mem_size[HC_DEV_KERN_MEMSET] / 4096;
        }

        hc_asprintf (&jit_build_options, "-D FIXED_LOCAL_SIZE_COMP=%u -D DYNAMIC_LOCAL", fixed_local_size);
      }
      else
      {
        if ((fixed_local_size * 4096) > (device_param->device_local_mem_size - overhead))
        {
          fixed_local_size = (device_param->device_local_mem_size - overhead) / 4096;
        }

        hc_asprintf (&jit_build_options, "-D FIXED_LOCAL_SIZE_COMP=%u", fixed_local_size);
      }
    }
    else
    {
      if (use_dynamic == true)
      {
        const u32 fixed_local_size = device_param->kernel_dynamic_local_mem_size[HC_DEV_KERN_MEMSET] / 4096;

        hc_asprintf (&jit_build_options, "-D FIXED_LOCAL_SIZE_COMP=%u -D DYNAMIC_LOCAL", fixed_local_size);
      }
      else
      {
        const u32 fixed_local_size = (device_param->device_local_mem_size - overhead) / 4096;

        hc_asprintf (&jit_build_options, "-D FIXED_LOCAL_SIZE_COMP=%u", fixed_local_size);
      }
    }
  }

  return jit_build_options;
}

static int parse_new_format (MAYBE_UNUSED const hashconfig_t *hashconfig, u32 *digest, salt_t *salt, odf_t *odf, const char *line_buf, const int line_len)
{
  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  token.token_cnt = 11;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_ODF;

  // $odf$
  token.sep[0]     = '*';
  token.len[0]     = 5;
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  // startkey: sha1 | sha256
  token.sep[1]     = '*';
  token.len_min[1] = 4;
  token.len_max[1] = 6;
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH;

  // kdf: pbkdf2
  token.sep[2]     = '*';
  token.len_min[2] = 6;
  token.len_max[2] = 6;
  token.attr[2]    = TOKEN_ATTR_VERIFY_LENGTH;

  // cipher: blowfish | aes256 | aes256gcm
  token.sep[3]     = '*';
  token.len_min[3] = 6;
  token.len_max[3] = 9;
  token.attr[3]    = TOKEN_ATTR_VERIFY_LENGTH;

  // iterations
  token.sep[4]     = '*';
  token.len_min[4] = 1;
  token.len_max[4] = 7;
  token.attr[4]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  // mem (0 for PBKDF2, up to 7 digits for Argon2)
  token.sep[5]     = '*';
  token.len_min[5] = 1;
  token.len_max[5] = 7;
  token.attr[5]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  // lanes (0 for PBKDF2, up to 3 digits for Argon2)
  token.sep[6]     = '*';
  token.len_min[6] = 1;
  token.len_max[6] = 3;
  token.attr[6]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  // salt hex
  token.sep[7]     = '*';
  token.len_min[7] = 2;
  token.len_max[7] = 256;
  token.attr[7]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  // iv hex
  token.sep[8]     = '*';
  token.len_min[8] = 16;
  token.len_max[8] = 32;
  token.attr[8]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  // checksum hex
  token.sep[9]     = '*';
  token.len_min[9] = 32;
  token.len_max[9] = 64;
  token.attr[9]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  // ciphertext hex
  token.sep[10]     = '*';
  token.len_min[10] = 16;
  token.len_max[10] = 2048;
  token.attr[10]    = TOKEN_ATTR_VERIFY_LENGTH
                    | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  // detect: if token[1] is a single digit, it's the legacy format
  if ((token.len[1] == 1) && (token.buf[1][0] >= '0') && (token.buf[1][0] <= '9')) return (PARSER_TOKEN_LENGTH);

  // startkey
  const u8 *startkey_pos = token.buf[1];
  const int startkey_len = token.len[1];

  if ((startkey_len == 4) && (memcmp (startkey_pos, "sha1", 4) == 0))
  {
    odf->start_key_type = 0;
  }
  else if ((startkey_len == 6) && (memcmp (startkey_pos, "sha256", 6) == 0))
  {
    odf->start_key_type = 1;
  }
  else
  {
    return (PARSER_SALT_VALUE);
  }

  // kdf
  const u8 *kdf_pos = token.buf[2];
  const int kdf_len = token.len[2];

  if ((kdf_len == 6) && (memcmp (kdf_pos, "pbkdf2", 6) == 0))
  {
    // PBKDF2 - supported
  }
  else if ((kdf_len == 6) && (memcmp (kdf_pos, "argon2", 6) == 0))
  {
    // Argon2 - not yet supported in kernels
    return (PARSER_SALT_VALUE);
  }
  else
  {
    return (PARSER_SALT_VALUE);
  }

  // cipher
  const u8 *cipher_pos = token.buf[3];
  const int cipher_len = token.len[3];

  if ((cipher_len == 8) && (memcmp (cipher_pos, "blowfish", 8) == 0))
  {
    odf->cipher_type = 0;
    odf->key_size    = 16;
  }
  else if ((cipher_len == 6) && (memcmp (cipher_pos, "aes256", 6) == 0))
  {
    odf->cipher_type = 1;
    odf->key_size    = 32;
  }
  else if ((cipher_len == 9) && (memcmp (cipher_pos, "aes256gcm", 9) == 0))
  {
    odf->cipher_type = 2;
    odf->key_size    = 32;
  }
  else
  {
    return (PARSER_SALT_VALUE);
  }

  // iterations
  const u32 iterations = hc_strtoul ((const char *) token.buf[4], NULL, 10);

  if (iterations < 1) return (PARSER_SALT_ITERATION);

  salt->salt_iter = iterations - 1;

  // salt
  const u8 *salt_pos = token.buf[7];
  const int salt_len = token.len[7];

  salt->salt_len = hex_decode (salt_pos, salt_len, (u8 *) salt->salt_buf);

  // iv
  const u8 *iv_pos = token.buf[8];
  const int iv_len = token.len[8];

  odf->iv_len = iv_len / 2;

  for (u32 i = 0; i < odf->iv_len / 4; i++)
  {
    odf->iv[i] = hex_to_u32 (iv_pos + (i * 8));
  }

  // checksum
  const u8 *checksum_pos = token.buf[9];
  const int checksum_len = token.len[9];
  const u32 checksum_words = checksum_len / 8;

  memset (odf->checksum, 0, sizeof (odf->checksum));

  for (u32 i = 0; i < checksum_words; i++)
  {
    odf->checksum[i] = hex_to_u32 (checksum_pos + (i * 8));
  }

  // ciphertext
  const u8 *ct_pos = token.buf[10];
  const int ct_len = token.len[10];

  odf->encrypted_len = hex_decode (ct_pos, ct_len, (u8 *) odf->encrypted_data);

  // digest
  memset (digest, 0, DGST_SIZE_4_8);

  for (u32 i = 0; i < checksum_words; i++)
  {
    digest[i] = odf->checksum[i];
  }

  return (PARSER_OK);
}

static int parse_legacy_format (MAYBE_UNUSED const hashconfig_t *hashconfig, u32 *digest, salt_t *salt, odf_t *odf, const char *line_buf, const int line_len)
{
  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  token.token_cnt = 12;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_ODF;

  token.sep[0]     = '*';
  token.len[0]     = 5;
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.sep[1]     = '*';
  token.len[1]     = 1;
  token.attr[1]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[2]     = '*';
  token.len[2]     = 1;
  token.attr[2]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[3]     = '*';
  token.len_min[3] = 4;
  token.len_max[3] = 6;
  token.attr[3]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[4]     = '*';
  token.len[4]     = 2;
  token.attr[4]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  // checksum: 40 hex (SHA-1) or 64 hex (SHA-256)
  token.sep[5]     = '*';
  token.len_min[5] = 40;
  token.len_max[5] = 64;
  token.attr[5]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  // iv_len digit
  token.sep[6]     = '*';
  token.len_min[6] = 1;
  token.len_max[6] = 2;
  token.attr[6]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  // iv hex
  token.sep[7]     = '*';
  token.len_min[7] = 16;
  token.len_max[7] = 32;
  token.attr[7]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  // salt_len digit
  token.sep[8]     = '*';
  token.len[8]     = 2;
  token.attr[8]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  // salt hex
  token.sep[9]     = '*';
  token.len[9]     = 32;
  token.attr[9]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  // unused
  token.sep[10]     = '*';
  token.len[10]     = 1;
  token.attr[10]    = TOKEN_ATTR_FIXED_LENGTH
                    | TOKEN_ATTR_VERIFY_DIGIT;

  // ciphertext
  token.sep[11]     = '*';
  token.len_min[11] = 16;
  token.len_max[11] = 2048;
  token.attr[11]    = TOKEN_ATTR_VERIFY_LENGTH
                    | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  const u32 cipher_type   = hc_strtoul ((const char *) token.buf[1],  NULL, 10);
  const u32 checksum_type = hc_strtoul ((const char *) token.buf[2],  NULL, 10);
  const u32 iterations    = hc_strtoul ((const char *) token.buf[3],  NULL, 10);
  const u32 key_size      = hc_strtoul ((const char *) token.buf[4],  NULL, 10);
  const u32 iv_len        = hc_strtoul ((const char *) token.buf[6],  NULL, 10);
  const u32 salt_len      = hc_strtoul ((const char *) token.buf[8],  NULL, 10);
  const u32 unused        = hc_strtoul ((const char *) token.buf[10], NULL, 10);

  if (unused != 0) return (PARSER_SALT_VALUE);

  // map legacy cipher_type/checksum_type to unified fields
  if ((cipher_type == 0) && (checksum_type == 0))
  {
    odf->start_key_type = 0;
    odf->cipher_type    = 0;
    odf->key_size       = key_size;
  }
  else if ((cipher_type == 1) && (checksum_type == 1))
  {
    odf->start_key_type = 1;
    odf->cipher_type    = 1;
    odf->key_size       = key_size;
  }
  else
  {
    return (PARSER_SALT_VALUE);
  }

  if (iterations < 1) return (PARSER_SALT_ITERATION);

  salt->salt_iter = iterations - 1;

  // checksum
  const u8 *checksum_pos  = token.buf[5];
  const int checksum_hlen = token.len[5];
  const u32 checksum_words = checksum_hlen / 8;

  memset (odf->checksum, 0, sizeof (odf->checksum));

  for (u32 i = 0; i < checksum_words; i++)
  {
    odf->checksum[i] = hex_to_u32 (checksum_pos + (i * 8));
  }

  // iv
  const u8 *iv_pos = token.buf[7];

  odf->iv_len = iv_len;

  for (u32 i = 0; i < iv_len / 4; i++)
  {
    odf->iv[i] = hex_to_u32 (iv_pos + (i * 8));
  }

  // ciphertext
  const u8 *ct_pos = token.buf[11];
  const int ct_len = token.len[11];

  odf->encrypted_len = hex_decode (ct_pos, ct_len, (u8 *) odf->encrypted_data);

  // salt
  const u8 *salt_buf = token.buf[9];

  salt->salt_len = salt_len;

  salt->salt_buf[0] = hex_to_u32 (&salt_buf[ 0]);
  salt->salt_buf[1] = hex_to_u32 (&salt_buf[ 8]);
  salt->salt_buf[2] = hex_to_u32 (&salt_buf[16]);
  salt->salt_buf[3] = hex_to_u32 (&salt_buf[24]);

  // digest
  memset (digest, 0, DGST_SIZE_4_8);

  for (u32 i = 0; i < checksum_words; i++)
  {
    digest[i] = odf->checksum[i];
  }

  return (PARSER_OK);
}

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  odf_t *odf = (odf_t *) esalt_buf;

  int rc = parse_new_format (hashconfig, digest, salt, odf, line_buf, line_len);

  if (rc == PARSER_OK) return (PARSER_OK);

  rc = parse_legacy_format (hashconfig, digest, salt, odf, line_buf, line_len);

  return rc;
}

int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const odf_t *odf = (const odf_t *) esalt_buf;

  const char *startkey_str = (odf->start_key_type == 0) ? "sha1" : "sha256";
  const char *cipher_str;

  switch (odf->cipher_type)
  {
    case 0:  cipher_str = "blowfish";  break;
    case 1:  cipher_str = "aes256";    break;
    case 2:  cipher_str = "aes256gcm"; break;
    default: cipher_str = "aes256";    break;
  }

  // checksum hex
  const u32 checksum_words = (odf->start_key_type == 0) ? 5 : 8;

  char checksum_hex[65];
  int checksum_hex_len = 0;

  for (u32 i = 0; i < checksum_words; i++)
  {
    checksum_hex_len += snprintf (checksum_hex + checksum_hex_len, sizeof (checksum_hex) - checksum_hex_len, "%08x", byte_swap_32 (odf->checksum[i]));
  }

  // iv hex
  const u32 iv_words = odf->iv_len / 4;

  char iv_hex[33];
  int iv_hex_len = 0;

  for (u32 i = 0; i < iv_words; i++)
  {
    iv_hex_len += snprintf (iv_hex + iv_hex_len, sizeof (iv_hex) - iv_hex_len, "%08x", byte_swap_32 (odf->iv[i]));
  }

  // salt hex
  char salt_hex[257];
  int salt_hex_len = 0;

  for (u32 i = 0; i < salt->salt_len / 4; i++)
  {
    salt_hex_len += snprintf (salt_hex + salt_hex_len, sizeof (salt_hex) - salt_hex_len, "%08x", byte_swap_32 (salt->salt_buf[i]));
  }

  // ct hex
  u8 ct_buf[(256 * 4 * 2) + 1];

  memset (ct_buf, 0, sizeof (ct_buf));

  const int ct_len = hex_encode ((const u8 *) odf->encrypted_data, odf->encrypted_len, ct_buf);

  ct_buf[ct_len] = 0;

  const int out_len = snprintf (line_buf, line_size, "%s*%s*pbkdf2*%s*%u*0*0*%s*%s*%s*%s",
    SIGNATURE_ODF,
    startkey_str,
    cipher_str,
    salt->salt_iter + 1,
    salt_hex,
    iv_hex,
    checksum_hex,
    (char *) ct_buf);

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
  module_ctx->module_pw_max                   = module_pw_max;
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
