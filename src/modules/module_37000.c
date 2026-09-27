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
static const u32   DGST_SIZE      = DGST_SIZE_4_4;
static const u32   HASH_CATEGORY  = HASH_CATEGORY_DOCUMENTS;
static const char *HASH_NAME      = "MS Office Document-Open (ECMA-376)";
static const u64   KERN_TYPE      = 37011;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE
                                  | OPTI_TYPE_SLOW_HASH_SIMD_LOOP;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE
                                  | OPTS_TYPE_DEEP_COMP_KERNEL
                                  | OPTS_TYPE_AUX1
                                  | OPTS_TYPE_AUX2
                                  | OPTS_TYPE_AUX3
                                  | OPTS_TYPE_AUX4
                                  | OPTS_TYPE_AUX5
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

typedef struct office_open
{
  u32 hash_type;
  u32 cipher_type;
  u32 key_bits;
  u32 encryptedVerifier[4];
  u32 encryptedVerifierHash[8];

} office_open_t;

typedef struct office_open_tmp
{
  u64 out[8];

} office_open_tmp_t;

static const char *SIGNATURE_OFFICE_OPEN   = "$office-open$";
static const char *SIGNATURE_OFFICE_LEGACY = "$office$";

enum
{
  KERN_TYPE_OFFICE_OPEN_SHA1   = 37011,
  KERN_TYPE_OFFICE_OPEN_SHA256 = 37012,
  KERN_TYPE_OFFICE_OPEN_SHA384 = 37013,
  KERN_TYPE_OFFICE_OPEN_SHA512 = 37014,
  KERN_TYPE_OFFICE_OPEN_MD5    = 37015,
  KERN_TYPE_OFFICE_OPEN_MD4    = 37016,
  KERN_TYPE_OFFICE_OPEN_MD2    = 37017,
};

static const int ROUNDS_OFFICE2007 = 50000;

u64 module_kern_type_dynamic (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info)
{
  const office_open_t *office_open = (const office_open_t *) esalt_buf;

  switch (office_open->hash_type)
  {
    case 0:  return KERN_TYPE_OFFICE_OPEN_SHA1;
    case 1:  return KERN_TYPE_OFFICE_OPEN_SHA256;
    case 2:  return KERN_TYPE_OFFICE_OPEN_SHA384;
    case 3:  return KERN_TYPE_OFFICE_OPEN_SHA512;
    case 4:  return KERN_TYPE_OFFICE_OPEN_MD5;
    case 5:  return KERN_TYPE_OFFICE_OPEN_MD4;
    case 6:  return KERN_TYPE_OFFICE_OPEN_MD2;
  }

  return KERN_TYPE_OFFICE_OPEN_SHA1;
}

u32 module_deep_comp_kernel (MAYBE_UNUSED const hashes_t *hashes, MAYBE_UNUSED const u32 salt_pos, MAYBE_UNUSED const u32 digest_pos)
{
  const u32 digests_offset = hashes->salts_buf[salt_pos].digests_offset;

  const office_open_t *office_opens = (const office_open_t *) hashes->esalts_buf;
  const office_open_t *office_open  = &office_opens[digests_offset + digest_pos];

  // SHA-1 kernel (37011) splits ECB (comp) and CBC (aux1) verification.
  // All other hash kernels handle AES-CBC in comp. Non-AES ciphers
  // (3DES, DES, DESX, RC2) use aux2-5 in ALL kernels.

  // SHA-1 (hash_type=0): _comp=ECB, _aux1=AES-CBC (both have real implementations)
  // SHA-256/384/512 (hash_type=1-3): _comp handles AES-CBC, _aux1 is an empty stub
  // MD5/MD4/MD2 (hash_type=4-6): _comp has wrong ipad/opad code, _aux1 has correct Agile code
  // Non-AES ciphers: _aux2-5 have real implementations in ALL kernels

  switch (office_open->cipher_type)
  {
    case 0:  return KERN_RUN_3;    // AES-ECB (Standard 2007, SHA-1 only)
    case 1:                        // AES-CBC (Agile)
      // SHA-256/384/512 kernels handle CBC in _comp; their _aux1 is a stub
      if ((office_open->hash_type >= 1) && (office_open->hash_type <= 3))
      {
        return KERN_RUN_3;
      }
      // SHA-1, MD5, MD4, MD2 have correct Agile code in _aux1
      return KERN_RUN_AUX1;
    case 2:  return KERN_RUN_AUX2; // 3DES-112 CBC
    case 3:  return KERN_RUN_AUX2; // 3DES CBC
    case 4:  return KERN_RUN_AUX3; // DES CBC
    case 5:  return KERN_RUN_AUX4; // DESX CBC
    case 6:  return KERN_RUN_AUX5; // RC2 CBC
  }

  return KERN_RUN_3;
}

void *module_benchmark_esalt (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  office_open_t *office_open = (office_open_t *) hcmalloc (sizeof (office_open_t));

  office_open->hash_type   = 0;
  office_open->cipher_type = 0;
  office_open->key_bits    = 128;

  return office_open;
}

salt_t *module_benchmark_salt (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  salt_t *salt = (salt_t *) hcmalloc (sizeof (salt_t));

  salt->salt_iter = ROUNDS_OFFICE2007;

  return salt;
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
  const u64 esalt_size = (const u64) sizeof (office_open_t);

  return esalt_size;
}

u64 module_tmp_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 tmp_size = (const u64) sizeof (office_open_tmp_t);

  return tmp_size;
}

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

// Returns key_bits (>0) for AES, or -(cipher_type) (<-1) for non-AES ciphers.
// Error: returns -1.
static int parse_cipher (const u8 *buf, const int len)
{
  // AES family: return key_bits directly
  if ((len == 6) && (memcmp (buf, "aes128",  6) == 0)) return 128;
  if ((len == 6) && (memcmp (buf, "aes192",  6) == 0)) return 192;
  if ((len == 6) && (memcmp (buf, "aes256",  6) == 0)) return 256;
  // Non-AES: return -(cipher_type) so caller can distinguish
  if ((len == 7) && (memcmp (buf, "3des112", 7) == 0)) return -2;
  if ((len == 4) && (memcmp (buf, "3des",    4) == 0)) return -3;
  if ((len == 3) && (memcmp (buf, "des",     3) == 0)) return -4;
  if ((len == 4) && (memcmp (buf, "desx",    4) == 0)) return -5;
  if ((len == 3) && (memcmp (buf, "rc2",     3) == 0)) return -6;

  return -1;
}

static int parse_mode (const u8 *buf, const int len)
{
  if ((len == 3) && (memcmp (buf, "ecb", 3) == 0)) return 0;
  if ((len == 3) && (memcmp (buf, "cbc", 3) == 0)) return 1;

  return -1;
}

static const char *hash_type_to_str (const u32 hash_type)
{
  switch (hash_type)
  {
    case 0:  return "sha1";
    case 1:  return "sha256";
    case 2:  return "sha384";
    case 3:  return "sha512";
    case 4:  return "md5";
    case 5:  return "md4";
    case 6:  return "md2";
  }

  return "sha1";
}

static const char *cipher_to_str (const u32 cipher_type, const u32 key_bits)
{
  switch (cipher_type)
  {
    case 0: // AES-ECB
    case 1: // AES-CBC
      switch (key_bits)
      {
        case 128: return "aes128";
        case 192: return "aes192";
        case 256: return "aes256";
      }
      return "aes128";
    case 2: return "3des112";
    case 3: return "3des";
    case 4: return "des";
    case 5: return "desx";
    case 6: return "rc2";
  }

  return "aes128";
}

static const char *mode_to_str (const u32 cipher_type)
{
  if (cipher_type == 0) return "ecb";

  return "cbc";
}

static void decode_common (const u8 *osalt_pos, const u8 *ev_pos, const u8 *evh_pos, const int evh_len, salt_t *salt, office_open_t *office_open, u32 *digest, const u32 salt_iter)
{
  salt->salt_len  = 16;
  salt->salt_iter = salt_iter;

  salt->salt_buf[0] = hex_to_u32 (osalt_pos +  0);
  salt->salt_buf[1] = hex_to_u32 (osalt_pos +  8);
  salt->salt_buf[2] = hex_to_u32 (osalt_pos + 16);
  salt->salt_buf[3] = hex_to_u32 (osalt_pos + 24);

  salt->salt_buf[0] = byte_swap_32 (salt->salt_buf[0]);
  salt->salt_buf[1] = byte_swap_32 (salt->salt_buf[1]);
  salt->salt_buf[2] = byte_swap_32 (salt->salt_buf[2]);
  salt->salt_buf[3] = byte_swap_32 (salt->salt_buf[3]);

  office_open->encryptedVerifier[0] = hex_to_u32 (ev_pos +  0);
  office_open->encryptedVerifier[1] = hex_to_u32 (ev_pos +  8);
  office_open->encryptedVerifier[2] = hex_to_u32 (ev_pos + 16);
  office_open->encryptedVerifier[3] = hex_to_u32 (ev_pos + 24);

  office_open->encryptedVerifier[0] = byte_swap_32 (office_open->encryptedVerifier[0]);
  office_open->encryptedVerifier[1] = byte_swap_32 (office_open->encryptedVerifier[1]);
  office_open->encryptedVerifier[2] = byte_swap_32 (office_open->encryptedVerifier[2]);
  office_open->encryptedVerifier[3] = byte_swap_32 (office_open->encryptedVerifier[3]);

  const int evh_words = evh_len / 8;

  memset (office_open->encryptedVerifierHash, 0, sizeof (office_open->encryptedVerifierHash));

  for (int i = 0; i < evh_words; i++)
  {
    office_open->encryptedVerifierHash[i] = hex_to_u32 (evh_pos + (i * 8));
    office_open->encryptedVerifierHash[i] = byte_swap_32 (office_open->encryptedVerifierHash[i]);
  }

  digest[0] = office_open->encryptedVerifierHash[0];
  digest[1] = office_open->encryptedVerifierHash[1];
  digest[2] = office_open->encryptedVerifierHash[2];
  digest[3] = office_open->encryptedVerifierHash[3];
}

static int try_parse_new_format (const u8 *line_buf, const int line_len, u32 *digest, salt_t *salt, office_open_t *office_open)
{
  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  token.token_cnt  = 8;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_OFFICE_OPEN;

  token.sep[0]     = '*';
  token.len[0]     = 13;
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.sep[1]     = '*';
  token.len_min[1] = 3;
  token.len_max[1] = 6;
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH;

  token.sep[2]     = '*';
  token.len_min[2] = 3;
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
  token.len_max[7] = 128;
  token.attr[7]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer (line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  const int hash_type  = parse_hash_type (token.buf[1], token.len[1]);
  const int cipher_val = parse_cipher    (token.buf[2], token.len[2]);
  const int mode       = parse_mode      (token.buf[3], token.len[3]);

  if (hash_type  == -1) return (PARSER_HASH_ENCODING);
  if (cipher_val == -1) return (PARSER_TOKEN_ENCODING);
  if (mode       == -1) return (PARSER_TOKEN_ENCODING);

  office_open->hash_type = (u32) hash_type;

  if (cipher_val > 0)
  {
    // AES family: cipher_val is key_bits, mode determines cipher_type
    office_open->cipher_type = (u32) mode;
    office_open->key_bits    = (u32) cipher_val;
  }
  else
  {
    // Non-AES: cipher_val encodes -(cipher_type)
    office_open->cipher_type = (u32) (-cipher_val);

    switch (office_open->cipher_type)
    {
      case 2:  office_open->key_bits = 128; break; // 3des112
      case 3:  office_open->key_bits = 192; break; // 3des
      case 4:  office_open->key_bits = 64;  break; // des
      case 5:  office_open->key_bits = 192; break; // desx
      case 6:  office_open->key_bits = 128; break; // rc2
      default: return (PARSER_TOKEN_ENCODING);
    }
  }

  const u32 iters = hc_strtoul ((const char *) token.buf[4], NULL, 10);

  decode_common (token.buf[5], token.buf[6], token.buf[7], token.len[7], salt, office_open, digest, iters);

  return (PARSER_OK);
}

static int try_parse_legacy_format (const u8 *line_buf, const int line_len, u32 *digest, salt_t *salt, office_open_t *office_open)
{
  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  token.token_cnt  = 8;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_OFFICE_LEGACY;

  token.sep[0]     = '*';
  token.len[0]     = 8;
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.sep[1]     = '*';
  token.len[1]     = 4;
  token.attr[1]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[2]     = '*';
  token.len_min[2] = 2;
  token.len_max[2] = 6;
  token.attr[2]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[3]     = '*';
  token.len[3]     = 3;
  token.attr[3]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[4]     = '*';
  token.len[4]     = 2;
  token.attr[4]    = TOKEN_ATTR_FIXED_LENGTH
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
  token.len_min[7] = 40;
  token.len_max[7] = 64;
  token.attr[7]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer (line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  const u32 version  = hc_strtoul ((const char *) token.buf[1], NULL, 10);
  const u32 keySize  = hc_strtoul ((const char *) token.buf[3], NULL, 10);
  const u32 saltSize = hc_strtoul ((const char *) token.buf[4], NULL, 10);

  if (saltSize != 16) return (PARSER_SALT_VALUE);

  u32 hash_type   = 0;
  u32 cipher_type = 0;
  u32 iters       = 0;

  if (version == 2007)
  {
    hash_type   = 0;
    cipher_type = 0;
    iters       = ROUNDS_OFFICE2007;
  }
  else if (version == 2010)
  {
    hash_type   = 0;
    cipher_type = 1;
    iters       = hc_strtoul ((const char *) token.buf[2], NULL, 10);
  }
  else if (version == 2013)
  {
    hash_type   = 3;
    cipher_type = 1;
    iters       = hc_strtoul ((const char *) token.buf[2], NULL, 10);
  }
  else
  {
    return (PARSER_SALT_VALUE);
  }

  office_open->hash_type   = hash_type;
  office_open->cipher_type = cipher_type;
  office_open->key_bits    = keySize;

  decode_common (token.buf[5], token.buf[6], token.buf[7], token.len[7], salt, office_open, digest, iters);

  return (PARSER_OK);
}

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  office_open_t *office_open = (office_open_t *) esalt_buf;

  int rc = try_parse_new_format ((const u8 *) line_buf, line_len, digest, salt, office_open);

  if (rc == PARSER_OK) return (PARSER_OK);

  // If the new format signature matched but a field was unsupported (cipher, hash type, mode),
  // return that error directly instead of falling through to the legacy parser
  // whose unrelated error would mask the real problem.

  if (rc != PARSER_SIGNATURE_UNMATCHED && rc != PARSER_TOKEN_LENGTH && rc != PARSER_GLOBAL_LENGTH)
  {
    return rc;
  }

  rc = try_parse_legacy_format ((const u8 *) line_buf, line_len, digest, salt, office_open);

  return rc;
}

int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const office_open_t *office_open = (const office_open_t *) esalt_buf;

  const char *hash_str   = hash_type_to_str (office_open->hash_type);
  const char *cipher_str = cipher_to_str (office_open->cipher_type, office_open->key_bits);
  const char *mode_str   = mode_to_str (office_open->cipher_type);

  int evh_words;

  if (office_open->hash_type >= 4)
  {
    evh_words = 4; // MD5, MD4 or MD2: 16-byte hash
  }
  else if (office_open->cipher_type == 0)
  {
    evh_words = 5; // AES-ECB: raw 20-byte SHA-1
  }
  else
  {
    evh_words = 8; // AES-CBC and non-AES: encrypted blocks
  }

  char evh_hex[65];

  memset (evh_hex, 0, sizeof (evh_hex));

  for (int i = 0; i < evh_words; i++)
  {
    snprintf (evh_hex + (i * 8), 9, "%08x", office_open->encryptedVerifierHash[i]);
  }

  const int line_len = snprintf (line_buf, line_size, "%s*%s*%s*%s*%u*%08x%08x%08x%08x*%08x%08x%08x%08x*%s",
    SIGNATURE_OFFICE_OPEN,
    hash_str,
    cipher_str,
    mode_str,
    salt->salt_iter,
    salt->salt_buf[0],
    salt->salt_buf[1],
    salt->salt_buf[2],
    salt->salt_buf[3],
    office_open->encryptedVerifier[0],
    office_open->encryptedVerifier[1],
    office_open->encryptedVerifier[2],
    office_open->encryptedVerifier[3],
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
  module_ctx->module_benchmark_mask           = MODULE_DEFAULT;
  module_ctx->module_benchmark_charset        = MODULE_DEFAULT;
  module_ctx->module_benchmark_salt           = module_benchmark_salt;
  module_ctx->module_bridge_name              = MODULE_DEFAULT;
  module_ctx->module_bridge_type              = MODULE_DEFAULT;
  module_ctx->module_build_plain_postprocess  = MODULE_DEFAULT;
  module_ctx->module_deep_comp_kernel         = module_deep_comp_kernel;
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
