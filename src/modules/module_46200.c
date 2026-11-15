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

#include <inttypes.h>

// WinZip AES: PBKDF2-HMAC-SHA1 with 1000 iterations gives the cipher key, the authentication key
// and a two byte verifier.
//
//   $zip$2$*strength*salt*verifier*auth*method*packed*data$/zip$
//
//   strength  1, 2 or 3 for AES-128, AES-192 or AES-256
//   salt      8, 12 or 16 bytes, hex
//   verifier  the two bytes stored behind the salt, hex
//   auth      the 10 byte authentication code stored behind the data, hex
//   method    the compression method the entry really uses, decimal
//   packed    the size of the encrypted data, hex
//   data      the encrypted data, or the start of it, or nothing
//
// A line with all of the data is tested against the authentication code. A line with the start
// of a deflate stream is tested by decrypting and inflating that start, one with the start of a
// bzip2 or xz stream by the signature it decrypts to, and one without data by the verifier alone.
//
// The lines of mode 13600 ($zip2$) are read as well and are written back in the form above.

static const u32   ATTACK_EXEC    = ATTACK_EXEC_OUTSIDE_KERNEL;
static const u32   DGST_POS0      = 0;
static const u32   DGST_POS1      = 1;
static const u32   DGST_POS2      = 2;
static const u32   DGST_POS3      = 3;
static const u32   DGST_SIZE      = DGST_SIZE_4_4;
static const u32   HASH_CATEGORY  = HASH_CATEGORY_ARCHIVE;
static const char *HASH_NAME      = "ZIP WinZip AES";
static const u64   KERN_TYPE      = 46200;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "$zip$2$*1*0675369741458183*5dc5*36b85538918416712640*0*0*$/zip$";

#include "hooks_common.c"

#define ZIP2_DATA_MAX (8 * 1024 * 1024)

#define ZIP2_VERIFY_NONE   0
#define ZIP2_VERIFY_HMAC   1
#define ZIP2_VERIFY_PREFIX 2
#define ZIP2_VERIFY_MAGIC  3

#define ZIP2_METHOD_DEFLATE 8
#define ZIP2_METHOD_BZIP2   12
#define ZIP2_METHOD_XZ      95

#define ZIP2_FIELDS 7

typedef struct pbkdf2_sha1_tmp
{
  u32  ipad[5];
  u32  opad[5];

  u32  dgst[32];
  u32  out[32];

} pbkdf2_sha1_tmp_t;

typedef struct zip2
{
  u32 mode;
  u32 salt_len;
  u32 salt_buf[4];
  u32 verify_bytes;
  u32 auth_buf[4];
  u32 method;
  u32 packed;
  u32 packed_hi;
  u32 verify;
  u32 magic_len;
  u32 magic[4];
  u32 magic_mask[4];
  u32 digest[4];
  u32 data_len;
  u32 data_buf[ZIP2_DATA_MAX / 4];

} zip2_t;

static const char *SIGNATURE_ZIP2      = "$zip$2$";
static const char *SIGNATURE_ZIP2_STOP = "$/zip$";
static const char *SIGNATURE_ZIP2_OLD  = "$zip2$";
static const int   ROUNDS_ZIP2         = 1000;

static u64 module_esalt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 esalt_size = (const u64) sizeof (zip2_t);

  return esalt_size;
}

static u64 module_tmp_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 tmp_size = (const u64) sizeof (pbkdf2_sha1_tmp_t);

  return tmp_size;
}

static u32 module_kernel_loops_min (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u32 kernel_loops_min = ROUNDS_ZIP2 - 1;

  return kernel_loops_min;
}

static u32 module_kernel_loops_max (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u32 kernel_loops_max = ROUNDS_ZIP2 - 1;

  return kernel_loops_max;
}

static const char *module_usage_notice (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  return "Use ArchiveWolf or tools/zip2hashcat.py to extract the hash from a ZIP archive. Lines of mode 13600 ($zip2$) are read as well.";
}

static bool zip2_is_hex (const u8 *buf, const u32 len)
{
  for (u32 i = 0; i < len; i++)
  {
    if (is_valid_hex_char (buf[i]) == false) return false;
  }

  return true;
}

static bool zip2_is_dec (const u8 *buf, const u32 len)
{
  for (u32 i = 0; i < len; i++)
  {
    if ((buf[i] < '0') || (buf[i] > '9')) return false;
  }

  return true;
}

static u64 zip2_number (const u8 *buf, const u32 len, const int base)
{
  char tmp[20] = { 0 };

  const u32 n = (len < 19) ? len : 19;

  memcpy (tmp, buf, n);

  return hc_strtoull (tmp, NULL, base);
}

static void zip2_put_byte (u32 *words, const u32 pos, const u8 value)
{
  words[pos / 4] |= ((u32) value) << ((pos & 3) * 8);
}

static u8 zip2_get_byte (const u32 *words, const u32 pos)
{
  return (u8) (words[pos / 4] >> ((pos & 3) * 8));
}

// What the kernel does with the data once the verifier has matched.

static int zip2_set_verify (zip2_t *zip2)
{
  const u64 packed = ((u64) zip2->packed_hi << 32) | zip2->packed;

  zip2->verify    = ZIP2_VERIFY_NONE;
  zip2->magic_len = 0;

  if ((u64) zip2->data_len > packed) return (PARSER_SALT_VALUE);

  if ((u64) zip2->data_len == packed)
  {
    // the authentication code covers all of it, and an empty entry has one as well

    zip2->verify = ZIP2_VERIFY_HMAC;

    return (PARSER_OK);
  }

  if (zip2->data_len == 0) return (PARSER_OK);

  if (zip2->method == ZIP2_METHOD_DEFLATE)
  {
    zip2->verify = ZIP2_VERIFY_PREFIX;

    return (PARSER_OK);
  }

  if (zip2->method == ZIP2_METHOD_BZIP2)
  {
    static const u8 sig[10]  = { 'B', 'Z', 'h', 0x30, 0x31, 0x41, 0x59, 0x26, 0x53, 0x59 };
    static const u8 mask[10] = { 0xff, 0xff, 0xff, 0xf0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

    if (zip2->data_len < 10) return (PARSER_SALT_VALUE);

    for (u32 i = 0; i < 10; i++)
    {
      zip2_put_byte (zip2->magic,      i, sig[i]);
      zip2_put_byte (zip2->magic_mask, i, mask[i]);
    }

    zip2->magic_len = 10;
    zip2->verify    = ZIP2_VERIFY_MAGIC;

    return (PARSER_OK);
  }

  if (zip2->method == ZIP2_METHOD_XZ)
  {
    static const u8 sig[8]  = { 0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00, 0x00, 0x00 };
    static const u8 mask[8] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xf0 };

    if (zip2->data_len < 8) return (PARSER_SALT_VALUE);

    for (u32 i = 0; i < 8; i++)
    {
      zip2_put_byte (zip2->magic,      i, sig[i]);
      zip2_put_byte (zip2->magic_mask, i, mask[i]);
    }

    zip2->magic_len = 8;
    zip2->verify    = ZIP2_VERIFY_MAGIC;

    return (PARSER_OK);
  }

  // the start of any other stream says nothing

  return (PARSER_SALT_VALUE);
}

static void zip2_set_digest (u32 *digest, salt_t *salt, zip2_t *zip2)
{
  for (u32 n = 0; n < 8; n++)
  {
    u32 value = 2166136261u ^ n;

    value = (value ^ zip2->mode)         * 16777619u;
    value = (value ^ zip2->verify_bytes) * 16777619u;
    value = (value ^ zip2->method)       * 16777619u;
    value = (value ^ zip2->packed)       * 16777619u;
    value = (value ^ zip2->packed_hi)    * 16777619u;
    value = (value ^ zip2->data_len)     * 16777619u;

    for (u32 i = 0; i < 4; i++) value = (value ^ zip2->salt_buf[i]) * 16777619u;
    for (u32 i = 0; i < 4; i++) value = (value ^ zip2->auth_buf[i]) * 16777619u;

    const u32 words = (zip2->data_len + 3) / 4;

    for (u32 i = 0; i < words; i++) value = (value ^ zip2->data_buf[i]) * 16777619u;

    salt->salt_buf[n] = value;
  }

  salt->salt_len  = 32;
  salt->salt_iter = ROUNDS_ZIP2 - 1;

  for (u32 i = 0; i < 4; i++)
  {
    digest[i] = salt->salt_buf[i];

    zip2->digest[i] = digest[i];
  }
}

// Every field has been split off the line by now, whichever form it came in.

static int zip2_fill (u32 *digest, salt_t *salt, zip2_t *zip2, const u8 *mode_buf, const u32 mode_len, const u8 *salt_buf, const u32 salt_len, const u8 *pv_buf, const u32 pv_len, const u8 *auth_buf, const u32 auth_len, const u32 method, const u64 packed, const u8 *data_buf, const u32 data_hex_len)
{
  if ((mode_len != 1) || (zip2_is_dec (mode_buf, 1) == false)) return (PARSER_SALT_VALUE);

  const u32 mode = (u32) zip2_number (mode_buf, 1, 10);

  if ((mode < 1) || (mode > 3)) return (PARSER_SALT_VALUE);

  if (salt_len != (4 + (mode * 4)) * 2) return (PARSER_SALT_LENGTH);

  if (zip2_is_hex (salt_buf, salt_len) == false) return (PARSER_SALT_ENCODING);

  if ((pv_len < 1) || (pv_len > 4) || (zip2_is_hex (pv_buf, pv_len) == false)) return (PARSER_SALT_VALUE);

  if ((auth_len != 20) || (zip2_is_hex (auth_buf, auth_len) == false)) return (PARSER_HASH_LENGTH);

  if ((data_hex_len & 1) != 0) return (PARSER_SALT_LENGTH);

  if (data_hex_len > ZIP2_DATA_MAX * 2) return (PARSER_SALT_LENGTH);

  if (zip2_is_hex (data_buf, data_hex_len) == false) return (PARSER_SALT_ENCODING);

  memset (zip2, 0, sizeof (zip2_t));

  zip2->mode     = mode;
  zip2->salt_len = salt_len / 2;

  for (u32 i = 0; i < zip2->salt_len; i++) zip2_put_byte (zip2->salt_buf, i, hex_to_u8 (&salt_buf[i * 2]));

  zip2->verify_bytes = (u32) zip2_number (pv_buf, pv_len, 16);

  for (u32 i = 0; i < 10; i++) zip2_put_byte (zip2->auth_buf, i, hex_to_u8 (&auth_buf[i * 2]));

  zip2->method    = method;
  zip2->packed    = (u32) packed;
  zip2->packed_hi = (u32) (packed >> 32);
  zip2->data_len  = data_hex_len / 2;

  for (u32 i = 0; i < zip2->data_len; i++) zip2_put_byte (zip2->data_buf, i, hex_to_u8 (&data_buf[i * 2]));

  const int rc = zip2_set_verify (zip2);

  if (rc != PARSER_OK) return rc;

  zip2_set_digest (digest, salt, zip2);

  return (PARSER_OK);
}

static int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  zip2_t *zip2 = (zip2_t *) esalt_buf;

  if (line_len < 7 + 6) return (PARSER_SIGNATURE_UNMATCHED);

  const bool old = (memcmp (line_buf, SIGNATURE_ZIP2_OLD, 6) == 0);

  if ((old == false) && (memcmp (line_buf, SIGNATURE_ZIP2, 7) != 0)) return (PARSER_SIGNATURE_UNMATCHED);

  // the old form ends in "*$/zip2$", the new one in "$/zip$"

  const u32 sig_len  = (old == true) ? 6 : 7;
  const u32 stop_len = (old == true) ? 8 : 6;

  if (old == true)
  {
    if (memcmp (&line_buf[line_len - 8], "*$/zip2$", 8) != 0) return (PARSER_SIGNATURE_UNMATCHED);
  }
  else
  {
    if (memcmp (&line_buf[line_len - 6], SIGNATURE_ZIP2_STOP, 6) != 0) return (PARSER_SIGNATURE_UNMATCHED);
  }

  const u8 *field[8];

  u32 flen[8];

  u32 cnt = 0;

  const u32 end = (u32) line_len - stop_len;

  u32 pos = sig_len;

  if ((pos >= end) || (line_buf[pos] != '*')) return (PARSER_SEPARATOR_UNMATCHED);

  while (pos < end)
  {
    pos++;

    const u32 start = pos;

    while ((pos < end) && (line_buf[pos] != '*')) pos++;

    if (cnt == 8) return (PARSER_TOKEN_LENGTH);

    field[cnt] = (const u8 *) &line_buf[start];
    flen[cnt]  = pos - start;

    cnt++;
  }

  if (old == true)
  {
    // type, mode, magic, salt, verifier, length, data, auth

    if (cnt != 8) return (PARSER_TOKEN_LENGTH);

    if ((flen[5] < 1) || (flen[5] > 8) || (zip2_is_hex (field[5], flen[5]) == false)) return (PARSER_SALT_VALUE);

    const u64 packed = zip2_number (field[5], flen[5], 16);

    return zip2_fill (digest, salt, zip2, field[1], flen[1], field[3], flen[3], field[4], flen[4], field[7], flen[7], 0, packed, field[6], flen[6]);
  }

  if (cnt != ZIP2_FIELDS) return (PARSER_TOKEN_LENGTH);

  if ((flen[4] < 1) || (flen[4] > 3)  || (zip2_is_dec (field[4], flen[4]) == false)) return (PARSER_SALT_VALUE);
  if ((flen[5] < 1) || (flen[5] > 16) || (zip2_is_hex (field[5], flen[5]) == false)) return (PARSER_SALT_VALUE);

  const u32 method = (u32) zip2_number (field[4], flen[4], 10);
  const u64 packed = zip2_number (field[5], flen[5], 16);

  return zip2_fill (digest, salt, zip2, field[0], flen[0], field[1], flen[1], field[2], flen[2], field[3], flen[3], method, packed, field[6], flen[6]);
}

static int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const zip2_t *zip2 = (const zip2_t *) esalt_buf;

  const u32 need = 7 + 3 + 33 + 5 + 21 + 5 + 18 + (zip2->data_len * 2) + 6 + 1;

  if (need > (u32) line_size) return 0;

  int out_len = snprintf (line_buf, line_size, "%s*%u*", SIGNATURE_ZIP2, zip2->mode);

  for (u32 i = 0; i < zip2->salt_len; i++)
  {
    u8_to_hex (zip2_get_byte (zip2->salt_buf, i), (u8 *) &line_buf[out_len]);

    out_len += 2;
  }

  out_len += snprintf (&line_buf[out_len], line_size - out_len, "*%04x*", zip2->verify_bytes);

  for (u32 i = 0; i < 10; i++)
  {
    u8_to_hex (zip2_get_byte (zip2->auth_buf, i), (u8 *) &line_buf[out_len]);

    out_len += 2;
  }

  const u64 packed = ((u64) zip2->packed_hi << 32) | zip2->packed;

  out_len += snprintf (&line_buf[out_len], line_size - out_len, "*%u*%" PRIx64 "*", zip2->method, packed);

  for (u32 i = 0; i < zip2->data_len; i++)
  {
    u8_to_hex (zip2_get_byte (zip2->data_buf, i), (u8 *) &line_buf[out_len]);

    out_len += 2;
  }

  out_len += snprintf (&line_buf[out_len], line_size - out_len, "%s", SIGNATURE_ZIP2_STOP);

  return out_len;
}

void module_init (module_ctx_t *module_ctx)
{
  module_init_common (module_ctx);

  module_ctx->module_esalt_size               = module_esalt_size;
  module_ctx->module_hash_decode              = module_hash_decode;
  module_ctx->module_hash_encode              = module_hash_encode;
  module_ctx->module_kernel_loops_max         = module_kernel_loops_max;
  module_ctx->module_kernel_loops_min         = module_kernel_loops_min;
  module_ctx->module_tmp_size                 = module_tmp_size;
  module_ctx->module_usage_notice             = module_usage_notice;
}
