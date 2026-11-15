/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

// The line format of PKWARE strong encryption with an AES cipher, shared by modes 46300, 46310 and
// 46320. A module defines ZIP3_BITS, its constants and then includes this file as one translation
// unit. The kernels are those of modes 23001, 23002 and 23003, which is why the kernel side of a
// hash keeps their layout and everything else about a line lives on the host.
//
//   $zip$3$*algorithm*bits*flags*iv*erd*vdata$/zip$
//
//   algorithm  the AlgID of the decryption header, hex: 660e, 660f or 6610
//   bits       key length: 128, 192 or 256
//   flags      the flags of the decryption header, hex; bit 0 says a password opens it
//   iv         the initialisation vector, hex: the 16 bytes the header stores, or the CRC-32 and
//              the 64 bit size of the entry (12 bytes) that stand in when it stores none
//   erd        the encrypted random data, hex
//   vdata      the encrypted validation data with its CRC-32, hex; may be empty
//
// The key derived from the password decrypts the random data, which ends in a full block of
// padding. That block is what the kernel tests: 16 bytes of 0x10.
//
// The lines of modes 23001 to 23003 ($zip3$) are read as well and are written back in the form
// above.

#define ZIP3_ERD_MAX   4096
#define ZIP3_VDATA_MAX 1024
#define ZIP3_FIELDS    6

typedef struct securezip
{
  u32 data[36];
  u32 file[16];
  u32 iv[4];
  u32 iv_len;

} securezip_t;

typedef struct zip3_line
{
  u32 alg_id;
  u32 bits;
  u32 flags;
  u32 iv_len;
  u32 erd_len;
  u32 vdata_len;

  u8 iv[16];
  u8 erd[ZIP3_ERD_MAX];
  u8 vdata[ZIP3_VDATA_MAX];

} zip3_line_t;

static const char *SIGNATURE_ZIP3      = "$zip$3$";
static const char *SIGNATURE_ZIP3_STOP = "$/zip$";
static const char *SIGNATURE_ZIP3_OLD  = "$zip3$";

static u64 module_esalt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 esalt_size = (const u64) sizeof (securezip_t);

  return esalt_size;
}

static u64 module_hook_salt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 hook_salt_size = (const u64) sizeof (zip3_line_t);

  return hook_salt_size;
}

static const char *module_usage_notice (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  return "Use ArchiveWolf or tools/zip2hashcat.py to extract the hash from a ZIP archive. The AES key size picks the mode: 46300 for 128 bit, 46310 for 192 bit, 46320 for 256 bit. Lines of modes 23001 to 23003 ($zip3$) are read as well.";
}

static bool zip3_is_hex (const u8 *buf, const u32 len)
{
  if ((len & 1) != 0) return false;

  for (u32 i = 0; i < len; i++)
  {
    if (is_valid_hex_char (buf[i]) == false) return false;
  }

  return true;
}

static u64 zip3_number (const u8 *buf, const u32 len, const int base)
{
  char tmp[20] = { 0 };

  const u32 n = (len < 19) ? len : 19;

  memcpy (tmp, buf, n);

  return hc_strtoull (tmp, NULL, base);
}

// The fields are known by now. This fills the layout the kernel reads: the last block of the
// random data and the block in front of it, which is the initialisation vector when there is
// only one block.

static int zip3_fill (u32 *digest, salt_t *salt, securezip_t *securezip, zip3_line_t *line)
{
  if (line->bits != ZIP3_BITS) return (PARSER_HASH_VALUE);

  if (line->alg_id != 0x660e + ((ZIP3_BITS - 128) / 64)) return (PARSER_HASH_VALUE);

  // random data wrapped with 3DES, or a header only certificates open

  if ((line->flags & 0x4000) != 0) return (PARSER_HASH_VALUE);
  if ((line->flags & 0x0001) == 0) return (PARSER_HASH_VALUE);

  if ((line->erd_len < 16) || ((line->erd_len & 15) != 0)) return (PARSER_SALT_LENGTH);

  memset (securezip, 0, sizeof (securezip_t));

  u8 prev[16] = { 0 };

  if (line->erd_len >= 32)
  {
    memcpy (prev, &line->erd[line->erd_len - 32], 16);
  }
  else
  {
    memcpy (prev, line->iv, line->iv_len);
  }

  u8 *data = (u8 *) securezip->data;

  memcpy (&data[112], prev, 16);
  memcpy (&data[128], &line->erd[line->erd_len - 16], 16);

  memcpy (securezip->iv, line->iv, line->iv_len);

  securezip->iv_len = line->iv_len;

  // the kernel tests the first hash of a salt only, so every line is a salt of its own

  for (u32 n = 0; n < 8; n++)
  {
    u32 value = 2166136261u ^ n;

    for (u32 i = 0; i < line->iv_len;    i++) value = (value ^ line->iv[i])    * 16777619u;
    for (u32 i = 0; i < line->erd_len;   i++) value = (value ^ line->erd[i])   * 16777619u;
    for (u32 i = 0; i < line->vdata_len; i++) value = (value ^ line->vdata[i]) * 16777619u;

    salt->salt_buf[n] = value;
  }

  salt->salt_len = 32;

  for (u32 i = 0; i < 4; i++) digest[i] = salt->salt_buf[i];

  return (PARSER_OK);
}

static int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  securezip_t *securezip = (securezip_t *) esalt_buf;

  zip3_line_t *line = (zip3_line_t *) hook_salt_buf;

  if (line_len < 7 + 6) return (PARSER_SIGNATURE_UNMATCHED);

  const bool old = (memcmp (line_buf, SIGNATURE_ZIP3_OLD, 6) == 0);

  if ((old == false) && (memcmp (line_buf, SIGNATURE_ZIP3, 7) != 0)) return (PARSER_SIGNATURE_UNMATCHED);

  u32 end = (u32) line_len;

  if (old == false)
  {
    if (memcmp (&line_buf[line_len - 6], SIGNATURE_ZIP3_STOP, 6) != 0) return (PARSER_SIGNATURE_UNMATCHED);

    end -= 6;
  }

  const u8 *field[10];

  u32 flen[10];

  u32 cnt = 0;

  u32 pos = (old == true) ? 6 : 7;

  if ((pos >= end) || (line_buf[pos] != '*')) return (PARSER_SEPARATOR_UNMATCHED);

  while (pos < end)
  {
    pos++;

    const u32 start = pos;

    // the last field of the old form is a file name, which may hold anything

    while ((pos < end) && ((line_buf[pos] != '*') || (cnt == 9))) pos++;

    if (cnt == 10) return (PARSER_TOKEN_LENGTH);

    field[cnt] = (const u8 *) &line_buf[start];
    flen[cnt]  = pos - start;

    cnt++;
  }

  memset (line, 0, sizeof (zip3_line_t));

  u32 iv_at  = 3;
  u32 erd_at = 4;

  if (old == true)
  {
    // version, type, bits, magic, iv, erd, three unused fields, file name

    if (cnt != 10) return (PARSER_TOKEN_LENGTH);

    if ((flen[0] != 1) || (field[0][0] != '0')) return (PARSER_HASH_ENCODING);
    if ((flen[1] != 1) || (field[1][0] != '1')) return (PARSER_HASH_ENCODING);

    if ((flen[2] != 3) || (zip3_number (field[2], 3, 10) != ZIP3_BITS)) return (PARSER_HASH_ENCODING);

    line->bits   = ZIP3_BITS;
    line->alg_id = 0x660e + ((ZIP3_BITS - 128) / 64);
    line->flags  = 1;

    iv_at  = 4;
    erd_at = 5;
  }
  else
  {
    if (cnt != ZIP3_FIELDS) return (PARSER_TOKEN_LENGTH);

    if ((flen[0] != 4) || (zip3_is_hex (field[0], 4) == false)) return (PARSER_HASH_VALUE);
    if ((flen[1] != 3))                                         return (PARSER_HASH_VALUE);

    if ((flen[2] < 1) || (flen[2] > 4)) return (PARSER_HASH_VALUE);

    for (u32 i = 0; i < flen[2]; i++)
    {
      if (is_valid_hex_char (field[2][i]) == false) return (PARSER_HASH_VALUE);
    }

    line->alg_id = (u32) zip3_number (field[0], 4, 16);
    line->bits   = (u32) zip3_number (field[1], 3, 10);
    line->flags  = (u32) zip3_number (field[2], flen[2], 16);

    if (zip3_is_hex (field[5], flen[5]) == false) return (PARSER_SALT_ENCODING);

    if (flen[5] > ZIP3_VDATA_MAX * 2) return (PARSER_SALT_LENGTH);

    line->vdata_len = flen[5] / 2;

    for (u32 i = 0; i < line->vdata_len; i++) line->vdata[i] = hex_to_u8 (&field[5][i * 2]);
  }

  if (zip3_is_hex (field[iv_at],  flen[iv_at])  == false) return (PARSER_SALT_ENCODING);
  if (zip3_is_hex (field[erd_at], flen[erd_at]) == false) return (PARSER_SALT_ENCODING);

  if (flen[iv_at]  > 16 * 2)           return (PARSER_SALT_LENGTH);
  if (flen[erd_at] > ZIP3_ERD_MAX * 2) return (PARSER_SALT_LENGTH);

  line->iv_len  = flen[iv_at]  / 2;
  line->erd_len = flen[erd_at] / 2;

  for (u32 i = 0; i < line->iv_len;  i++) line->iv[i]  = hex_to_u8 (&field[iv_at][i * 2]);
  for (u32 i = 0; i < line->erd_len; i++) line->erd[i] = hex_to_u8 (&field[erd_at][i * 2]);

  return zip3_fill (digest, salt, securezip, line);
}

static int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const zip3_line_t *line = (const zip3_line_t *) hook_salt_buf;

  const u32 need = 7 + 5 + 4 + 5 + ((line->iv_len + line->erd_len + line->vdata_len) * 2) + 3 + 6 + 1;

  if (need > (u32) line_size) return 0;

  int out_len = snprintf (line_buf, line_size, "%s*%04x*%u*%x*", SIGNATURE_ZIP3, line->alg_id, line->bits, line->flags);

  for (u32 i = 0; i < line->iv_len; i++)
  {
    u8_to_hex (line->iv[i], (u8 *) &line_buf[out_len]);

    out_len += 2;
  }

  line_buf[out_len++] = '*';

  for (u32 i = 0; i < line->erd_len; i++)
  {
    u8_to_hex (line->erd[i], (u8 *) &line_buf[out_len]);

    out_len += 2;
  }

  line_buf[out_len++] = '*';

  for (u32 i = 0; i < line->vdata_len; i++)
  {
    u8_to_hex (line->vdata[i], (u8 *) &line_buf[out_len]);

    out_len += 2;
  }

  out_len += snprintf (&line_buf[out_len], line_size - out_len, "%s", SIGNATURE_ZIP3_STOP);

  return out_len;
}

void module_init (module_ctx_t *module_ctx)
{
  module_init_common (module_ctx);

  module_ctx->module_esalt_size               = module_esalt_size;
  module_ctx->module_hash_decode              = module_hash_decode;
  module_ctx->module_hash_encode              = module_hash_encode;
  module_ctx->module_hook_salt_size           = module_hook_salt_size;
  module_ctx->module_usage_notice             = module_usage_notice;
}
