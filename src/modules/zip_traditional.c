/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

// The line format of ZIP traditional encryption (ZipCrypto), shared by the modules that read it.
// It is included by a module as one translation unit, the way rar3_decode.c is.
//
//   $zip$1$*N*check_1*...*check_N*method*crc32*unpacked*packed*data$/zip$
//
//   N         members the line tests, 1 to 8
//   check_i   the 12 byte encryption header of a member as 24 hex digits, a slash and the value
//             its last byte decrypts to (2 hex digits) or its last two bytes decrypt to (4 hex
//             digits, the second last byte in the low half). A second slash and a second value
//             name an alternative: a writer that did not know the CRC-32 yet used the file time.
//   method    compression method of the first member, decimal
//   crc32     CRC-32 of the first member's contents, 8 hex digits
//   unpacked  its size, hex
//   packed    the size of its encrypted stream without the 12 byte header, hex
//   data      that stream, or the start of it, or nothing
//
// The lines John the Ripper's zip2john writes ($pkzip$ and $pkzip2$) are read as well and are
// written back in the form above.

#define ZIP1_CHECK_MAX 8
#define ZIP1_DATA_MAX  (4 * 1024 * 1024)
#define ZIP1_HOT_DATA  8

// What the kernel needs for every candidate sits in one block: the headers, the first bytes of
// the data, and for each header the mask and the two values its last bytes may decrypt to.

#define ZIP1_HOT_HEAD  0
#define ZIP1_HOT_FIRST (ZIP1_CHECK_MAX * 3)
#define ZIP1_HOT_MASK  (ZIP1_HOT_FIRST + ZIP1_HOT_DATA)
#define ZIP1_HOT_A     (ZIP1_HOT_MASK + ZIP1_CHECK_MAX)
#define ZIP1_HOT_B     (ZIP1_HOT_A + ZIP1_CHECK_MAX)
#define ZIP1_HOT_WORDS (ZIP1_HOT_B + ZIP1_CHECK_MAX)

#define ZIP1_VERIFY_NONE    0
#define ZIP1_VERIFY_STORED  1
#define ZIP1_VERIFY_INFLATE 2
#define ZIP1_VERIFY_PREFIX  3
#define ZIP1_VERIFY_MAGIC   4

#define ZIP1_METHOD_STORED  0
#define ZIP1_METHOD_DEFLATE 8
#define ZIP1_METHOD_BZIP2   12
#define ZIP1_METHOD_XZ      95

#define ZIP1_FIELDS_MAX (1 + ZIP1_CHECK_MAX + 5)

#define ZIP1_USAGE_NOTICE "Use ArchiveWolf or tools/zip2hashcat.py to extract the hash from a ZIP archive. Lines written by zip2john ($pkzip$, $pkzip2$) are read as well."

typedef struct zip1
{
  u32 hot[ZIP1_HOT_WORDS];
  u32 check_cnt;
  u32 verify;
  u32 method;
  u32 crc32;
  u32 unpacked;
  u32 unpacked_hi;
  u32 packed;
  u32 packed_hi;
  u32 data_len;
  u32 magic_len;
  u32 magic[ZIP1_HOT_DATA];
  u32 magic_mask[ZIP1_HOT_DATA];
  u32 digest[4];
  u32 data[ZIP1_DATA_MAX / 4];

} zip1_t;

static const char *SIGNATURE_ZIP1       = "$zip$1$";
static const char *SIGNATURE_ZIP1_STOP  = "$/zip$";
static const char *SIGNATURE_PKZIP_V1   = "$pkzip$";
static const char *SIGNATURE_PKZIP_V2   = "$pkzip2$";

static bool zip1_is_hex (const char *buf, const u32 len)
{
  for (u32 i = 0; i < len; i++)
  {
    if (is_valid_hex_char ((u8) buf[i]) == false) return false;
  }

  return true;
}

static bool zip1_is_dec (const char *buf, const u32 len)
{
  for (u32 i = 0; i < len; i++)
  {
    if ((buf[i] < '0') || (buf[i] > '9')) return false;
  }

  return true;
}

// The fields are not terminated, so a number is copied out before it is converted.

static u64 zip1_number (const char *buf, const u32 len, const int base)
{
  char tmp[20] = { 0 };

  const u32 n = (len < 19) ? len : 19;

  memcpy (tmp, buf, n);

  return hc_strtoull (tmp, NULL, base);
}

static void zip1_put_byte (u32 *words, const u32 pos, const u8 value)
{
  words[pos / 4] |= ((u32) value) << ((pos & 3) * 8);
}

static u8 zip1_get_byte (const u32 *words, const u32 pos)
{
  return (u8) (words[pos / 4] >> ((pos & 3) * 8));
}

// Which test the data of the first member gets. Nothing but the answer depends on the line, so the
// kernel reads it and does not work it out again.

static int zip1_set_verify (zip1_t *zip)
{
  zip->verify    = ZIP1_VERIFY_NONE;
  zip->magic_len = 0;

  if (zip->data_len == 0) return (PARSER_OK);

  const u64 packed   = ((u64) zip->packed_hi   << 32) | zip->packed;
  const u64 unpacked = ((u64) zip->unpacked_hi << 32) | zip->unpacked;

  if ((u64) zip->data_len > packed) return (PARSER_SALT_VALUE);

  if (zip->method == ZIP1_METHOD_STORED)
  {
    // the CRC-32 covers every byte, so a stored member has to be here in full

    if ((u64) zip->data_len != packed)   return (PARSER_SALT_VALUE);
    if ((u64) zip->data_len != unpacked) return (PARSER_SALT_VALUE);

    zip->verify = ZIP1_VERIFY_STORED;

    return (PARSER_OK);
  }

  if (zip->method == ZIP1_METHOD_DEFLATE)
  {
    zip->verify = ((u64) zip->data_len == packed) ? ZIP1_VERIFY_INFLATE : ZIP1_VERIFY_PREFIX;

    return (PARSER_OK);
  }

  if (zip->method == ZIP1_METHOD_BZIP2)
  {
    // "BZh", the block size digit, then the block signature, or the end signature of a stream
    // that holds no block

    static const u8 block[6] = { 0x31, 0x41, 0x59, 0x26, 0x53, 0x59 };
    static const u8 empty[6] = { 0x17, 0x72, 0x45, 0x38, 0x50, 0x90 };

    if (zip->data_len < 10) return (PARSER_SALT_VALUE);

    zip1_put_byte (zip->magic, 0, 'B');
    zip1_put_byte (zip->magic, 1, 'Z');
    zip1_put_byte (zip->magic, 2, 'h');
    zip1_put_byte (zip->magic, 3, 0x30);

    zip1_put_byte (zip->magic_mask, 0, 0xff);
    zip1_put_byte (zip->magic_mask, 1, 0xff);
    zip1_put_byte (zip->magic_mask, 2, 0xff);
    zip1_put_byte (zip->magic_mask, 3, 0xf0);

    for (u32 i = 0; i < 6; i++)
    {
      zip1_put_byte (zip->magic, 4 + i, (unpacked == 0) ? empty[i] : block[i]);

      zip1_put_byte (zip->magic_mask, 4 + i, 0xff);
    }

    zip->magic_len = 10;
    zip->verify    = ZIP1_VERIFY_MAGIC;

    return (PARSER_OK);
  }

  if (zip->method == ZIP1_METHOD_XZ)
  {
    // the six byte signature, then two bytes of stream flags of which only four bits are in use

    static const u8 sig[8]  = { 0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00, 0x00, 0x00 };
    static const u8 mask[8] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xf0 };

    if (zip->data_len < 8) return (PARSER_SALT_VALUE);

    for (u32 i = 0; i < 8; i++)
    {
      zip1_put_byte (zip->magic,      i, sig[i]);
      zip1_put_byte (zip->magic_mask, i, mask[i]);
    }

    zip->magic_len = 8;
    zip->verify    = ZIP1_VERIFY_MAGIC;

    return (PARSER_OK);
  }

  return (PARSER_PKZIP_CT_UNMATCHED);
}

// Every line is its own salt: the kernel tests a candidate against one line and answers with the
// digest that line was given here.

static void zip1_set_digest (u32 *digest, salt_t *salt, zip1_t *zip)
{
  for (u32 n = 0; n < 8; n++)
  {
    u32 value = 2166136261u ^ n;

    for (u32 i = 0; i < ZIP1_HOT_WORDS; i++) value = (value ^ zip->hot[i]) * 16777619u;

    value = (value ^ zip->method)   * 16777619u;
    value = (value ^ zip->crc32)    * 16777619u;
    value = (value ^ zip->unpacked)    * 16777619u;
    value = (value ^ zip->unpacked_hi) * 16777619u;
    value = (value ^ zip->packed)      * 16777619u;
    value = (value ^ zip->packed_hi)   * 16777619u;
    value = (value ^ zip->data_len) * 16777619u;

    const u32 words = (zip->data_len + 3) / 4;

    for (u32 i = 0; i < words; i++) value = (value ^ zip->data[i]) * 16777619u;

    salt->salt_buf[n] = value;
  }

  salt->salt_len  = 32;
  salt->salt_iter = 1;

  for (u32 i = 0; i < 4; i++)
  {
    digest[i] = salt->salt_buf[i];

    zip->digest[i] = digest[i];
  }
}

static int zip1_decode_check (zip1_t *zip, const u32 idx, const char *buf, const u32 len)
{
  if (len < 24 + 1 + 2) return (PARSER_SALT_LENGTH);

  if (zip1_is_hex (buf, 24) == false) return (PARSER_SALT_ENCODING);

  if (buf[24] != '/') return (PARSER_SEPARATOR_UNMATCHED);

  for (u32 i = 0; i < 12; i++) zip1_put_byte (zip->hot, (idx * 12) + i, hex_to_u8 ((const u8 *) &buf[i * 2]));

  u32 slash = 0;

  for (u32 i = 25; i < len; i++)
  {
    if (buf[i] != '/') continue;

    if (slash != 0) return (PARSER_SEPARATOR_UNMATCHED);

    slash = i;
  }

  const u32 a_len = ((slash == 0) ? len : slash) - 25;

  if ((a_len != 2) && (a_len != 4)) return (PARSER_SALT_LENGTH);

  if (zip1_is_hex (&buf[25], a_len) == false) return (PARSER_SALT_ENCODING);

  const u32 a = (u32) zip1_number (&buf[25], a_len, 16);

  u32 b = a;

  if (slash != 0)
  {
    const u32 b_len = len - slash - 1;

    if (b_len != a_len) return (PARSER_SALT_LENGTH);

    if (zip1_is_hex (&buf[slash + 1], b_len) == false) return (PARSER_SALT_ENCODING);

    b = (u32) zip1_number (&buf[slash + 1], b_len, 16);
  }

  // a one byte value is the last byte of the header and sits in the high half here

  if (a_len == 2)
  {
    zip->hot[ZIP1_HOT_MASK + idx] = 0xff00;
    zip->hot[ZIP1_HOT_A + idx]    = a << 8;
    zip->hot[ZIP1_HOT_B + idx]    = b << 8;
  }
  else
  {
    zip->hot[ZIP1_HOT_MASK + idx] = 0xffff;
    zip->hot[ZIP1_HOT_A + idx]    = a;
    zip->hot[ZIP1_HOT_B + idx]    = b;
  }

  return (PARSER_OK);
}

static int zip1_decode_new (u32 *digest, salt_t *salt, zip1_t *zip, const char *line_buf, const int line_len)
{
  if (line_len < 7 + 6) return (PARSER_SIGNATURE_UNMATCHED);

  if (memcmp (&line_buf[line_len - 6], SIGNATURE_ZIP1_STOP, 6) != 0) return (PARSER_SIGNATURE_UNMATCHED);

  const char *field[ZIP1_FIELDS_MAX];

  u32 flen[ZIP1_FIELDS_MAX];

  u32 cnt = 0;

  const u32 end = (u32) line_len - 6;

  u32 pos = 7;

  if ((pos >= end) || (line_buf[pos] != '*')) return (PARSER_SEPARATOR_UNMATCHED);

  while (pos < end)
  {
    pos++;

    const u32 start = pos;

    while ((pos < end) && (line_buf[pos] != '*')) pos++;

    if (cnt == ZIP1_FIELDS_MAX) return (PARSER_TOKEN_LENGTH);

    field[cnt] = &line_buf[start];
    flen[cnt]  = pos - start;

    cnt++;
  }

  if (cnt < 1) return (PARSER_TOKEN_LENGTH);

  if ((flen[0] != 1) || (zip1_is_dec (field[0], 1) == false)) return (PARSER_SALT_VALUE);

  const u32 check_cnt = (u32) zip1_number (field[0], 1, 10);

  if ((check_cnt < 1) || (check_cnt > ZIP1_CHECK_MAX)) return (PARSER_SALT_VALUE);

  if (cnt != 1 + check_cnt + 5) return (PARSER_TOKEN_LENGTH);

  memset (zip, 0, sizeof (zip1_t));

  zip->check_cnt = check_cnt;

  for (u32 i = 0; i < check_cnt; i++)
  {
    const int rc = zip1_decode_check (zip, i, field[1 + i], flen[1 + i]);

    if (rc != PARSER_OK) return rc;
  }

  const u32 at = 1 + check_cnt;

  if ((flen[at + 0] < 1) || (flen[at + 0] > 3) || (zip1_is_dec (field[at + 0], flen[at + 0]) == false)) return (PARSER_SALT_VALUE);
  if ((flen[at + 1] != 8)                      || (zip1_is_hex (field[at + 1], flen[at + 1]) == false)) return (PARSER_SALT_VALUE);
  if ((flen[at + 2] < 1) || (flen[at + 2] > 16) || (zip1_is_hex (field[at + 2], flen[at + 2]) == false)) return (PARSER_SALT_VALUE);
  if ((flen[at + 3] < 1) || (flen[at + 3] > 16) || (zip1_is_hex (field[at + 3], flen[at + 3]) == false)) return (PARSER_SALT_VALUE);

  zip->method   = (u32) zip1_number (field[at + 0], flen[at + 0], 10);
  zip->crc32    = (u32) zip1_number (field[at + 1], flen[at + 1], 16);
  const u64 unpacked = zip1_number (field[at + 2], flen[at + 2], 16);
  const u64 packed   = zip1_number (field[at + 3], flen[at + 3], 16);

  zip->unpacked    = (u32) unpacked;
  zip->unpacked_hi = (u32) (unpacked >> 32);
  zip->packed      = (u32) packed;
  zip->packed_hi   = (u32) (packed >> 32);

  const u32 data_hex_len = flen[at + 4];

  if ((data_hex_len & 1) != 0) return (PARSER_SALT_LENGTH);

  if (data_hex_len > ZIP1_DATA_MAX * 2) return (PARSER_SALT_LENGTH);

  if (zip1_is_hex (field[at + 4], data_hex_len) == false) return (PARSER_SALT_ENCODING);

  const u32 data_len = data_hex_len / 2;

  for (u32 i = 0; i < data_len; i++) zip1_put_byte (zip->data, i, hex_to_u8 ((const u8 *) &field[at + 4][i * 2]));

  zip->data_len = data_len;

  const u32 hot_len = (data_len < (ZIP1_HOT_DATA * 4)) ? data_len : (ZIP1_HOT_DATA * 4);

  for (u32 i = 0; i < hot_len; i++) zip1_put_byte (zip->hot, (ZIP1_CHECK_MAX * 12) + i, zip1_get_byte (zip->data, i));

  const int rc = zip1_set_verify (zip);

  if (rc != PARSER_OK) return rc;

  zip1_set_digest (digest, salt, zip);

  return (PARSER_OK);
}

// One member of a zip2john line.

typedef struct zip1_john
{
  u32 data_type;
  u32 packed;
  u32 unpacked;
  u32 crc32;
  u32 method;
  u32 data_len;
  u32 check_crc;
  u32 check_time;

  const char *data;

} zip1_john_t;

static int zip1_decode_john (u32 *digest, salt_t *salt, zip1_t *zip, const char *line_buf, const int line_len)
{
  const u32 version = (memcmp (line_buf, SIGNATURE_PKZIP_V2, 8) == 0) ? 2 : 1;

  const u32 sig_len = (version == 2) ? 8 : 7;

  // the member count follows the signature without a separator

  if ((u32) line_len < sig_len + 2) return (PARSER_HASH_LENGTH);

  const char *field[8 * 13 + 4];

  u32 flen[8 * 13 + 4];

  u32 cnt = 0;

  u32 pos = sig_len;

  const u32 end = (u32) line_len;

  while (pos < end)
  {
    const u32 start = pos;

    while ((pos < end) && (line_buf[pos] != '*')) pos++;

    if (cnt == 8 * 13 + 4) return (PARSER_TOKEN_LENGTH);

    field[cnt] = &line_buf[start];
    flen[cnt]  = pos - start;

    cnt++;

    pos++;
  }

  if (cnt < 2) return (PARSER_HASH_LENGTH);

  if ((flen[0] != 1) || (zip1_is_dec (field[0], 1) == false)) return (PARSER_HASH_VALUE);
  if ((flen[1] != 1) || (zip1_is_dec (field[1], 1) == false)) return (PARSER_HASH_VALUE);

  const u32 hash_count    = (u32) zip1_number (field[0], 1, 10);
  const u32 checksum_size = (u32) zip1_number (field[1], 1, 10);

  if ((hash_count < 1) || (hash_count > ZIP1_CHECK_MAX)) return (PARSER_HASH_VALUE);

  if ((checksum_size != 1) && (checksum_size != 2)) return (PARSER_HASH_VALUE);

  zip1_john_t members[ZIP1_CHECK_MAX];

  memset (members, 0, sizeof (members));

  u32 at = 2;

  for (u32 i = 0; i < hash_count; i++)
  {
    zip1_john_t *m = &members[i];

    if (at + 2 > cnt) return (PARSER_HASH_LENGTH);

    if ((flen[at] != 1) || (zip1_is_dec (field[at], 1) == false)) return (PARSER_HASH_VALUE);

    m->data_type = (u32) zip1_number (field[at], 1, 10);

    if ((m->data_type < 1) || (m->data_type > 3)) return (PARSER_HASH_VALUE);

    at += 2;

    if (m->data_type > 1)
    {
      if (at + 5 > cnt) return (PARSER_HASH_LENGTH);

      for (u32 k = 0; k < 5; k++)
      {
        if ((flen[at + k] < 1) || (flen[at + k] > 16) || (zip1_is_hex (field[at + k], flen[at + k]) == false)) return (PARSER_HASH_VALUE);
      }

      m->packed   = (u32) zip1_number (field[at + 0], flen[at + 0], 16);
      m->unpacked = (u32) zip1_number (field[at + 1], flen[at + 1], 16);
      m->crc32    = (u32) zip1_number (field[at + 2], flen[at + 2], 16);

      at += 5;
    }

    const u32 need = (version == 2) ? 5 : 4;

    if (at + need > cnt) return (PARSER_HASH_LENGTH);

    if ((flen[at] < 1) || (flen[at] > 3) || (zip1_is_dec (field[at], flen[at]) == false)) return (PARSER_HASH_VALUE);

    m->method = (u32) zip1_number (field[at], flen[at], 10);

    for (u32 k = 1; k < need - 1; k++)
    {
      if ((flen[at + k] < 1) || (flen[at + k] > 8) || (zip1_is_hex (field[at + k], flen[at + k]) == false)) return (PARSER_HASH_VALUE);
    }

    m->data_len  = (u32) zip1_number (field[at + 1], flen[at + 1], 16);
    m->check_crc = (u32) zip1_number (field[at + 2], flen[at + 2], 16);

    m->check_time = (version == 2) ? (u32) zip1_number (field[at + 3], flen[at + 3], 16) : m->check_crc;

    const u32 data_at = at + need - 1;

    // a member whose data stayed in the archive (type 3) names the archive here instead

    if (m->data_type != 3)
    {
      if (flen[data_at] != m->data_len * 2) return (PARSER_HASH_LENGTH);

      if (zip1_is_hex (field[data_at], flen[data_at]) == false) return (PARSER_HASH_ENCODING);

      if (m->data_len < 12) return (PARSER_HASH_LENGTH);

      m->data = field[data_at];
    }

    at += need;
  }

  // The member whose data gets tested goes first: one that is here in full, or else a deflated
  // one whose first bytes are here.

  u32 first = hash_count;

  for (u32 i = 0; i < hash_count; i++)
  {
    if (members[i].data_type != 2) continue;

    if ((members[i].method != ZIP1_METHOD_STORED) && (members[i].method != ZIP1_METHOD_DEFLATE)) continue;

    if (members[i].data_len - 12 > ZIP1_DATA_MAX) continue;

    first = i;

    break;
  }

  if (first == hash_count)
  {
    for (u32 i = 0; i < hash_count; i++)
    {
      if ((members[i].data_type != 1) || (members[i].method != ZIP1_METHOD_DEFLATE)) continue;

      if (members[i].data_len - 12 > ZIP1_DATA_MAX) continue;

      first = i;

      break;
    }
  }

  memset (zip, 0, sizeof (zip1_t));

  u32 out = 0;

  for (u32 n = 0; n < hash_count; n++)
  {
    // position 0 is the chosen member, the others keep their order behind it

    u32 i = n;

    if (first != hash_count)
    {
      if (n == 0)
      {
        i = first;
      }
      else
      {
        i = (n <= first) ? n - 1 : n;
      }
    }

    const zip1_john_t *m = &members[i];

    if (m->data == NULL) continue;

    for (u32 k = 0; k < 12; k++) zip1_put_byte (zip->hot, (out * 12) + k, hex_to_u8 ((const u8 *) &m->data[k * 2]));

    zip->hot[ZIP1_HOT_MASK + out] = (checksum_size == 2) ? 0xffff : 0xff00;
    zip->hot[ZIP1_HOT_A + out]    = m->check_crc;
    zip->hot[ZIP1_HOT_B + out]    = m->check_time;

    if ((out == 0) && (i == first))
    {
      const u32 data_len = m->data_len - 12;

      for (u32 k = 0; k < data_len; k++) zip1_put_byte (zip->data, k, hex_to_u8 ((const u8 *) &m->data[(12 + k) * 2]));

      zip->data_len = data_len;
      zip->method   = m->method;

      if (m->data_type == 2)
      {
        zip->crc32    = m->crc32;
        zip->unpacked = m->unpacked;
        zip->packed   = data_len;
      }
      else
      {
        // only the start is here and the line does not say how long the stream is

        zip->packed = data_len + 1;
      }

      const u32 hot_len = (data_len < (ZIP1_HOT_DATA * 4)) ? data_len : (ZIP1_HOT_DATA * 4);

      for (u32 k = 0; k < hot_len; k++) zip1_put_byte (zip->hot, (ZIP1_CHECK_MAX * 12) + k, zip1_get_byte (zip->data, k));
    }

    out++;
  }

  if (out == 0) return (PARSER_HASH_VALUE);

  zip->check_cnt = out;

  const int rc = zip1_set_verify (zip);

  if (rc != PARSER_OK) return rc;

  zip1_set_digest (digest, salt, zip);

  return (PARSER_OK);
}

static int zip1_hash_decode (u32 *digest, salt_t *salt, zip1_t *zip, const char *line_buf, const int line_len)
{
  if (line_len < 8) return (PARSER_SIGNATURE_UNMATCHED);

  if (memcmp (line_buf, SIGNATURE_ZIP1, 7) == 0) return zip1_decode_new (digest, salt, zip, line_buf, line_len);

  if ((memcmp (line_buf, SIGNATURE_PKZIP_V1, 7) == 0) || (memcmp (line_buf, SIGNATURE_PKZIP_V2, 8) == 0))
  {
    // the stop signature is the start signature with a slash in it

    int len = line_len;

    const char *stop = (memcmp (line_buf, SIGNATURE_PKZIP_V2, 8) == 0) ? "$/pkzip2$" : "$/pkzip$";

    const int stop_len = (int) strlen (stop);

    if ((len > stop_len) && (memcmp (&line_buf[len - stop_len], stop, stop_len) == 0)) len -= stop_len;

    if ((len > 0) && (line_buf[len - 1] == '*')) len--;

    return zip1_decode_john (digest, salt, zip, line_buf, len);
  }

  return (PARSER_SIGNATURE_UNMATCHED);
}

static int zip1_hash_encode (const zip1_t *zip, char *line_buf, const int line_size)
{
  const u32 need = 7 + 3 + (zip->check_cnt * 36) + 60 + (zip->data_len * 2) + 6 + 1;

  if (need > (u32) line_size) return 0;

  int out_len = snprintf (line_buf, line_size, "%s*%u", SIGNATURE_ZIP1, zip->check_cnt);

  for (u32 i = 0; i < zip->check_cnt; i++)
  {
    line_buf[out_len++] = '*';

    for (u32 k = 0; k < 12; k++) out_len += snprintf (&line_buf[out_len], line_size - out_len, "%02x", zip1_get_byte (zip->hot, (i * 12) + k));

    if (zip->hot[ZIP1_HOT_MASK + i] == 0xffff)
    {
      out_len += snprintf (&line_buf[out_len], line_size - out_len, "/%04x", zip->hot[ZIP1_HOT_A + i]);

      if (zip->hot[ZIP1_HOT_B + i] != zip->hot[ZIP1_HOT_A + i]) out_len += snprintf (&line_buf[out_len], line_size - out_len, "/%04x", zip->hot[ZIP1_HOT_B + i]);
    }
    else
    {
      out_len += snprintf (&line_buf[out_len], line_size - out_len, "/%02x", zip->hot[ZIP1_HOT_A + i] >> 8);

      if (zip->hot[ZIP1_HOT_B + i] != zip->hot[ZIP1_HOT_A + i]) out_len += snprintf (&line_buf[out_len], line_size - out_len, "/%02x", zip->hot[ZIP1_HOT_B + i] >> 8);
    }
  }

  const u64 packed   = ((u64) zip->packed_hi   << 32) | zip->packed;
  const u64 unpacked = ((u64) zip->unpacked_hi << 32) | zip->unpacked;

  out_len += snprintf (&line_buf[out_len], line_size - out_len, "*%u*%08x*%" PRIx64 "*%" PRIx64 "*", zip->method, zip->crc32, unpacked, packed);

  for (u32 i = 0; i < zip->data_len; i++)
  {
    u8_to_hex (zip1_get_byte (zip->data, i), (u8 *) &line_buf[out_len]);

    out_len += 2;
  }

  out_len += snprintf (&line_buf[out_len], line_size - out_len, "%s", SIGNATURE_ZIP1_STOP);

  return out_len;
}
