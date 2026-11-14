/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

// What module 46800 needs on the host to verify a RAR5 entry that has no password check value:
// the RAR5 decompressor, BLAKE2sp, HMAC-SHA256 and CRC32. Included the way rar3_decode.c is: one
// translation unit, nothing exported.
//
// The decompressor follows UnRAR 7.3.2 (unpack50.cpp and the Huffman table code in unpack.cpp),
// written out in C for a hook that needs one thing from it: the checksum of what a candidate
// password unpacks to.
//
// UnRAR's license, paragraph 2, which has to accompany code derived from its source:
//
//   UnRAR source code may be used in any software to handle
//   RAR archives without limitations free of charge, but cannot be
//   used to develop RAR (WinRAR) compatible archiver and to
//   re-create RAR compression algorithm, which is proprietary.
//   Distribution of modified UnRAR source code in separate form
//   or as a part of other software is permitted, provided that
//   full text of this paragraph, starting from "UnRAR source code"
//   words, is included in license, or in documentation if license
//   is not available, and in source code comments of resulting package.
//
// The full license is in docs/license_libs/UNRAR_LICENSE.txt.

// ---- CRC32 ----

// The CRC32 is the one of rar_fast.c, which the module includes first.

static void rar5_crc32_init (void)
{
  rarf_crc32_init ();
}

static u32 rar5_crc32 (const u32 crc, const u8 *buf, const u64 len)
{
  const u32 next = rarf_crc32_large (crc, buf, len);

  return next;
}

// ---- SHA-256 and HMAC-SHA256 over bytes ----

static const u32 rar5_sha256_k[64] =
{
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

#define RAR5_ROR32(x,n) (((x) >> (n)) | ((x) << (32 - (n))))

static void rar5_sha256_block (u32 *h, const u8 *block)
{
  u32 w[64];

  for (u32 i = 0; i < 16; i++) w[i] = ((u32) block[i * 4] << 24) | ((u32) block[i * 4 + 1] << 16) | ((u32) block[i * 4 + 2] << 8) | (u32) block[i * 4 + 3];

  for (u32 i = 16; i < 64; i++)
  {
    const u32 s0 = RAR5_ROR32 (w[i - 15], 7) ^ RAR5_ROR32 (w[i - 15], 18) ^ (w[i - 15] >> 3);
    const u32 s1 = RAR5_ROR32 (w[i - 2], 17) ^ RAR5_ROR32 (w[i - 2], 19) ^ (w[i - 2] >> 10);

    w[i] = w[i - 16] + s0 + w[i - 7] + s1;
  }

  u32 a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];

  for (u32 i = 0; i < 64; i++)
  {
    const u32 t1 = hh + (RAR5_ROR32 (e, 6) ^ RAR5_ROR32 (e, 11) ^ RAR5_ROR32 (e, 25)) + ((e & f) ^ (~e & g)) + rar5_sha256_k[i] + w[i];
    const u32 t2 = (RAR5_ROR32 (a, 2) ^ RAR5_ROR32 (a, 13) ^ RAR5_ROR32 (a, 22)) + ((a & b) ^ (a & c) ^ (b & c));

    hh = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
  }

  h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
}

// SHA-256 of two short pieces, enough for an HMAC over at most 32 bytes of message.

static void rar5_sha256_2 (const u8 *a, const u64 a_len, const u8 *b, const u64 b_len, u8 *out)
{
  u32 h[8] = { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 };

  u8 buf[192];

  memset (buf, 0, sizeof (buf));

  const u64 len = a_len + b_len;

  memcpy (&buf[0],     a, a_len);
  memcpy (&buf[a_len], b, b_len);

  buf[len] = 0x80;

  const u64 total = ((len + 9 + 63) / 64) * 64;

  const u64 bits = (u64) len * 8;

  for (u32 i = 0; i < 8; i++) buf[total - 1 - i] = (u8) (bits >> (i * 8));

  for (u64 off = 0; off < total; off += 64) rar5_sha256_block (h, &buf[off]);

  for (u32 i = 0; i < 8; i++)
  {
    out[i * 4 + 0] = (u8) (h[i] >> 24);
    out[i * 4 + 1] = (u8) (h[i] >> 16);
    out[i * 4 + 2] = (u8) (h[i] >>  8);
    out[i * 4 + 3] = (u8) (h[i] >>  0);
  }
}

// HMAC-SHA256 with a 32 byte key over a message of at most 32 bytes.

static void rar5_hmac_sha256 (const u8 *key, const u8 *msg, const u64 msg_len, u8 *out)
{
  u8 ipad[64];
  u8 opad[64];

  memset (ipad, 0x36, 64);
  memset (opad, 0x5c, 64);

  for (u32 i = 0; i < 32; i++)
  {
    ipad[i] ^= key[i];
    opad[i] ^= key[i];
  }

  u8 inner[32];

  rar5_sha256_2 (ipad, 64, msg, msg_len, inner);
  rar5_sha256_2 (opad, 64, inner, 32, out);
}

// ---- BLAKE2sp ----

static const u32 rar5_blake2s_iv[8] =
{
  0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};

static const u8 rar5_blake2s_sigma[10][16] =
{
  {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 },
  { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 },
  { 11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4 },
  {  7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8 },
  {  9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13 },
  {  2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9 },
  { 12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11 },
  { 13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10 },
  {  6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5 },
  { 10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13,  0 }
};

typedef struct rar5_blake2s
{
  u32 h[8];
  u64 t;
  u8  buf[64];
  u32 buf_len;
  bool last_node;

} rar5_blake2s_t;

#define RAR5_B2S_G(a,b,c,d,x,y)                    \
{                                                  \
  v[a] = v[a] + v[b] + (x); v[d] = RAR5_ROR32 (v[d] ^ v[a], 16); \
  v[c] = v[c] + v[d];       v[b] = RAR5_ROR32 (v[b] ^ v[c], 12); \
  v[a] = v[a] + v[b] + (y); v[d] = RAR5_ROR32 (v[d] ^ v[a],  8); \
  v[c] = v[c] + v[d];       v[b] = RAR5_ROR32 (v[b] ^ v[c],  7); \
}

static void rar5_blake2s_compress (rar5_blake2s_t *s, const u8 *block, const bool final)
{
  u32 m[16];
  u32 v[16];

  for (u32 i = 0; i < 16; i++) m[i] = (u32) block[i * 4] | ((u32) block[i * 4 + 1] << 8) | ((u32) block[i * 4 + 2] << 16) | ((u32) block[i * 4 + 3] << 24);

  for (u32 i = 0; i < 8; i++)
  {
    v[i]     = s->h[i];
    v[i + 8] = rar5_blake2s_iv[i];
  }

  v[12] ^= (u32) (s->t >>  0);
  v[13] ^= (u32) (s->t >> 32);

  if (final == true)
  {
    v[14] ^= 0xffffffff;

    if (s->last_node == true) v[15] ^= 0xffffffff;
  }

  for (u32 r = 0; r < 10; r++)
  {
    const u8 *sg = rar5_blake2s_sigma[r];

    RAR5_B2S_G (0, 4,  8, 12, m[sg[ 0]], m[sg[ 1]]);
    RAR5_B2S_G (1, 5,  9, 13, m[sg[ 2]], m[sg[ 3]]);
    RAR5_B2S_G (2, 6, 10, 14, m[sg[ 4]], m[sg[ 5]]);
    RAR5_B2S_G (3, 7, 11, 15, m[sg[ 6]], m[sg[ 7]]);
    RAR5_B2S_G (0, 5, 10, 15, m[sg[ 8]], m[sg[ 9]]);
    RAR5_B2S_G (1, 6, 11, 12, m[sg[10]], m[sg[11]]);
    RAR5_B2S_G (2, 7,  8, 13, m[sg[12]], m[sg[13]]);
    RAR5_B2S_G (3, 4,  9, 14, m[sg[14]], m[sg[15]]);
  }

  for (u32 i = 0; i < 8; i++) s->h[i] ^= v[i] ^ v[i + 8];
}

// One node of the BLAKE2sp tree: 8 leaves at depth 0 and the root at depth 1.

static void rar5_blake2s_init_node (rar5_blake2s_t *s, const u32 node_offset, const u32 node_depth, const bool last_node)
{
  memset (s, 0, sizeof (rar5_blake2s_t));

  for (u32 i = 0; i < 8; i++) s->h[i] = rar5_blake2s_iv[i];

  // Word 0: digest length 32, no key, fanout 8, depth 2. Word 3: the node depth and an inner hash
  // length of 32.

  s->h[0] ^= 32 | (8u << 16) | (2u << 24);
  s->h[2] ^= node_offset;
  s->h[3] ^= (node_depth << 16) | (32u << 24);

  s->last_node = last_node;
}

static void rar5_blake2s_update (rar5_blake2s_t *s, const u8 *in, const u64 len)
{
  u64 at = 0;

  while (at < len)
  {
    // A full buffer is only compressed once more input arrives, because the last block is special.

    if (s->buf_len == 64)
    {
      s->t += 64;

      rar5_blake2s_compress (s, s->buf, false);

      s->buf_len = 0;
    }

    const u64 take = MIN (len - at, (u64) (64 - s->buf_len));

    memcpy (&s->buf[s->buf_len], &in[at], take);

    s->buf_len += (u32) take;

    at += take;
  }
}

static void rar5_blake2s_final (rar5_blake2s_t *s, u8 *out)
{
  s->t += s->buf_len;

  memset (&s->buf[s->buf_len], 0, 64 - s->buf_len);

  rar5_blake2s_compress (s, s->buf, true);

  for (u32 i = 0; i < 8; i++)
  {
    out[i * 4 + 0] = (u8) (s->h[i] >>  0);
    out[i * 4 + 1] = (u8) (s->h[i] >>  8);
    out[i * 4 + 2] = (u8) (s->h[i] >> 16);
    out[i * 4 + 3] = (u8) (s->h[i] >> 24);
  }
}

typedef struct rar5_blake2sp
{
  rar5_blake2s_t leaf[8];

  u64 total;

} rar5_blake2sp_t;

static void rar5_blake2sp_init (rar5_blake2sp_t *s)
{
  for (u32 i = 0; i < 8; i++) rar5_blake2s_init_node (&s->leaf[i], i, 0, (i == 7));

  s->total = 0;
}

// Input is dealt to the leaves in 64 byte blocks, round robin.

static void rar5_blake2sp_update (rar5_blake2sp_t *s, const u8 *in, const u64 len)
{
  u64 at = 0;

  while (at < len)
  {
    const u32    leaf = (u32) ((s->total / 64) % 8);
    const u64 room = 64 - (u64) (s->total % 64);
    const u64 take = MIN (len - at, room);

    rar5_blake2s_update (&s->leaf[leaf], &in[at], take);

    s->total += take;

    at += take;
  }
}

static void rar5_blake2sp_final (rar5_blake2sp_t *s, u8 *out)
{
  rar5_blake2s_t root;

  rar5_blake2s_init_node (&root, 0, 1, true);

  for (u32 i = 0; i < 8; i++)
  {
    u8 digest[32];

    rar5_blake2s_final (&s->leaf[i], digest);

    rar5_blake2s_update (&root, digest, 32);
  }

  rar5_blake2s_final (&root, out);
}

// ---- the checksum an entry is verified against ----

#define RAR5_CHECK_CRC32          0
#define RAR5_CHECK_CRC32_MAC      1
#define RAR5_CHECK_BLAKE2SP       2
#define RAR5_CHECK_BLAKE2SP_MAC   3
#define RAR5_CHECK_HEADER         4

typedef struct rar5_sum
{
  bool use_blake;

  u32 crc;

  rar5_blake2sp_t blake;

} rar5_sum_t;

static void rar5_sum_init (rar5_sum_t *sum, const u32 check_type)
{
  sum->use_blake = ((check_type == RAR5_CHECK_BLAKE2SP) || (check_type == RAR5_CHECK_BLAKE2SP_MAC));

  sum->crc = 0xffffffff;

  if (sum->use_blake == true) rar5_blake2sp_init (&sum->blake);
}

static void rar5_sum_update (rar5_sum_t *sum, const u8 *buf, const u64 len)
{
  if (sum->use_blake == true)
  {
    rar5_blake2sp_update (&sum->blake, buf, len);
  }
  else
  {
    sum->crc = rar5_crc32 (sum->crc, buf, len);
  }
}

// Whether the finished checksum is the one in the hash line. hash_key is the second PBKDF2 output,
// which RAR5 keys the checksum with when the entry's HASHMAC flag is set.

static bool rar5_sum_matches (rar5_sum_t *sum, const u32 check_type, const u8 *hash_key, const u8 *want)
{
  if (sum->use_blake == true)
  {
    u8 digest[32];

    rar5_blake2sp_final (&sum->blake, digest);

    if (check_type == RAR5_CHECK_BLAKE2SP_MAC)
    {
      u8 mac[32];

      rar5_hmac_sha256 (hash_key, digest, 32, mac);

      const bool mac_ok = (memcmp (mac, want, 32) == 0);

      return mac_ok;
    }

    const bool digest_ok = (memcmp (digest, want, 32) == 0);

    return digest_ok;
  }

  u32 crc = sum->crc ^ 0xffffffff;

  if (check_type == RAR5_CHECK_CRC32_MAC)
  {
    u8 raw[4];
    u8 mac[32];

    raw[0] = (u8) (crc >>  0);
    raw[1] = (u8) (crc >>  8);
    raw[2] = (u8) (crc >> 16);
    raw[3] = (u8) (crc >> 24);

    rar5_hmac_sha256 (hash_key, raw, 4, mac);

    crc = 0;

    for (u32 i = 0; i < 32; i++) crc ^= (u32) mac[i] << ((i & 3) * 8);
  }

  const u32 want_crc = ((u32) want[0] << 24) | ((u32) want[1] << 16) | ((u32) want[2] << 8) | (u32) want[3];

  const bool crc_ok = (crc == want_crc);

  return crc_ok;
}

// ---- Unpack50 ----

// The alphabet sizes: literals and match codes, distance codes as RAR 5.x and as RAR 7.x write
// them, low distance bits, repeat lengths, and the code the tables themselves are written in.

#define RAR5_NC   306
#define RAR5_DCB   64
#define RAR5_DCX   80
#define RAR5_LDC   16
#define RAR5_RC    44
#define RAR5_BC    20

#define RAR5_TABLE_MAX (RAR5_NC + RAR5_DCX + RAR5_RC + RAR5_LDC)

#define RAR5_FILTER_DELTA 0
#define RAR5_FILTER_E8    1
#define RAR5_FILTER_E8E9  2
#define RAR5_FILTER_ARM   3

#define RAR5_FILTER_BLOCK_MAX 0x400000
#define RAR5_FILTERS_MAX      8192

// The window is sized to the file, up to this. A file larger than the window still unpacks as
// long as no match reaches further back than the window is long.

#define RAR5_WIN_MIN 0x40000
#define RAR5_WIN_MAX 0x10000000

typedef struct rar5_huff
{
  u32 max_num;
  u32 decode_len[16];
  u32 decode_pos[16];
  u16 decode_num[RAR5_NC];

} rar5_huff_t;

typedef struct rar5_filter
{
  u64 start;
  u32 length;
  u32 type;
  u32 channels;

} rar5_filter_t;

typedef struct rar5_ctx
{
  const u8 *in;
  u64       in_bits;
  u64       bit;

  u8  *win;
  u64  win_mask;

  // produced counts the bytes unpacked into the window, written those handed to the checksum
  // after their filters ran.

  u64  produced;
  u64  written;
  u64  dest_size;

  rar5_sum_t *sum;

  rar5_filter_t *filters;
  u32            filters_cnt;
  u32            filters_at;

  u8 *filter_src;
  u8 *filter_dst;

  bool extra_dist;

  rar5_huff_t ld;
  rar5_huff_t dd;
  rar5_huff_t ldd;
  rar5_huff_t rd;
  rar5_huff_t bd;

  bool tables_read;

  // the block being read

  i64 block_start;
  i64 block_size;
  u32 block_bit_size;
  bool block_last;
  bool block_tables;

  bool failed;
  bool unsupported;

} rar5_ctx_t;

// The buffers one hook thread keeps between candidates.

typedef struct rar5_buffers
{
  u8  *win;
  u64  win_size;

  u8  *filter_src;
  u8  *filter_dst;

  rar5_filter_t *filters;

} rar5_buffers_t;

static void rar5_buffers_free (rar5_buffers_t *b)
{
  hcfree (b->win);
  hcfree (b->filter_src);
  hcfree (b->filter_dst);
  hcfree (b->filters);

  memset (b, 0, sizeof (rar5_buffers_t));
}

static bool rar5_buffers_ready (rar5_buffers_t *b, const u64 unpack_size)
{
  u64 want = RAR5_WIN_MIN;

  while ((want < unpack_size) && (want < RAR5_WIN_MAX)) want <<= 1;

  if ((b->win == NULL) || (b->win_size < want))
  {
    hcfree (b->win);

    b->win      = (u8 *) hcmalloc (want);
    b->win_size = (b->win == NULL) ? 0 : want;
  }

  if (b->filter_src == NULL) b->filter_src = (u8 *) hcmalloc (RAR5_FILTER_BLOCK_MAX);
  if (b->filter_dst == NULL) b->filter_dst = (u8 *) hcmalloc (RAR5_FILTER_BLOCK_MAX);
  if (b->filters    == NULL) b->filters    = (rar5_filter_t *) hccalloc (RAR5_FILTERS_MAX, sizeof (rar5_filter_t));

  if (b->win        == NULL) return false;
  if (b->filter_src == NULL) return false;
  if (b->filter_dst == NULL) return false;
  if (b->filters    == NULL) return false;

  return true;
}

// Up to 32 bits, zero filled past the end of the input.

static u32 rar5_peek (const rar5_ctx_t *ctx, const u32 count)
{
  const u64 byte = ctx->bit >> 3;
  const u64 size = ctx->in_bits >> 3;

  u64 v = 0;

  for (u32 i = 0; i < 5; i++)
  {
    v <<= 8;

    if (byte + i < size) v |= ctx->in[byte + i];
  }

  v <<= 24 + (ctx->bit & 7);

  const u32 bits = (count == 0) ? 0 : (u32) (v >> (64 - count));

  return bits;
}

static u32 rar5_getbits (const rar5_ctx_t *ctx)
{
  const u32 bits = rar5_peek (ctx, 16);

  return bits;
}

static void rar5_addbits (rar5_ctx_t *ctx, const u32 count)
{
  ctx->bit += count;

  // A stream that asks for more bits than the entry holds was not written by RAR.

  if (ctx->bit > ctx->in_bits) ctx->failed = true;
}

// A set of code lengths that claims more of the code space than there is describes no Huffman
// code. No packer writes one, and a wrong key produces one almost every time, so it is the
// cheapest way to turn a candidate down before anything is unpacked.

static bool rar5_code_fits (const u8 *lengths, const u32 size)
{
  u32 used = 0;

  for (u32 i = 0; i < size; i++)
  {
    const u32 length = lengths[i] & 0xf;

    if (length != 0) used += 0x8000 >> length;
  }

  const bool fits = (used <= 0x8000);

  return fits;
}

static void rar5_make_tables (const u8 *lengths, rar5_huff_t *dec, const u32 size)
{
  dec->max_num = size;

  u32 count[16];

  memset (count, 0, sizeof (count));

  for (u32 i = 0; i < size; i++) count[lengths[i] & 0xf]++;

  count[0] = 0;

  memset (dec->decode_num, 0, size * sizeof (dec->decode_num[0]));

  dec->decode_pos[0] = 0;
  dec->decode_len[0] = 0;

  u32 upper_limit = 0;

  for (u32 i = 1; i < 16; i++)
  {
    upper_limit += count[i];

    dec->decode_len[i] = upper_limit << (16 - i);

    upper_limit *= 2;

    dec->decode_pos[i] = dec->decode_pos[i - 1] + count[i - 1];
  }

  u32 copy_pos[16];

  memcpy (copy_pos, dec->decode_pos, sizeof (copy_pos));

  for (u32 i = 0; i < size; i++)
  {
    const u32 len = lengths[i] & 0xf;

    if (len == 0) continue;

    const u32 pos = copy_pos[len]++;

    if (pos < size) dec->decode_num[pos] = (u16) i;
  }
}

static u32 rar5_decode_number (rar5_ctx_t *ctx, const rar5_huff_t *dec)
{
  const u32 bit_field = rar5_getbits (ctx) & 0xfffe;

  u32 bits = 15;

  for (u32 i = 1; i < 15; i++)
  {
    if (bit_field < dec->decode_len[i])
    {
      bits = i;

      break;
    }
  }

  rar5_addbits (ctx, bits);

  u32 dist = bit_field - dec->decode_len[bits - 1];

  dist >>= (16 - bits);

  u32 pos = dec->decode_pos[bits] + dist;

  if (pos >= dec->max_num) pos = 0;

  return dec->decode_num[pos];
}

// Whether the bytes at the start of a block can be a RAR5 block header: the flags byte, the
// checksum byte and 1 to 3 size bytes. The first 16 decrypted bytes are enough to ask this.

static bool rar5_block_header_ok (const u8 *in)
{
  const u8 flags = in[0];

  const u32 byte_count = ((flags >> 3) & 3) + 1;

  if (byte_count == 4) return false;

  u8 sum = 0x5a ^ flags;

  for (u32 i = 0; i < byte_count; i++) sum ^= in[2 + i];

  const bool ok = (sum == in[1]);

  return ok;
}

static bool rar5_read_block_header (rar5_ctx_t *ctx)
{
  rar5_addbits (ctx, (u32) ((8 - (ctx->bit & 7)) & 7));

  const u8 flags = (u8) (rar5_getbits (ctx) >> 8);

  rar5_addbits (ctx, 8);

  const u32 byte_count = ((flags >> 3) & 3) + 1;

  if (byte_count == 4) return false;

  ctx->block_bit_size = (flags & 7) + 1;

  const u8 saved_sum = (u8) (rar5_getbits (ctx) >> 8);

  rar5_addbits (ctx, 8);

  u32 block_size = 0;

  for (u32 i = 0; i < byte_count; i++)
  {
    block_size += (rar5_getbits (ctx) >> 8) << (i * 8);

    rar5_addbits (ctx, 8);
  }

  const u8 sum = (u8) (0x5a ^ flags ^ block_size ^ (block_size >> 8) ^ (block_size >> 16));

  if (sum != saved_sum) return false;

  if (ctx->failed == true) return false;

  // A block cannot be longer than what is left of the entry.

  const u64 block_start = ctx->bit >> 3;

  if ((block_start + block_size) > (ctx->in_bits >> 3)) return false;

  ctx->block_size   = (i64) block_size;
  ctx->block_start  = (i64) block_start;
  ctx->block_last   = ((flags & 0x40) != 0);
  ctx->block_tables = ((flags & 0x80) != 0);

  return true;
}

static bool rar5_read_tables (rar5_ctx_t *ctx)
{
  // A block may only do without tables once an earlier one has brought them.

  if (ctx->block_tables == false) return ctx->tables_read;

  u8 bit_length[RAR5_BC];

  for (u32 i = 0; i < RAR5_BC; i++)
  {
    const u32 length = (rar5_getbits (ctx) >> 12) & 0xf;

    rar5_addbits (ctx, 4);

    if (length == 15)
    {
      u32 zero_count = (rar5_getbits (ctx) >> 12) & 0xf;

      rar5_addbits (ctx, 4);

      if (zero_count == 0)
      {
        bit_length[i] = 15;
      }
      else
      {
        zero_count += 2;

        for (u32 j = 0; (j < zero_count) && (i < RAR5_BC); j++, i++) bit_length[i] = 0;

        i--;
      }
    }
    else
    {
      bit_length[i] = (u8) length;
    }
  }

  if (rar5_code_fits (bit_length, RAR5_BC) == false) return false;

  rar5_make_tables (bit_length, &ctx->bd, RAR5_BC);

  u8 table[RAR5_TABLE_MAX];

  const u32 dcodes     = (ctx->extra_dist == true) ? RAR5_DCX : RAR5_DCB;
  const u32 table_size = RAR5_NC + dcodes + RAR5_RC + RAR5_LDC;

  for (u32 i = 0; i < table_size; )
  {
    if (ctx->failed == true) return false;

    const u32 number = rar5_decode_number (ctx, &ctx->bd);

    if (number < 16)
    {
      table[i] = (u8) number;

      i++;
    }
    else if (number < 18)
    {
      u32 n;

      if (number == 16)
      {
        n = (rar5_getbits (ctx) >> 13) + 3;

        rar5_addbits (ctx, 3);
      }
      else
      {
        n = (rar5_getbits (ctx) >> 9) + 11;

        rar5_addbits (ctx, 7);
      }

      // There is nothing to repeat at the first position.

      if (i == 0) return false;

      for (u32 j = 0; (j < n) && (i < table_size); j++, i++) table[i] = table[i - 1];
    }
    else
    {
      u32 n;

      if (number == 18)
      {
        n = (rar5_getbits (ctx) >> 13) + 3;

        rar5_addbits (ctx, 3);
      }
      else
      {
        n = (rar5_getbits (ctx) >> 9) + 11;

        rar5_addbits (ctx, 7);
      }

      for (u32 j = 0; (j < n) && (i < table_size); j++, i++) table[i] = 0;
    }
  }

  if (ctx->failed == true) return false;

  ctx->tables_read = true;

  if (rar5_code_fits (&table[0], RAR5_NC) == false) return false;

  rar5_make_tables (&table[0],                          &ctx->ld,  RAR5_NC);
  if (rar5_code_fits (&table[RAR5_NC], dcodes) == false) return false;

  rar5_make_tables (&table[RAR5_NC],                    &ctx->dd,  dcodes);
  if (rar5_code_fits (&table[RAR5_NC + dcodes], RAR5_LDC) == false) return false;

  rar5_make_tables (&table[RAR5_NC + dcodes],           &ctx->ldd, RAR5_LDC);
  if (rar5_code_fits (&table[RAR5_NC + dcodes + RAR5_LDC], RAR5_RC) == false) return false;

  rar5_make_tables (&table[RAR5_NC + dcodes + RAR5_LDC], &ctx->rd,  RAR5_RC);

  return true;
}

static u32 rar5_slot_to_length (rar5_ctx_t *ctx, const u32 slot)
{
  u32 lbits;
  u32 length = 2;

  if (slot < 8)
  {
    lbits = 0;

    length += slot;
  }
  else
  {
    lbits = (slot / 4) - 1;

    length += (4 | (slot & 3)) << lbits;
  }

  if (lbits > 0)
  {
    length += rar5_getbits (ctx) >> (16 - lbits);

    rar5_addbits (ctx, lbits);
  }

  return length;
}

static void rar5_apply_filter (rar5_ctx_t *ctx, const rar5_filter_t *flt, u8 **out)
{
  u8 *data = ctx->filter_src;

  const u32 size = flt->length;

  *out = data;

  switch (flt->type)
  {
    case RAR5_FILTER_E8:
    case RAR5_FILTER_E8E9:
    {
      const u32 file_offset = (u32) flt->start;
      const u32 file_size   = 0x1000000;

      const u8 cmp2 = (flt->type == RAR5_FILTER_E8E9) ? 0xe9 : 0xe8;

      for (u32 cur = 0; cur + 4 < size; )
      {
        const u8 byte = data[cur];

        cur++;

        if ((byte == 0xe8) || (byte == cmp2))
        {
          const u32 offset = (cur + file_offset) % file_size;

          u8 *p = &data[cur];

          const u32 addr = (u32) p[0] | ((u32) p[1] << 8) | ((u32) p[2] << 16) | ((u32) p[3] << 24);

          u32  put  = addr;
          bool doit = false;

          if ((addr & 0x80000000) != 0)
          {
            if (((addr + offset) & 0x80000000) == 0)
            {
              put  = addr + file_size;
              doit = true;
            }
          }
          else if (((addr - file_size) & 0x80000000) != 0)
          {
            put  = addr - offset;
            doit = true;
          }

          if (doit == true)
          {
            p[0] = (u8) (put >>  0);
            p[1] = (u8) (put >>  8);
            p[2] = (u8) (put >> 16);
            p[3] = (u8) (put >> 24);
          }

          cur += 4;
        }
      }

      break;
    }

    case RAR5_FILTER_ARM:
    {
      const u32 file_offset = (u32) flt->start;

      for (u32 cur = 0; cur + 3 < size; cur += 4)
      {
        u8 *d = &data[cur];

        // BL with the Always condition

        if (d[3] == 0xeb)
        {
          u32 offset = (u32) d[0] + ((u32) d[1] << 8) + ((u32) d[2] << 16);

          offset -= (file_offset + cur) / 4;

          d[0] = (u8) (offset >>  0);
          d[1] = (u8) (offset >>  8);
          d[2] = (u8) (offset >> 16);
        }
      }

      break;
    }

    case RAR5_FILTER_DELTA:
    {
      u8 *dst = ctx->filter_dst;

      u32 src_pos = 0;

      for (u32 channel = 0; channel < flt->channels; channel++)
      {
        u8 prev = 0;

        for (u32 dest_pos = channel; dest_pos < size; dest_pos += flt->channels, src_pos++)
        {
          prev = (u8) (prev - data[src_pos]);

          dst[dest_pos] = prev;
        }
      }

      *out = dst;

      break;
    }

    default:

      // A filter type this decoder does not know: the bytes would reach the checksum untransformed.

      ctx->unsupported = true;

      break;
  }
}

static void rar5_sum_window (rar5_ctx_t *ctx, const u64 from, const u64 to)
{
  u64 at = from;

  while (at < to)
  {
    const u64 off  = at & ctx->win_mask;
    const u64 take = MIN (to - at, (ctx->win_mask + 1) - off);

    rar5_sum_update (ctx->sum, &ctx->win[off], take);

    at += take;
  }
}

// Hands unpacked bytes to the checksum, running each filter over its block once the block is
// complete. Bytes in front of an incomplete block wait in the window.

static void rar5_flush (rar5_ctx_t *ctx)
{
  while (ctx->filters_at < ctx->filters_cnt)
  {
    const rar5_filter_t *flt = &ctx->filters[ctx->filters_at];

    if (flt->start < ctx->written)
    {
      // A filter over bytes that already reached the checksum.

      ctx->failed = true;

      return;
    }

    if (flt->start >= ctx->produced)
    {
      break;
    }

    if (flt->start > ctx->written)
    {
      rar5_sum_window (ctx, ctx->written, flt->start);

      ctx->written = flt->start;
    }

    if (ctx->produced < flt->start + flt->length) return;

    if (flt->length > 0)
    {
      for (u32 i = 0; i < flt->length; i++) ctx->filter_src[i] = ctx->win[(flt->start + i) & ctx->win_mask];

      u8 *out = NULL;

      rar5_apply_filter (ctx, flt, &out);

      rar5_sum_update (ctx->sum, out, flt->length);

      ctx->written += flt->length;
    }

    ctx->filters_at++;
  }

  if (ctx->filters_at == ctx->filters_cnt)
  {
    ctx->filters_at  = 0;
    ctx->filters_cnt = 0;
  }

  if ((ctx->filters_cnt == 0) || (ctx->filters[ctx->filters_at].start >= ctx->produced))
  {
    const u64 to = (ctx->filters_cnt == 0) ? ctx->produced : MIN (ctx->produced, ctx->filters[ctx->filters_at].start);

    rar5_sum_window (ctx, ctx->written, to);

    ctx->written = to;
  }
}

static void rar5_emit (rar5_ctx_t *ctx, const u8 byte)
{
  if (ctx->produced >= ctx->dest_size)
  {
    ctx->failed = true;

    return;
  }

  // Unwritten bytes are about to be overwritten: flush, and if a filter block larger than the
  // window is what holds them back, the stream cannot be unpacked here.

  if (ctx->produced - ctx->written > ctx->win_mask)
  {
    rar5_flush (ctx);

    if (ctx->produced - ctx->written > ctx->win_mask)
    {
      ctx->unsupported = true;
      ctx->failed      = true;

      return;
    }
  }

  ctx->win[ctx->produced & ctx->win_mask] = byte;

  ctx->produced++;
}

// A match that reaches before the first byte of the file reads zeros, as UnRAR does for a file
// that does not continue a solid stream.

static void rar5_copy (rar5_ctx_t *ctx, const u32 length, const u64 dist)
{
  if (ctx->produced + length > ctx->dest_size)
  {
    ctx->failed = true;

    return;
  }

  if ((dist != 0) && (dist <= ctx->produced) && (dist > ctx->win_mask + 1))
  {
    // A real match further back than the window this thread could allocate.

    ctx->unsupported = true;
    ctx->failed      = true;

    return;
  }

  const bool before = ((dist == 0) || (dist > ctx->produced));

  for (u32 i = 0; (i < length) && (ctx->failed == false); i++)
  {
    const u8 byte = (before == true) ? 0 : ctx->win[(ctx->produced - dist) & ctx->win_mask];

    rar5_emit (ctx, byte);
  }
}

static u32 rar5_read_filter_data (rar5_ctx_t *ctx)
{
  const u32 byte_count = (rar5_getbits (ctx) >> 14) + 1;

  rar5_addbits (ctx, 2);

  u32 data = 0;

  for (u32 i = 0; i < byte_count; i++)
  {
    data += (rar5_getbits (ctx) >> 8) << (i * 8);

    rar5_addbits (ctx, 8);
  }

  return data;
}

static bool rar5_read_filter (rar5_ctx_t *ctx)
{
  rar5_filter_t flt;

  memset (&flt, 0, sizeof (flt));

  const u32 block_start = rar5_read_filter_data (ctx);

  flt.length = rar5_read_filter_data (ctx);

  if (flt.length > RAR5_FILTER_BLOCK_MAX) flt.length = 0;

  flt.type = rar5_getbits (ctx) >> 13;

  rar5_addbits (ctx, 3);

  if (flt.type == RAR5_FILTER_DELTA)
  {
    flt.channels = (rar5_getbits (ctx) >> 11) + 1;

    rar5_addbits (ctx, 5);
  }

  flt.start = ctx->produced + block_start;

  if (ctx->filters_cnt >= RAR5_FILTERS_MAX)
  {
    rar5_flush (ctx);

    if (ctx->filters_cnt >= RAR5_FILTERS_MAX)
    {
      ctx->unsupported = true;

      return false;
    }
  }

  ctx->filters[ctx->filters_cnt] = flt;

  ctx->filters_cnt++;

  return true;
}

// Unpacks one RAR5 file that does not continue a solid stream, feeding the unpacked bytes to sum.
// extra_dist selects the RAR 7.x distance table. Returns 1 when the stream produced exactly
// unpack_size bytes. *header_ok says whether the first block header was valid, which is what tells
// a wrong password from a stream of the other table layout. *unsupported says the stream is one
// this decoder cannot unpack.

static bool rar5_unpack (rar5_buffers_t *buffers, const u8 *in, const u64 pack_size, const u64 unpack_size, const bool extra_dist, rar5_sum_t *sum, bool *header_ok, bool *unsupported)
{
  // Too large for the hook thread's stack, so it lives in static storage per thread.

  static __thread rar5_ctx_t ctx;

  memset (&ctx, 0, sizeof (ctx));

  ctx.in         = in;
  ctx.in_bits    = pack_size * 8;
  ctx.win        = buffers->win;
  ctx.win_mask   = buffers->win_size - 1;
  ctx.dest_size  = unpack_size;
  ctx.sum        = sum;
  ctx.filters    = buffers->filters;
  ctx.filter_src = buffers->filter_src;
  ctx.filter_dst = buffers->filter_dst;
  ctx.extra_dist = extra_dist;

  *header_ok   = false;
  *unsupported = false;

  u64 old_dist[4] = { (u64) -1, (u64) -1, (u64) -1, (u64) -1 };

  u32 last_length = 0;

  if (rar5_read_block_header (&ctx) == false) return false;

  *header_ok = true;

  if (rar5_read_tables (&ctx) == false) return false;

  if (ctx.tables_read == false) return false;

  while (ctx.failed == false)
  {
    // The end of the block: the last byte holds block_bit_size bits.

    bool file_done = false;

    while (1)
    {
      const i64 addr = (i64) (ctx.bit >> 3);
      const u32 inb  = (u32) (ctx.bit & 7);

      const i64 last = ctx.block_start + ctx.block_size - 1;

      if ((addr > last) || ((addr == last) && (inb >= ctx.block_bit_size)))
      {
        if (ctx.block_last == true)
        {
          file_done = true;

          break;
        }

        if ((rar5_read_block_header (&ctx) == false) || (rar5_read_tables (&ctx) == false))
        {
          ctx.failed = true;

          break;
        }

        continue;
      }

      break;
    }

    if (file_done == true) break;

    if (ctx.failed == true) break;

    const u32 main_slot = rar5_decode_number (&ctx, &ctx.ld);

    if (main_slot < 256)
    {
      rar5_emit (&ctx, (u8) main_slot);

      continue;
    }

    if (main_slot >= 262)
    {
      u32 length = rar5_slot_to_length (&ctx, main_slot - 262);

      u64 dist = 1;

      u32 dbits;

      const u32 dist_slot = rar5_decode_number (&ctx, &ctx.dd);

      if (dist_slot < 4)
      {
        dbits = 0;

        dist += dist_slot;
      }
      else
      {
        dbits = (dist_slot / 2) - 1;

        dist += (u64) (2 | (dist_slot & 1)) << dbits;
      }

      if (dbits > 0)
      {
        if (dbits >= 4)
        {
          if (dbits > 4)
          {
            // The high bits, up to 34 of them for the RAR 7.x table, in two reads.

            u32 left = dbits - 4;

            u64 high = 0;

            while (left > 0)
            {
              const u32 take = MIN (left, 16);

              high = (high << take) | (rar5_getbits (&ctx) >> (16 - take));

              rar5_addbits (&ctx, take);

              left -= take;
            }

            dist += high << 4;
          }

          dist += rar5_decode_number (&ctx, &ctx.ldd);
        }
        else
        {
          dist += rar5_getbits (&ctx) >> (16 - dbits);

          rar5_addbits (&ctx, dbits);
        }
      }

      if (dist > 0x100)
      {
        length++;

        if (dist > 0x2000)
        {
          length++;

          if (dist > 0x40000) length++;
        }
      }

      old_dist[3] = old_dist[2];
      old_dist[2] = old_dist[1];
      old_dist[1] = old_dist[0];
      old_dist[0] = dist;

      last_length = length;

      rar5_copy (&ctx, length, dist);

      continue;
    }

    if (main_slot == 256)
    {
      if (rar5_read_filter (&ctx) == false) break;

      continue;
    }

    if (main_slot == 257)
    {
      if (last_length != 0) rar5_copy (&ctx, last_length, old_dist[0]);

      continue;
    }

    // 258..261: one of the 4 last distances

    const u32 dist_num = main_slot - 258;

    const u64 dist = old_dist[dist_num];

    for (u32 i = dist_num; i > 0; i--) old_dist[i] = old_dist[i - 1];

    old_dist[0] = dist;

    const u32 length_slot = rar5_decode_number (&ctx, &ctx.rd);

    const u32 length = rar5_slot_to_length (&ctx, length_slot);

    last_length = length;

    rar5_copy (&ctx, length, dist);
  }

  if (ctx.failed == false) rar5_flush (&ctx);

  *unsupported = ctx.unsupported;

  if (ctx.failed      == true) return false;
  if (ctx.unsupported == true) return false;

  // Every byte has to have reached the checksum: a filter still waiting for its block means the
  // stream ended inside one.

  const bool complete = ((ctx.produced == ctx.dest_size) && (ctx.written == ctx.dest_size));

  return complete;
}

// ---- checktype 4: the first header behind an archive encryption header ----

// The decrypted bytes begin with a header: its CRC32, its size as a vint, then that many bytes
// which the CRC32 covers together with the size field. The first header of an archive is the main
// archive header, type 1.

static bool rar5_header_matches (const u8 *plain, const u32 len)
{
  if (len < 8) return false;

  const u32 want = (u32) plain[0] | ((u32) plain[1] << 8) | ((u32) plain[2] << 16) | ((u32) plain[3] << 24);

  u64 size  = 0;
  u32 shift = 0;
  u32 pos   = 4;

  while (1)
  {
    // A header size takes at most 3 bytes.

    if ((pos >= len) || (shift > 14)) return false;

    const u8 b = plain[pos];

    pos++;

    size |= (u64) (b & 0x7f) << shift;

    shift += 7;

    if ((b & 0x80) == 0) break;
  }

  if (size < 2) return false;

  if ((u64) pos + size > len) return false;

  if (plain[pos] != 1) return false;

  const u32 crc = rar5_crc32 (0xffffffff, &plain[4], (u64) ((pos - 4) + size)) ^ 0xffffffff;

  const bool ok = (crc == want);

  return ok;
}
