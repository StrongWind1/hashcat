/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "inc_vendor.h"
#include "inc_types.h"
#include "inc_platform.h"
#include "inc_common.h"
#include "inc_hash_md2.h"

// MD2 S-box (RFC 1319, derived from digits of pi)

CONSTANT_VK u32a md2_S[256] =
{
   41,  46,  67, 201, 162, 216, 124,   1,  61,  54,  84, 161,
  236, 240,   6,  19,  98, 167,   5, 243, 192, 199, 115, 140,
  152, 147,  43, 217, 188,  76, 130, 202,  30, 155,  87,  60,
  253, 212, 224,  22, 103,  66, 111,  24, 138,  23, 229,  18,
  190,  78, 196, 214, 218, 158, 222,  73, 160, 251, 245, 142,
  187,  47, 238, 122, 169, 104, 121, 145,  21, 178,   7,  63,
  148, 194,  16, 137,  11,  34,  95,  33, 128, 127,  93, 154,
   90, 144,  50,  39,  53,  62, 204, 231, 191, 247, 151,   3,
  255,  25,  48, 179,  72, 165, 181, 209, 215,  94, 146,  42,
  172,  86, 170, 198,  79, 184,  56, 210, 150, 164, 125, 182,
  118, 252, 107, 226, 156, 116,   4, 241,  69, 157, 112,  89,
  100, 113, 135,  32, 134,  91, 207, 101, 230,  45, 168,   2,
   27,  96,  37, 173, 174, 176, 185, 246,  28,  70,  97, 105,
   52,  64, 126,  15,  85,  71, 163,  35, 221,  81, 175,  58,
  195,  92, 249, 206, 186, 197, 234,  38,  44,  83,  13, 110,
  133,  40, 132,   9, 211, 223, 205, 244,  65, 129,  77,  82,
  106, 220,  55, 200, 108, 193, 171, 250,  36, 225, 123,   8,
   12, 189, 177,  74, 120, 136, 149, 139, 227,  99, 232, 109,
  233, 203, 213, 254,  59,   0,  29,  57, 242, 239, 183,  14,
  102,  88, 208, 228, 166, 119, 114, 248, 235, 117,  75,  10,
   49,  68,  80, 180, 143, 237,  31,  26, 219, 153, 141,  51,
  159,  17, 131,  20,
};

// MD2 block transform.  Processes one 16-byte block: updates state h[4],
// checksum C[4], and accumulator L.  block[4] is the 16-byte input.
// Per RFC 1319 (corrected errata).

DECLSPEC void md2_transform (PRIVATE_AS u32 *h, PRIVATE_AS u32 *C, PRIVATE_AS u32 *L_ptr, PRIVATE_AS const u32 *block)
{
  u32 X[12];

  X[ 0] = h[0];
  X[ 1] = h[1];
  X[ 2] = h[2];
  X[ 3] = h[3];
  X[ 4] = block[0];
  X[ 5] = block[1];
  X[ 6] = block[2];
  X[ 7] = block[3];
  X[ 8] = h[0] ^ block[0];
  X[ 9] = h[1] ^ block[1];
  X[10] = h[2] ^ block[2];
  X[11] = h[3] ^ block[3];

  // Update checksum: C[j] ^= S[block[j] ^ L], L = new C[j]

  u32 Lval = *L_ptr;

  for (int j = 0; j < 4; j++)
  {
    u32 bw = block[j];
    u32 cw = C[j];

    u32 b0 = (bw >>  0) & 0xff;
    u32 b1 = (bw >>  8) & 0xff;
    u32 b2 = (bw >> 16) & 0xff;
    u32 b3 = (bw >> 24) & 0xff;

    u32 c0 = (cw >>  0) & 0xff;
    u32 c1 = (cw >>  8) & 0xff;
    u32 c2 = (cw >> 16) & 0xff;
    u32 c3 = (cw >> 24) & 0xff;

    c0 ^= md2_S[b0 ^ Lval]; Lval = c0;
    c1 ^= md2_S[b1 ^ Lval]; Lval = c1;
    c2 ^= md2_S[b2 ^ Lval]; Lval = c2;
    c3 ^= md2_S[b3 ^ Lval]; Lval = c3;

    C[j] = (c0 <<  0)
         | (c1 <<  8)
         | (c2 << 16)
         | (c3 << 24);
  }

  *L_ptr = Lval;

  // 18 rounds of substitution over 48 bytes (12 u32 words)

  u32 t = 0;

  for (int j = 0; j < 18; j++)
  {
    for (int k = 0; k < 12; k++)
    {
      u32 word = X[k];

      u32 v0 = (word >>  0) & 0xff;
      u32 v1 = (word >>  8) & 0xff;
      u32 v2 = (word >> 16) & 0xff;
      u32 v3 = (word >> 24) & 0xff;

      v0 ^= md2_S[t]; t = v0;
      v1 ^= md2_S[t]; t = v1;
      v2 ^= md2_S[t]; t = v2;
      v3 ^= md2_S[t]; t = v3;

      X[k] = (v0 <<  0)
           | (v1 <<  8)
           | (v2 << 16)
           | (v3 << 24);
    }

    t = (t + (u32) j) & 0xff;
  }

  h[0] = X[0];
  h[1] = X[1];
  h[2] = X[2];
  h[3] = X[3];
}

DECLSPEC void md2_init (PRIVATE_AS md2_ctx_t *ctx)
{
  ctx->h[0] = 0;
  ctx->h[1] = 0;
  ctx->h[2] = 0;
  ctx->h[3] = 0;

  ctx->C[0] = 0;
  ctx->C[1] = 0;
  ctx->C[2] = 0;
  ctx->C[3] = 0;

  ctx->L = 0;

  ctx->w0[0] = 0;
  ctx->w0[1] = 0;
  ctx->w0[2] = 0;
  ctx->w0[3] = 0;

  ctx->len = 0;
}

// Append up to 64 bytes (in w0-w3) to the MD2 context.
// MD2 block size is 16 bytes; full blocks are processed immediately.

DECLSPEC void md2_update_64 (PRIVATE_AS md2_ctx_t *ctx, PRIVATE_AS u32 *w0, PRIVATE_AS u32 *w1, PRIVATE_AS u32 *w2, PRIVATE_AS u32 *w3, const int len)
{
  if (len == 0) return;

  const int pos = ctx->len & 15;

  ctx->len += len;

  if (pos == 0)
  {
    if (len < 16)
    {
      ctx->w0[0] = w0[0];
      ctx->w0[1] = w0[1];
      ctx->w0[2] = w0[2];
      ctx->w0[3] = w0[3];

      return;
    }

    md2_transform (ctx->h, ctx->C, &ctx->L, w0);

    if (len < 32)
    {
      if (len > 16)
      {
        ctx->w0[0] = w1[0];
        ctx->w0[1] = w1[1];
        ctx->w0[2] = w1[2];
        ctx->w0[3] = w1[3];
      }

      return;
    }

    md2_transform (ctx->h, ctx->C, &ctx->L, w1);

    if (len < 48)
    {
      if (len > 32)
      {
        ctx->w0[0] = w2[0];
        ctx->w0[1] = w2[1];
        ctx->w0[2] = w2[2];
        ctx->w0[3] = w2[3];
      }

      return;
    }

    md2_transform (ctx->h, ctx->C, &ctx->L, w2);

    if (len < 64)
    {
      if (len > 48)
      {
        ctx->w0[0] = w3[0];
        ctx->w0[1] = w3[1];
        ctx->w0[2] = w3[2];
        ctx->w0[3] = w3[3];
      }

      return;
    }

    md2_transform (ctx->h, ctx->C, &ctx->L, w3);

    return;
  }

  // pos > 0: merge incoming data with partial buffer byte-by-byte

  u32 w[16];

  w[ 0] = w0[0]; w[ 1] = w0[1]; w[ 2] = w0[2]; w[ 3] = w0[3];
  w[ 4] = w1[0]; w[ 5] = w1[1]; w[ 6] = w1[2]; w[ 7] = w1[3];
  w[ 8] = w2[0]; w[ 9] = w2[1]; w[10] = w2[2]; w[11] = w2[3];
  w[12] = w3[0]; w[13] = w3[1]; w[14] = w3[2]; w[15] = w3[3];

  int src = 0;
  int dst = pos;

  while (src < len)
  {
    const u32 sv = (w[src >> 2] >> ((src & 3) << 3)) & 0xff;
    const u32 ds = (dst & 3) << 3;

    ctx->w0[dst >> 2] = (ctx->w0[dst >> 2] & ~(0xffu << ds)) | (sv << ds);

    src++;
    dst++;

    if (dst == 16)
    {
      md2_transform (ctx->h, ctx->C, &ctx->L, ctx->w0);

      ctx->w0[0] = 0;
      ctx->w0[1] = 0;
      ctx->w0[2] = 0;
      ctx->w0[3] = 0;

      dst = 0;
    }
  }
}

DECLSPEC void md2_update (PRIVATE_AS md2_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len)
{
  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  int pos1;
  int pos4;

  for (pos1 = 0, pos4 = 0; pos1 < len - 64; pos1 += 64, pos4 += 16)
  {
    w0[0] = w[pos4 +  0];
    w0[1] = w[pos4 +  1];
    w0[2] = w[pos4 +  2];
    w0[3] = w[pos4 +  3];
    w1[0] = w[pos4 +  4];
    w1[1] = w[pos4 +  5];
    w1[2] = w[pos4 +  6];
    w1[3] = w[pos4 +  7];
    w2[0] = w[pos4 +  8];
    w2[1] = w[pos4 +  9];
    w2[2] = w[pos4 + 10];
    w2[3] = w[pos4 + 11];
    w3[0] = w[pos4 + 12];
    w3[1] = w[pos4 + 13];
    w3[2] = w[pos4 + 14];
    w3[3] = w[pos4 + 15];

    md2_update_64 (ctx, w0, w1, w2, w3, 64);
  }

  const int tail = len - pos1;

  u32 t[16];

  t[ 0] = hc_bounded_word_le_S (w, pos4 +  0, tail -   0);
  t[ 1] = hc_bounded_word_le_S (w, pos4 +  1, tail -   4);
  t[ 2] = hc_bounded_word_le_S (w, pos4 +  2, tail -   8);
  t[ 3] = hc_bounded_word_le_S (w, pos4 +  3, tail -  12);
  t[ 4] = hc_bounded_word_le_S (w, pos4 +  4, tail -  16);
  t[ 5] = hc_bounded_word_le_S (w, pos4 +  5, tail -  20);
  t[ 6] = hc_bounded_word_le_S (w, pos4 +  6, tail -  24);
  t[ 7] = hc_bounded_word_le_S (w, pos4 +  7, tail -  28);
  t[ 8] = hc_bounded_word_le_S (w, pos4 +  8, tail -  32);
  t[ 9] = hc_bounded_word_le_S (w, pos4 +  9, tail -  36);
  t[10] = hc_bounded_word_le_S (w, pos4 + 10, tail -  40);
  t[11] = hc_bounded_word_le_S (w, pos4 + 11, tail -  44);
  t[12] = hc_bounded_word_le_S (w, pos4 + 12, tail -  48);
  t[13] = hc_bounded_word_le_S (w, pos4 + 13, tail -  52);
  t[14] = hc_bounded_word_le_S (w, pos4 + 14, tail -  56);
  t[15] = hc_bounded_word_le_S (w, pos4 + 15, tail -  60);

  w0[0] = t[ 0];
  w0[1] = t[ 1];
  w0[2] = t[ 2];
  w0[3] = t[ 3];
  w1[0] = t[ 4];
  w1[1] = t[ 5];
  w1[2] = t[ 6];
  w1[3] = t[ 7];
  w2[0] = t[ 8];
  w2[1] = t[ 9];
  w2[2] = t[10];
  w2[3] = t[11];
  w3[0] = t[12];
  w3[1] = t[13];
  w3[2] = t[14];
  w3[3] = t[15];

  md2_update_64 (ctx, w0, w1, w2, w3, len - pos1);
}

DECLSPEC void md2_update_swap (PRIVATE_AS md2_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len)
{
  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  int pos1;
  int pos4;

  for (pos1 = 0, pos4 = 0; pos1 < len - 64; pos1 += 64, pos4 += 16)
  {
    w0[0] = hc_swap32_S (w[pos4 +  0]);
    w0[1] = hc_swap32_S (w[pos4 +  1]);
    w0[2] = hc_swap32_S (w[pos4 +  2]);
    w0[3] = hc_swap32_S (w[pos4 +  3]);
    w1[0] = hc_swap32_S (w[pos4 +  4]);
    w1[1] = hc_swap32_S (w[pos4 +  5]);
    w1[2] = hc_swap32_S (w[pos4 +  6]);
    w1[3] = hc_swap32_S (w[pos4 +  7]);
    w2[0] = hc_swap32_S (w[pos4 +  8]);
    w2[1] = hc_swap32_S (w[pos4 +  9]);
    w2[2] = hc_swap32_S (w[pos4 + 10]);
    w2[3] = hc_swap32_S (w[pos4 + 11]);
    w3[0] = hc_swap32_S (w[pos4 + 12]);
    w3[1] = hc_swap32_S (w[pos4 + 13]);
    w3[2] = hc_swap32_S (w[pos4 + 14]);
    w3[3] = hc_swap32_S (w[pos4 + 15]);

    md2_update_64 (ctx, w0, w1, w2, w3, 64);
  }

  const int tail = len - pos1;

  u32 t[16];

  t[ 0] = hc_bounded_word_be_S (w, pos4 +  0, tail -   0);
  t[ 1] = hc_bounded_word_be_S (w, pos4 +  1, tail -   4);
  t[ 2] = hc_bounded_word_be_S (w, pos4 +  2, tail -   8);
  t[ 3] = hc_bounded_word_be_S (w, pos4 +  3, tail -  12);
  t[ 4] = hc_bounded_word_be_S (w, pos4 +  4, tail -  16);
  t[ 5] = hc_bounded_word_be_S (w, pos4 +  5, tail -  20);
  t[ 6] = hc_bounded_word_be_S (w, pos4 +  6, tail -  24);
  t[ 7] = hc_bounded_word_be_S (w, pos4 +  7, tail -  28);
  t[ 8] = hc_bounded_word_be_S (w, pos4 +  8, tail -  32);
  t[ 9] = hc_bounded_word_be_S (w, pos4 +  9, tail -  36);
  t[10] = hc_bounded_word_be_S (w, pos4 + 10, tail -  40);
  t[11] = hc_bounded_word_be_S (w, pos4 + 11, tail -  44);
  t[12] = hc_bounded_word_be_S (w, pos4 + 12, tail -  48);
  t[13] = hc_bounded_word_be_S (w, pos4 + 13, tail -  52);
  t[14] = hc_bounded_word_be_S (w, pos4 + 14, tail -  56);
  t[15] = hc_bounded_word_be_S (w, pos4 + 15, tail -  60);

  w0[0] = hc_swap32_S (t[ 0]);
  w0[1] = hc_swap32_S (t[ 1]);
  w0[2] = hc_swap32_S (t[ 2]);
  w0[3] = hc_swap32_S (t[ 3]);
  w1[0] = hc_swap32_S (t[ 4]);
  w1[1] = hc_swap32_S (t[ 5]);
  w1[2] = hc_swap32_S (t[ 6]);
  w1[3] = hc_swap32_S (t[ 7]);
  w2[0] = hc_swap32_S (t[ 8]);
  w2[1] = hc_swap32_S (t[ 9]);
  w2[2] = hc_swap32_S (t[10]);
  w2[3] = hc_swap32_S (t[11]);
  w3[0] = hc_swap32_S (t[12]);
  w3[1] = hc_swap32_S (t[13]);
  w3[2] = hc_swap32_S (t[14]);
  w3[3] = hc_swap32_S (t[15]);

  md2_update_64 (ctx, w0, w1, w2, w3, len - pos1);
}

DECLSPEC void md2_update_utf16le (PRIVATE_AS md2_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len)
{
  if (hc_enc_scan (w, len))
  {
    hc_enc_t hc_enc;

    hc_enc_init (&hc_enc);

    while (hc_enc_has_next (&hc_enc, len))
    {
      u32 enc_buf[16] = { 0 };

      const int enc_len = hc_enc_next (&hc_enc, w, len, 256, enc_buf, sizeof (enc_buf));

      if (enc_len == -1)
      {
        ctx->len = -1;

        return;
      }

      md2_update_64 (ctx, enc_buf + 0, enc_buf + 4, enc_buf + 8, enc_buf + 12, enc_len);
    }

    return;
  }

  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  int pos1;
  int pos4;

  for (pos1 = 0, pos4 = 0; pos1 < len - 32; pos1 += 32, pos4 += 8)
  {
    w0[0] = w[pos4 + 0];
    w0[1] = w[pos4 + 1];
    w0[2] = w[pos4 + 2];
    w0[3] = w[pos4 + 3];
    w1[0] = w[pos4 + 4];
    w1[1] = w[pos4 + 5];
    w1[2] = w[pos4 + 6];
    w1[3] = w[pos4 + 7];

    make_utf16le_S (w1, w2, w3);
    make_utf16le_S (w0, w0, w1);

    md2_update_64 (ctx, w0, w1, w2, w3, 32 * 2);
  }

  const int tail = len - pos1;

  u32 t[8];

  t[0] = hc_bounded_word_le_S (w, pos4 + 0, tail -  0);
  t[1] = hc_bounded_word_le_S (w, pos4 + 1, tail -  4);
  t[2] = hc_bounded_word_le_S (w, pos4 + 2, tail -  8);
  t[3] = hc_bounded_word_le_S (w, pos4 + 3, tail - 12);
  t[4] = hc_bounded_word_le_S (w, pos4 + 4, tail - 16);
  t[5] = hc_bounded_word_le_S (w, pos4 + 5, tail - 20);
  t[6] = hc_bounded_word_le_S (w, pos4 + 6, tail - 24);
  t[7] = hc_bounded_word_le_S (w, pos4 + 7, tail - 28);

  w0[0] = t[0];
  w0[1] = t[1];
  w0[2] = t[2];
  w0[3] = t[3];
  w1[0] = t[4];
  w1[1] = t[5];
  w1[2] = t[6];
  w1[3] = t[7];

  make_utf16le_S (w1, w2, w3);
  make_utf16le_S (w0, w0, w1);

  md2_update_64 (ctx, w0, w1, w2, w3, tail * 2);
}

DECLSPEC void md2_update_global (PRIVATE_AS md2_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len)
{
  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  int pos1;
  int pos4;

  for (pos1 = 0, pos4 = 0; pos1 < len - 64; pos1 += 64, pos4 += 16)
  {
    w0[0] = w[pos4 +  0];
    w0[1] = w[pos4 +  1];
    w0[2] = w[pos4 +  2];
    w0[3] = w[pos4 +  3];
    w1[0] = w[pos4 +  4];
    w1[1] = w[pos4 +  5];
    w1[2] = w[pos4 +  6];
    w1[3] = w[pos4 +  7];
    w2[0] = w[pos4 +  8];
    w2[1] = w[pos4 +  9];
    w2[2] = w[pos4 + 10];
    w2[3] = w[pos4 + 11];
    w3[0] = w[pos4 + 12];
    w3[1] = w[pos4 + 13];
    w3[2] = w[pos4 + 14];
    w3[3] = w[pos4 + 15];

    md2_update_64 (ctx, w0, w1, w2, w3, 64);
  }

  const int tail = len - pos1;

  u32 t[16];

  t[ 0] = hc_bounded_word_global_le_S (w, pos4 +  0, tail -   0);
  t[ 1] = hc_bounded_word_global_le_S (w, pos4 +  1, tail -   4);
  t[ 2] = hc_bounded_word_global_le_S (w, pos4 +  2, tail -   8);
  t[ 3] = hc_bounded_word_global_le_S (w, pos4 +  3, tail -  12);
  t[ 4] = hc_bounded_word_global_le_S (w, pos4 +  4, tail -  16);
  t[ 5] = hc_bounded_word_global_le_S (w, pos4 +  5, tail -  20);
  t[ 6] = hc_bounded_word_global_le_S (w, pos4 +  6, tail -  24);
  t[ 7] = hc_bounded_word_global_le_S (w, pos4 +  7, tail -  28);
  t[ 8] = hc_bounded_word_global_le_S (w, pos4 +  8, tail -  32);
  t[ 9] = hc_bounded_word_global_le_S (w, pos4 +  9, tail -  36);
  t[10] = hc_bounded_word_global_le_S (w, pos4 + 10, tail -  40);
  t[11] = hc_bounded_word_global_le_S (w, pos4 + 11, tail -  44);
  t[12] = hc_bounded_word_global_le_S (w, pos4 + 12, tail -  48);
  t[13] = hc_bounded_word_global_le_S (w, pos4 + 13, tail -  52);
  t[14] = hc_bounded_word_global_le_S (w, pos4 + 14, tail -  56);
  t[15] = hc_bounded_word_global_le_S (w, pos4 + 15, tail -  60);

  w0[0] = t[ 0];
  w0[1] = t[ 1];
  w0[2] = t[ 2];
  w0[3] = t[ 3];
  w1[0] = t[ 4];
  w1[1] = t[ 5];
  w1[2] = t[ 6];
  w1[3] = t[ 7];
  w2[0] = t[ 8];
  w2[1] = t[ 9];
  w2[2] = t[10];
  w2[3] = t[11];
  w3[0] = t[12];
  w3[1] = t[13];
  w3[2] = t[14];
  w3[3] = t[15];

  md2_update_64 (ctx, w0, w1, w2, w3, len - pos1);
}

DECLSPEC void md2_update_global_swap (PRIVATE_AS md2_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len)
{
  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  int pos1;
  int pos4;

  for (pos1 = 0, pos4 = 0; pos1 < len - 64; pos1 += 64, pos4 += 16)
  {
    w0[0] = hc_swap32_S (w[pos4 +  0]);
    w0[1] = hc_swap32_S (w[pos4 +  1]);
    w0[2] = hc_swap32_S (w[pos4 +  2]);
    w0[3] = hc_swap32_S (w[pos4 +  3]);
    w1[0] = hc_swap32_S (w[pos4 +  4]);
    w1[1] = hc_swap32_S (w[pos4 +  5]);
    w1[2] = hc_swap32_S (w[pos4 +  6]);
    w1[3] = hc_swap32_S (w[pos4 +  7]);
    w2[0] = hc_swap32_S (w[pos4 +  8]);
    w2[1] = hc_swap32_S (w[pos4 +  9]);
    w2[2] = hc_swap32_S (w[pos4 + 10]);
    w2[3] = hc_swap32_S (w[pos4 + 11]);
    w3[0] = hc_swap32_S (w[pos4 + 12]);
    w3[1] = hc_swap32_S (w[pos4 + 13]);
    w3[2] = hc_swap32_S (w[pos4 + 14]);
    w3[3] = hc_swap32_S (w[pos4 + 15]);

    md2_update_64 (ctx, w0, w1, w2, w3, 64);
  }

  const int tail = len - pos1;

  u32 t[16];

  t[ 0] = hc_bounded_word_global_be_S (w, pos4 +  0, tail -   0);
  t[ 1] = hc_bounded_word_global_be_S (w, pos4 +  1, tail -   4);
  t[ 2] = hc_bounded_word_global_be_S (w, pos4 +  2, tail -   8);
  t[ 3] = hc_bounded_word_global_be_S (w, pos4 +  3, tail -  12);
  t[ 4] = hc_bounded_word_global_be_S (w, pos4 +  4, tail -  16);
  t[ 5] = hc_bounded_word_global_be_S (w, pos4 +  5, tail -  20);
  t[ 6] = hc_bounded_word_global_be_S (w, pos4 +  6, tail -  24);
  t[ 7] = hc_bounded_word_global_be_S (w, pos4 +  7, tail -  28);
  t[ 8] = hc_bounded_word_global_be_S (w, pos4 +  8, tail -  32);
  t[ 9] = hc_bounded_word_global_be_S (w, pos4 +  9, tail -  36);
  t[10] = hc_bounded_word_global_be_S (w, pos4 + 10, tail -  40);
  t[11] = hc_bounded_word_global_be_S (w, pos4 + 11, tail -  44);
  t[12] = hc_bounded_word_global_be_S (w, pos4 + 12, tail -  48);
  t[13] = hc_bounded_word_global_be_S (w, pos4 + 13, tail -  52);
  t[14] = hc_bounded_word_global_be_S (w, pos4 + 14, tail -  56);
  t[15] = hc_bounded_word_global_be_S (w, pos4 + 15, tail -  60);

  w0[0] = hc_swap32_S (t[ 0]);
  w0[1] = hc_swap32_S (t[ 1]);
  w0[2] = hc_swap32_S (t[ 2]);
  w0[3] = hc_swap32_S (t[ 3]);
  w1[0] = hc_swap32_S (t[ 4]);
  w1[1] = hc_swap32_S (t[ 5]);
  w1[2] = hc_swap32_S (t[ 6]);
  w1[3] = hc_swap32_S (t[ 7]);
  w2[0] = hc_swap32_S (t[ 8]);
  w2[1] = hc_swap32_S (t[ 9]);
  w2[2] = hc_swap32_S (t[10]);
  w2[3] = hc_swap32_S (t[11]);
  w3[0] = hc_swap32_S (t[12]);
  w3[1] = hc_swap32_S (t[13]);
  w3[2] = hc_swap32_S (t[14]);
  w3[3] = hc_swap32_S (t[15]);

  md2_update_64 (ctx, w0, w1, w2, w3, len - pos1);
}

DECLSPEC void md2_update_global_utf16le (PRIVATE_AS md2_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len)
{
  if (hc_enc_scan_global (w, len))
  {
    hc_enc_t hc_enc;

    hc_enc_init (&hc_enc);

    while (hc_enc_has_next (&hc_enc, len))
    {
      u32 enc_buf[16] = { 0 };

      const int enc_len = hc_enc_next_global (&hc_enc, w, len, 256, enc_buf, sizeof (enc_buf));

      if (enc_len == -1)
      {
        ctx->len = -1;

        return;
      }

      md2_update_64 (ctx, enc_buf + 0, enc_buf + 4, enc_buf + 8, enc_buf + 12, enc_len);
    }

    return;
  }

  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  int pos1;
  int pos4;

  for (pos1 = 0, pos4 = 0; pos1 < len - 32; pos1 += 32, pos4 += 8)
  {
    w0[0] = w[pos4 + 0];
    w0[1] = w[pos4 + 1];
    w0[2] = w[pos4 + 2];
    w0[3] = w[pos4 + 3];
    w1[0] = w[pos4 + 4];
    w1[1] = w[pos4 + 5];
    w1[2] = w[pos4 + 6];
    w1[3] = w[pos4 + 7];

    make_utf16le_S (w1, w2, w3);
    make_utf16le_S (w0, w0, w1);

    md2_update_64 (ctx, w0, w1, w2, w3, 32 * 2);
  }

  const int tail = len - pos1;

  u32 t[8];

  t[0] = hc_bounded_word_global_le_S (w, pos4 + 0, tail -  0);
  t[1] = hc_bounded_word_global_le_S (w, pos4 + 1, tail -  4);
  t[2] = hc_bounded_word_global_le_S (w, pos4 + 2, tail -  8);
  t[3] = hc_bounded_word_global_le_S (w, pos4 + 3, tail - 12);
  t[4] = hc_bounded_word_global_le_S (w, pos4 + 4, tail - 16);
  t[5] = hc_bounded_word_global_le_S (w, pos4 + 5, tail - 20);
  t[6] = hc_bounded_word_global_le_S (w, pos4 + 6, tail - 24);
  t[7] = hc_bounded_word_global_le_S (w, pos4 + 7, tail - 28);

  w0[0] = t[0];
  w0[1] = t[1];
  w0[2] = t[2];
  w0[3] = t[3];
  w1[0] = t[4];
  w1[1] = t[5];
  w1[2] = t[6];
  w1[3] = t[7];

  make_utf16le_S (w1, w2, w3);
  make_utf16le_S (w0, w0, w1);

  md2_update_64 (ctx, w0, w1, w2, w3, tail * 2);
}

// MD2 finalization: RFC 1319 padding (fill remaining bytes with pad count),
// then process checksum as a final block.

DECLSPEC void md2_final (PRIVATE_AS md2_ctx_t *ctx)
{
  const int pos = ctx->len & 15;
  const u32 pad = (u32) (16 - pos);

  // Fill bytes pos..15 with pad value

  for (int i = pos; i < 16; i++)
  {
    const u32 shift = (i & 3) << 3;

    ctx->w0[i >> 2] = (ctx->w0[i >> 2] & ~(0xffu << shift)) | (pad << shift);
  }

  md2_transform (ctx->h, ctx->C, &ctx->L, ctx->w0);

  // Final block: the checksum.  Copy to buffer first -- transform reads
  // 'block' while modifying C, so they must not alias.

  ctx->w0[0] = ctx->C[0];
  ctx->w0[1] = ctx->C[1];
  ctx->w0[2] = ctx->C[2];
  ctx->w0[3] = ctx->C[3];

  md2_transform (ctx->h, ctx->C, &ctx->L, ctx->w0);
}
