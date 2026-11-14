/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

// What the RAR hooks spend their time in when an entry is large: CRC32 over the whole plaintext
// and AES-CBC decryption of the whole entry. Included the way rar3_decode.c is: one translation
// unit, nothing exported.
//
// The CRC32 takes eight bytes a step from eight tables. The CBC decryption uses the AES
// instructions of the processor where it has them, found out at run time, and says so when it does
// not, so the caller falls back to the table AES.

// ---- CRC32, eight bytes a step ----

static u32  rarf_crc32tab[8][256];
static bool rarf_crc32tab_ready = false;

static void rarf_crc32_init (void)
{
  if (rarf_crc32tab_ready == true) return;

  for (u32 i = 0; i < 256; i++)
  {
    u32 c = i;

    for (u32 j = 0; j < 8; j++) c = ((c & 1) != 0) ? ((c >> 1) ^ 0xedb88320) : (c >> 1);

    rarf_crc32tab[0][i] = c;
  }

  for (u32 i = 0; i < 256; i++)
  {
    u32 c = rarf_crc32tab[0][i];

    for (u32 t = 1; t < 8; t++)
    {
      c = rarf_crc32tab[0][c & 0xff] ^ (c >> 8);

      rarf_crc32tab[t][i] = c;
    }
  }

  rarf_crc32tab_ready = true;
}

// The running CRC32, without the inversion at either end. rarf_crc32_init has to have run.

MAYBE_UNUSED static u32 rarf_crc32 (const u32 crc_in, const u8 *buf, const u64 len)
{
  u32 crc = crc_in;

  u64 pos = 0;

  while (pos + 8 <= len)
  {
    const u32 lo = crc ^ ((u32) buf[pos + 0] | ((u32) buf[pos + 1] << 8) | ((u32) buf[pos + 2] << 16) | ((u32) buf[pos + 3] << 24));
    const u32 hi =       ((u32) buf[pos + 4] | ((u32) buf[pos + 5] << 8) | ((u32) buf[pos + 6] << 16) | ((u32) buf[pos + 7] << 24));

    crc = rarf_crc32tab[7][(lo >>  0) & 0xff]
        ^ rarf_crc32tab[6][(lo >>  8) & 0xff]
        ^ rarf_crc32tab[5][(lo >> 16) & 0xff]
        ^ rarf_crc32tab[4][(lo >> 24) & 0xff]
        ^ rarf_crc32tab[3][(hi >>  0) & 0xff]
        ^ rarf_crc32tab[2][(hi >>  8) & 0xff]
        ^ rarf_crc32tab[1][(hi >> 16) & 0xff]
        ^ rarf_crc32tab[0][(hi >> 24) & 0xff];

    pos += 8;
  }

  while (pos < len)
  {
    crc = (crc >> 8) ^ rarf_crc32tab[0][(crc ^ buf[pos]) & 0xff];

    pos++;
  }

  return crc;
}

// ---- CRC32 with carry-less multiplication ----

#if defined (__x86_64__) && (defined (__GNUC__) || defined (__clang__))

#include <emmintrin.h>
#include <smmintrin.h>
#include <wmmintrin.h>

#define RARF_CLMUL_TARGET __attribute__ ((target ("pclmul,sse4.1")))

// Folds 64 bytes a step, the way "Fast CRC Computation for Generic Polynomials Using PCLMULQDQ
// Instruction" (Gopal et al., Intel, 2009) lays it out for the reflected polynomial 0xedb88320.
// The constants are x^n mod P for the fold distances, then P and its inverse for the last
// reduction. len is at least 64 and a multiple of 16.

RARF_CLMUL_TARGET static u32 rarf_crc32_clmul (const u32 crc, const u8 *buf, const u64 len)
{
  const __m128i k1k2 = _mm_set_epi64x (0x01c6e41596, 0x0154442bd4);
  const __m128i k3k4 = _mm_set_epi64x (0x00ccaa009e, 0x01751997d0);
  const __m128i k5k0 = _mm_set_epi64x (0x0000000000, 0x0163cd6124);
  const __m128i poly = _mm_set_epi64x (0x01f7011641, 0x01db710641);

  __m128i x1 = _mm_loadu_si128 ((const __m128i *) &buf[ 0]);
  __m128i x2 = _mm_loadu_si128 ((const __m128i *) &buf[16]);
  __m128i x3 = _mm_loadu_si128 ((const __m128i *) &buf[32]);
  __m128i x4 = _mm_loadu_si128 ((const __m128i *) &buf[48]);

  x1 = _mm_xor_si128 (x1, _mm_cvtsi32_si128 ((int) crc));

  u64 pos = 64;

  while (pos + 64 <= len)
  {
    const __m128i lo1 = _mm_clmulepi64_si128 (x1, k1k2, 0x00);
    const __m128i lo2 = _mm_clmulepi64_si128 (x2, k1k2, 0x00);
    const __m128i lo3 = _mm_clmulepi64_si128 (x3, k1k2, 0x00);
    const __m128i lo4 = _mm_clmulepi64_si128 (x4, k1k2, 0x00);

    x1 = _mm_clmulepi64_si128 (x1, k1k2, 0x11);
    x2 = _mm_clmulepi64_si128 (x2, k1k2, 0x11);
    x3 = _mm_clmulepi64_si128 (x3, k1k2, 0x11);
    x4 = _mm_clmulepi64_si128 (x4, k1k2, 0x11);

    x1 = _mm_xor_si128 (_mm_xor_si128 (x1, lo1), _mm_loadu_si128 ((const __m128i *) &buf[pos +  0]));
    x2 = _mm_xor_si128 (_mm_xor_si128 (x2, lo2), _mm_loadu_si128 ((const __m128i *) &buf[pos + 16]));
    x3 = _mm_xor_si128 (_mm_xor_si128 (x3, lo3), _mm_loadu_si128 ((const __m128i *) &buf[pos + 32]));
    x4 = _mm_xor_si128 (_mm_xor_si128 (x4, lo4), _mm_loadu_si128 ((const __m128i *) &buf[pos + 48]));

    pos += 64;
  }

  // The four lanes into one.

  __m128i lo = _mm_clmulepi64_si128 (x1, k3k4, 0x00);

  x1 = _mm_clmulepi64_si128 (x1, k3k4, 0x11);
  x1 = _mm_xor_si128 (_mm_xor_si128 (x1, x2), lo);

  lo = _mm_clmulepi64_si128 (x1, k3k4, 0x00);

  x1 = _mm_clmulepi64_si128 (x1, k3k4, 0x11);
  x1 = _mm_xor_si128 (_mm_xor_si128 (x1, x3), lo);

  lo = _mm_clmulepi64_si128 (x1, k3k4, 0x00);

  x1 = _mm_clmulepi64_si128 (x1, k3k4, 0x11);
  x1 = _mm_xor_si128 (_mm_xor_si128 (x1, x4), lo);

  // What is left, 16 bytes a step.

  while (pos + 16 <= len)
  {
    lo = _mm_clmulepi64_si128 (x1, k3k4, 0x00);

    x1 = _mm_clmulepi64_si128 (x1, k3k4, 0x11);
    x1 = _mm_xor_si128 (_mm_xor_si128 (x1, _mm_loadu_si128 ((const __m128i *) &buf[pos])), lo);

    pos += 16;
  }

  // 128 bits to 64, then the Barrett reduction to 32.

  const __m128i mask = _mm_setr_epi32 (~0, 0, ~0, 0);

  __m128i t = _mm_clmulepi64_si128 (x1, k3k4, 0x10);

  x1 = _mm_xor_si128 (_mm_srli_si128 (x1, 8), t);

  t = _mm_srli_si128 (x1, 4);

  x1 = _mm_and_si128 (x1, mask);
  x1 = _mm_clmulepi64_si128 (x1, k5k0, 0x00);
  x1 = _mm_xor_si128 (x1, t);

  t = _mm_and_si128 (x1, mask);
  t = _mm_clmulepi64_si128 (t, poly, 0x10);
  t = _mm_and_si128 (t, mask);
  t = _mm_clmulepi64_si128 (t, poly, 0x00);

  x1 = _mm_xor_si128 (x1, t);

  const u32 folded = (u32) _mm_extract_epi32 (x1, 1);

  return folded;
}

static bool rarf_have_clmul (void)
{
  const bool have = ((__builtin_cpu_supports ("pclmul") != 0) && (__builtin_cpu_supports ("sse4.1") != 0));

  return have;
}

#else

static u32 rarf_crc32_clmul (const u32 crc, MAYBE_UNUSED const u8 *buf, MAYBE_UNUSED const u64 len)
{
  return crc;
}

static bool rarf_have_clmul (void)
{
  return false;
}

#endif

// The running CRC32 of a large buffer: carry-less multiplication over the whole 16 byte blocks
// where the processor has it, the tables for the rest and everywhere else.

MAYBE_UNUSED static u32 rarf_crc32_large (const u32 crc_in, const u8 *buf, const u64 len)
{
  if ((len < 64) || (rarf_have_clmul () == false))
  {
    const u32 crc = rarf_crc32 (crc_in, buf, len);

    return crc;
  }

  const u64 whole = len & ~15ull;

  const u32 folded = rarf_crc32_clmul (crc_in, buf, whole);

  const u32 crc = rarf_crc32 (folded, &buf[whole], len - whole);

  return crc;
}

// ---- AES-CBC decryption with the AES instructions ----

#if defined (__x86_64__) && (defined (__GNUC__) || defined (__clang__))

#define RARF_TARGET __attribute__ ((target ("aes,sse2")))

// One step of the AES-128 key expansion. assist comes from _mm_aeskeygenassist_si128, which wants
// its round constant as a literal, so the caller spells each round out.

RARF_TARGET static __m128i rarf_expand128 (const __m128i key_in, const __m128i assist_in)
{
  const __m128i assist = _mm_shuffle_epi32 (assist_in, 0xff);

  __m128i key = key_in;

  key = _mm_xor_si128 (key, _mm_slli_si128 (key, 4));
  key = _mm_xor_si128 (key, _mm_slli_si128 (key, 4));
  key = _mm_xor_si128 (key, _mm_slli_si128 (key, 4));
  key = _mm_xor_si128 (key, assist);

  return key;
}

// The two halves of an AES-256 expansion step. The second takes its assist from the half just
// made, with round constant 0, and uses another word of it.

RARF_TARGET static __m128i rarf_expand256_hi (const __m128i key_in, const __m128i lo)
{
  const __m128i assist = _mm_shuffle_epi32 (_mm_aeskeygenassist_si128 (lo, 0), 0xaa);

  __m128i key = key_in;

  key = _mm_xor_si128 (key, _mm_slli_si128 (key, 4));
  key = _mm_xor_si128 (key, _mm_slli_si128 (key, 4));
  key = _mm_xor_si128 (key, _mm_slli_si128 (key, 4));
  key = _mm_xor_si128 (key, assist);

  return key;
}

// The round keys for encryption, rounds + 1 of them. key_bytes is 16 or 32.

RARF_TARGET static void rarf_expand (const u8 *key, const u32 key_bytes, __m128i *rk)
{
  rk[0] = _mm_loadu_si128 ((const __m128i *) &key[0]);

  if (key_bytes == 16)
  {
    rk[ 1] = rarf_expand128 (rk[0], _mm_aeskeygenassist_si128 (rk[0], 0x01));
    rk[ 2] = rarf_expand128 (rk[1], _mm_aeskeygenassist_si128 (rk[1], 0x02));
    rk[ 3] = rarf_expand128 (rk[2], _mm_aeskeygenassist_si128 (rk[2], 0x04));
    rk[ 4] = rarf_expand128 (rk[3], _mm_aeskeygenassist_si128 (rk[3], 0x08));
    rk[ 5] = rarf_expand128 (rk[4], _mm_aeskeygenassist_si128 (rk[4], 0x10));
    rk[ 6] = rarf_expand128 (rk[5], _mm_aeskeygenassist_si128 (rk[5], 0x20));
    rk[ 7] = rarf_expand128 (rk[6], _mm_aeskeygenassist_si128 (rk[6], 0x40));
    rk[ 8] = rarf_expand128 (rk[7], _mm_aeskeygenassist_si128 (rk[7], 0x80));
    rk[ 9] = rarf_expand128 (rk[8], _mm_aeskeygenassist_si128 (rk[8], 0x1b));
    rk[10] = rarf_expand128 (rk[9], _mm_aeskeygenassist_si128 (rk[9], 0x36));

    return;
  }

  rk[1] = _mm_loadu_si128 ((const __m128i *) &key[16]);

  rk[ 2] = rarf_expand128    (rk[ 0], _mm_aeskeygenassist_si128 (rk[ 1], 0x01));
  rk[ 3] = rarf_expand256_hi (rk[ 1], rk[ 2]);
  rk[ 4] = rarf_expand128    (rk[ 2], _mm_aeskeygenassist_si128 (rk[ 3], 0x02));
  rk[ 5] = rarf_expand256_hi (rk[ 3], rk[ 4]);
  rk[ 6] = rarf_expand128    (rk[ 4], _mm_aeskeygenassist_si128 (rk[ 5], 0x04));
  rk[ 7] = rarf_expand256_hi (rk[ 5], rk[ 6]);
  rk[ 8] = rarf_expand128    (rk[ 6], _mm_aeskeygenassist_si128 (rk[ 7], 0x08));
  rk[ 9] = rarf_expand256_hi (rk[ 7], rk[ 8]);
  rk[10] = rarf_expand128    (rk[ 8], _mm_aeskeygenassist_si128 (rk[ 9], 0x10));
  rk[11] = rarf_expand256_hi (rk[ 9], rk[10]);
  rk[12] = rarf_expand128    (rk[10], _mm_aeskeygenassist_si128 (rk[11], 0x20));
  rk[13] = rarf_expand256_hi (rk[11], rk[12]);
  rk[14] = rarf_expand128    (rk[12], _mm_aeskeygenassist_si128 (rk[13], 0x40));
}

RARF_TARGET static void rarf_cbc_decrypt_aesni (const u8 *key, const u32 key_bytes, u8 *chain, const u8 *in, u8 *out, const u32 len)
{
  const u32 rounds = (key_bytes == 16) ? 10 : 14;

  __m128i rk[15];
  __m128i dk[15];

  rarf_expand (key, key_bytes, rk);

  // The round keys for decryption: the same ones backwards, the inner ones through InvMixColumns.

  dk[0] = rk[rounds];

  for (u32 i = 1; i < rounds; i++) dk[i] = _mm_aesimc_si128 (rk[rounds - i]);

  dk[rounds] = rk[0];

  __m128i prev = _mm_loadu_si128 ((const __m128i *) chain);

  u32 off = 0;

  // Four blocks at a time: decryption of one block does not wait for the one before it.

  while (off + 64 <= len)
  {
    const __m128i c0 = _mm_loadu_si128 ((const __m128i *) &in[off +  0]);
    const __m128i c1 = _mm_loadu_si128 ((const __m128i *) &in[off + 16]);
    const __m128i c2 = _mm_loadu_si128 ((const __m128i *) &in[off + 32]);
    const __m128i c3 = _mm_loadu_si128 ((const __m128i *) &in[off + 48]);

    __m128i b0 = _mm_xor_si128 (c0, dk[0]);
    __m128i b1 = _mm_xor_si128 (c1, dk[0]);
    __m128i b2 = _mm_xor_si128 (c2, dk[0]);
    __m128i b3 = _mm_xor_si128 (c3, dk[0]);

    for (u32 i = 1; i < rounds; i++)
    {
      b0 = _mm_aesdec_si128 (b0, dk[i]);
      b1 = _mm_aesdec_si128 (b1, dk[i]);
      b2 = _mm_aesdec_si128 (b2, dk[i]);
      b3 = _mm_aesdec_si128 (b3, dk[i]);
    }

    b0 = _mm_aesdeclast_si128 (b0, dk[rounds]);
    b1 = _mm_aesdeclast_si128 (b1, dk[rounds]);
    b2 = _mm_aesdeclast_si128 (b2, dk[rounds]);
    b3 = _mm_aesdeclast_si128 (b3, dk[rounds]);

    _mm_storeu_si128 ((__m128i *) &out[off +  0], _mm_xor_si128 (b0, prev));
    _mm_storeu_si128 ((__m128i *) &out[off + 16], _mm_xor_si128 (b1, c0));
    _mm_storeu_si128 ((__m128i *) &out[off + 32], _mm_xor_si128 (b2, c1));
    _mm_storeu_si128 ((__m128i *) &out[off + 48], _mm_xor_si128 (b3, c2));

    prev = c3;

    off += 64;
  }

  while (off + 16 <= len)
  {
    const __m128i c0 = _mm_loadu_si128 ((const __m128i *) &in[off]);

    __m128i b0 = _mm_xor_si128 (c0, dk[0]);

    for (u32 i = 1; i < rounds; i++) b0 = _mm_aesdec_si128 (b0, dk[i]);

    b0 = _mm_aesdeclast_si128 (b0, dk[rounds]);

    _mm_storeu_si128 ((__m128i *) &out[off], _mm_xor_si128 (b0, prev));

    prev = c0;

    off += 16;
  }

  _mm_storeu_si128 ((__m128i *) chain, prev);
}

static bool rarf_have_aesni (void)
{
  const bool have = (__builtin_cpu_supports ("aes") != 0);

  return have;
}

#else

static void rarf_cbc_decrypt_aesni (MAYBE_UNUSED const u8 *key, MAYBE_UNUSED const u32 key_bytes, MAYBE_UNUSED u8 *chain, MAYBE_UNUSED const u8 *in, MAYBE_UNUSED u8 *out, MAYBE_UNUSED const u32 len)
{
}

static bool rarf_have_aesni (void)
{
  return false;
}

#endif

// AES-CBC over whole blocks, in and out not overlapping. key is the key as bytes, 16 or 32 of
// them. chain is the 16 byte block before the first one, the IV at the start, and is left at the
// last ciphertext block, so a stream can be decrypted in pieces. Returns false, having done
// nothing, where the processor lacks the instructions.

static bool rarf_cbc_decrypt (const u8 *key, const u32 key_bytes, u8 *chain, const u8 *in, u8 *out, const u32 len)
{
  if (rarf_have_aesni () == false) return false;

  rarf_cbc_decrypt_aesni (key, key_bytes, chain, in, out, len);

  return true;
}
