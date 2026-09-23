/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

/**
 * RC2 block cipher per RFC 2268.
 *
 * 64-bit block (4 little-endian u16 words), variable key length 1-128 bytes.
 * Key expansion via PITABLE produces 64 u16 subkeys.
 * Encrypt: 5 mixing + mash + 6 mixing + mash + 5 mixing.
 * Decrypt: reverse of encrypt.
 *
 * No table lookups in the encrypt/decrypt hot loop -- purely arithmetic,
 * which suits GPU execution well.
 */

#include "inc_vendor.h"
#include "inc_types.h"
#include "inc_platform.h"
#include "inc_common.h"
#include "inc_cipher_rc2.h"

// --- PITABLE (RFC 2268 Section 7) ---

CONSTANT_VK u32 rc2_pitable[256] =
{
  0xd9, 0x78, 0xf9, 0xc4, 0x19, 0xdd, 0xb5, 0xed,
  0x28, 0xe9, 0xfd, 0x79, 0x4a, 0xa0, 0xd8, 0x9d,
  0xc6, 0x7e, 0x37, 0x83, 0x2b, 0x76, 0x53, 0x8e,
  0x62, 0x4c, 0x64, 0x88, 0x44, 0x8b, 0xfb, 0xa2,
  0x17, 0x9a, 0x59, 0xf5, 0x87, 0xb3, 0x4f, 0x13,
  0x61, 0x45, 0x6d, 0x8d, 0x09, 0x81, 0x7d, 0x32,
  0xbd, 0x8f, 0x40, 0xeb, 0x86, 0xb7, 0x7b, 0x0b,
  0xf0, 0x95, 0x21, 0x22, 0x5c, 0x6b, 0x4e, 0x82,
  0x54, 0xd6, 0x65, 0x93, 0xce, 0x60, 0xb2, 0x1c,
  0x73, 0x56, 0xc0, 0x14, 0xa7, 0x8c, 0xf1, 0xdc,
  0x12, 0x75, 0xca, 0x1f, 0x3b, 0xbe, 0xe4, 0xd1,
  0x42, 0x3d, 0xd4, 0x30, 0xa3, 0x3c, 0xb6, 0x26,
  0x6f, 0xbf, 0x0e, 0xda, 0x46, 0x69, 0x07, 0x57,
  0x27, 0xf2, 0x1d, 0x9b, 0xbc, 0x94, 0x43, 0x03,
  0xf8, 0x11, 0xc7, 0xf6, 0x90, 0xef, 0x3e, 0xe7,
  0x06, 0xc3, 0xd5, 0x2f, 0xc8, 0x66, 0x1e, 0xd7,
  0x08, 0xe8, 0xea, 0xde, 0x80, 0x52, 0xee, 0xf7,
  0x84, 0xaa, 0x72, 0xac, 0x35, 0x4d, 0x6a, 0x2a,
  0x96, 0x1a, 0xd2, 0x71, 0x5a, 0x15, 0x49, 0x74,
  0x4b, 0x9f, 0xd0, 0x5e, 0x04, 0x18, 0xa4, 0xec,
  0xc2, 0xe0, 0x41, 0x6e, 0x0f, 0x51, 0xcb, 0xcc,
  0x24, 0x91, 0xaf, 0x50, 0xa1, 0xf4, 0x70, 0x39,
  0x99, 0x7c, 0x3a, 0x85, 0x23, 0xb8, 0xb4, 0x7a,
  0xfc, 0x02, 0x36, 0x5b, 0x25, 0x55, 0x97, 0x31,
  0x2d, 0x5d, 0xfa, 0x98, 0xe3, 0x8a, 0x92, 0xae,
  0x05, 0xdf, 0x29, 0x10, 0x67, 0x6c, 0xba, 0xc9,
  0xd3, 0x00, 0xe6, 0xcf, 0xe1, 0x9e, 0xa8, 0x2c,
  0x63, 0x16, 0x01, 0x3f, 0x58, 0xe2, 0x89, 0xa9,
  0x0d, 0x38, 0x34, 0x1b, 0xab, 0x33, 0xff, 0xb0,
  0xbb, 0x48, 0x0c, 0x5f, 0xb9, 0xb1, 0xcd, 0x2e,
  0xc5, 0xf3, 0xdb, 0x47, 0xe5, 0xa5, 0x9c, 0x77,
  0x0a, 0xa6, 0x20, 0x68, 0xfe, 0x7f, 0xc1, 0xad,
};

// --- Key expansion (RFC 2268 Section 2) ---

DECLSPEC void rc2_key_setup (PRIVATE_AS u32 *xk, PRIVATE_AS const u32 *key, const int key_bytes, const int effective_bits)
{
  // L[0..127]: key expansion buffer (bytes).
  // Stored as u32[32] with 4 bytes packed per u32 (little-endian).

  u32 L[32];

  // Zero the full buffer

  for (int i = 0; i < 32; i++)
  {
    L[i] = 0;
  }

  // Step 1: copy key bytes into L[].
  // Key arrives as big-endian u32 (hashcat SHA-1 convention).
  // Extract bytes: byte 0 = MSByte of key[0], byte 1 = next, etc.
  // Pack into L[] as 4 bytes per u32, little-endian word order:
  //   L[i/4] |= byte << (8 * (i % 4))

  const int T = key_bytes;

  for (int i = 0; i < T; i++)
  {
    // Big-endian key: byte i = (key[i/4] >> (24 - 8*(i%4))) & 0xFF
    const u32 ki = i >> 2;
    const u32 bi = 24 - ((i & 3) << 3);
    const u32 b  = (key[ki] >> bi) & 0xff;

    // Pack into L[] little-endian
    const u32 li = i >> 2;
    const u32 ls = (i & 3) << 3;
    L[li] |= b << ls;
  }

  // Macro to read/write individual bytes from packed L[]
  #define L_GET(idx) ((L[(idx) >> 2] >> (((idx) & 3) << 3)) & 0xff)
  #define L_SET(idx, val)                                         \
  {                                                               \
    const u32 _li = (idx) >> 2;                                   \
    const u32 _ls = ((idx) & 3) << 3;                             \
    L[_li] = (L[_li] & ~(0xffu << _ls)) | (((val) & 0xff) << _ls); \
  }

  // Step 2: expand L[T..127] via PITABLE

  for (int i = T; i < 128; i++)
  {
    const u32 v = rc2_pitable[(L_GET (i - 1) + L_GET (i - T)) & 0xff];
    L_SET (i, v);
  }

  // Step 3: reduce effective key bits
  // T8 = ceil(effective_bits / 8)
  // TM = 255 >> (8 * T8 - effective_bits)  (mask for partial byte)

  const int T1 = effective_bits;
  const int T8 = (T1 + 7) >> 3;
  const int mask_shift = (T8 << 3) - T1;   // 8*T8 - T1, range 0..7
  const u32 TM = 0xff >> mask_shift;

  {
    const int idx = 128 - T8;
    L_SET (idx, rc2_pitable[L_GET (idx) & TM]);
  }

  for (int i = 127 - T8; i >= 0; i--)
  {
    const u32 v = rc2_pitable[L_GET (i + 1) ^ L_GET (i + T8)];
    L_SET (i, v);
  }

  // Step 4: convert L[0..127] to 64 u16 subkeys.
  // K[i] = L[2*i] + L[2*i+1] * 256  (little-endian u16 from byte pair)
  // Store as u32[64], one subkey per entry (zero-extended).

  for (int i = 0; i < 64; i++)
  {
    xk[i] = L_GET (i * 2) | (L_GET (i * 2 + 1) << 8);
  }

  #undef L_GET
  #undef L_SET
}

// --- Encrypt (RFC 2268 Section 4) ---

DECLSPEC void rc2_encrypt (PRIVATE_AS const u32 *xk, PRIVATE_AS const u32 *in, PRIVATE_AS u32 *out)
{
  // Swap from big-endian to little-endian (same pattern as AES uppercase functions)

  const u32 in0 = hc_swap32_S (in[0]);
  const u32 in1 = hc_swap32_S (in[1]);

  // Extract 4 u16 words from little-endian u32 pair

  u32 R0 = in0 & 0xffff;
  u32 R1 = (in0 >> 16) & 0xffff;
  u32 R2 = in1 & 0xffff;
  u32 R3 = (in1 >> 16) & 0xffff;

  // Rotation amounts per word position (RFC 2268)

  // Mixing round: process all 4 words with subkeys xk[j..j+3]
  #define RC2_MIX(R0, R1, R2, R3, j, s)                           \
  {                                                                \
    R0 = (R0 + xk[(j)] + (R3 & R2) + (~R3 & R1)) & 0xffff;       \
    R0 = ((R0 << (s)) | (R0 >> (16 - (s)))) & 0xffff;             \
  }

  #define RC2_MIX_ROUND(j)        \
  {                                \
    RC2_MIX (R0, R1, R2, R3, (j) + 0, 1); \
    RC2_MIX (R1, R2, R3, R0, (j) + 1, 2); \
    RC2_MIX (R2, R3, R0, R1, (j) + 2, 3); \
    RC2_MIX (R3, R0, R1, R2, (j) + 3, 5); \
  }

  // Mashing round
  #define RC2_MASH(R0, R1, R2, R3)                  \
  {                                                  \
    R0 = (R0 + xk[R3 & 63]) & 0xffff;               \
    R1 = (R1 + xk[R0 & 63]) & 0xffff;               \
    R2 = (R2 + xk[R1 & 63]) & 0xffff;               \
    R3 = (R3 + xk[R2 & 63]) & 0xffff;               \
  }

  // 5 mixing rounds (j = 0..19)
  RC2_MIX_ROUND ( 0);
  RC2_MIX_ROUND ( 4);
  RC2_MIX_ROUND ( 8);
  RC2_MIX_ROUND (12);
  RC2_MIX_ROUND (16);

  // Mashing
  RC2_MASH (R0, R1, R2, R3);

  // 6 mixing rounds (j = 20..43)
  RC2_MIX_ROUND (20);
  RC2_MIX_ROUND (24);
  RC2_MIX_ROUND (28);
  RC2_MIX_ROUND (32);
  RC2_MIX_ROUND (36);
  RC2_MIX_ROUND (40);

  // Mashing
  RC2_MASH (R0, R1, R2, R3);

  // 5 mixing rounds (j = 44..63)
  RC2_MIX_ROUND (44);
  RC2_MIX_ROUND (48);
  RC2_MIX_ROUND (52);
  RC2_MIX_ROUND (56);
  RC2_MIX_ROUND (60);

  #undef RC2_MIX
  #undef RC2_MIX_ROUND
  #undef RC2_MASH

  // Pack u16 words back to little-endian u32 pair, then swap to big-endian

  out[0] = hc_swap32_S (R0 | (R1 << 16));
  out[1] = hc_swap32_S (R2 | (R3 << 16));
}

// --- Decrypt (RFC 2268 Section 5) ---

DECLSPEC void rc2_decrypt (PRIVATE_AS const u32 *xk, PRIVATE_AS const u32 *in, PRIVATE_AS u32 *out)
{
  // Swap from big-endian to little-endian

  const u32 in0 = hc_swap32_S (in[0]);
  const u32 in1 = hc_swap32_S (in[1]);

  // Extract 4 u16 words

  u32 R0 = in0 & 0xffff;
  u32 R1 = (in0 >> 16) & 0xffff;
  u32 R2 = in1 & 0xffff;
  u32 R3 = (in1 >> 16) & 0xffff;

  // Reverse mixing round: undo one word
  #define RC2_RMIX(R0, R1, R2, R3, j, s)                                    \
  {                                                                          \
    R0 = ((R0 >> (s)) | (R0 << (16 - (s)))) & 0xffff;                       \
    R0 = (R0 - xk[(j)] - (R3 & R2) - (~R3 & R1)) & 0xffff;                 \
  }

  #define RC2_RMIX_ROUND(j)        \
  {                                 \
    RC2_RMIX (R3, R0, R1, R2, (j) + 3, 5); \
    RC2_RMIX (R2, R3, R0, R1, (j) + 2, 3); \
    RC2_RMIX (R1, R2, R3, R0, (j) + 1, 2); \
    RC2_RMIX (R0, R1, R2, R3, (j) + 0, 1); \
  }

  // Reverse mashing round
  #define RC2_RMASH(R0, R1, R2, R3)                  \
  {                                                   \
    R3 = (R3 - xk[R2 & 63]) & 0xffff;                \
    R2 = (R2 - xk[R1 & 63]) & 0xffff;                \
    R1 = (R1 - xk[R0 & 63]) & 0xffff;                \
    R0 = (R0 - xk[R3 & 63]) & 0xffff;                \
  }

  // 5 reverse mixing rounds (j = 60..44)
  RC2_RMIX_ROUND (60);
  RC2_RMIX_ROUND (56);
  RC2_RMIX_ROUND (52);
  RC2_RMIX_ROUND (48);
  RC2_RMIX_ROUND (44);

  // Reverse mashing
  RC2_RMASH (R0, R1, R2, R3);

  // 6 reverse mixing rounds (j = 40..20)
  RC2_RMIX_ROUND (40);
  RC2_RMIX_ROUND (36);
  RC2_RMIX_ROUND (32);
  RC2_RMIX_ROUND (28);
  RC2_RMIX_ROUND (24);
  RC2_RMIX_ROUND (20);

  // Reverse mashing
  RC2_RMASH (R0, R1, R2, R3);

  // 5 reverse mixing rounds (j = 16..0)
  RC2_RMIX_ROUND (16);
  RC2_RMIX_ROUND (12);
  RC2_RMIX_ROUND ( 8);
  RC2_RMIX_ROUND ( 4);
  RC2_RMIX_ROUND ( 0);

  #undef RC2_RMIX
  #undef RC2_RMIX_ROUND
  #undef RC2_RMASH

  // Pack and swap back to big-endian

  out[0] = hc_swap32_S (R0 | (R1 << 16));
  out[1] = hc_swap32_S (R2 | (R3 << 16));
}
