/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#define NEW_SIMD_CODE

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_simd.cl)
#include M2S(INCLUDE_PATH/inc_hash_sha512.cl)
#endif

#define COMPARE_S M2S(INCLUDE_PATH/inc_comp_single.cl)
#define COMPARE_M M2S(INCLUDE_PATH/inc_comp_multi.cl)

typedef struct office_protect
{
  u32 hash_type;
  u32 kdf_type;

} office_protect_t;

typedef struct office_protect_tmp
{
  u64 out[8];

} office_protect_tmp_t;

// CreatePasswordVerifier_Method2 ([MS-OFFCRYPTO] Section 2.3.7.4)
//
// The crypt* documentProtection KDF first reduces the password through the
// legacy Method2 verifier, then hex-encodes and UTF-16LE-encodes the result
// before feeding it to the salted iterated hash. Method2 combines:
//   - CreatePasswordVerifier_Method1 ([MS-OFFCRYPTO] Section 2.3.7.1): 15-bit
//     rotate-left-XOR with 0xCE4B finalisation -> 16-bit verifier (low word)
//   - CreateXorKey_Method1 ([MS-OFFCRYPTO] Section 2.3.7.2): InitialCode +
//     XorMatrix table-driven derivation -> 16-bit XOR key (high word)
// Result: (XorKey << 16) | Verifier -> 32-bit DWORD

// InitialCode[15]: seed words indexed by (password_length - 1)
// [MS-OFFCRYPTO] Section 2.3.7.2
CONSTANT_VK u32 m2_initial_code[15] =
{
  0xE1F0, 0x1D0F, 0xCC9C, 0x84C0, 0x110C,
  0x0E10, 0xF1CE, 0x313E, 0x1872, 0xE139,
  0xD40F, 0x84F9, 0x280C, 0xA96A, 0x4EC3
};

// XorMatrix[105]: mixing words walked downward from index 0x68,
// 7 entries per password character in reverse order
// [MS-OFFCRYPTO] Section 2.3.7.2
CONSTANT_VK u32 m2_xor_matrix[105] =
{
  0xAEFC, 0x4DD9, 0x9BB2, 0x2745, 0x4E8A, 0x9D14, 0x2A09,
  0x7B61, 0xF6C2, 0xFDA5, 0xEB6B, 0xC6F7, 0x9DCF, 0x2BBF,
  0x4563, 0x8AC6, 0x05AD, 0x0B5A, 0x16B4, 0x2D68, 0x5AD0,
  0x0375, 0x06EA, 0x0DD4, 0x1BA8, 0x3750, 0x6EA0, 0xDD40,
  0xD849, 0xA0B3, 0x5147, 0xA28E, 0x553D, 0xAA7A, 0x44D5,
  0x6F45, 0xDE8A, 0xAD35, 0x4A4B, 0x9496, 0x390D, 0x721A,
  0xEB23, 0xC667, 0x9CEF, 0x29FF, 0x53FE, 0xA7FC, 0x5FD9,
  0x47D3, 0x8FA6, 0x0F6D, 0x1EDA, 0x3DB4, 0x7B68, 0xF6D0,
  0xB861, 0x60E3, 0xC1C6, 0x93AD, 0x377B, 0x6EF6, 0xDDEC,
  0x45A0, 0x8B40, 0x06A1, 0x0D42, 0x1A84, 0x3508, 0x6A10,
  0xAA51, 0x4483, 0x8906, 0x022D, 0x045A, 0x08B4, 0x1168,
  0x76B4, 0xED68, 0xCAF1, 0x85C3, 0x1BA7, 0x374E, 0x6E9C,
  0x3730, 0x6E60, 0xDCC0, 0xA9A1, 0x4363, 0x86C6, 0x1DAD,
  0x3331, 0x6662, 0xCCC4, 0x89A9, 0x0373, 0x06E6, 0x0DCC,
  0x1021, 0x2042, 0x4084, 0x8108, 0x1231, 0x2462, 0x48C4
};

DECLSPEC u32 nibble_to_hex_upper (const u32 n)
{
  return (n < 10) ? ('0' + n) : ('A' + n - 10);
}

DECLSPEC void method2_prestage (GLOBAL_AS const u32 *pw_buf, const u32 pw_len, PRIVATE_AS u32 *out_buf, PRIVATE_AS u32 *out_len)
{
  // --- CreatePasswordVerifier_Method1 ([MS-OFFCRYPTO] Section 2.3.7.1) ---
  // PasswordArray = [pw_len] ++ password_bytes, processed in reverse order.
  // 15-bit rotate-left-1 with XOR, finalised by XOR 0xCE4B.

  const u32 ansi_len = pw_len / 2;

  u32 verifier = 0;

  for (int idx = (int) ansi_len; idx >= 0; idx--)
  {
    u32 byte_val;

    if (idx == 0)
    {
      byte_val = ansi_len & 0xff;
    }
    else
    {
      const u32 k = idx - 1;
      byte_val = (pw_buf[k / 2] >> ((k % 2) * 16)) & 0xff;
    }

    const u32 wrapped = (verifier & 0x4000) ? 1 : 0;

    verifier = ((verifier << 1) & 0x7fff) | wrapped;
    verifier ^= byte_val;
  }

  verifier ^= 0xce4b;

  // --- CreateXorKey_Method1 ([MS-OFFCRYPTO] Section 2.3.7.2) ---
  // Seed from InitialCode[pw_len - 1], then walk XorMatrix downward from
  // index 0x68, 7 conditional XOR iterations per password char in reverse.

  u32 xor_key = m2_initial_code[ansi_len - 1];
  u32 current = 0x68;

  for (int idx = (int) ansi_len - 1; idx >= 0; idx--)
  {
    u32 c = (pw_buf[idx / 2] >> ((idx % 2) * 16)) & 0xff;

    for (int j = 0; j < 7; j++)
    {
      if (c & 0x40)
      {
        xor_key ^= m2_xor_matrix[current];
      }

      c = (c << 1) & 0xff;
      current--;
    }
  }

  xor_key &= 0xffff;

  // --- CreatePasswordVerifier_Method2 ([MS-OFFCRYPTO] Section 2.3.7.4) ---
  // Combine XorKey (high 16 bits) and Method1 verifier (low 16 bits).

  const u32 method2 = (xor_key << 16) | (verifier & 0xffff);

  // Render the 32-bit DWORD as 4 LE bytes, each byte to 2 uppercase hex
  // ASCII chars. Result: 8 ASCII chars, UTF-16LE encoded to 16 bytes.
  // Python reference: method2.to_bytes(4, "little").hex().upper()

  const u32 h0 = nibble_to_hex_upper ((method2 >>  4) & 0xf);
  const u32 h1 = nibble_to_hex_upper ((method2 >>  0) & 0xf);
  const u32 h2 = nibble_to_hex_upper ((method2 >> 12) & 0xf);
  const u32 h3 = nibble_to_hex_upper ((method2 >>  8) & 0xf);
  const u32 h4 = nibble_to_hex_upper ((method2 >> 20) & 0xf);
  const u32 h5 = nibble_to_hex_upper ((method2 >> 16) & 0xf);
  const u32 h6 = nibble_to_hex_upper ((method2 >> 28) & 0xf);
  const u32 h7 = nibble_to_hex_upper ((method2 >> 24) & 0xf);

  // UTF-16LE encode: each ASCII char becomes a u16 (low byte = char, high = 0)
  // pack two u16 per u32

  out_buf[0] = (h1 << 16) | h0;
  out_buf[1] = (h3 << 16) | h2;
  out_buf[2] = (h5 << 16) | h4;
  out_buf[3] = (h7 << 16) | h6;

  *out_len = 16;
}

KERNEL_FQ KERNEL_FA void m37242_init (KERN_ATTR_TMPS_ESALT (office_protect_tmp_t, office_protect_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  // pre-stage: transform password through Method2 legacy hash

  u32 prestage_buf[4];
  u32 prestage_len = 0;

  method2_prestage (pws[gid].i, pws[gid].pw_len, prestage_buf, &prestage_len);

  sha512_ctx_t ctx;

  sha512_init (&ctx);

  sha512_update_global_swap (&ctx, salt_bufs[SALT_POS_HOST].salt_buf, salt_bufs[SALT_POS_HOST].salt_len);

  sha512_update (&ctx, prestage_buf, prestage_len);

  sha512_final (&ctx);

  tmps[gid].out[0] = ctx.h[0];
  tmps[gid].out[1] = ctx.h[1];
  tmps[gid].out[2] = ctx.h[2];
  tmps[gid].out[3] = ctx.h[3];
  tmps[gid].out[4] = ctx.h[4];
  tmps[gid].out[5] = ctx.h[5];
  tmps[gid].out[6] = ctx.h[6];
  tmps[gid].out[7] = ctx.h[7];
}

KERNEL_FQ KERNEL_FA void m37242_loop (KERN_ATTR_TMPS_ESALT (office_protect_tmp_t, office_protect_t))
{
  // identical to m37241_loop: counter APPENDED SHA-512

  const u64 gid = get_global_id (0);

  if ((gid * VECT_SIZE) >= GID_CNT) return;

  u64x t0 = pack64v (tmps, out, gid, 0);
  u64x t1 = pack64v (tmps, out, gid, 1);
  u64x t2 = pack64v (tmps, out, gid, 2);
  u64x t3 = pack64v (tmps, out, gid, 3);
  u64x t4 = pack64v (tmps, out, gid, 4);
  u64x t5 = pack64v (tmps, out, gid, 5);
  u64x t6 = pack64v (tmps, out, gid, 6);
  u64x t7 = pack64v (tmps, out, gid, 7);

  u32x w0[4];
  u32x w1[4];
  u32x w2[4];
  u32x w3[4];
  u32x w4[4];
  u32x w5[4];
  u32x w6[4];
  u32x w7[4];

  w0[0] = 0;
  w0[1] = 0;
  w0[2] = 0;
  w0[3] = 0;
  w1[0] = 0;
  w1[1] = 0;
  w1[2] = 0;
  w1[3] = 0;
  w2[0] = 0;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;
  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = 0;
  w4[0] = 0;
  w4[1] = 0x80000000;
  w4[2] = 0;
  w4[3] = 0;
  w5[0] = 0;
  w5[1] = 0;
  w5[2] = 0;
  w5[3] = 0;
  w6[0] = 0;
  w6[1] = 0;
  w6[2] = 0;
  w6[3] = 0;
  w7[0] = 0;
  w7[1] = 0;
  w7[2] = 0;
  w7[3] = (64 + 4) * 8;

  for (u32 i = 0, j = LOOP_POS; i < LOOP_CNT; i++, j++)
  {
    w0[0] = h32_from_64 (t0);
    w0[1] = l32_from_64 (t0);
    w0[2] = h32_from_64 (t1);
    w0[3] = l32_from_64 (t1);
    w1[0] = h32_from_64 (t2);
    w1[1] = l32_from_64 (t2);
    w1[2] = h32_from_64 (t3);
    w1[3] = l32_from_64 (t3);
    w2[0] = h32_from_64 (t4);
    w2[1] = l32_from_64 (t4);
    w2[2] = h32_from_64 (t5);
    w2[3] = l32_from_64 (t5);
    w3[0] = h32_from_64 (t6);
    w3[1] = l32_from_64 (t6);
    w3[2] = h32_from_64 (t7);
    w3[3] = l32_from_64 (t7);
    w4[0] = hc_swap32 (j);

    u64x digest[8];

    digest[0] = SHA512M_A;
    digest[1] = SHA512M_B;
    digest[2] = SHA512M_C;
    digest[3] = SHA512M_D;
    digest[4] = SHA512M_E;
    digest[5] = SHA512M_F;
    digest[6] = SHA512M_G;
    digest[7] = SHA512M_H;

    sha512_transform_vector (w0, w1, w2, w3, w4, w5, w6, w7, digest);

    t0 = digest[0];
    t1 = digest[1];
    t2 = digest[2];
    t3 = digest[3];
    t4 = digest[4];
    t5 = digest[5];
    t6 = digest[6];
    t7 = digest[7];
  }

  unpack64v (tmps, out, gid, 0, t0);
  unpack64v (tmps, out, gid, 1, t1);
  unpack64v (tmps, out, gid, 2, t2);
  unpack64v (tmps, out, gid, 3, t3);
  unpack64v (tmps, out, gid, 4, t4);
  unpack64v (tmps, out, gid, 5, t5);
  unpack64v (tmps, out, gid, 6, t6);
  unpack64v (tmps, out, gid, 7, t7);
}

KERNEL_FQ KERNEL_FA void m37242_comp (KERN_ATTR_TMPS_ESALT (office_protect_tmp_t, office_protect_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  const u32 r0 = (u32) tmps[gid].out[0];
  const u32 r1 = (u32) tmps[gid].out[1];
  const u32 r2 = (u32) tmps[gid].out[2];
  const u32 r3 = (u32) tmps[gid].out[3];

  #define il_pos 0

  #ifdef KERNEL_STATIC
  #include COMPARE_M
  #endif
}
