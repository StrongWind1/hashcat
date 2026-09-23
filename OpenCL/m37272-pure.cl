/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
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

// --- MD2 inline implementation (RFC 1319) ---

CONSTANT_VK u32 md2_S[256] =
{
   41,  46,  67, 201, 162, 216, 124,   1,  61,  54,  84, 161, 236, 240,   6,  19,
   98, 167,   5, 243, 192, 199, 115, 140, 152, 147,  43, 217, 188,  76, 130, 202,
   30, 155,  87,  60, 253, 212, 224,  22, 103,  66, 111,  24, 138,  23, 229,  18,
  190,  78, 196, 214, 218, 158, 222,  73, 160, 251, 245, 142, 187,  47, 238, 122,
  169, 104, 121, 145,  21, 178,   7,  63, 148, 194,  16, 137,  11,  34,  95,  33,
  128, 127,  93, 154,  90, 144,  50,  39,  53,  62, 204, 231, 191, 247, 151,   3,
  255,  25,  48, 179,  72, 165, 181, 209, 215,  94, 146,  42, 172,  86, 170, 198,
   79, 184,  56, 210, 150, 164, 125, 182, 118, 252, 107, 226, 156, 116,   4, 241,
   69, 157, 112,  89, 100, 113, 135,  32, 134,  91, 207, 101, 230,  45, 168,   2,
   27,  96,  37, 173, 174, 176, 185, 246,  28,  70,  97, 105,  52,  64, 126,  15,
   85,  71, 163,  35, 221,  81, 175,  58, 195,  92, 249, 206, 186, 197, 234,  38,
   44,  83,  13, 110, 133,  40, 132,   9, 211, 223, 205, 244,  65, 129,  77,  82,
  106, 220,  55, 200, 108, 193, 171, 250,  36, 225, 123,   8,  12, 189, 177,  74,
  120, 136, 149, 139, 227,  99, 232, 109, 233, 203, 213, 254,  59,   0,  29,  57,
  242, 239, 183,  14, 102,  88, 208, 228, 166, 119, 114, 248, 235, 117,  75,  10,
   49,  68,  80, 180, 143, 237,  31,  26, 219, 153, 141,  51, 159,  17, 131,  20
};

DECLSPEC u32 md2_gb (PRIVATE_AS const u32 *buf, const int idx)
{
  return (buf[idx >> 2] >> ((idx & 3) << 3)) & 0xff;
}

DECLSPEC void md2_sb (PRIVATE_AS u32 *buf, const int idx, const u32 val)
{
  const int w = idx >> 2;
  const int s = (idx & 3) << 3;

  buf[w] = (buf[w] & ~(0xffu << s)) | ((val & 0xff) << s);
}

DECLSPEC u32 md2_gb_g (GLOBAL_AS const u32 *buf, const int idx)
{
  return (buf[idx >> 2] >> ((idx & 3) << 3)) & 0xff;
}

DECLSPEC void md2_checksum_update (PRIVATE_AS u32 *C, PRIVATE_AS u32 *L_ptr, PRIVATE_AS const u32 *block)
{
  u32 L = *L_ptr;

  for (int j = 0; j < 16; j++)
  {
    const u32 m = md2_gb (block, j);
    u32 cv = md2_gb (C, j);

    cv ^= md2_S[m ^ L];

    md2_sb (C, j, cv);

    L = cv;
  }

  *L_ptr = L;
}

DECLSPEC void md2_state_update (PRIVATE_AS u32 *X, PRIVATE_AS const u32 *block)
{
  for (int j = 0; j < 16; j++)
  {
    const u32 m = md2_gb (block, j);

    md2_sb (X, 16 + j, m);
    md2_sb (X, 32 + j, md2_gb (X, j) ^ m);
  }

  u32 t = 0;

  for (int j = 0; j < 18; j++)
  {
    for (int k = 0; k < 48; k++)
    {
      t = md2_gb (X, k) ^ md2_S[t];

      md2_sb (X, k, t);
    }

    t = (t + (u32) j) & 0xff;
  }
}

DECLSPEC void md2_process_block (PRIVATE_AS u32 *X, PRIVATE_AS u32 *C, PRIVATE_AS u32 *L_ptr, PRIVATE_AS const u32 *block)
{
  md2_checksum_update (C, L_ptr, block);
  md2_state_update (X, block);
}

// --- CreatePasswordVerifier_Method2 ([MS-OFFCRYPTO] Section 2.3.7.4) ---

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
  // Method2 operates on ANSI passwords of length 1-15 ([MS-OFFCRYPTO] Section 2.3.7).

  if (pw_len == 0 || pw_len > 15)
  {
    out_buf[0] = 0; out_buf[1] = 0; out_buf[2] = 0; out_buf[3] = 0;
    *out_len = 0;
    return;
  }

  // --- CreatePasswordVerifier_Method1 ([MS-OFFCRYPTO] Section 2.3.7.1) ---

  u32 verifier = 0;

  for (int idx = (int) pw_len; idx >= 0; idx--)
  {
    u32 byte_val;

    if (idx == 0)
    {
      byte_val = pw_len & 0xff;
    }
    else
    {
      const u32 k = idx - 1;
      byte_val = (pw_buf[k / 4] >> ((k % 4) * 8)) & 0xff;
    }

    const u32 wrapped = (verifier & 0x4000) ? 1 : 0;

    verifier = ((verifier << 1) & 0x7fff) | wrapped;
    verifier ^= byte_val;
  }

  verifier ^= 0xce4b;

  // --- CreateXorKey_Method1 ([MS-OFFCRYPTO] Section 2.3.7.2) ---

  u32 xor_key = m2_initial_code[pw_len - 1];
  u32 current = 0x68;

  for (int idx = (int) pw_len - 1; idx >= 0; idx--)
  {
    u32 c = (pw_buf[idx / 4] >> ((idx % 4) * 8)) & 0xff;

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

  const u32 method2 = (xor_key << 16) | (verifier & 0xffff);

  const u32 h0 = nibble_to_hex_upper ((method2 >>  4) & 0xf);
  const u32 h1 = nibble_to_hex_upper ((method2 >>  0) & 0xf);
  const u32 h2 = nibble_to_hex_upper ((method2 >> 12) & 0xf);
  const u32 h3 = nibble_to_hex_upper ((method2 >>  8) & 0xf);
  const u32 h4 = nibble_to_hex_upper ((method2 >> 20) & 0xf);
  const u32 h5 = nibble_to_hex_upper ((method2 >> 16) & 0xf);
  const u32 h6 = nibble_to_hex_upper ((method2 >> 28) & 0xf);
  const u32 h7 = nibble_to_hex_upper ((method2 >> 24) & 0xf);

  out_buf[0] = (h1 << 16) | h0;
  out_buf[1] = (h3 << 16) | h2;
  out_buf[2] = (h5 << 16) | h4;
  out_buf[3] = (h7 << 16) | h6;

  *out_len = 16;
}

KERNEL_FQ KERNEL_FA void m37272_init (KERN_ATTR_TMPS_ESALT (office_protect_tmp_t, office_protect_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  // pre-stage: transform password through Method2 legacy hash

  u32 prestage_buf[4];
  u32 prestage_len = 0;

  method2_prestage (pws[gid].i, pws[gid].pw_len, prestage_buf, &prestage_len);

  // MD2(salt || prestage)

  u32 X[12];

  for (int i = 0; i < 12; i++) X[i] = 0;

  u32 C[4] = { 0, 0, 0, 0 };
  u32 blk[4] = { 0, 0, 0, 0 };
  u32 L = 0;
  u32 bl = 0;

  // Feed salt bytes

  const u32 salt_len = salt_bufs[SALT_POS_HOST].salt_len;

  for (u32 pos = 0; pos < salt_len; pos++)
  {
    const u32 b = md2_gb_g (salt_bufs[SALT_POS_HOST].salt_buf, pos);

    md2_sb (blk, bl, b);

    bl++;

    if (bl == 16)
    {
      md2_process_block (X, C, &L, blk);

      blk[0] = 0; blk[1] = 0; blk[2] = 0; blk[3] = 0;

      bl = 0;
    }
  }

  // Feed prestage bytes (16 bytes, already UTF-16LE encoded)

  for (u32 pos = 0; pos < prestage_len; pos++)
  {
    const u32 b = md2_gb (prestage_buf, pos);

    md2_sb (blk, bl, b);

    bl++;

    if (bl == 16)
    {
      md2_process_block (X, C, &L, blk);

      blk[0] = 0; blk[1] = 0; blk[2] = 0; blk[3] = 0;

      bl = 0;
    }
  }

  // Pad
  const u32 pad = 16 - bl;

  for (u32 i = bl; i < 16; i++)
  {
    md2_sb (blk, i, pad);
  }

  md2_process_block (X, C, &L, blk);

  // Checksum block
  md2_state_update (X, C);

  tmps[gid].out[0] = (u64) X[0];
  tmps[gid].out[1] = (u64) X[1];
  tmps[gid].out[2] = (u64) X[2];
  tmps[gid].out[3] = (u64) X[3];
  tmps[gid].out[4] = 0;
  tmps[gid].out[5] = 0;
  tmps[gid].out[6] = 0;
  tmps[gid].out[7] = 0;
}

KERNEL_FQ KERNEL_FA void m37272_loop (KERN_ATTR_TMPS_ESALT (office_protect_tmp_t, office_protect_t))
{
  // identical to m37271_loop: counter APPENDED MD2

  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  u32 h0 = (u32) tmps[gid].out[0];
  u32 h1 = (u32) tmps[gid].out[1];
  u32 h2 = (u32) tmps[gid].out[2];
  u32 h3 = (u32) tmps[gid].out[3];

  for (u32 i = 0, j = LOOP_POS; i < LOOP_CNT; i++, j++)
  {
    u32 X[12];

    for (int k = 0; k < 12; k++) X[k] = 0;

    u32 C[4] = { 0, 0, 0, 0 };
    u32 L = 0;

    // Block 0: previous hash (16 bytes)

    u32 blk[4];

    blk[0] = h0;
    blk[1] = h1;
    blk[2] = h2;
    blk[3] = h3;

    md2_process_block (X, C, &L, blk);

    // Block 1: LE32 counter (4 bytes) + padding (12 bytes of 0x0c)

    blk[0] = j;
    blk[1] = 0x0c0c0c0c;
    blk[2] = 0x0c0c0c0c;
    blk[3] = 0x0c0c0c0c;

    md2_process_block (X, C, &L, blk);

    // Checksum block (state update only)

    md2_state_update (X, C);

    h0 = X[0];
    h1 = X[1];
    h2 = X[2];
    h3 = X[3];
  }

  tmps[gid].out[0] = (u64) h0;
  tmps[gid].out[1] = (u64) h1;
  tmps[gid].out[2] = (u64) h2;
  tmps[gid].out[3] = (u64) h3;
}

KERNEL_FQ KERNEL_FA void m37272_comp (KERN_ATTR_TMPS_ESALT (office_protect_tmp_t, office_protect_t))
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
