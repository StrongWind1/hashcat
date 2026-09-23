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
//
// MD2 is byte-oriented with a 16-byte digest. No hashcat include exists for
// it, so the algorithm is implemented inline. The 256-byte S-box (PI_SUBST)
// is taken directly from RFC 1319 Appendix.

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

// Get byte at position idx from a u32 array (LE byte order within each u32)
DECLSPEC u32 md2_gb (PRIVATE_AS const u32 *buf, const int idx)
{
  return (buf[idx >> 2] >> ((idx & 3) << 3)) & 0xff;
}

// Set byte at position idx in a u32 array (LE byte order within each u32)
DECLSPEC void md2_sb (PRIVATE_AS u32 *buf, const int idx, const u32 val)
{
  const int w = idx >> 2;
  const int s = (idx & 3) << 3;

  buf[w] = (buf[w] & ~(0xffu << s)) | ((val & 0xff) << s);
}

// Get byte from GLOBAL_AS u32 array
DECLSPEC u32 md2_gb_g (GLOBAL_AS const u32 *buf, const int idx)
{
  return (buf[idx >> 2] >> ((idx & 3) << 3)) & 0xff;
}

// Update the 16-byte checksum C with one 16-byte block.
// L is the chain variable carried across blocks.
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

// Update the 48-byte state X with one 16-byte block (RFC 1319 step 4).
DECLSPEC void md2_state_update (PRIVATE_AS u32 *X, PRIVATE_AS const u32 *block)
{
  // Copy block into X[16..31] and compute X[32..47] = X[0..15] ^ block
  for (int j = 0; j < 16; j++)
  {
    const u32 m = md2_gb (block, j);

    md2_sb (X, 16 + j, m);
    md2_sb (X, 32 + j, md2_gb (X, j) ^ m);
  }

  // 18 rounds of S-box mixing over all 48 bytes
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

// Process one 16-byte block through both checksum and state (RFC 1319 steps 2+4)
DECLSPEC void md2_process_block (PRIVATE_AS u32 *X, PRIVATE_AS u32 *C, PRIVATE_AS u32 *L_ptr, PRIVATE_AS const u32 *block)
{
  md2_checksum_update (C, L_ptr, block);
  md2_state_update (X, block);
}

KERNEL_FQ KERNEL_FA void m37271_init (KERN_ATTR_TMPS_ESALT (office_protect_tmp_t, office_protect_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  // MD2(salt || UTF-16LE(password))
  //
  // Stream salt and password bytes into a 16-byte block buffer, processing
  // each full block through the MD2 checksum + state update.

  u32 X[12];  // 48-byte state

  for (int i = 0; i < 12; i++) X[i] = 0;

  u32 C[4] = { 0, 0, 0, 0 };   // 16-byte checksum
  u32 blk[4] = { 0, 0, 0, 0 }; // 16-byte block buffer
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

  // Feed password bytes as UTF-16LE (each byte -> byte, 0x00)

  const u32 pw_len = pws[gid].pw_len;

  for (u32 pos = 0; pos < pw_len; pos++)
  {
    const u32 b = (pws[gid].i[pos >> 2] >> ((pos & 3) << 3)) & 0xff;

    // low byte
    md2_sb (blk, bl, b);

    bl++;

    if (bl == 16)
    {
      md2_process_block (X, C, &L, blk);

      blk[0] = 0; blk[1] = 0; blk[2] = 0; blk[3] = 0;

      bl = 0;
    }

    // high byte (0x00)
    md2_sb (blk, bl, 0);

    bl++;

    if (bl == 16)
    {
      md2_process_block (X, C, &L, blk);

      blk[0] = 0; blk[1] = 0; blk[2] = 0; blk[3] = 0;

      bl = 0;
    }
  }

  // Pad: fill remaining bytes with (16 - bl)
  // If bl == 0, pad is a full block of 0x10

  const u32 pad = 16 - bl;

  for (u32 i = bl; i < 16; i++)
  {
    md2_sb (blk, i, pad);
  }

  md2_process_block (X, C, &L, blk);

  // Process checksum as final block (state update only, per RFC 1319)

  md2_state_update (X, C);

  // Output: first 16 bytes of X = X[0..3], stored as u32 LE words

  tmps[gid].out[0] = (u64) X[0];
  tmps[gid].out[1] = (u64) X[1];
  tmps[gid].out[2] = (u64) X[2];
  tmps[gid].out[3] = (u64) X[3];
  tmps[gid].out[4] = 0;
  tmps[gid].out[5] = 0;
  tmps[gid].out[6] = 0;
  tmps[gid].out[7] = 0;
}

KERNEL_FQ KERNEL_FA void m37271_loop (KERN_ATTR_TMPS_ESALT (office_protect_tmp_t, office_protect_t))
{
  // counter APPENDED: MD2(H || LE32(j))
  // input = 16 + 4 = 20 bytes
  // padded = 20 + 12 = 32 bytes (2 blocks, pad byte 0x0c)
  // + checksum block = 3 blocks total

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

KERNEL_FQ KERNEL_FA void m37271_comp (KERN_ATTR_TMPS_ESALT (office_protect_tmp_t, office_protect_t))
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
