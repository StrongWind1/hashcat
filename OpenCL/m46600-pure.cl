/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

// RAR 2.0: a 32 round block cipher over 16 byte blocks, with a substitution table shuffled by the
// password and a key that moves on with every ciphertext block.
//
// Shuffling the table is what a candidate costs, and it is done here. A stored entry small enough
// to sit in the esalt is decrypted and its CRC32 compared here as well. Anything else, a
// compressed or a larger entry, goes to the host hook with the key and the table, where it is
// decrypted and unpacked.

// Where the key is set up depends on the device. A discrete GPU does it here, in _init. For an
// integrated one the module defines RARL_HOST_KEY: _hook12 then hands the password to the host,
// which is faster at shuffling the table, and _hook23 takes the key back.

// The cipher and its key setup follow UnRAR 7.3.2 (crypt2.cpp).
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

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_checksum_crc.cl)
#endif

#define RARL_KERNEL_DATA 262144

// The most threads a work group may have, each with a table of its own in shared memory.

#define RARL_GROUP_THREADS 64

typedef struct rar20_tmp
{
  u32 key[4];
  u8  subst[256];

} rar20_tmp_t;

// pw and pw_len are only filled where the host sets the key up.

typedef struct rar20_hook
{
  u32 key[4];

  u32 hook_success;

  u8  subst[256];

  u32 pw[32];
  u32 pw_len;

} rar20_hook_t;

typedef struct rar_legacy
{
  u32 type;
  u32 method;
  u32 crc32;
  u32 unpack_size;
  u32 data_len;
  u32 in_kernel;

  u32 data[RARL_KERNEL_DATA / 4];

} rar_legacy_t;

CONSTANT_VK u8a init_subst20[256] =
{
  215,  19, 149,  35,  73, 197, 192, 205, 249,  28,  16, 119,  48, 221,   2,  42,
  232,   1, 177, 233,  14,  88, 219,  25, 223, 195, 244,  90,  87, 239, 153, 137,
  255, 199, 147,  70,  92,  66, 246,  13, 216,  40,  62,  29, 217, 230,  86,   6,
   71,  24, 171, 196, 101, 113, 218, 123,  93,  91, 163, 178, 202,  67,  44, 235,
  107, 250,  75, 234,  49, 167, 125, 211,  83, 114, 157, 144,  32, 193, 143,  36,
  158, 124, 247, 187,  89, 214, 141,  47, 121, 228,  61, 130, 213, 194, 174, 251,
   97, 110,  54, 229, 115,  57, 152,  94, 105, 243, 212,  55, 209, 245,  63,  11,
  164, 200,  31, 156,  81, 176, 227,  21,  76,  99, 139, 188, 127,  17, 248,  51,
  207, 120, 189, 210,   8, 226,  41,  72, 183, 203, 135, 165, 166,  60,  98,   7,
  122,  38, 155, 170,  69, 172, 252, 238,  39, 134,  59, 128, 236,  27, 240,  80,
  131,   3,  85, 206, 145,  79, 154, 142, 159, 220, 201, 133,  74,  64,  20, 129,
  224, 185, 138, 103, 173, 182,  43,  34, 254,  82, 198, 151, 231, 180,  58,  10,
  118,  26, 102,  12,  50, 132,  22, 191, 136, 111, 162, 179,  45,   4, 148, 108,
  161,  56,  78, 126, 242, 222,  15, 175, 146,  23,  33, 241, 181, 190,  77, 225,
    0,  46, 169, 186,  68,  95, 237,  65,  53, 208, 253, 168,   9,  18, 100,  52,
  116, 184, 160,  96, 109,  37,  30, 106, 140, 104, 150,   5, 204, 117, 112,  84
};

#define RARL_SUBST(t,st) ( (u32) (st)[ (t)        & 0xff]        \
                         | ((u32) (st)[((t) >>  8) & 0xff] <<  8) \
                         | ((u32) (st)[((t) >> 16) & 0xff] << 16) \
                         | ((u32) (st)[((t) >> 24) & 0xff] << 24))

// One block through the 32 rounds, forwards or backwards. The key is updated from the ciphertext
// in both directions, which is the block as written when encrypting and as read when decrypting.

DECLSPEC void rar20_block (PRIVATE_AS u32 *key, LOCAL_AS const u8 *subst, PRIVATE_AS u32 *block, const u32 decrypt, SHM_TYPE u32 *s_crc32tab)
{
  const u32 in0 = block[0];
  const u32 in1 = block[1];
  const u32 in2 = block[2];
  const u32 in3 = block[3];

  u32 a = in0 ^ key[0];
  u32 b = in1 ^ key[1];
  u32 c = in2 ^ key[2];
  u32 d = in3 ^ key[3];

  for (u32 i = 0; i < 32; i++)
  {
    const u32 round = (decrypt == 1) ? (31 - i) : i;

    const u32 k = key[round & 3];

    u32 t = (c + hc_rotl32_S (d, 11)) ^ k;

    const u32 ta = a ^ RARL_SUBST (t, subst);

    t = (d ^ hc_rotl32_S (c, 17)) + k;

    const u32 tb = b ^ RARL_SUBST (t, subst);

    a = c;
    b = d;
    c = ta;
    d = tb;
  }

  block[0] = c ^ key[0];
  block[1] = d ^ key[1];
  block[2] = a ^ key[2];
  block[3] = b ^ key[3];

  const u32 ct0 = (decrypt == 1) ? in0 : block[0];
  const u32 ct1 = (decrypt == 1) ? in1 : block[1];
  const u32 ct2 = (decrypt == 1) ? in2 : block[2];
  const u32 ct3 = (decrypt == 1) ? in3 : block[3];

  key[0] ^= s_crc32tab[(ct0 >>  0) & 0xff] ^ s_crc32tab[(ct1 >>  0) & 0xff] ^ s_crc32tab[(ct2 >>  0) & 0xff] ^ s_crc32tab[(ct3 >>  0) & 0xff];
  key[1] ^= s_crc32tab[(ct0 >>  8) & 0xff] ^ s_crc32tab[(ct1 >>  8) & 0xff] ^ s_crc32tab[(ct2 >>  8) & 0xff] ^ s_crc32tab[(ct3 >>  8) & 0xff];
  key[2] ^= s_crc32tab[(ct0 >> 16) & 0xff] ^ s_crc32tab[(ct1 >> 16) & 0xff] ^ s_crc32tab[(ct2 >> 16) & 0xff] ^ s_crc32tab[(ct3 >> 16) & 0xff];
  key[3] ^= s_crc32tab[(ct0 >> 24) & 0xff] ^ s_crc32tab[(ct1 >> 24) & 0xff] ^ s_crc32tab[(ct2 >> 24) & 0xff] ^ s_crc32tab[(ct3 >> 24) & 0xff];
}

KERNEL_FQ KERNEL_FA void m46600_init (KERN_ATTR_TMPS_HOOKS_ESALT (rar20_tmp_t, rar20_hook_t, rar_legacy_t))
{
  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  // The CRC32 table is read for every byte of the entry, so it is copied to where a device reads
  // it fastest, the shared memory of the work group.

  #ifdef REAL_SHM

  LOCAL_VK u32 s_crc32tab[256];

  for (u32 i = lid; i < 256; i += lsz) s_crc32tab[i] = crc32tab[i];

  SYNC_THREADS ();

  #else

  CONSTANT_AS u32a *s_crc32tab = crc32tab;

  #endif

  if (gid >= GID_CNT) return;

  #ifndef RARL_HOST_KEY

  const u32 pw_len = (pws[gid].pw_len > 127) ? 127 : pws[gid].pw_len;

  // The password, zero filled, so that an odd length reads a zero for its missing pair byte and
  // the last block is padded.

  u32 psw[36];

  for (u32 i = 0; i < 36; i++) psw[i] = 0;

  for (u32 i = 0; i < (pw_len + 3) / 4; i++) psw[i] = pws[gid].i[i];

  if ((pw_len & 3) != 0) psw[pw_len / 4] &= 0xffffffff >> ((4 - (pw_len & 3)) * 8);

  // The table is shuffled in the shared memory of the work group, one table for each thread, and
  // stored when it is done. On an RTX 4090 that is three times as fast as shuffling it in private
  // memory. Shuffling it in the tmps buffer, or as one word for each byte, measured slower still.
  // The module keeps the threads of a work group to RARL_GROUP_THREADS.

  LOCAL_VK u8 s_table[RARL_GROUP_THREADS][256];

  LOCAL_AS u8 *table = s_table[lid];

  for (u32 i = 0; i < 256; i++) table[i] = init_subst20[i];

  // The table is shuffled by runs of swaps, one run for each of the 256 rounds and each pair of
  // password bytes. A run goes from one byte derived from the pair up to another.

  for (u32 j = 0; j < 256; j++)
  {
    for (u32 i = 0; i < pw_len; i += 2)
    {
      const u32 p0 = (psw[(i + 0) / 4] >> (((i + 0) & 3) * 8)) & 0xff;
      const u32 p1 = (psw[(i + 1) / 4] >> (((i + 1) & 3) * 8)) & 0xff;

      u32 n1 = s_crc32tab[(p0 - j) & 0xff] & 0xff;

      const u32 n2 = s_crc32tab[(p1 + j) & 0xff] & 0xff;

      for (u32 k = 1; n1 != n2; k++)
      {
        const u32 other = (n1 + i + k) & 0xff;

        const u8 tmp = table[n1];

        table[n1]    = table[other];
        table[other] = tmp;

        n1 = (n1 + 1) & 0xff;
      }
    }
  }

  for (u32 i = 0; i < 256; i++) tmps[gid].subst[i] = table[i];

  u32 key[4];

  key[0] = 0xD3A3B879;
  key[1] = 0x3F6D12F7;
  key[2] = 0x7515A235;
  key[3] = 0xA4E7F123;

  for (u32 i = 0; i < pw_len; i += 16)
  {
    u32 block[4];

    block[0] = psw[(i / 4) + 0];
    block[1] = psw[(i / 4) + 1];
    block[2] = psw[(i / 4) + 2];
    block[3] = psw[(i / 4) + 3];

    rar20_block (key, table, block, 0, s_crc32tab);
  }

  tmps[gid].key[0] = key[0];
  tmps[gid].key[1] = key[1];
  tmps[gid].key[2] = key[2];
  tmps[gid].key[3] = key[3];

  #endif
}

KERNEL_FQ KERNEL_FA void m46600_hook12 (KERN_ATTR_TMPS_HOOKS_ESALT (rar20_tmp_t, rar20_hook_t, rar_legacy_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  #ifdef RARL_HOST_KEY

  for (u32 i = 0; i < 32; i++) hooks[gid].pw[i] = pws[gid].i[i];

  hooks[gid].pw_len = pws[gid].pw_len;

  #endif
}

KERNEL_FQ KERNEL_FA void m46600_loop (KERN_ATTR_TMPS_HOOKS_ESALT (rar20_tmp_t, rar20_hook_t, rar_legacy_t))
{
  // The cipher has no iterated key derivation.
}

KERNEL_FQ KERNEL_FA void m46600_hook23 (KERN_ATTR_TMPS_HOOKS_ESALT (rar20_tmp_t, rar20_hook_t, rar_legacy_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  #ifdef RARL_HOST_KEY

  // The host set the key up and left it in the hook buffer.

  tmps[gid].key[0] = hooks[gid].key[0];
  tmps[gid].key[1] = hooks[gid].key[1];
  tmps[gid].key[2] = hooks[gid].key[2];
  tmps[gid].key[3] = hooks[gid].key[3];

  for (u32 i = 0; i < 256; i++) tmps[gid].subst[i] = hooks[gid].subst[i];

  hooks[gid].hook_success = 0;

  #else

  // Only an entry the kernel does not verify itself goes to the host.

  if (esalt_bufs[DIGESTS_OFFSET_HOST].in_kernel == 1) return;

  hooks[gid].key[0] = tmps[gid].key[0];
  hooks[gid].key[1] = tmps[gid].key[1];
  hooks[gid].key[2] = tmps[gid].key[2];
  hooks[gid].key[3] = tmps[gid].key[3];

  for (u32 i = 0; i < 256; i++) hooks[gid].subst[i] = tmps[gid].subst[i];

  hooks[gid].hook_success = 0;

  #endif
}

KERNEL_FQ KERNEL_FA void m46600_comp (KERN_ATTR_TMPS_HOOKS_ESALT (rar20_tmp_t, rar20_hook_t, rar_legacy_t))
{
  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  // The CRC32 table is read for every byte of the entry, so it is copied to where a device reads
  // it fastest, the shared memory of the work group.

  #ifdef REAL_SHM

  LOCAL_VK u32 s_crc32tab[256];

  for (u32 i = lid; i < 256; i += lsz) s_crc32tab[i] = crc32tab[i];

  SYNC_THREADS ();

  #else

  CONSTANT_AS u32a *s_crc32tab = crc32tab;

  #endif

  // The table of this thread, in shared memory as well.

  LOCAL_VK u8 s_table[RARL_GROUP_THREADS][256];

  LOCAL_AS u8 *subst = s_table[lid];

  if (gid >= GID_CNT) return;

  u32 matched = 0;

  if (esalt_bufs[DIGESTS_OFFSET_HOST].in_kernel == 1)
  {
    u32 key[4];

    key[0] = tmps[gid].key[0];
    key[1] = tmps[gid].key[1];
    key[2] = tmps[gid].key[2];
    key[3] = tmps[gid].key[3];

    for (u32 i = 0; i < 256; i++) subst[i] = tmps[gid].subst[i];

    const u32 data_len    = esalt_bufs[DIGESTS_OFFSET_HOST].data_len;
    const u32 unpack_size = esalt_bufs[DIGESTS_OFFSET_HOST].unpack_size;

    u32 crc = 0xffffffff;

    for (u32 off = 0; off < data_len; off += 16)
    {
      u32 block[4];

      block[0] = esalt_bufs[DIGESTS_OFFSET_HOST].data[(off / 4) + 0];
      block[1] = esalt_bufs[DIGESTS_OFFSET_HOST].data[(off / 4) + 1];
      block[2] = esalt_bufs[DIGESTS_OFFSET_HOST].data[(off / 4) + 2];
      block[3] = esalt_bufs[DIGESTS_OFFSET_HOST].data[(off / 4) + 3];

      rar20_block (key, subst, block, 1, s_crc32tab);

      for (u32 i = 0; i < 16; i++)
      {
        if (off + i >= unpack_size) break;

        const u32 dec = (block[i / 4] >> ((i & 3) * 8)) & 0xff;

        crc = (crc >> 8) ^ s_crc32tab[(crc ^ dec) & 0xff];
      }
    }

    if ((crc ^ 0xffffffff) == esalt_bufs[DIGESTS_OFFSET_HOST].crc32) matched = 1;
  }
  else
  {
    matched = hooks[gid].hook_success;
  }

  if (matched == 1)
  {
    if (hc_atomic_inc (&hashes_shown[DIGESTS_OFFSET_HOST]) == 0)
    {
      mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, 0, DIGESTS_OFFSET_HOST + 0, gid, 0, 0, 0);
    }
  }
}
