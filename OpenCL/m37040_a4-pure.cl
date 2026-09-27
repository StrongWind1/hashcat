/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

//#define NEW_SIMD_CODE

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_scalar.cl)
#include M2S(INCLUDE_PATH/inc_hash_sha1.cl)
#include M2S(INCLUDE_PATH/inc_cipher_rc4.cl)
#endif

typedef struct office_rc4
{
  u32 hash_type;
  u32 key_bits;
  u32 version;
  u32 encryptedVerifier[4];
  u32 encryptedVerifierHash[5];
  u32 secondBlockData[8];
  u32 secondBlockLen;
  u32 rc4key[2];

} office_rc4_t;

// Variable-length RC4 KSA: key is key_len bytes stored in little-endian u32s.
// CryptoAPI RC4 for key sizes > 40 bits uses the actual key length
// (not zero-padded to 16); the Base Provider 40-bit path pads to 16
// and uses rc4_init_128 instead.
DECLSPEC void rc4_init_var (LOCAL_AS u32 *S, PRIVATE_AS const u32 *key, const u32 key_len, const u64 lid)
{
  u32 v = 0x03020100;
  u32 a = 0x04040404;

  for (u8 i = 0; i < 64; i++)
  {
    SET_KEY32 (S, i, v, lid); v += a;
  }

  u8 j = 0;
  u32 ki = 0;

  for (u32 i = 0; i < 256; i++)
  {
    const u8 kb = (key[ki >> 2] >> ((ki & 3) << 3)) & 0xff;

    j += GET_KEY8 (S, i, lid) + kb;

    rc4_swap (S, i, j, lid);

    ki++;

    if (ki >= key_len) ki = 0;
  }
}

KERNEL_FQ KERNEL_FA void m37040_mxx (KERN_ATTR_ESALT (office_rc4_t))
{
  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  LOCAL_VK u32 S[64 * FIXED_LOCAL_SIZE];

  u32 salt_buf[4];

  salt_buf[0] = salt_bufs[SALT_POS_HOST].salt_buf[0];
  salt_buf[1] = salt_bufs[SALT_POS_HOST].salt_buf[1];
  salt_buf[2] = salt_bufs[SALT_POS_HOST].salt_buf[2];
  salt_buf[3] = salt_bufs[SALT_POS_HOST].salt_buf[3];

  const u32 key_bits = esalt_bufs[DIGESTS_OFFSET_HOST].key_bits;

  u32 encryptedVerifier[4];

  encryptedVerifier[0] = esalt_bufs[DIGESTS_OFFSET_HOST].encryptedVerifier[0];
  encryptedVerifier[1] = esalt_bufs[DIGESTS_OFFSET_HOST].encryptedVerifier[1];
  encryptedVerifier[2] = esalt_bufs[DIGESTS_OFFSET_HOST].encryptedVerifier[2];
  encryptedVerifier[3] = esalt_bufs[DIGESTS_OFFSET_HOST].encryptedVerifier[3];

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos++)
  {
    sha1_ctx_t ctx;

    sha1_init (&ctx);

    sha1_update_swap (&ctx, salt_buf, 16);

    sha1_update_global_utf16le_swap (&ctx, pws[gid].i, pws[gid].pw_len);

    sha1_update_global_utf16le_swap (&ctx, combs_buf[il_pos].i, combs_buf[il_pos].pw_len);

    sha1_final (&ctx);

    u32 pass_hash[5];

    pass_hash[0] = ctx.h[0];
    pass_hash[1] = ctx.h[1];
    pass_hash[2] = ctx.h[2];
    pass_hash[3] = ctx.h[3];
    pass_hash[4] = ctx.h[4];

    u32 w0[4];
    u32 w1[4];
    u32 w2[4];
    u32 w3[4];

    w0[0] = pass_hash[0];
    w0[1] = pass_hash[1];
    w0[2] = pass_hash[2];
    w0[3] = pass_hash[3];
    w1[0] = pass_hash[4];
    w1[1] = 0;
    w1[2] = 0x80000000;
    w1[3] = 0;
    w2[0] = 0;
    w2[1] = 0;
    w2[2] = 0;
    w2[3] = 0;
    w3[0] = 0;
    w3[1] = 0;
    w3[2] = 0;
    w3[3] = (20 + 4) * 8;

    u32 digest[5];

    digest[0] = SHA1M_A;
    digest[1] = SHA1M_B;
    digest[2] = SHA1M_C;
    digest[3] = SHA1M_D;
    digest[4] = SHA1M_E;

    sha1_transform (w0, w1, w2, w3, digest);

    digest[0] = hc_swap32_S (digest[0]);
    digest[1] = hc_swap32_S (digest[1]);
    digest[2] = hc_swap32_S (digest[2]);
    digest[3] = hc_swap32_S (digest[3]);

    const u32 key_bytes = key_bits / 8;
    const u32 tb = key_bytes & 3;
    const u32 byte_mask = (tb > 0) ? (0xffffffffu >> ((4 - tb) * 8)) : 0;

    if (key_bytes < 8)
    {
      digest[1] &= byte_mask;
      digest[2]  = 0;
      digest[3]  = 0;
    }
    else if (key_bytes < 12)
    {
      digest[2] &= byte_mask;
      digest[3]  = 0;
    }
    else if (key_bytes < 16)
    {
      digest[3] &= byte_mask;
    }

    // Base Provider 40-bit uses zero-padded 16-byte key;
    // all other sub-128 sizes use actual key length per CryptoAPI
    if (key_bytes <= 5 || key_bytes >= 16)
    {
      rc4_init_128 (S, digest, lid);
    }
    else
    {
      rc4_init_var (S, digest, key_bytes, lid);
    }

    u32 out[4];

    u8 j = rc4_next_16 (S, 0, 0, encryptedVerifier, out, lid);

    w0[0] = hc_swap32_S (out[0]);
    w0[1] = hc_swap32_S (out[1]);
    w0[2] = hc_swap32_S (out[2]);
    w0[3] = hc_swap32_S (out[3]);
    w1[0] = 0x80000000;
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
    w3[3] = 16 * 8;

    digest[0] = SHA1M_A;
    digest[1] = SHA1M_B;
    digest[2] = SHA1M_C;
    digest[3] = SHA1M_D;
    digest[4] = SHA1M_E;

    sha1_transform (w0, w1, w2, w3, digest);

    digest[0] = hc_swap32_S (digest[0]);
    digest[1] = hc_swap32_S (digest[1]);
    digest[2] = hc_swap32_S (digest[2]);
    digest[3] = hc_swap32_S (digest[3]);

    rc4_next_16 (S, 16, j, digest, out, lid);

    COMPARE_M_SCALAR (out[0], out[1], out[2], out[3]);
  }
}

KERNEL_FQ KERNEL_FA void m37040_sxx (KERN_ATTR_ESALT (office_rc4_t))
{
  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  LOCAL_VK u32 S[64 * FIXED_LOCAL_SIZE];

  const u32 search[4] =
  {
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R0],
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R1],
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R2],
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R3]
  };

  u32 salt_buf[4];

  salt_buf[0] = salt_bufs[SALT_POS_HOST].salt_buf[0];
  salt_buf[1] = salt_bufs[SALT_POS_HOST].salt_buf[1];
  salt_buf[2] = salt_bufs[SALT_POS_HOST].salt_buf[2];
  salt_buf[3] = salt_bufs[SALT_POS_HOST].salt_buf[3];

  const u32 key_bits = esalt_bufs[DIGESTS_OFFSET_HOST].key_bits;

  u32 encryptedVerifier[4];

  encryptedVerifier[0] = esalt_bufs[DIGESTS_OFFSET_HOST].encryptedVerifier[0];
  encryptedVerifier[1] = esalt_bufs[DIGESTS_OFFSET_HOST].encryptedVerifier[1];
  encryptedVerifier[2] = esalt_bufs[DIGESTS_OFFSET_HOST].encryptedVerifier[2];
  encryptedVerifier[3] = esalt_bufs[DIGESTS_OFFSET_HOST].encryptedVerifier[3];

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos++)
  {
    sha1_ctx_t ctx;

    sha1_init (&ctx);

    sha1_update_swap (&ctx, salt_buf, 16);

    sha1_update_global_utf16le_swap (&ctx, pws[gid].i, pws[gid].pw_len);

    sha1_update_global_utf16le_swap (&ctx, combs_buf[il_pos].i, combs_buf[il_pos].pw_len);

    sha1_final (&ctx);

    u32 pass_hash[5];

    pass_hash[0] = ctx.h[0];
    pass_hash[1] = ctx.h[1];
    pass_hash[2] = ctx.h[2];
    pass_hash[3] = ctx.h[3];
    pass_hash[4] = ctx.h[4];

    u32 w0[4];
    u32 w1[4];
    u32 w2[4];
    u32 w3[4];

    w0[0] = pass_hash[0];
    w0[1] = pass_hash[1];
    w0[2] = pass_hash[2];
    w0[3] = pass_hash[3];
    w1[0] = pass_hash[4];
    w1[1] = 0;
    w1[2] = 0x80000000;
    w1[3] = 0;
    w2[0] = 0;
    w2[1] = 0;
    w2[2] = 0;
    w2[3] = 0;
    w3[0] = 0;
    w3[1] = 0;
    w3[2] = 0;
    w3[3] = (20 + 4) * 8;

    u32 digest[5];

    digest[0] = SHA1M_A;
    digest[1] = SHA1M_B;
    digest[2] = SHA1M_C;
    digest[3] = SHA1M_D;
    digest[4] = SHA1M_E;

    sha1_transform (w0, w1, w2, w3, digest);

    digest[0] = hc_swap32_S (digest[0]);
    digest[1] = hc_swap32_S (digest[1]);
    digest[2] = hc_swap32_S (digest[2]);
    digest[3] = hc_swap32_S (digest[3]);

    const u32 key_bytes = key_bits / 8;
    const u32 tb = key_bytes & 3;
    const u32 byte_mask = (tb > 0) ? (0xffffffffu >> ((4 - tb) * 8)) : 0;

    if (key_bytes < 8)
    {
      digest[1] &= byte_mask;
      digest[2]  = 0;
      digest[3]  = 0;
    }
    else if (key_bytes < 12)
    {
      digest[2] &= byte_mask;
      digest[3]  = 0;
    }
    else if (key_bytes < 16)
    {
      digest[3] &= byte_mask;
    }

    // Base Provider 40-bit uses zero-padded 16-byte key;
    // all other sub-128 sizes use actual key length per CryptoAPI
    if (key_bytes <= 5 || key_bytes >= 16)
    {
      rc4_init_128 (S, digest, lid);
    }
    else
    {
      rc4_init_var (S, digest, key_bytes, lid);
    }

    u32 out[4];

    u8 j = rc4_next_16 (S, 0, 0, encryptedVerifier, out, lid);

    w0[0] = hc_swap32_S (out[0]);
    w0[1] = hc_swap32_S (out[1]);
    w0[2] = hc_swap32_S (out[2]);
    w0[3] = hc_swap32_S (out[3]);
    w1[0] = 0x80000000;
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
    w3[3] = 16 * 8;

    digest[0] = SHA1M_A;
    digest[1] = SHA1M_B;
    digest[2] = SHA1M_C;
    digest[3] = SHA1M_D;
    digest[4] = SHA1M_E;

    sha1_transform (w0, w1, w2, w3, digest);

    digest[0] = hc_swap32_S (digest[0]);
    digest[1] = hc_swap32_S (digest[1]);
    digest[2] = hc_swap32_S (digest[2]);
    digest[3] = hc_swap32_S (digest[3]);

    rc4_next_16 (S, 16, j, digest, out, lid);

    COMPARE_S_SCALAR (out[0], out[1], out[2], out[3]);
  }
}
