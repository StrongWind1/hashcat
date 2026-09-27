/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

//too much register pressure
//#define NEW_SIMD_CODE

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_scalar.cl)
#include M2S(INCLUDE_PATH/inc_hash_md5.cl)
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

DECLSPEC void gen336 (PRIVATE_AS u32 *digest_pre, PRIVATE_AS u32 *salt_buf, PRIVATE_AS u32 *digest)
{
  u32 digest_t0[2];
  u32 digest_t1[2];
  u32 digest_t2[2];
  u32 digest_t3[2];

  digest_t0[0] = digest_pre[0];
  digest_t0[1] = digest_pre[1] & 0xff;

  digest_t1[0] =                       digest_pre[0] <<  8;
  digest_t1[1] = digest_pre[0] >> 24 | digest_pre[1] <<  8;

  digest_t2[0] =                       digest_pre[0] << 16;
  digest_t2[1] = digest_pre[0] >> 16 | digest_pre[1] << 16;

  digest_t3[0] =                       digest_pre[0] << 24;
  digest_t3[1] = digest_pre[0] >>  8 | digest_pre[1] << 24;

  u32 salt_buf_t0[4];
  u32 salt_buf_t1[5];
  u32 salt_buf_t2[5];
  u32 salt_buf_t3[5];

  salt_buf_t0[0] = salt_buf[0];
  salt_buf_t0[1] = salt_buf[1];
  salt_buf_t0[2] = salt_buf[2];
  salt_buf_t0[3] = salt_buf[3];

  salt_buf_t1[0] =                     salt_buf[0] <<  8;
  salt_buf_t1[1] = salt_buf[0] >> 24 | salt_buf[1] <<  8;
  salt_buf_t1[2] = salt_buf[1] >> 24 | salt_buf[2] <<  8;
  salt_buf_t1[3] = salt_buf[2] >> 24 | salt_buf[3] <<  8;
  salt_buf_t1[4] = salt_buf[3] >> 24;

  salt_buf_t2[0] =                     salt_buf[0] << 16;
  salt_buf_t2[1] = salt_buf[0] >> 16 | salt_buf[1] << 16;
  salt_buf_t2[2] = salt_buf[1] >> 16 | salt_buf[2] << 16;
  salt_buf_t2[3] = salt_buf[2] >> 16 | salt_buf[3] << 16;
  salt_buf_t2[4] = salt_buf[3] >> 16;

  salt_buf_t3[0] =                     salt_buf[0] << 24;
  salt_buf_t3[1] = salt_buf[0] >>  8 | salt_buf[1] << 24;
  salt_buf_t3[2] = salt_buf[1] >>  8 | salt_buf[2] << 24;
  salt_buf_t3[3] = salt_buf[2] >>  8 | salt_buf[3] << 24;
  salt_buf_t3[4] = salt_buf[3] >>  8;

  u32 w0_t[4];
  u32 w1_t[4];
  u32 w2_t[4];
  u32 w3_t[4];

  w0_t[0] = 0; w0_t[1] = 0; w0_t[2] = 0; w0_t[3] = 0;
  w1_t[0] = 0; w1_t[1] = 0; w1_t[2] = 0; w1_t[3] = 0;
  w2_t[0] = 0; w2_t[1] = 0; w2_t[2] = 0; w2_t[3] = 0;
  w3_t[0] = 0; w3_t[1] = 0; w3_t[2] = 0; w3_t[3] = 0;

  w0_t[0]  = digest_t0[0];
  w0_t[1]  = digest_t0[1];
  w0_t[1] |= salt_buf_t1[0];
  w0_t[2]  = salt_buf_t1[1];
  w0_t[3]  = salt_buf_t1[2];
  w1_t[0]  = salt_buf_t1[3];
  w1_t[1]  = salt_buf_t1[4];
  w1_t[1] |= digest_t1[0];
  w1_t[2]  = digest_t1[1];
  w1_t[2] |= salt_buf_t2[0];
  w1_t[3]  = salt_buf_t2[1];
  w2_t[0]  = salt_buf_t2[2];
  w2_t[1]  = salt_buf_t2[3];
  w2_t[2]  = salt_buf_t2[4];
  w2_t[2] |= digest_t2[0];
  w2_t[3]  = digest_t2[1];
  w2_t[3] |= salt_buf_t3[0];
  w3_t[0]  = salt_buf_t3[1];
  w3_t[1]  = salt_buf_t3[2];
  w3_t[2]  = salt_buf_t3[3];
  w3_t[3]  = salt_buf_t3[4];
  w3_t[3] |= digest_t3[0];

  md5_transform (w0_t, w1_t, w2_t, w3_t, digest);

  w0_t[0] = 0; w0_t[1] = 0; w0_t[2] = 0; w0_t[3] = 0;
  w1_t[0] = 0; w1_t[1] = 0; w1_t[2] = 0; w1_t[3] = 0;
  w2_t[0] = 0; w2_t[1] = 0; w2_t[2] = 0; w2_t[3] = 0;
  w3_t[0] = 0; w3_t[1] = 0; w3_t[2] = 0; w3_t[3] = 0;

  w0_t[0]  = digest_t3[1];
  w0_t[1]  = salt_buf_t0[0];
  w0_t[2]  = salt_buf_t0[1];
  w0_t[3]  = salt_buf_t0[2];
  w1_t[0]  = salt_buf_t0[3];
  w1_t[1]  = digest_t0[0];
  w1_t[2]  = digest_t0[1];
  w1_t[2] |= salt_buf_t1[0];
  w1_t[3]  = salt_buf_t1[1];
  w2_t[0]  = salt_buf_t1[2];
  w2_t[1]  = salt_buf_t1[3];
  w2_t[2]  = salt_buf_t1[4];
  w2_t[2] |= digest_t1[0];
  w2_t[3]  = digest_t1[1];
  w2_t[3] |= salt_buf_t2[0];
  w3_t[0]  = salt_buf_t2[1];
  w3_t[1]  = salt_buf_t2[2];
  w3_t[2]  = salt_buf_t2[3];
  w3_t[3]  = salt_buf_t2[4];
  w3_t[3] |= digest_t2[0];

  md5_transform (w0_t, w1_t, w2_t, w3_t, digest);

  w0_t[0] = 0; w0_t[1] = 0; w0_t[2] = 0; w0_t[3] = 0;
  w1_t[0] = 0; w1_t[1] = 0; w1_t[2] = 0; w1_t[3] = 0;
  w2_t[0] = 0; w2_t[1] = 0; w2_t[2] = 0; w2_t[3] = 0;
  w3_t[0] = 0; w3_t[1] = 0; w3_t[2] = 0; w3_t[3] = 0;

  w0_t[0]  = digest_t2[1];
  w0_t[0] |= salt_buf_t3[0];
  w0_t[1]  = salt_buf_t3[1];
  w0_t[2]  = salt_buf_t3[2];
  w0_t[3]  = salt_buf_t3[3];
  w1_t[0]  = salt_buf_t3[4];
  w1_t[0] |= digest_t3[0];
  w1_t[1]  = digest_t3[1];
  w1_t[2]  = salt_buf_t0[0];
  w1_t[3]  = salt_buf_t0[1];
  w2_t[0]  = salt_buf_t0[2];
  w2_t[1]  = salt_buf_t0[3];
  w2_t[2]  = digest_t0[0];
  w2_t[3]  = digest_t0[1];
  w2_t[3] |= salt_buf_t1[0];
  w3_t[0]  = salt_buf_t1[1];
  w3_t[1]  = salt_buf_t1[2];
  w3_t[2]  = salt_buf_t1[3];
  w3_t[3]  = salt_buf_t1[4];
  w3_t[3] |= digest_t1[0];

  md5_transform (w0_t, w1_t, w2_t, w3_t, digest);

  w0_t[0] = 0; w0_t[1] = 0; w0_t[2] = 0; w0_t[3] = 0;
  w1_t[0] = 0; w1_t[1] = 0; w1_t[2] = 0; w1_t[3] = 0;
  w2_t[0] = 0; w2_t[1] = 0; w2_t[2] = 0; w2_t[3] = 0;
  w3_t[0] = 0; w3_t[1] = 0; w3_t[2] = 0; w3_t[3] = 0;

  w0_t[0]  = digest_t1[1];
  w0_t[0] |= salt_buf_t2[0];
  w0_t[1]  = salt_buf_t2[1];
  w0_t[2]  = salt_buf_t2[2];
  w0_t[3]  = salt_buf_t2[3];
  w1_t[0]  = salt_buf_t2[4];
  w1_t[0] |= digest_t2[0];
  w1_t[1]  = digest_t2[1];
  w1_t[1] |= salt_buf_t3[0];
  w1_t[2]  = salt_buf_t3[1];
  w1_t[3]  = salt_buf_t3[2];
  w2_t[0]  = salt_buf_t3[3];
  w2_t[1]  = salt_buf_t3[4];
  w2_t[1] |= digest_t3[0];
  w2_t[2]  = digest_t3[1];
  w2_t[3]  = salt_buf_t0[0];
  w3_t[0]  = salt_buf_t0[1];
  w3_t[1]  = salt_buf_t0[2];
  w3_t[2]  = salt_buf_t0[3];
  w3_t[3]  = digest_t0[0];

  md5_transform (w0_t, w1_t, w2_t, w3_t, digest);

  w0_t[0] = 0; w0_t[1] = 0; w0_t[2] = 0; w0_t[3] = 0;
  w1_t[0] = 0; w1_t[1] = 0; w1_t[2] = 0; w1_t[3] = 0;
  w2_t[0] = 0; w2_t[1] = 0; w2_t[2] = 0; w2_t[3] = 0;
  w3_t[0] = 0; w3_t[1] = 0; w3_t[2] = 0; w3_t[3] = 0;

  w0_t[0]  = digest_t0[1];
  w0_t[0] |= salt_buf_t1[0];
  w0_t[1]  = salt_buf_t1[1];
  w0_t[2]  = salt_buf_t1[2];
  w0_t[3]  = salt_buf_t1[3];
  w1_t[0]  = salt_buf_t1[4];
  w1_t[0] |= digest_t1[0];
  w1_t[1]  = digest_t1[1];
  w1_t[1] |= salt_buf_t2[0];
  w1_t[2]  = salt_buf_t2[1];
  w1_t[3]  = salt_buf_t2[2];
  w2_t[0]  = salt_buf_t2[3];
  w2_t[1]  = salt_buf_t2[4];
  w2_t[1] |= digest_t2[0];
  w2_t[2]  = digest_t2[1];
  w2_t[2] |= salt_buf_t3[0];
  w2_t[3]  = salt_buf_t3[1];
  w3_t[0]  = salt_buf_t3[2];
  w3_t[1]  = salt_buf_t3[3];
  w3_t[2]  = salt_buf_t3[4];
  w3_t[2] |= digest_t3[0];
  w3_t[3]  = digest_t3[1];

  md5_transform (w0_t, w1_t, w2_t, w3_t, digest);

  w0_t[0]  = salt_buf_t0[0];
  w0_t[1]  = salt_buf_t0[1];
  w0_t[2]  = salt_buf_t0[2];
  w0_t[3]  = salt_buf_t0[3];
  w1_t[0]  = 0x80;
  w1_t[1]  = 0;
  w1_t[2]  = 0;
  w1_t[3]  = 0;
  w2_t[0]  = 0;
  w2_t[1]  = 0;
  w2_t[2]  = 0;
  w2_t[3]  = 0;
  w3_t[0]  = 0;
  w3_t[1]  = 0;
  w3_t[2]  = 21 * 16 * 8;
  w3_t[3]  = 0;

  md5_transform (w0_t, w1_t, w2_t, w3_t, digest);
}

KERNEL_FQ KERNEL_FA void m37030_mxx (KERN_ATTR_ESALT (office_rc4_t))
{
  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  LOCAL_VK u32 S[64 * FIXED_LOCAL_SIZE];

  u32 encryptedVerifier[4];

  encryptedVerifier[0] = esalt_bufs[DIGESTS_OFFSET_HOST].encryptedVerifier[0];
  encryptedVerifier[1] = esalt_bufs[DIGESTS_OFFSET_HOST].encryptedVerifier[1];
  encryptedVerifier[2] = esalt_bufs[DIGESTS_OFFSET_HOST].encryptedVerifier[2];
  encryptedVerifier[3] = esalt_bufs[DIGESTS_OFFSET_HOST].encryptedVerifier[3];

  u32 salt_buf[4];

  salt_buf[0] = salt_bufs[SALT_POS_HOST].salt_buf[0];
  salt_buf[1] = salt_bufs[SALT_POS_HOST].salt_buf[1];
  salt_buf[2] = salt_bufs[SALT_POS_HOST].salt_buf[2];
  salt_buf[3] = salt_bufs[SALT_POS_HOST].salt_buf[3];


  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos++)
  {
    // MD5(UTF16LE(pw)) — password is ASCII, kernel converts to UTF-16LE

    md5_ctx_t ctx;

    md5_init (&ctx);

    md5_update_utf16le (&ctx, pws[gid].i, pws[gid].pw_len);

    md5_update_global_utf16le (&ctx, combs_buf[il_pos].i, combs_buf[il_pos].pw_len);

    md5_final (&ctx);

    u32 digest_pre[4];

    digest_pre[0] = ctx.h[0];
    digest_pre[1] = ctx.h[1];
    digest_pre[2] = ctx.h[2];
    digest_pre[3] = ctx.h[3];

    digest_pre[0] &= 0xffffffff;
    digest_pre[1] &= 0x000000ff;
    digest_pre[2]  = 0;
    digest_pre[3]  = 0;

    u32 w0[4];
    u32 w1[4];
    u32 w2[4];
    u32 w3[4];

    u32 digest[4];

    digest[0] = MD5M_A;
    digest[1] = MD5M_B;
    digest[2] = MD5M_C;
    digest[3] = MD5M_D;

    gen336 (digest_pre, salt_buf, digest);

    // truncate gen336 result to 40 bits

    digest[0] &= 0xffffffff;
    digest[1] &= 0x000000ff;
    digest[2]  = 0;
    digest[3]  = 0;

    // MD5(t1 || LE32(0)) to get the 16-byte RC4 key

    w0[0] = digest[0];
    w0[1] = digest[1];
    w0[2] = 0x8000;
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
    w3[2] = 9 * 8;
    w3[3] = 0;

    digest[0] = MD5M_A;
    digest[1] = MD5M_B;
    digest[2] = MD5M_C;
    digest[3] = MD5M_D;

    md5_transform (w0, w1, w2, w3, digest);

    // RC4

    rc4_init_128 (S, digest, lid);

    u32 out[4];

    u8 j = rc4_next_16 (S, 0, 0, encryptedVerifier, out, lid);

    w0[0] = out[0];
    w0[1] = out[1];
    w0[2] = out[2];
    w0[3] = out[3];
    w1[0] = 0x80;
    w1[1] = 0;
    w1[2] = 0;
    w1[3] = 0;
    w2[0] = 0;
    w2[1] = 0;
    w2[2] = 0;
    w2[3] = 0;
    w3[0] = 0;
    w3[1] = 0;
    w3[2] = 16 * 8;
    w3[3] = 0;

    digest[0] = MD5M_A;
    digest[1] = MD5M_B;
    digest[2] = MD5M_C;
    digest[3] = MD5M_D;

    md5_transform (w0, w1, w2, w3, digest);

    rc4_next_16 (S, 16, j, digest, out, lid);

    const u32 r0 = out[0];
    const u32 r1 = out[1];
    const u32 r2 = out[2];
    const u32 r3 = out[3];

    COMPARE_M_SCALAR (r0, r1, r2, r3);
  }
}

KERNEL_FQ KERNEL_FA void m37030_sxx (KERN_ATTR_ESALT (office_rc4_t))
{
  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  LOCAL_VK u32 S[64 * FIXED_LOCAL_SIZE];

  u32 encryptedVerifier[4];

  encryptedVerifier[0] = esalt_bufs[DIGESTS_OFFSET_HOST].encryptedVerifier[0];
  encryptedVerifier[1] = esalt_bufs[DIGESTS_OFFSET_HOST].encryptedVerifier[1];
  encryptedVerifier[2] = esalt_bufs[DIGESTS_OFFSET_HOST].encryptedVerifier[2];
  encryptedVerifier[3] = esalt_bufs[DIGESTS_OFFSET_HOST].encryptedVerifier[3];

  u32 salt_buf[4];

  salt_buf[0] = salt_bufs[SALT_POS_HOST].salt_buf[0];
  salt_buf[1] = salt_bufs[SALT_POS_HOST].salt_buf[1];
  salt_buf[2] = salt_bufs[SALT_POS_HOST].salt_buf[2];
  salt_buf[3] = salt_bufs[SALT_POS_HOST].salt_buf[3];

  const u32 search[4] =
  {
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R0],
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R1],
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R2],
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R3]
  };


  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos++)
  {
    const u32 pw_len = pws[gid].pw_len;


    u32 w0[4];
    u32 w1[4];
    u32 w2[4];
    u32 w3[4];

    w0[0] = pws[gid].i[0];
    w0[1] = pws[gid].i[1];
    w0[2] = pws[gid].i[2];
    w0[3] = pws[gid].i[3];
    w1[0] = pws[gid].i[4];
    w1[1] = pws[gid].i[5];
    w1[2] = pws[gid].i[6];
    w1[3] = pws[gid].i[7];
    w2[0] = 0;
    w2[1] = 0;
    w2[2] = 0;
    w2[3] = 0;
    w3[0] = 0;
    w3[1] = 0;
    w3[2] = 0;
    w3[3] = 0;

    append_0x80_2x4_S (w0, w1, pws[gid].pw_len);

    w3[2] = pws[gid].pw_len * 8;

    u32 digest_pre[4];

    digest_pre[0] = MD5M_A;
    digest_pre[1] = MD5M_B;
    digest_pre[2] = MD5M_C;
    digest_pre[3] = MD5M_D;

    md5_transform (w0, w1, w2, w3, digest_pre);

    digest_pre[0] &= 0xffffffff;
    digest_pre[1] &= 0x000000ff;
    digest_pre[2]  = 0;
    digest_pre[3]  = 0;

    u32 digest[4];

    digest[0] = MD5M_A;
    digest[1] = MD5M_B;
    digest[2] = MD5M_C;
    digest[3] = MD5M_D;

    gen336 (digest_pre, salt_buf, digest);

    digest[0] &= 0xffffffff;
    digest[1] &= 0x000000ff;
    digest[2]  = 0;
    digest[3]  = 0;

    w0[0] = digest[0];
    w0[1] = digest[1];
    w0[2] = 0x8000;
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
    w3[2] = 9 * 8;
    w3[3] = 0;

    digest[0] = MD5M_A;
    digest[1] = MD5M_B;
    digest[2] = MD5M_C;
    digest[3] = MD5M_D;

    md5_transform (w0, w1, w2, w3, digest);

    rc4_init_128 (S, digest, lid);

    u32 out[4];

    u8 j = rc4_next_16 (S, 0, 0, encryptedVerifier, out, lid);

    w0[0] = out[0];
    w0[1] = out[1];
    w0[2] = out[2];
    w0[3] = out[3];
    w1[0] = 0x80;
    w1[1] = 0;
    w1[2] = 0;
    w1[3] = 0;
    w2[0] = 0;
    w2[1] = 0;
    w2[2] = 0;
    w2[3] = 0;
    w3[0] = 0;
    w3[1] = 0;
    w3[2] = 16 * 8;
    w3[3] = 0;

    digest[0] = MD5M_A;
    digest[1] = MD5M_B;
    digest[2] = MD5M_C;
    digest[3] = MD5M_D;

    md5_transform (w0, w1, w2, w3, digest);

    rc4_next_16 (S, 16, j, digest, out, lid);

    const u32 r0 = out[0];
    const u32 r1 = out[1];
    const u32 r2 = out[2];
    const u32 r3 = out[3];

    COMPARE_S_SCALAR (r0, r1, r2, r3);
  }
}
