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
#include M2S(INCLUDE_PATH/inc_hash_md5.cl)
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

DECLSPEC void gen336 (PRIVATE_AS u32x *digest_pre, PRIVATE_AS u32 *salt_buf, PRIVATE_AS u32x *digest)
{
  u32x digest_t0[2];
  u32x digest_t1[2];
  u32x digest_t2[2];
  u32x digest_t3[2];

  digest_t0[0] = digest_pre[0];
  digest_t0[1] = digest_pre[1] & 0xff;

  digest_t1[0] =                       digest_pre[0] <<  8;
  digest_t1[1] = digest_pre[0] >> 24 | digest_pre[1] <<  8;

  digest_t2[0] =                       digest_pre[0] << 16;
  digest_t2[1] = digest_pre[0] >> 16 | digest_pre[1] << 16;

  digest_t3[0] =                       digest_pre[0] << 24;
  digest_t3[1] = digest_pre[0] >>  8 | digest_pre[1] << 24;

  u32x salt_buf_t0[4];
  u32x salt_buf_t1[5];
  u32x salt_buf_t2[5];
  u32x salt_buf_t3[5];

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

  u32x w0_t[4];
  u32x w1_t[4];
  u32x w2_t[4];
  u32x w3_t[4];

  // generate the 16 * 21 buffer

  w0_t[0] = 0;
  w0_t[1] = 0;
  w0_t[2] = 0;
  w0_t[3] = 0;
  w1_t[0] = 0;
  w1_t[1] = 0;
  w1_t[2] = 0;
  w1_t[3] = 0;
  w2_t[0] = 0;
  w2_t[1] = 0;
  w2_t[2] = 0;
  w2_t[3] = 0;
  w3_t[0] = 0;
  w3_t[1] = 0;
  w3_t[2] = 0;
  w3_t[3] = 0;

  // 0..5
  w0_t[0]  = digest_t0[0];
  w0_t[1]  = digest_t0[1];

  // 5..21
  w0_t[1] |= salt_buf_t1[0];
  w0_t[2]  = salt_buf_t1[1];
  w0_t[3]  = salt_buf_t1[2];
  w1_t[0]  = salt_buf_t1[3];
  w1_t[1]  = salt_buf_t1[4];

  // 21..26
  w1_t[1] |= digest_t1[0];
  w1_t[2]  = digest_t1[1];

  // 26..42
  w1_t[2] |= salt_buf_t2[0];
  w1_t[3]  = salt_buf_t2[1];
  w2_t[0]  = salt_buf_t2[2];
  w2_t[1]  = salt_buf_t2[3];
  w2_t[2]  = salt_buf_t2[4];

  // 42..47
  w2_t[2] |= digest_t2[0];
  w2_t[3]  = digest_t2[1];

  // 47..63
  w2_t[3] |= salt_buf_t3[0];
  w3_t[0]  = salt_buf_t3[1];
  w3_t[1]  = salt_buf_t3[2];
  w3_t[2]  = salt_buf_t3[3];
  w3_t[3]  = salt_buf_t3[4];

  // 63..
  w3_t[3] |= digest_t3[0];

  md5_transform_vector (w0_t, w1_t, w2_t, w3_t, digest);

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

  md5_transform_vector (w0_t, w1_t, w2_t, w3_t, digest);

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

  md5_transform_vector (w0_t, w1_t, w2_t, w3_t, digest);

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

  md5_transform_vector (w0_t, w1_t, w2_t, w3_t, digest);

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

  md5_transform_vector (w0_t, w1_t, w2_t, w3_t, digest);

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

  md5_transform_vector (w0_t, w1_t, w2_t, w3_t, digest);
}

KERNEL_FQ KERNEL_FA void m37032_mxx (KERN_ATTR_VECTOR_ESALT (office_rc4_t))
{
  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  u32 salt_buf[4];

  salt_buf[0] = salt_bufs[SALT_POS_HOST].salt_buf[0];
  salt_buf[1] = salt_bufs[SALT_POS_HOST].salt_buf[1];
  salt_buf[2] = salt_bufs[SALT_POS_HOST].salt_buf[2];
  salt_buf[3] = salt_bufs[SALT_POS_HOST].salt_buf[3];


  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos++)
  {
    const u32 pw_len = pws[gid].pw_len;


    // MD5(UTF16LE(pw))

    u32x w0[4] = { 0 };
    u32x w1[4] = { 0 };
    u32x w2[4] = { 0 };
    u32x w3[4] = { 0 };

    w0[0] = pws[gid].i[0];
    w0[1] = pws[gid].i[1];
    w0[2] = pws[gid].i[2];
    w0[3] = pws[gid].i[3];
    w1[0] = pws[gid].i[4];
    w1[1] = pws[gid].i[5];
    w1[2] = pws[gid].i[6];
    w1[3] = pws[gid].i[7];

    // pw is already UTF16LE from PT_UTF16LE

    const u32 pw_len = pws[gid].pw_len;

    // add 0x80 padding

    append_0x80_2x4_VV (w0, w1, pw_len);

    w3[2] = pw_len * 8;
    w3[3] = 0;

    u32x digest_pre[4];

    digest_pre[0] = MD5M_A;
    digest_pre[1] = MD5M_B;
    digest_pre[2] = MD5M_C;
    digest_pre[3] = MD5M_D;

    md5_transform_vector (w0, w1, w2, w3, digest_pre);

    // truncate to 40 bits

    digest_pre[0] &= 0xffffffff;
    digest_pre[1] &= 0x000000ff;
    digest_pre[2]  = 0;
    digest_pre[3]  = 0;

    u32x digest[4];

    digest[0] = MD5M_A;
    digest[1] = MD5M_B;
    digest[2] = MD5M_C;
    digest[3] = MD5M_D;

    gen336 (digest_pre, salt_buf, digest);

    // the digest now holds the gen336 result, truncate and compare against rc4key

    u32x a = digest[0];
    u32x b = digest[1] & 0xff;
    u32x c = 0;
    u32x d = 0;

    COMPARE_M_SIMD (a, b, c, d);
  }
}

KERNEL_FQ KERNEL_FA void m37032_sxx (KERN_ATTR_VECTOR_ESALT (office_rc4_t))
{
  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  u32 salt_buf[4];

  salt_buf[0] = salt_bufs[SALT_POS_HOST].salt_buf[0];
  salt_buf[1] = salt_bufs[SALT_POS_HOST].salt_buf[1];
  salt_buf[2] = salt_bufs[SALT_POS_HOST].salt_buf[2];
  salt_buf[3] = salt_bufs[SALT_POS_HOST].salt_buf[3];

  const u32 search[4] =
  {
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R0],
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R1],
    0,
    0
  };


  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos++)
  {
    const u32 pw_len = pws[gid].pw_len;


    u32x w0[4] = { 0 };
    u32x w1[4] = { 0 };
    u32x w2[4] = { 0 };
    u32x w3[4] = { 0 };

    w0[0] = pws[gid].i[0];
    w0[1] = pws[gid].i[1];
    w0[2] = pws[gid].i[2];
    w0[3] = pws[gid].i[3];
    w1[0] = pws[gid].i[4];
    w1[1] = pws[gid].i[5];
    w1[2] = pws[gid].i[6];
    w1[3] = pws[gid].i[7];

    const u32 pw_len = pws[gid].pw_len;

    append_0x80_2x4_VV (w0, w1, pw_len);

    w3[2] = pw_len * 8;
    w3[3] = 0;

    u32x digest_pre[4];

    digest_pre[0] = MD5M_A;
    digest_pre[1] = MD5M_B;
    digest_pre[2] = MD5M_C;
    digest_pre[3] = MD5M_D;

    md5_transform_vector (w0, w1, w2, w3, digest_pre);

    digest_pre[0] &= 0xffffffff;
    digest_pre[1] &= 0x000000ff;
    digest_pre[2]  = 0;
    digest_pre[3]  = 0;

    u32x digest[4];

    digest[0] = MD5M_A;
    digest[1] = MD5M_B;
    digest[2] = MD5M_C;
    digest[3] = MD5M_D;

    gen336 (digest_pre, salt_buf, digest);

    u32x a = digest[0];
    u32x b = digest[1] & 0xff;
    u32x c = 0;
    u32x d = 0;

    COMPARE_S_SIMD (a, b, c, d);
  }
}
