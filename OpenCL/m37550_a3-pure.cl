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
#include M2S(INCLUDE_PATH/inc_hash_md5.cl)
#include M2S(INCLUDE_PATH/inc_cipher_rc4.cl)
#endif

typedef struct office_msisam
{
  u32 hash_type;
  u32 adjustment;
  u32 crypt_check[8];
  u32 crypt_check_len;

} office_msisam_t;

// uppercase ASCII bytes packed in u32 words (LE byte order)
DECLSPEC void uppercase_ascii (PRIVATE_AS u32 *w, const u32 pw_len)
{
  const u32 wc = (pw_len + 3) / 4;

  for (u32 i = 0; i < wc; i++)
  {
    u32 v = w[i];

    u32 b0 = (v >>  0) & 0xff;
    u32 b1 = (v >>  8) & 0xff;
    u32 b2 = (v >> 16) & 0xff;
    u32 b3 = (v >> 24) & 0xff;

    if (b0 >= 0x61 && b0 <= 0x7a) b0 -= 0x20;
    if (b1 >= 0x61 && b1 <= 0x7a) b1 -= 0x20;
    if (b2 >= 0x61 && b2 <= 0x7a) b2 -= 0x20;
    if (b3 >= 0x61 && b3 <= 0x7a) b3 -= 0x20;

    w[i] = (b3 << 24) | (b2 << 16) | (b1 << 8) | b0;
  }
}

DECLSPEC void rc4_init_192 (LOCAL_AS u32 *S, PRIVATE_AS const u32 *key, const u64 lid)
{
  u32 v = 0x03020100;
  u32 a = 0x04040404;

  #ifdef _unroll
  #pragma unroll
  #endif
  for (u8 i = 0; i < 64; i++)
  {
    SET_KEY32 (S, i, v, lid); v += a;
  }

  const u8 d0  = v8a_from_v32_S (key[0]);
  const u8 d1  = v8b_from_v32_S (key[0]);
  const u8 d2  = v8c_from_v32_S (key[0]);
  const u8 d3  = v8d_from_v32_S (key[0]);
  const u8 d4  = v8a_from_v32_S (key[1]);
  const u8 d5  = v8b_from_v32_S (key[1]);
  const u8 d6  = v8c_from_v32_S (key[1]);
  const u8 d7  = v8d_from_v32_S (key[1]);
  const u8 d8  = v8a_from_v32_S (key[2]);
  const u8 d9  = v8b_from_v32_S (key[2]);
  const u8 d10 = v8c_from_v32_S (key[2]);
  const u8 d11 = v8d_from_v32_S (key[2]);
  const u8 d12 = v8a_from_v32_S (key[3]);
  const u8 d13 = v8b_from_v32_S (key[3]);
  const u8 d14 = v8c_from_v32_S (key[3]);
  const u8 d15 = v8d_from_v32_S (key[3]);
  const u8 d16 = v8a_from_v32_S (key[4]);
  const u8 d17 = v8b_from_v32_S (key[4]);
  const u8 d18 = v8c_from_v32_S (key[4]);
  const u8 d19 = v8d_from_v32_S (key[4]);
  const u8 d20 = v8a_from_v32_S (key[5]);
  const u8 d21 = v8b_from_v32_S (key[5]);
  const u8 d22 = v8c_from_v32_S (key[5]);
  const u8 d23 = v8d_from_v32_S (key[5]);

  u8 j = 0;

  for (u32 i = 0; i < 240; i += 24)
  {
    j += GET_KEY8 (S, i +  0, lid) + d0;  rc4_swap (S, i +  0, j, lid);
    j += GET_KEY8 (S, i +  1, lid) + d1;  rc4_swap (S, i +  1, j, lid);
    j += GET_KEY8 (S, i +  2, lid) + d2;  rc4_swap (S, i +  2, j, lid);
    j += GET_KEY8 (S, i +  3, lid) + d3;  rc4_swap (S, i +  3, j, lid);
    j += GET_KEY8 (S, i +  4, lid) + d4;  rc4_swap (S, i +  4, j, lid);
    j += GET_KEY8 (S, i +  5, lid) + d5;  rc4_swap (S, i +  5, j, lid);
    j += GET_KEY8 (S, i +  6, lid) + d6;  rc4_swap (S, i +  6, j, lid);
    j += GET_KEY8 (S, i +  7, lid) + d7;  rc4_swap (S, i +  7, j, lid);
    j += GET_KEY8 (S, i +  8, lid) + d8;  rc4_swap (S, i +  8, j, lid);
    j += GET_KEY8 (S, i +  9, lid) + d9;  rc4_swap (S, i +  9, j, lid);
    j += GET_KEY8 (S, i + 10, lid) + d10; rc4_swap (S, i + 10, j, lid);
    j += GET_KEY8 (S, i + 11, lid) + d11; rc4_swap (S, i + 11, j, lid);
    j += GET_KEY8 (S, i + 12, lid) + d12; rc4_swap (S, i + 12, j, lid);
    j += GET_KEY8 (S, i + 13, lid) + d13; rc4_swap (S, i + 13, j, lid);
    j += GET_KEY8 (S, i + 14, lid) + d14; rc4_swap (S, i + 14, j, lid);
    j += GET_KEY8 (S, i + 15, lid) + d15; rc4_swap (S, i + 15, j, lid);
    j += GET_KEY8 (S, i + 16, lid) + d16; rc4_swap (S, i + 16, j, lid);
    j += GET_KEY8 (S, i + 17, lid) + d17; rc4_swap (S, i + 17, j, lid);
    j += GET_KEY8 (S, i + 18, lid) + d18; rc4_swap (S, i + 18, j, lid);
    j += GET_KEY8 (S, i + 19, lid) + d19; rc4_swap (S, i + 19, j, lid);
    j += GET_KEY8 (S, i + 20, lid) + d20; rc4_swap (S, i + 20, j, lid);
    j += GET_KEY8 (S, i + 21, lid) + d21; rc4_swap (S, i + 21, j, lid);
    j += GET_KEY8 (S, i + 22, lid) + d22; rc4_swap (S, i + 22, j, lid);
    j += GET_KEY8 (S, i + 23, lid) + d23; rc4_swap (S, i + 23, j, lid);
  }

  j += GET_KEY8 (S, 240, lid) + d0;  rc4_swap (S, 240, j, lid);
  j += GET_KEY8 (S, 241, lid) + d1;  rc4_swap (S, 241, j, lid);
  j += GET_KEY8 (S, 242, lid) + d2;  rc4_swap (S, 242, j, lid);
  j += GET_KEY8 (S, 243, lid) + d3;  rc4_swap (S, 243, j, lid);
  j += GET_KEY8 (S, 244, lid) + d4;  rc4_swap (S, 244, j, lid);
  j += GET_KEY8 (S, 245, lid) + d5;  rc4_swap (S, 245, j, lid);
  j += GET_KEY8 (S, 246, lid) + d6;  rc4_swap (S, 246, j, lid);
  j += GET_KEY8 (S, 247, lid) + d7;  rc4_swap (S, 247, j, lid);
  j += GET_KEY8 (S, 248, lid) + d8;  rc4_swap (S, 248, j, lid);
  j += GET_KEY8 (S, 249, lid) + d9;  rc4_swap (S, 249, j, lid);
  j += GET_KEY8 (S, 250, lid) + d10; rc4_swap (S, 250, j, lid);
  j += GET_KEY8 (S, 251, lid) + d11; rc4_swap (S, 251, j, lid);
  j += GET_KEY8 (S, 252, lid) + d12; rc4_swap (S, 252, j, lid);
  j += GET_KEY8 (S, 253, lid) + d13; rc4_swap (S, 253, j, lid);
  j += GET_KEY8 (S, 254, lid) + d14; rc4_swap (S, 254, j, lid);
  j += GET_KEY8 (S, 255, lid) + d15; rc4_swap (S, 255, j, lid);
}

KERNEL_FQ KERNEL_FA void m37550_mxx (KERN_ATTR_VECTOR_ESALT (office_msisam_t))
{
  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  LOCAL_VK u32 S[64 * FIXED_LOCAL_SIZE];

  u32 crypt_check[4];

  crypt_check[0] = esalt_bufs[DIGESTS_OFFSET_HOST].crypt_check[0];
  crypt_check[1] = 0;
  crypt_check[2] = 0;
  crypt_check[3] = 0;

  const u32 pw_len = pws[gid].pw_len;

  u32x w[64] = { 0 };

  for (u32 i = 0, idx = 0; i < pw_len; i += 4, idx += 1)
  {
    w[idx] = pws[gid].i[idx];
  }

  u32 w0l = w[0];

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos += VECT_SIZE)
  {
    const u32 w0r = words_buf_r[il_pos / VECT_SIZE];

    const u32 w0 = w0l | w0r;

    u32 pw_buf[64];

    for (u32 i = 0; i < 64; i++)
    {
      pw_buf[i] = w[i];
    }

    pw_buf[0] = w0;

    uppercase_ascii (pw_buf, pw_len);

    const u32 pw_len20 = (pw_len < 20) ? pw_len : 20;

    u32 pw20[5];

    pw20[0] = (pw_len20 >  0) ? pw_buf[0] : 0;
    pw20[1] = (pw_len20 >  4) ? pw_buf[1] : 0;
    pw20[2] = (pw_len20 >  8) ? pw_buf[2] : 0;
    pw20[3] = (pw_len20 > 12) ? pw_buf[3] : 0;
    pw20[4] = (pw_len20 > 16) ? pw_buf[4] : 0;

    const u32 partial = pw_len20 & 3;

    if (partial)
    {
      const u32 idx20 = pw_len20 / 4;
      const u32 mask  = (1u << (partial * 8)) - 1;

      pw20[idx20] &= mask;
    }

    md5_ctx_t ctx;

    md5_init (&ctx);

    md5_update_utf16le (&ctx, pw20, 20);

    md5_final (&ctx);

    u32 rc4key[6];

    rc4key[0] = ctx.h[0];
    rc4key[1] = ctx.h[1];
    rc4key[2] = ctx.h[2];
    rc4key[3] = ctx.h[3];
    rc4key[4] = salt_bufs[SALT_POS_HOST].salt_buf[0];
    rc4key[5] = salt_bufs[SALT_POS_HOST].salt_buf[1];

    rc4_init_192 (S, rc4key, lid);

    u32 out[4];

    rc4_next_16 (S, 0, 0, crypt_check, out, lid);

    out[1] = 0;
    out[2] = 0;
    out[3] = 0;

    COMPARE_M_SCALAR (out[0], out[1], out[2], out[3]);
  }
}

KERNEL_FQ KERNEL_FA void m37550_sxx (KERN_ATTR_VECTOR_ESALT (office_msisam_t))
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

  u32 crypt_check[4];

  crypt_check[0] = esalt_bufs[DIGESTS_OFFSET_HOST].crypt_check[0];
  crypt_check[1] = 0;
  crypt_check[2] = 0;
  crypt_check[3] = 0;

  const u32 pw_len = pws[gid].pw_len;

  u32x w[64] = { 0 };

  for (u32 i = 0, idx = 0; i < pw_len; i += 4, idx += 1)
  {
    w[idx] = pws[gid].i[idx];
  }

  u32 w0l = w[0];

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos += VECT_SIZE)
  {
    const u32 w0r = words_buf_r[il_pos / VECT_SIZE];

    const u32 w0 = w0l | w0r;

    u32 pw_buf[64];

    for (u32 i = 0; i < 64; i++)
    {
      pw_buf[i] = w[i];
    }

    pw_buf[0] = w0;

    uppercase_ascii (pw_buf, pw_len);

    const u32 pw_len20 = (pw_len < 20) ? pw_len : 20;

    u32 pw20[5];

    pw20[0] = (pw_len20 >  0) ? pw_buf[0] : 0;
    pw20[1] = (pw_len20 >  4) ? pw_buf[1] : 0;
    pw20[2] = (pw_len20 >  8) ? pw_buf[2] : 0;
    pw20[3] = (pw_len20 > 12) ? pw_buf[3] : 0;
    pw20[4] = (pw_len20 > 16) ? pw_buf[4] : 0;

    const u32 partial = pw_len20 & 3;

    if (partial)
    {
      const u32 idx20 = pw_len20 / 4;
      const u32 mask  = (1u << (partial * 8)) - 1;

      pw20[idx20] &= mask;
    }

    md5_ctx_t ctx;

    md5_init (&ctx);

    md5_update_utf16le (&ctx, pw20, 20);

    md5_final (&ctx);

    u32 rc4key[6];

    rc4key[0] = ctx.h[0];
    rc4key[1] = ctx.h[1];
    rc4key[2] = ctx.h[2];
    rc4key[3] = ctx.h[3];
    rc4key[4] = salt_bufs[SALT_POS_HOST].salt_buf[0];
    rc4key[5] = salt_bufs[SALT_POS_HOST].salt_buf[1];

    rc4_init_192 (S, rc4key, lid);

    u32 out[4];

    rc4_next_16 (S, 0, 0, crypt_check, out, lid);

    out[1] = 0;
    out[2] = 0;
    out[3] = 0;

    COMPARE_S_SCALAR (out[0], out[1], out[2], out[3]);
  }
}
