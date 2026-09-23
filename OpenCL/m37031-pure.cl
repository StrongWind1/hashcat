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
#include M2S(INCLUDE_PATH/inc_hash_sha384.cl)
#include M2S(INCLUDE_PATH/inc_cipher_aes.cl)
#include M2S(INCLUDE_PATH/inc_cipher_des.cl)
#include M2S(INCLUDE_PATH/inc_cipher_rc2.cl)
#endif

#define COMPARE_S M2S(INCLUDE_PATH/inc_comp_single.cl)
#define COMPARE_M M2S(INCLUDE_PATH/inc_comp_multi.cl)

typedef struct office_open
{
  u32 hash_type;
  u32 cipher_type;
  u32 key_bits;
  u32 encryptedVerifier[4];
  u32 encryptedVerifierHash[8];

} office_open_t;

typedef struct office_open_tmp
{
  u64 out[8];

} office_open_tmp_t;

KERNEL_FQ KERNEL_FA void m37031_init (KERN_ATTR_TMPS_ESALT (office_open_tmp_t, office_open_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  sha384_ctx_t ctx;

  sha384_init (&ctx);

  sha384_update_global (&ctx, salt_bufs[SALT_POS_HOST].salt_buf, salt_bufs[SALT_POS_HOST].salt_len);

  sha384_update_global_utf16le_swap (&ctx, pws[gid].i, pws[gid].pw_len);

  sha384_final (&ctx);

  tmps[gid].out[0] = ctx.h[0];
  tmps[gid].out[1] = ctx.h[1];
  tmps[gid].out[2] = ctx.h[2];
  tmps[gid].out[3] = ctx.h[3];
  tmps[gid].out[4] = ctx.h[4];
  tmps[gid].out[5] = ctx.h[5];
  tmps[gid].out[6] = 0;
  tmps[gid].out[7] = 0;
}

KERNEL_FQ KERNEL_FA void m37031_loop (KERN_ATTR_TMPS_ESALT (office_open_tmp_t, office_open_t))
{
  const u64 gid = get_global_id (0);

  if ((gid * VECT_SIZE) >= GID_CNT) return;

  u64x t0 = pack64v (tmps, out, gid, 0);
  u64x t1 = pack64v (tmps, out, gid, 1);
  u64x t2 = pack64v (tmps, out, gid, 2);
  u64x t3 = pack64v (tmps, out, gid, 3);
  u64x t4 = pack64v (tmps, out, gid, 4);
  u64x t5 = pack64v (tmps, out, gid, 5);

  // counter PREPENDED: SHA-384(BE32(j) || H), 52 bytes

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
  w3[1] = 0x80000000;
  w3[2] = 0;
  w3[3] = 0;
  w4[0] = 0;
  w4[1] = 0;
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
  w7[3] = (4 + 48) * 8;

  for (u32 i = 0, j = LOOP_POS; i < LOOP_CNT; i++, j++)
  {
    w0[0] = hc_swap32 (j);
    w0[1] = h32_from_64 (t0);
    w0[2] = l32_from_64 (t0);
    w0[3] = h32_from_64 (t1);
    w1[0] = l32_from_64 (t1);
    w1[1] = h32_from_64 (t2);
    w1[2] = l32_from_64 (t2);
    w1[3] = h32_from_64 (t3);
    w2[0] = l32_from_64 (t3);
    w2[1] = h32_from_64 (t4);
    w2[2] = l32_from_64 (t4);
    w2[3] = h32_from_64 (t5);
    w3[0] = l32_from_64 (t5);

    u64x digest[8];

    digest[0] = SHA384M_A;
    digest[1] = SHA384M_B;
    digest[2] = SHA384M_C;
    digest[3] = SHA384M_D;
    digest[4] = SHA384M_E;
    digest[5] = SHA384M_F;
    digest[6] = SHA384M_G;
    digest[7] = SHA384M_H;

    sha384_transform_vector (w0, w1, w2, w3, w4, w5, w6, w7, digest);

    t0 = digest[0];
    t1 = digest[1];
    t2 = digest[2];
    t3 = digest[3];
    t4 = digest[4];
    t5 = digest[5];
  }

  unpack64v (tmps, out, gid, 0, t0);
  unpack64v (tmps, out, gid, 1, t1);
  unpack64v (tmps, out, gid, 2, t2);
  unpack64v (tmps, out, gid, 3, t3);
  unpack64v (tmps, out, gid, 4, t4);
  unpack64v (tmps, out, gid, 5, t5);
}

KERNEL_FQ KERNEL_FA void m37031_comp (KERN_ATTR_TMPS_ESALT (office_open_tmp_t, office_open_t))
{
  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * aes shared
   */

  #ifdef REAL_SHM

  LOCAL_VK u32 s_td0[256];
  LOCAL_VK u32 s_td1[256];
  LOCAL_VK u32 s_td2[256];
  LOCAL_VK u32 s_td3[256];
  LOCAL_VK u32 s_td4[256];

  LOCAL_VK u32 s_te0[256];
  LOCAL_VK u32 s_te1[256];
  LOCAL_VK u32 s_te2[256];
  LOCAL_VK u32 s_te3[256];
  LOCAL_VK u32 s_te4[256];

  for (u32 i = lid; i < 256; i += lsz)
  {
    s_td0[i] = td0[i];
    s_td1[i] = td1[i];
    s_td2[i] = td2[i];
    s_td3[i] = td3[i];
    s_td4[i] = td4[i];

    s_te0[i] = te0[i];
    s_te1[i] = te1[i];
    s_te2[i] = te2[i];
    s_te3[i] = te3[i];
    s_te4[i] = te4[i];
  }

  SYNC_THREADS ();

  #else

  CONSTANT_AS u32a *s_td0 = td0;
  CONSTANT_AS u32a *s_td1 = td1;
  CONSTANT_AS u32a *s_td2 = td2;
  CONSTANT_AS u32a *s_td3 = td3;
  CONSTANT_AS u32a *s_td4 = td4;

  CONSTANT_AS u32a *s_te0 = te0;
  CONSTANT_AS u32a *s_te1 = te1;
  CONSTANT_AS u32a *s_te2 = te2;
  CONSTANT_AS u32a *s_te3 = te3;
  CONSTANT_AS u32a *s_te4 = te4;

  #endif

  if (gid >= GID_CNT) return;

  const u32 encryptedVerifierHashInputBlockKey[2] = { 0xfea7d276, 0x3b4b9e79 };
  const u32 encryptedVerifierHashValueBlockKey[2] = { 0xd7aa0f6d, 0x3061344e };

  u64 tmp[6];

  tmp[0] = tmps[gid].out[0];
  tmp[1] = tmps[gid].out[1];
  tmp[2] = tmps[gid].out[2];
  tmp[3] = tmps[gid].out[3];
  tmp[4] = tmps[gid].out[4];
  tmp[5] = tmps[gid].out[5];

  // derive verifier-input key: SHA-384(loop_output || blockKey1)

  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];
  u32 w4[4];
  u32 w5[4];
  u32 w6[4];
  u32 w7[4];

  w0[0] = h32_from_64_S (tmp[0]);
  w0[1] = l32_from_64_S (tmp[0]);
  w0[2] = h32_from_64_S (tmp[1]);
  w0[3] = l32_from_64_S (tmp[1]);
  w1[0] = h32_from_64_S (tmp[2]);
  w1[1] = l32_from_64_S (tmp[2]);
  w1[2] = h32_from_64_S (tmp[3]);
  w1[3] = l32_from_64_S (tmp[3]);
  w2[0] = h32_from_64_S (tmp[4]);
  w2[1] = l32_from_64_S (tmp[4]);
  w2[2] = h32_from_64_S (tmp[5]);
  w2[3] = l32_from_64_S (tmp[5]);
  w3[0] = encryptedVerifierHashInputBlockKey[0];
  w3[1] = encryptedVerifierHashInputBlockKey[1];
  w3[2] = 0;
  w3[3] = 0;
  w4[0] = 0;
  w4[1] = 0;
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
  w7[3] = 0;

  sha384_ctx_t ctx;

  sha384_init (&ctx);

  sha384_update_128 (&ctx, w0, w1, w2, w3, w4, w5, w6, w7, 48 + 8);

  sha384_final (&ctx);

  u64 digest0[4];

  digest0[0] = ctx.h[0];
  digest0[1] = ctx.h[1];
  digest0[2] = ctx.h[2];
  digest0[3] = ctx.h[3];

  // derive verifier-value key: SHA-384(loop_output || blockKey2)

  w0[0] = h32_from_64_S (tmp[0]);
  w0[1] = l32_from_64_S (tmp[0]);
  w0[2] = h32_from_64_S (tmp[1]);
  w0[3] = l32_from_64_S (tmp[1]);
  w1[0] = h32_from_64_S (tmp[2]);
  w1[1] = l32_from_64_S (tmp[2]);
  w1[2] = h32_from_64_S (tmp[3]);
  w1[3] = l32_from_64_S (tmp[3]);
  w2[0] = h32_from_64_S (tmp[4]);
  w2[1] = l32_from_64_S (tmp[4]);
  w2[2] = h32_from_64_S (tmp[5]);
  w2[3] = l32_from_64_S (tmp[5]);
  w3[0] = encryptedVerifierHashValueBlockKey[0];
  w3[1] = encryptedVerifierHashValueBlockKey[1];
  w3[2] = 0;
  w3[3] = 0;
  w4[0] = 0;
  w4[1] = 0;
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
  w7[3] = 0;

  sha384_init (&ctx);

  sha384_update_128 (&ctx, w0, w1, w2, w3, w4, w5, w6, w7, 48 + 8);

  sha384_final (&ctx);

  u64 digest1[4];

  digest1[0] = ctx.h[0];
  digest1[1] = ctx.h[1];
  digest1[2] = ctx.h[2];
  digest1[3] = ctx.h[3];

  // AES-256 key from first 32 bytes of digest0

  u32 ukey[8];

  ukey[0] = h32_from_64_S (digest0[0]);
  ukey[1] = l32_from_64_S (digest0[0]);
  ukey[2] = h32_from_64_S (digest0[1]);
  ukey[3] = l32_from_64_S (digest0[1]);
  ukey[4] = h32_from_64_S (digest0[2]);
  ukey[5] = l32_from_64_S (digest0[2]);
  ukey[6] = h32_from_64_S (digest0[3]);
  ukey[7] = l32_from_64_S (digest0[3]);

  u32 ks[60];

  AES256_set_decrypt_key (ks, ukey, s_te0, s_te1, s_te2, s_te3, s_td0, s_td1, s_td2, s_td3);

  const u32 digest_cur = DIGESTS_OFFSET_HOST + LOOP_POS;

  u32 data[4];

  data[0] = esalt_bufs[digest_cur].encryptedVerifier[0];
  data[1] = esalt_bufs[digest_cur].encryptedVerifier[1];
  data[2] = esalt_bufs[digest_cur].encryptedVerifier[2];
  data[3] = esalt_bufs[digest_cur].encryptedVerifier[3];

  u32 out[4];

  AES256_decrypt (ks, data, out, s_td0, s_td1, s_td2, s_td3, s_td4);

  // CBC: XOR with salt as IV

  out[0] ^= salt_bufs[SALT_POS_HOST].salt_buf[0];
  out[1] ^= salt_bufs[SALT_POS_HOST].salt_buf[1];
  out[2] ^= salt_bufs[SALT_POS_HOST].salt_buf[2];
  out[3] ^= salt_bufs[SALT_POS_HOST].salt_buf[3];

  // SHA-384 of the decrypted verifier

  w0[0] = out[0];
  w0[1] = out[1];
  w0[2] = out[2];
  w0[3] = out[3];
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
  w4[1] = 0;
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
  w7[3] = 0;

  sha384_init (&ctx);

  sha384_update_128 (&ctx, w0, w1, w2, w3, w4, w5, w6, w7, 16);

  sha384_final (&ctx);

  u64 digest[4];

  digest[0] = ctx.h[0];
  digest[1] = ctx.h[1];
  digest[2] = ctx.h[2];
  digest[3] = ctx.h[3];

  // re-encrypt with verifier-value key

  ukey[0] = h32_from_64_S (digest1[0]);
  ukey[1] = l32_from_64_S (digest1[0]);
  ukey[2] = h32_from_64_S (digest1[1]);
  ukey[3] = l32_from_64_S (digest1[1]);
  ukey[4] = h32_from_64_S (digest1[2]);
  ukey[5] = l32_from_64_S (digest1[2]);
  ukey[6] = h32_from_64_S (digest1[3]);
  ukey[7] = l32_from_64_S (digest1[3]);

  AES256_set_encrypt_key (ks, ukey, s_te0, s_te1, s_te2, s_te3);

  data[0] = h32_from_64_S (digest[0]) ^ salt_bufs[SALT_POS_HOST].salt_buf[0];
  data[1] = l32_from_64_S (digest[0]) ^ salt_bufs[SALT_POS_HOST].salt_buf[1];
  data[2] = h32_from_64_S (digest[1]) ^ salt_bufs[SALT_POS_HOST].salt_buf[2];
  data[3] = l32_from_64_S (digest[1]) ^ salt_bufs[SALT_POS_HOST].salt_buf[3];

  AES256_encrypt (ks, data, out, s_te0, s_te1, s_te2, s_te3, s_te4);

  const u32 r0 = out[0];
  const u32 r1 = out[1];
  const u32 r2 = out[2];
  const u32 r3 = out[3];

  #define il_pos 0

  #ifdef KERNEL_STATIC
  #include COMPARE_M
  #endif
}

KERNEL_FQ KERNEL_FA void m37031_aux1 (KERN_ATTR_TMPS_ESALT (office_open_tmp_t, office_open_t))
{
}

// _aux2: Agile 3DES-CBC verification (2-key or 3-key Triple DES)

KERNEL_FQ KERNEL_FA void m37031_aux2 (KERN_ATTR_TMPS_ESALT (office_open_tmp_t, office_open_t))
{
  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * des shared
   */

  #ifdef REAL_SHM

  LOCAL_VK u32 s_SPtrans[8][64];
  LOCAL_VK u32 s_skb[8][64];

  for (u32 i = lid; i < 64; i += lsz)
  {
    s_SPtrans[0][i] = c_SPtrans[0][i];
    s_SPtrans[1][i] = c_SPtrans[1][i];
    s_SPtrans[2][i] = c_SPtrans[2][i];
    s_SPtrans[3][i] = c_SPtrans[3][i];
    s_SPtrans[4][i] = c_SPtrans[4][i];
    s_SPtrans[5][i] = c_SPtrans[5][i];
    s_SPtrans[6][i] = c_SPtrans[6][i];
    s_SPtrans[7][i] = c_SPtrans[7][i];

    s_skb[0][i] = c_skb[0][i];
    s_skb[1][i] = c_skb[1][i];
    s_skb[2][i] = c_skb[2][i];
    s_skb[3][i] = c_skb[3][i];
    s_skb[4][i] = c_skb[4][i];
    s_skb[5][i] = c_skb[5][i];
    s_skb[6][i] = c_skb[6][i];
    s_skb[7][i] = c_skb[7][i];
  }

  SYNC_THREADS ();

  #else

  CONSTANT_AS u32a (*s_SPtrans)[64] = c_SPtrans;
  CONSTANT_AS u32a (*s_skb)[64]     = c_skb;

  #endif

  if (gid >= GID_CNT) return;

  const u32 encryptedVerifierHashInputBlockKey[2] = { 0xfea7d276, 0x3b4b9e79 };
  const u32 encryptedVerifierHashValueBlockKey[2] = { 0xd7aa0f6d, 0x3061344e };

  u64 tmp[6];

  tmp[0] = tmps[gid].out[0];
  tmp[1] = tmps[gid].out[1];
  tmp[2] = tmps[gid].out[2];
  tmp[3] = tmps[gid].out[3];
  tmp[4] = tmps[gid].out[4];
  tmp[5] = tmps[gid].out[5];

  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];
  u32 w4[4];
  u32 w5[4];
  u32 w6[4];
  u32 w7[4];

  w0[0] = h32_from_64_S (tmp[0]);
  w0[1] = l32_from_64_S (tmp[0]);
  w0[2] = h32_from_64_S (tmp[1]);
  w0[3] = l32_from_64_S (tmp[1]);
  w1[0] = h32_from_64_S (tmp[2]);
  w1[1] = l32_from_64_S (tmp[2]);
  w1[2] = h32_from_64_S (tmp[3]);
  w1[3] = l32_from_64_S (tmp[3]);
  w2[0] = h32_from_64_S (tmp[4]);
  w2[1] = l32_from_64_S (tmp[4]);
  w2[2] = h32_from_64_S (tmp[5]);
  w2[3] = l32_from_64_S (tmp[5]);
  w3[0] = encryptedVerifierHashInputBlockKey[0];
  w3[1] = encryptedVerifierHashInputBlockKey[1];
  w3[2] = 0;
  w3[3] = 0;
  w4[0] = 0; w4[1] = 0; w4[2] = 0; w4[3] = 0;
  w5[0] = 0; w5[1] = 0; w5[2] = 0; w5[3] = 0;
  w6[0] = 0; w6[1] = 0; w6[2] = 0; w6[3] = 0;
  w7[0] = 0; w7[1] = 0; w7[2] = 0; w7[3] = 0;

  sha384_ctx_t ctx;

  sha384_init (&ctx);

  sha384_update_128 (&ctx, w0, w1, w2, w3, w4, w5, w6, w7, 48 + 8);

  sha384_final (&ctx);

  u64 digest0[3];

  digest0[0] = ctx.h[0];
  digest0[1] = ctx.h[1];
  digest0[2] = ctx.h[2];

  w0[0] = h32_from_64_S (tmp[0]);
  w0[1] = l32_from_64_S (tmp[0]);
  w0[2] = h32_from_64_S (tmp[1]);
  w0[3] = l32_from_64_S (tmp[1]);
  w1[0] = h32_from_64_S (tmp[2]);
  w1[1] = l32_from_64_S (tmp[2]);
  w1[2] = h32_from_64_S (tmp[3]);
  w1[3] = l32_from_64_S (tmp[3]);
  w2[0] = h32_from_64_S (tmp[4]);
  w2[1] = l32_from_64_S (tmp[4]);
  w2[2] = h32_from_64_S (tmp[5]);
  w2[3] = l32_from_64_S (tmp[5]);
  w3[0] = encryptedVerifierHashValueBlockKey[0];
  w3[1] = encryptedVerifierHashValueBlockKey[1];
  w3[2] = 0;
  w3[3] = 0;
  w4[0] = 0; w4[1] = 0; w4[2] = 0; w4[3] = 0;
  w5[0] = 0; w5[1] = 0; w5[2] = 0; w5[3] = 0;
  w6[0] = 0; w6[1] = 0; w6[2] = 0; w6[3] = 0;
  w7[0] = 0; w7[1] = 0; w7[2] = 0; w7[3] = 0;

  sha384_init (&ctx);

  sha384_update_128 (&ctx, w0, w1, w2, w3, w4, w5, w6, w7, 48 + 8);

  sha384_final (&ctx);

  u64 digest1[3];

  digest1[0] = ctx.h[0];
  digest1[1] = ctx.h[1];
  digest1[2] = ctx.h[2];

  const u32 digest_cur = DIGESTS_OFFSET_HOST + LOOP_POS;

  const u32 key_bits = esalt_bufs[digest_cur].key_bits;

  u32 K1c[16], K1d[16], K2c[16], K2d[16], K3c[16], K3d[16];

  _des_crypt_keysetup (hc_swap32_S (h32_from_64_S (digest0[0])), hc_swap32_S (l32_from_64_S (digest0[0])), K1c, K1d, s_skb);
  _des_crypt_keysetup (hc_swap32_S (h32_from_64_S (digest0[1])), hc_swap32_S (l32_from_64_S (digest0[1])), K2c, K2d, s_skb);

  if (key_bits >= 192)
  {
    _des_crypt_keysetup (hc_swap32_S (h32_from_64_S (digest0[2])), hc_swap32_S (l32_from_64_S (digest0[2])), K3c, K3d, s_skb);
  }
  else
  {
    for (u32 i = 0; i < 16; i++) { K3c[i] = K1c[i]; K3d[i] = K1d[i]; }
  }

  u32 ct[4];

  ct[0] = hc_swap32_S (esalt_bufs[digest_cur].encryptedVerifier[0]);
  ct[1] = hc_swap32_S (esalt_bufs[digest_cur].encryptedVerifier[1]);
  ct[2] = hc_swap32_S (esalt_bufs[digest_cur].encryptedVerifier[2]);
  ct[3] = hc_swap32_S (esalt_bufs[digest_cur].encryptedVerifier[3]);

  u32 iv0 = hc_swap32_S (salt_bufs[SALT_POS_HOST].salt_buf[0]);
  u32 iv1 = hc_swap32_S (salt_bufs[SALT_POS_HOST].salt_buf[1]);

  u32 des_in[2];
  u32 des_out[2];
  u32 des_tmp[2];

  // 3DES-EDE CBC decrypt block 0: D(K3) -> E(K2) -> D(K1)

  des_in[0] = ct[0];
  des_in[1] = ct[1];

  _des_crypt_decrypt (des_out, des_in, K3c, K3d, s_SPtrans);
  _des_crypt_encrypt (des_tmp, des_out, K2c, K2d, s_SPtrans);
  _des_crypt_decrypt (des_out, des_tmp, K1c, K1d, s_SPtrans);

  u32 pt[4];

  pt[0] = hc_swap32_S (des_out[0] ^ iv0);
  pt[1] = hc_swap32_S (des_out[1] ^ iv1);

  // 3DES-EDE CBC decrypt block 1

  des_in[0] = ct[2];
  des_in[1] = ct[3];

  _des_crypt_decrypt (des_out, des_in, K3c, K3d, s_SPtrans);
  _des_crypt_encrypt (des_tmp, des_out, K2c, K2d, s_SPtrans);
  _des_crypt_decrypt (des_out, des_tmp, K1c, K1d, s_SPtrans);

  pt[2] = hc_swap32_S (des_out[0] ^ ct[0]);
  pt[3] = hc_swap32_S (des_out[1] ^ ct[1]);

  // SHA-384 of decrypted verifier

  w0[0] = pt[0];
  w0[1] = pt[1];
  w0[2] = pt[2];
  w0[3] = pt[3];
  w1[0] = 0; w1[1] = 0; w1[2] = 0; w1[3] = 0;
  w2[0] = 0; w2[1] = 0; w2[2] = 0; w2[3] = 0;
  w3[0] = 0; w3[1] = 0; w3[2] = 0; w3[3] = 0;
  w4[0] = 0; w4[1] = 0; w4[2] = 0; w4[3] = 0;
  w5[0] = 0; w5[1] = 0; w5[2] = 0; w5[3] = 0;
  w6[0] = 0; w6[1] = 0; w6[2] = 0; w6[3] = 0;
  w7[0] = 0; w7[1] = 0; w7[2] = 0; w7[3] = 0;

  sha384_init (&ctx);

  sha384_update_128 (&ctx, w0, w1, w2, w3, w4, w5, w6, w7, 16);

  sha384_final (&ctx);

  // re-encrypt with verifier-value key

  _des_crypt_keysetup (hc_swap32_S (h32_from_64_S (digest1[0])), hc_swap32_S (l32_from_64_S (digest1[0])), K1c, K1d, s_skb);
  _des_crypt_keysetup (hc_swap32_S (h32_from_64_S (digest1[1])), hc_swap32_S (l32_from_64_S (digest1[1])), K2c, K2d, s_skb);

  if (key_bits >= 192)
  {
    _des_crypt_keysetup (hc_swap32_S (h32_from_64_S (digest1[2])), hc_swap32_S (l32_from_64_S (digest1[2])), K3c, K3d, s_skb);
  }
  else
  {
    for (u32 i = 0; i < 16; i++) { K3c[i] = K1c[i]; K3d[i] = K1d[i]; }
  }

  // 3DES-EDE CBC encrypt block 0: E(K1) -> D(K2) -> E(K3)

  u32 enc[4];

  des_in[0] = hc_swap32_S (h32_from_64_S (ctx.h[0])) ^ iv0;
  des_in[1] = hc_swap32_S (l32_from_64_S (ctx.h[0])) ^ iv1;

  _des_crypt_encrypt (des_out, des_in, K1c, K1d, s_SPtrans);
  _des_crypt_decrypt (des_tmp, des_out, K2c, K2d, s_SPtrans);
  _des_crypt_encrypt (des_out, des_tmp, K3c, K3d, s_SPtrans);

  enc[0] = des_out[0];
  enc[1] = des_out[1];

  // 3DES-EDE CBC encrypt block 1

  des_in[0] = hc_swap32_S (h32_from_64_S (ctx.h[1])) ^ enc[0];
  des_in[1] = hc_swap32_S (l32_from_64_S (ctx.h[1])) ^ enc[1];

  _des_crypt_encrypt (des_out, des_in, K1c, K1d, s_SPtrans);
  _des_crypt_decrypt (des_tmp, des_out, K2c, K2d, s_SPtrans);
  _des_crypt_encrypt (des_out, des_tmp, K3c, K3d, s_SPtrans);

  enc[2] = des_out[0];
  enc[3] = des_out[1];

  const u32 r0 = hc_swap32_S (enc[0]);
  const u32 r1 = hc_swap32_S (enc[1]);
  const u32 r2 = hc_swap32_S (enc[2]);
  const u32 r3 = hc_swap32_S (enc[3]);

  #define il_pos 0

  #ifdef KERNEL_STATIC
  #include COMPARE_M
  #endif
}

// _aux3: Agile DES-CBC verification

KERNEL_FQ KERNEL_FA void m37031_aux3 (KERN_ATTR_TMPS_ESALT (office_open_tmp_t, office_open_t))
{
  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * des shared
   */

  #ifdef REAL_SHM

  LOCAL_VK u32 s_SPtrans[8][64];
  LOCAL_VK u32 s_skb[8][64];

  for (u32 i = lid; i < 64; i += lsz)
  {
    s_SPtrans[0][i] = c_SPtrans[0][i];
    s_SPtrans[1][i] = c_SPtrans[1][i];
    s_SPtrans[2][i] = c_SPtrans[2][i];
    s_SPtrans[3][i] = c_SPtrans[3][i];
    s_SPtrans[4][i] = c_SPtrans[4][i];
    s_SPtrans[5][i] = c_SPtrans[5][i];
    s_SPtrans[6][i] = c_SPtrans[6][i];
    s_SPtrans[7][i] = c_SPtrans[7][i];

    s_skb[0][i] = c_skb[0][i];
    s_skb[1][i] = c_skb[1][i];
    s_skb[2][i] = c_skb[2][i];
    s_skb[3][i] = c_skb[3][i];
    s_skb[4][i] = c_skb[4][i];
    s_skb[5][i] = c_skb[5][i];
    s_skb[6][i] = c_skb[6][i];
    s_skb[7][i] = c_skb[7][i];
  }

  SYNC_THREADS ();

  #else

  CONSTANT_AS u32a (*s_SPtrans)[64] = c_SPtrans;
  CONSTANT_AS u32a (*s_skb)[64]     = c_skb;

  #endif

  if (gid >= GID_CNT) return;

  const u32 encryptedVerifierHashInputBlockKey[2] = { 0xfea7d276, 0x3b4b9e79 };
  const u32 encryptedVerifierHashValueBlockKey[2] = { 0xd7aa0f6d, 0x3061344e };

  u64 tmp[6];

  tmp[0] = tmps[gid].out[0];
  tmp[1] = tmps[gid].out[1];
  tmp[2] = tmps[gid].out[2];
  tmp[3] = tmps[gid].out[3];
  tmp[4] = tmps[gid].out[4];
  tmp[5] = tmps[gid].out[5];

  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];
  u32 w4[4];
  u32 w5[4];
  u32 w6[4];
  u32 w7[4];

  w0[0] = h32_from_64_S (tmp[0]);
  w0[1] = l32_from_64_S (tmp[0]);
  w0[2] = h32_from_64_S (tmp[1]);
  w0[3] = l32_from_64_S (tmp[1]);
  w1[0] = h32_from_64_S (tmp[2]);
  w1[1] = l32_from_64_S (tmp[2]);
  w1[2] = h32_from_64_S (tmp[3]);
  w1[3] = l32_from_64_S (tmp[3]);
  w2[0] = h32_from_64_S (tmp[4]);
  w2[1] = l32_from_64_S (tmp[4]);
  w2[2] = h32_from_64_S (tmp[5]);
  w2[3] = l32_from_64_S (tmp[5]);
  w3[0] = encryptedVerifierHashInputBlockKey[0];
  w3[1] = encryptedVerifierHashInputBlockKey[1];
  w3[2] = 0;
  w3[3] = 0;
  w4[0] = 0; w4[1] = 0; w4[2] = 0; w4[3] = 0;
  w5[0] = 0; w5[1] = 0; w5[2] = 0; w5[3] = 0;
  w6[0] = 0; w6[1] = 0; w6[2] = 0; w6[3] = 0;
  w7[0] = 0; w7[1] = 0; w7[2] = 0; w7[3] = 0;

  sha384_ctx_t ctx;

  sha384_init (&ctx);

  sha384_update_128 (&ctx, w0, w1, w2, w3, w4, w5, w6, w7, 48 + 8);

  sha384_final (&ctx);

  u64 digest0_k;

  digest0_k = ctx.h[0];

  w0[0] = h32_from_64_S (tmp[0]);
  w0[1] = l32_from_64_S (tmp[0]);
  w0[2] = h32_from_64_S (tmp[1]);
  w0[3] = l32_from_64_S (tmp[1]);
  w1[0] = h32_from_64_S (tmp[2]);
  w1[1] = l32_from_64_S (tmp[2]);
  w1[2] = h32_from_64_S (tmp[3]);
  w1[3] = l32_from_64_S (tmp[3]);
  w2[0] = h32_from_64_S (tmp[4]);
  w2[1] = l32_from_64_S (tmp[4]);
  w2[2] = h32_from_64_S (tmp[5]);
  w2[3] = l32_from_64_S (tmp[5]);
  w3[0] = encryptedVerifierHashValueBlockKey[0];
  w3[1] = encryptedVerifierHashValueBlockKey[1];
  w3[2] = 0;
  w3[3] = 0;
  w4[0] = 0; w4[1] = 0; w4[2] = 0; w4[3] = 0;
  w5[0] = 0; w5[1] = 0; w5[2] = 0; w5[3] = 0;
  w6[0] = 0; w6[1] = 0; w6[2] = 0; w6[3] = 0;
  w7[0] = 0; w7[1] = 0; w7[2] = 0; w7[3] = 0;

  sha384_init (&ctx);

  sha384_update_128 (&ctx, w0, w1, w2, w3, w4, w5, w6, w7, 48 + 8);

  sha384_final (&ctx);

  u64 digest1_k;

  digest1_k = ctx.h[0];

  u32 Kc[16], Kd[16];

  _des_crypt_keysetup (hc_swap32_S (h32_from_64_S (digest0_k)), hc_swap32_S (l32_from_64_S (digest0_k)), Kc, Kd, s_skb);

  const u32 digest_cur = DIGESTS_OFFSET_HOST + LOOP_POS;

  u32 ct[4];

  ct[0] = hc_swap32_S (esalt_bufs[digest_cur].encryptedVerifier[0]);
  ct[1] = hc_swap32_S (esalt_bufs[digest_cur].encryptedVerifier[1]);
  ct[2] = hc_swap32_S (esalt_bufs[digest_cur].encryptedVerifier[2]);
  ct[3] = hc_swap32_S (esalt_bufs[digest_cur].encryptedVerifier[3]);

  u32 des_in[2];
  u32 des_out[2];

  // DES-CBC decrypt block 0

  des_in[0] = ct[0];
  des_in[1] = ct[1];

  _des_crypt_decrypt (des_out, des_in, Kc, Kd, s_SPtrans);

  u32 pt[4];

  pt[0] = hc_swap32_S (des_out[0] ^ hc_swap32_S (salt_bufs[SALT_POS_HOST].salt_buf[0]));
  pt[1] = hc_swap32_S (des_out[1] ^ hc_swap32_S (salt_bufs[SALT_POS_HOST].salt_buf[1]));

  // DES-CBC decrypt block 1

  des_in[0] = ct[2];
  des_in[1] = ct[3];

  _des_crypt_decrypt (des_out, des_in, Kc, Kd, s_SPtrans);

  pt[2] = hc_swap32_S (des_out[0] ^ ct[0]);
  pt[3] = hc_swap32_S (des_out[1] ^ ct[1]);

  // SHA-384 of decrypted verifier

  w0[0] = pt[0];
  w0[1] = pt[1];
  w0[2] = pt[2];
  w0[3] = pt[3];
  w1[0] = 0; w1[1] = 0; w1[2] = 0; w1[3] = 0;
  w2[0] = 0; w2[1] = 0; w2[2] = 0; w2[3] = 0;
  w3[0] = 0; w3[1] = 0; w3[2] = 0; w3[3] = 0;
  w4[0] = 0; w4[1] = 0; w4[2] = 0; w4[3] = 0;
  w5[0] = 0; w5[1] = 0; w5[2] = 0; w5[3] = 0;
  w6[0] = 0; w6[1] = 0; w6[2] = 0; w6[3] = 0;
  w7[0] = 0; w7[1] = 0; w7[2] = 0; w7[3] = 0;

  sha384_init (&ctx);

  sha384_update_128 (&ctx, w0, w1, w2, w3, w4, w5, w6, w7, 16);

  sha384_final (&ctx);

  _des_crypt_keysetup (hc_swap32_S (h32_from_64_S (digest1_k)), hc_swap32_S (l32_from_64_S (digest1_k)), Kc, Kd, s_skb);

  u32 enc[4];

  des_in[0] = hc_swap32_S (h32_from_64_S (ctx.h[0])) ^ hc_swap32_S (salt_bufs[SALT_POS_HOST].salt_buf[0]);
  des_in[1] = hc_swap32_S (l32_from_64_S (ctx.h[0])) ^ hc_swap32_S (salt_bufs[SALT_POS_HOST].salt_buf[1]);

  _des_crypt_encrypt (des_out, des_in, Kc, Kd, s_SPtrans);

  enc[0] = des_out[0];
  enc[1] = des_out[1];

  des_in[0] = hc_swap32_S (h32_from_64_S (ctx.h[1])) ^ enc[0];
  des_in[1] = hc_swap32_S (l32_from_64_S (ctx.h[1])) ^ enc[1];

  _des_crypt_encrypt (des_out, des_in, Kc, Kd, s_SPtrans);

  enc[2] = des_out[0];
  enc[3] = des_out[1];

  const u32 r0 = hc_swap32_S (enc[0]);
  const u32 r1 = hc_swap32_S (enc[1]);
  const u32 r2 = hc_swap32_S (enc[2]);
  const u32 r3 = hc_swap32_S (enc[3]);

  #define il_pos 0

  #ifdef KERNEL_STATIC
  #include COMPARE_M
  #endif
}

// _aux4: Agile DESX-CBC verification

KERNEL_FQ KERNEL_FA void m37031_aux4 (KERN_ATTR_TMPS_ESALT (office_open_tmp_t, office_open_t))
{
  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * des shared
   */

  #ifdef REAL_SHM

  LOCAL_VK u32 s_SPtrans[8][64];
  LOCAL_VK u32 s_skb[8][64];

  for (u32 i = lid; i < 64; i += lsz)
  {
    s_SPtrans[0][i] = c_SPtrans[0][i];
    s_SPtrans[1][i] = c_SPtrans[1][i];
    s_SPtrans[2][i] = c_SPtrans[2][i];
    s_SPtrans[3][i] = c_SPtrans[3][i];
    s_SPtrans[4][i] = c_SPtrans[4][i];
    s_SPtrans[5][i] = c_SPtrans[5][i];
    s_SPtrans[6][i] = c_SPtrans[6][i];
    s_SPtrans[7][i] = c_SPtrans[7][i];

    s_skb[0][i] = c_skb[0][i];
    s_skb[1][i] = c_skb[1][i];
    s_skb[2][i] = c_skb[2][i];
    s_skb[3][i] = c_skb[3][i];
    s_skb[4][i] = c_skb[4][i];
    s_skb[5][i] = c_skb[5][i];
    s_skb[6][i] = c_skb[6][i];
    s_skb[7][i] = c_skb[7][i];
  }

  SYNC_THREADS ();

  #else

  CONSTANT_AS u32a (*s_SPtrans)[64] = c_SPtrans;
  CONSTANT_AS u32a (*s_skb)[64]     = c_skb;

  #endif

  if (gid >= GID_CNT) return;

  const u32 encryptedVerifierHashInputBlockKey[2] = { 0xfea7d276, 0x3b4b9e79 };
  const u32 encryptedVerifierHashValueBlockKey[2] = { 0xd7aa0f6d, 0x3061344e };

  u64 tmp[6];

  tmp[0] = tmps[gid].out[0];
  tmp[1] = tmps[gid].out[1];
  tmp[2] = tmps[gid].out[2];
  tmp[3] = tmps[gid].out[3];
  tmp[4] = tmps[gid].out[4];
  tmp[5] = tmps[gid].out[5];

  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];
  u32 w4[4];
  u32 w5[4];
  u32 w6[4];
  u32 w7[4];

  w0[0] = h32_from_64_S (tmp[0]);
  w0[1] = l32_from_64_S (tmp[0]);
  w0[2] = h32_from_64_S (tmp[1]);
  w0[3] = l32_from_64_S (tmp[1]);
  w1[0] = h32_from_64_S (tmp[2]);
  w1[1] = l32_from_64_S (tmp[2]);
  w1[2] = h32_from_64_S (tmp[3]);
  w1[3] = l32_from_64_S (tmp[3]);
  w2[0] = h32_from_64_S (tmp[4]);
  w2[1] = l32_from_64_S (tmp[4]);
  w2[2] = h32_from_64_S (tmp[5]);
  w2[3] = l32_from_64_S (tmp[5]);
  w3[0] = encryptedVerifierHashInputBlockKey[0];
  w3[1] = encryptedVerifierHashInputBlockKey[1];
  w3[2] = 0;
  w3[3] = 0;
  w4[0] = 0; w4[1] = 0; w4[2] = 0; w4[3] = 0;
  w5[0] = 0; w5[1] = 0; w5[2] = 0; w5[3] = 0;
  w6[0] = 0; w6[1] = 0; w6[2] = 0; w6[3] = 0;
  w7[0] = 0; w7[1] = 0; w7[2] = 0; w7[3] = 0;

  sha384_ctx_t ctx;

  sha384_init (&ctx);

  sha384_update_128 (&ctx, w0, w1, w2, w3, w4, w5, w6, w7, 48 + 8);

  sha384_final (&ctx);

  // DESX key = 24 bytes: DES key (8) + K_post (8) + K_pre (8)

  u32 dkey0[2], kpost0[2], kpre0[2];

  dkey0[0] = h32_from_64_S (ctx.h[0]);
  dkey0[1] = l32_from_64_S (ctx.h[0]);
  kpost0[0] = h32_from_64_S (ctx.h[1]);
  kpost0[1] = l32_from_64_S (ctx.h[1]);
  kpre0[0] = h32_from_64_S (ctx.h[2]);
  kpre0[1] = l32_from_64_S (ctx.h[2]);

  w0[0] = h32_from_64_S (tmp[0]);
  w0[1] = l32_from_64_S (tmp[0]);
  w0[2] = h32_from_64_S (tmp[1]);
  w0[3] = l32_from_64_S (tmp[1]);
  w1[0] = h32_from_64_S (tmp[2]);
  w1[1] = l32_from_64_S (tmp[2]);
  w1[2] = h32_from_64_S (tmp[3]);
  w1[3] = l32_from_64_S (tmp[3]);
  w2[0] = h32_from_64_S (tmp[4]);
  w2[1] = l32_from_64_S (tmp[4]);
  w2[2] = h32_from_64_S (tmp[5]);
  w2[3] = l32_from_64_S (tmp[5]);
  w3[0] = encryptedVerifierHashValueBlockKey[0];
  w3[1] = encryptedVerifierHashValueBlockKey[1];
  w3[2] = 0;
  w3[3] = 0;
  w4[0] = 0; w4[1] = 0; w4[2] = 0; w4[3] = 0;
  w5[0] = 0; w5[1] = 0; w5[2] = 0; w5[3] = 0;
  w6[0] = 0; w6[1] = 0; w6[2] = 0; w6[3] = 0;
  w7[0] = 0; w7[1] = 0; w7[2] = 0; w7[3] = 0;

  sha384_init (&ctx);

  sha384_update_128 (&ctx, w0, w1, w2, w3, w4, w5, w6, w7, 48 + 8);

  sha384_final (&ctx);

  u32 dkey1[2], kpost1[2], kpre1[2];

  dkey1[0] = h32_from_64_S (ctx.h[0]);
  dkey1[1] = l32_from_64_S (ctx.h[0]);
  kpost1[0] = h32_from_64_S (ctx.h[1]);
  kpost1[1] = l32_from_64_S (ctx.h[1]);
  kpre1[0] = h32_from_64_S (ctx.h[2]);
  kpre1[1] = l32_from_64_S (ctx.h[2]);

  u32 Kc[16], Kd[16];

  _des_crypt_keysetup (hc_swap32_S (dkey0[0]), hc_swap32_S (dkey0[1]), Kc, Kd, s_skb);

  // Swap whitening keys from SHA-384 BE to DES byte order
  u32 pre_w0[2], post_w0[2];
  pre_w0[0]  = hc_swap32_S (kpost0[0]);
  pre_w0[1]  = hc_swap32_S (kpost0[1]);
  post_w0[0] = hc_swap32_S (kpre0[0]);
  post_w0[1] = hc_swap32_S (kpre0[1]);

  const u32 digest_cur = DIGESTS_OFFSET_HOST + LOOP_POS;

  u32 ct[4];

  ct[0] = hc_swap32_S (esalt_bufs[digest_cur].encryptedVerifier[0]);
  ct[1] = hc_swap32_S (esalt_bufs[digest_cur].encryptedVerifier[1]);
  ct[2] = hc_swap32_S (esalt_bufs[digest_cur].encryptedVerifier[2]);
  ct[3] = hc_swap32_S (esalt_bufs[digest_cur].encryptedVerifier[3]);

  u32 iv0 = hc_swap32_S (salt_bufs[SALT_POS_HOST].salt_buf[0]);
  u32 iv1 = hc_swap32_S (salt_bufs[SALT_POS_HOST].salt_buf[1]);

  u32 des_in[2];
  u32 des_out[2];

  // DESX-CBC decrypt block 0

  des_in[0] = ct[0] ^ post_w0[0];
  des_in[1] = ct[1] ^ post_w0[1];

  _des_crypt_decrypt (des_out, des_in, Kc, Kd, s_SPtrans);

  u32 pt[4];

  pt[0] = hc_swap32_S (des_out[0] ^ pre_w0[0] ^ iv0);
  pt[1] = hc_swap32_S (des_out[1] ^ pre_w0[1] ^ iv1);

  // DESX-CBC decrypt block 1

  des_in[0] = ct[2] ^ post_w0[0];
  des_in[1] = ct[3] ^ post_w0[1];

  _des_crypt_decrypt (des_out, des_in, Kc, Kd, s_SPtrans);

  pt[2] = hc_swap32_S (des_out[0] ^ pre_w0[0] ^ ct[0]);
  pt[3] = hc_swap32_S (des_out[1] ^ pre_w0[1] ^ ct[1]);

  // SHA-384 of decrypted verifier (pt is BE for SHA-384)

  w0[0] = pt[0];
  w0[1] = pt[1];
  w0[2] = pt[2];
  w0[3] = pt[3];
  w1[0] = 0; w1[1] = 0; w1[2] = 0; w1[3] = 0;
  w2[0] = 0; w2[1] = 0; w2[2] = 0; w2[3] = 0;
  w3[0] = 0; w3[1] = 0; w3[2] = 0; w3[3] = 0;
  w4[0] = 0; w4[1] = 0; w4[2] = 0; w4[3] = 0;
  w5[0] = 0; w5[1] = 0; w5[2] = 0; w5[3] = 0;
  w6[0] = 0; w6[1] = 0; w6[2] = 0; w6[3] = 0;
  w7[0] = 0; w7[1] = 0; w7[2] = 0; w7[3] = 0;

  sha384_init (&ctx);

  sha384_update_128 (&ctx, w0, w1, w2, w3, w4, w5, w6, w7, 16);

  sha384_final (&ctx);

  // Re-encrypt with verifier-value key

  _des_crypt_keysetup (hc_swap32_S (dkey1[0]), hc_swap32_S (dkey1[1]), Kc, Kd, s_skb);

  u32 pre_w1[2], post_w1[2];
  pre_w1[0]  = hc_swap32_S (kpost1[0]);
  pre_w1[1]  = hc_swap32_S (kpost1[1]);
  post_w1[0] = hc_swap32_S (kpre1[0]);
  post_w1[1] = hc_swap32_S (kpre1[1]);

  u32 enc[4];

  des_in[0] = hc_swap32_S (h32_from_64_S (ctx.h[0])) ^ iv0 ^ pre_w1[0];
  des_in[1] = hc_swap32_S (l32_from_64_S (ctx.h[0])) ^ iv1 ^ pre_w1[1];

  _des_crypt_encrypt (des_out, des_in, Kc, Kd, s_SPtrans);

  enc[0] = des_out[0] ^ post_w1[0];
  enc[1] = des_out[1] ^ post_w1[1];

  des_in[0] = hc_swap32_S (h32_from_64_S (ctx.h[1])) ^ enc[0] ^ pre_w1[0];
  des_in[1] = hc_swap32_S (l32_from_64_S (ctx.h[1])) ^ enc[1] ^ pre_w1[1];

  _des_crypt_encrypt (des_out, des_in, Kc, Kd, s_SPtrans);

  enc[2] = des_out[0] ^ post_w1[0];
  enc[3] = des_out[1] ^ post_w1[1];

  const u32 r0 = hc_swap32_S (enc[0]);
  const u32 r1 = hc_swap32_S (enc[1]);
  const u32 r2 = hc_swap32_S (enc[2]);
  const u32 r3 = hc_swap32_S (enc[3]);

  #define il_pos 0

  #ifdef KERNEL_STATIC
  #include COMPARE_M
  #endif
}

// _aux5: Agile RC2-CBC verification (RFC 2268, 8-byte block)

KERNEL_FQ KERNEL_FA void m37031_aux5 (KERN_ATTR_TMPS_ESALT (office_open_tmp_t, office_open_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  const u32 encryptedVerifierHashInputBlockKey[2] = { 0xfea7d276, 0x3b4b9e79 };
  const u32 encryptedVerifierHashValueBlockKey[2] = { 0xd7aa0f6d, 0x3061344e };

  u64 tmp[6];

  tmp[0] = tmps[gid].out[0];
  tmp[1] = tmps[gid].out[1];
  tmp[2] = tmps[gid].out[2];
  tmp[3] = tmps[gid].out[3];
  tmp[4] = tmps[gid].out[4];
  tmp[5] = tmps[gid].out[5];

  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];
  u32 w4[4];
  u32 w5[4];
  u32 w6[4];
  u32 w7[4];

  w0[0] = h32_from_64_S (tmp[0]);
  w0[1] = l32_from_64_S (tmp[0]);
  w0[2] = h32_from_64_S (tmp[1]);
  w0[3] = l32_from_64_S (tmp[1]);
  w1[0] = h32_from_64_S (tmp[2]);
  w1[1] = l32_from_64_S (tmp[2]);
  w1[2] = h32_from_64_S (tmp[3]);
  w1[3] = l32_from_64_S (tmp[3]);
  w2[0] = h32_from_64_S (tmp[4]);
  w2[1] = l32_from_64_S (tmp[4]);
  w2[2] = h32_from_64_S (tmp[5]);
  w2[3] = l32_from_64_S (tmp[5]);
  w3[0] = encryptedVerifierHashInputBlockKey[0];
  w3[1] = encryptedVerifierHashInputBlockKey[1];
  w3[2] = 0;
  w3[3] = 0;
  w4[0] = 0; w4[1] = 0; w4[2] = 0; w4[3] = 0;
  w5[0] = 0; w5[1] = 0; w5[2] = 0; w5[3] = 0;
  w6[0] = 0; w6[1] = 0; w6[2] = 0; w6[3] = 0;
  w7[0] = 0; w7[1] = 0; w7[2] = 0; w7[3] = 0;

  sha384_ctx_t ctx;

  sha384_init (&ctx);

  sha384_update_128 (&ctx, w0, w1, w2, w3, w4, w5, w6, w7, 48 + 8);

  sha384_final (&ctx);

  // RC2 key = first 16 bytes of SHA-384 derived key (2 u64 = 4 u32)

  u32 digest0[4];

  digest0[0] = h32_from_64_S (ctx.h[0]);
  digest0[1] = l32_from_64_S (ctx.h[0]);
  digest0[2] = h32_from_64_S (ctx.h[1]);
  digest0[3] = l32_from_64_S (ctx.h[1]);

  w0[0] = h32_from_64_S (tmp[0]);
  w0[1] = l32_from_64_S (tmp[0]);
  w0[2] = h32_from_64_S (tmp[1]);
  w0[3] = l32_from_64_S (tmp[1]);
  w1[0] = h32_from_64_S (tmp[2]);
  w1[1] = l32_from_64_S (tmp[2]);
  w1[2] = h32_from_64_S (tmp[3]);
  w1[3] = l32_from_64_S (tmp[3]);
  w2[0] = h32_from_64_S (tmp[4]);
  w2[1] = l32_from_64_S (tmp[4]);
  w2[2] = h32_from_64_S (tmp[5]);
  w2[3] = l32_from_64_S (tmp[5]);
  w3[0] = encryptedVerifierHashValueBlockKey[0];
  w3[1] = encryptedVerifierHashValueBlockKey[1];
  w3[2] = 0;
  w3[3] = 0;
  w4[0] = 0; w4[1] = 0; w4[2] = 0; w4[3] = 0;
  w5[0] = 0; w5[1] = 0; w5[2] = 0; w5[3] = 0;
  w6[0] = 0; w6[1] = 0; w6[2] = 0; w6[3] = 0;
  w7[0] = 0; w7[1] = 0; w7[2] = 0; w7[3] = 0;

  sha384_init (&ctx);

  sha384_update_128 (&ctx, w0, w1, w2, w3, w4, w5, w6, w7, 48 + 8);

  sha384_final (&ctx);

  u32 digest1[4];

  digest1[0] = h32_from_64_S (ctx.h[0]);
  digest1[1] = l32_from_64_S (ctx.h[0]);
  digest1[2] = h32_from_64_S (ctx.h[1]);
  digest1[3] = l32_from_64_S (ctx.h[1]);

  u32 xk0[64];

  rc2_key_setup (xk0, digest0, 16, 128);

  const u32 digest_cur = DIGESTS_OFFSET_HOST + LOOP_POS;

  u32 ct[4];

  ct[0] = esalt_bufs[digest_cur].encryptedVerifier[0];
  ct[1] = esalt_bufs[digest_cur].encryptedVerifier[1];
  ct[2] = esalt_bufs[digest_cur].encryptedVerifier[2];
  ct[3] = esalt_bufs[digest_cur].encryptedVerifier[3];

  u32 rc2_in[2];
  u32 rc2_out[2];

  rc2_in[0] = ct[0];
  rc2_in[1] = ct[1];

  rc2_decrypt (xk0, rc2_in, rc2_out);

  u32 pt[4];

  pt[0] = rc2_out[0] ^ salt_bufs[SALT_POS_HOST].salt_buf[0];
  pt[1] = rc2_out[1] ^ salt_bufs[SALT_POS_HOST].salt_buf[1];

  rc2_in[0] = ct[2];
  rc2_in[1] = ct[3];

  rc2_decrypt (xk0, rc2_in, rc2_out);

  pt[2] = rc2_out[0] ^ ct[0];
  pt[3] = rc2_out[1] ^ ct[1];

  // SHA-384 of decrypted verifier

  w0[0] = pt[0];
  w0[1] = pt[1];
  w0[2] = pt[2];
  w0[3] = pt[3];
  w1[0] = 0; w1[1] = 0; w1[2] = 0; w1[3] = 0;
  w2[0] = 0; w2[1] = 0; w2[2] = 0; w2[3] = 0;
  w3[0] = 0; w3[1] = 0; w3[2] = 0; w3[3] = 0;
  w4[0] = 0; w4[1] = 0; w4[2] = 0; w4[3] = 0;
  w5[0] = 0; w5[1] = 0; w5[2] = 0; w5[3] = 0;
  w6[0] = 0; w6[1] = 0; w6[2] = 0; w6[3] = 0;
  w7[0] = 0; w7[1] = 0; w7[2] = 0; w7[3] = 0;

  sha384_init (&ctx);

  sha384_update_128 (&ctx, w0, w1, w2, w3, w4, w5, w6, w7, 16);

  sha384_final (&ctx);

  u32 xk1[64];

  rc2_key_setup (xk1, digest1, 16, 128);

  u32 enc[4];

  rc2_in[0] = h32_from_64_S (ctx.h[0]) ^ salt_bufs[SALT_POS_HOST].salt_buf[0];
  rc2_in[1] = l32_from_64_S (ctx.h[0]) ^ salt_bufs[SALT_POS_HOST].salt_buf[1];

  rc2_encrypt (xk1, rc2_in, rc2_out);

  enc[0] = rc2_out[0];
  enc[1] = rc2_out[1];

  rc2_in[0] = h32_from_64_S (ctx.h[1]) ^ enc[0];
  rc2_in[1] = l32_from_64_S (ctx.h[1]) ^ enc[1];

  rc2_encrypt (xk1, rc2_in, rc2_out);

  enc[2] = rc2_out[0];
  enc[3] = rc2_out[1];

  const u32 r0 = enc[0];
  const u32 r1 = enc[1];
  const u32 r2 = enc[2];
  const u32 r3 = enc[3];

  #define il_pos 0

  #ifdef KERNEL_STATIC
  #include COMPARE_M
  #endif
}
