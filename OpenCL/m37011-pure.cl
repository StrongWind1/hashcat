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
#include M2S(INCLUDE_PATH/inc_hash_sha1.cl)
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

KERNEL_FQ KERNEL_FA void m37011_init (KERN_ATTR_TMPS_ESALT (office_open_tmp_t, office_open_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  sha1_ctx_t ctx;

  sha1_init (&ctx);

  sha1_update_global (&ctx, salt_bufs[SALT_POS_HOST].salt_buf, salt_bufs[SALT_POS_HOST].salt_len);

  sha1_update_global_utf16le_swap (&ctx, pws[gid].i, pws[gid].pw_len);

  sha1_final (&ctx);

  // Store u32 SHA-1 words zero-extended into u64 slots

  tmps[gid].out[0] = (u64) ctx.h[0];
  tmps[gid].out[1] = (u64) ctx.h[1];
  tmps[gid].out[2] = (u64) ctx.h[2];
  tmps[gid].out[3] = (u64) ctx.h[3];
  tmps[gid].out[4] = (u64) ctx.h[4];
  tmps[gid].out[5] = 0;
  tmps[gid].out[6] = 0;
  tmps[gid].out[7] = 0;
}

KERNEL_FQ KERNEL_FA void m37011_loop (KERN_ATTR_TMPS_ESALT (office_open_tmp_t, office_open_t))
{
  const u64 gid = get_global_id (0);

  if ((gid * VECT_SIZE) >= GID_CNT) return;

  // Read u64 slots and extract the u32 SHA-1 words from the low halves

  u32x t0 = l32_from_64 (pack64v (tmps, out, gid, 0));
  u32x t1 = l32_from_64 (pack64v (tmps, out, gid, 1));
  u32x t2 = l32_from_64 (pack64v (tmps, out, gid, 2));
  u32x t3 = l32_from_64 (pack64v (tmps, out, gid, 3));
  u32x t4 = l32_from_64 (pack64v (tmps, out, gid, 4));

  u32x w0[4];
  u32x w1[4];
  u32x w2[4];
  u32x w3[4];

  w0[0] = 0;
  w0[1] = 0;
  w0[2] = 0;
  w0[3] = 0;
  w1[0] = 0;
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
  w3[3] = (4 + 20) * 8;

  for (u32 i = 0, j = LOOP_POS; i < LOOP_CNT; i++, j++)
  {
    w0[0] = hc_swap32 (j);
    w0[1] = t0;
    w0[2] = t1;
    w0[3] = t2;
    w1[0] = t3;
    w1[1] = t4;

    u32x digest[5];

    digest[0] = SHA1M_A;
    digest[1] = SHA1M_B;
    digest[2] = SHA1M_C;
    digest[3] = SHA1M_D;
    digest[4] = SHA1M_E;

    sha1_transform_vector (w0, w1, w2, w3, digest);

    t0 = digest[0];
    t1 = digest[1];
    t2 = digest[2];
    t3 = digest[3];
    t4 = digest[4];
  }

  // Store u32 results back as zero-extended u64

  unpack64v (tmps, out, gid, 0, hl32_to_64 (0, t0));
  unpack64v (tmps, out, gid, 1, hl32_to_64 (0, t1));
  unpack64v (tmps, out, gid, 2, hl32_to_64 (0, t2));
  unpack64v (tmps, out, gid, 3, hl32_to_64 (0, t3));
  unpack64v (tmps, out, gid, 4, hl32_to_64 (0, t4));
}

// _comp: Standard 2007 AES-ECB verification (from m09400)

KERNEL_FQ KERNEL_FA void m37011_comp (KERN_ATTR_TMPS_ESALT (office_open_tmp_t, office_open_t))
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

  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  w0[0] = l32_from_64_S (tmps[gid].out[0]);
  w0[1] = l32_from_64_S (tmps[gid].out[1]);
  w0[2] = l32_from_64_S (tmps[gid].out[2]);
  w0[3] = l32_from_64_S (tmps[gid].out[3]);
  w1[0] = l32_from_64_S (tmps[gid].out[4]);
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

  sha1_ctx_t ctx;

  sha1_init (&ctx);

  sha1_update_64 (&ctx, w0, w1, w2, w3, 20 + 4);

  sha1_final (&ctx);

  u32 digest_common[5];

  digest_common[0] = ctx.h[0];
  digest_common[1] = ctx.h[1];
  digest_common[2] = ctx.h[2];
  digest_common[3] = ctx.h[3];
  digest_common[4] = ctx.h[4];

  w0[0] = 0x36363636 ^ digest_common[0];
  w0[1] = 0x36363636 ^ digest_common[1];
  w0[2] = 0x36363636 ^ digest_common[2];
  w0[3] = 0x36363636 ^ digest_common[3];
  w1[0] = 0x36363636 ^ digest_common[4];
  w1[1] = 0x36363636;
  w1[2] = 0x36363636;
  w1[3] = 0x36363636;
  w2[0] = 0x36363636;
  w2[1] = 0x36363636;
  w2[2] = 0x36363636;
  w2[3] = 0x36363636;
  w3[0] = 0x36363636;
  w3[1] = 0x36363636;
  w3[2] = 0x36363636;
  w3[3] = 0x36363636;

  sha1_init (&ctx);

  sha1_update_64 (&ctx, w0, w1, w2, w3, 64);

  sha1_final (&ctx);

  u32 digest_saved[5];

  digest_saved[0] = ctx.h[0];
  digest_saved[1] = ctx.h[1];
  digest_saved[2] = ctx.h[2];
  digest_saved[3] = ctx.h[3];
  digest_saved[4] = ctx.h[4];

  u32 ukey[8];

  ukey[0] = digest_saved[0];
  ukey[1] = digest_saved[1];
  ukey[2] = digest_saved[2];
  ukey[3] = digest_saved[3];

  u32 ks[60];

  AES128_set_decrypt_key (ks, ukey, s_te0, s_te1, s_te2, s_te3, s_td0, s_td1, s_td2, s_td3);

  u32 verifier[4];

  verifier[0] = esalt_bufs[DIGESTS_OFFSET_HOST].encryptedVerifier[0];
  verifier[1] = esalt_bufs[DIGESTS_OFFSET_HOST].encryptedVerifier[1];
  verifier[2] = esalt_bufs[DIGESTS_OFFSET_HOST].encryptedVerifier[2];
  verifier[3] = esalt_bufs[DIGESTS_OFFSET_HOST].encryptedVerifier[3];

  u32 data[4];

  data[0] = verifier[0];
  data[1] = verifier[1];
  data[2] = verifier[2];
  data[3] = verifier[3];

  u32 out[4];

  AES128_decrypt (ks, data, out, s_td0, s_td1, s_td2, s_td3, s_td4);

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

  sha1_init (&ctx);

  sha1_update_64 (&ctx, w0, w1, w2, w3, 16);

  sha1_final (&ctx);

  AES128_set_encrypt_key (ks, ukey, s_te0, s_te1, s_te2, s_te3);

  data[0] = ctx.h[0];
  data[1] = ctx.h[1];
  data[2] = ctx.h[2];
  data[3] = ctx.h[3];

  AES128_encrypt (ks, data, out, s_te0, s_te1, s_te2, s_te3, s_te4);

  {
    const u32 r0 = out[0];
    const u32 r1 = out[1];
    const u32 r2 = out[2];
    const u32 r3 = out[3];

    #ifdef KERNEL_STATIC
    #define il_pos 0
    #endif

    #include COMPARE_M
  }

  // AES-256 test

  w0[0] = 0x5c5c5c5c ^ digest_common[0];
  w0[1] = 0x5c5c5c5c ^ digest_common[1];
  w0[2] = 0x5c5c5c5c ^ digest_common[2];
  w0[3] = 0x5c5c5c5c ^ digest_common[3];
  w1[0] = 0x5c5c5c5c ^ digest_common[4];
  w1[1] = 0x5c5c5c5c;
  w1[2] = 0x5c5c5c5c;
  w1[3] = 0x5c5c5c5c;
  w2[0] = 0x5c5c5c5c;
  w2[1] = 0x5c5c5c5c;
  w2[2] = 0x5c5c5c5c;
  w2[3] = 0x5c5c5c5c;
  w3[0] = 0x5c5c5c5c;
  w3[1] = 0x5c5c5c5c;
  w3[2] = 0x5c5c5c5c;
  w3[3] = 0x5c5c5c5c;

  sha1_init (&ctx);

  sha1_update_64 (&ctx, w0, w1, w2, w3, 64);

  sha1_final (&ctx);

  ukey[0] = digest_saved[0];
  ukey[1] = digest_saved[1];
  ukey[2] = digest_saved[2];
  ukey[3] = digest_saved[3];
  ukey[4] = digest_saved[4];
  ukey[5] = ctx.h[0];
  ukey[6] = ctx.h[1];
  ukey[7] = ctx.h[2];

  AES256_set_decrypt_key (ks, ukey, s_te0, s_te1, s_te2, s_te3, s_td0, s_td1, s_td2, s_td3);

  data[0] = verifier[0];
  data[1] = verifier[1];
  data[2] = verifier[2];
  data[3] = verifier[3];

  AES256_decrypt (ks, data, out, s_td0, s_td1, s_td2, s_td3, s_td4);

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

  sha1_init (&ctx);

  sha1_update_64 (&ctx, w0, w1, w2, w3, 16);

  sha1_final (&ctx);

  AES256_set_encrypt_key (ks, ukey, s_te0, s_te1, s_te2, s_te3);

  data[0] = ctx.h[0];
  data[1] = ctx.h[1];
  data[2] = ctx.h[2];
  data[3] = ctx.h[3];

  AES256_encrypt (ks, data, out, s_te0, s_te1, s_te2, s_te3, s_te4);

  {
    const u32 r0 = out[0];
    const u32 r1 = out[1];
    const u32 r2 = out[2];
    const u32 r3 = out[3];

    #define il_pos 0

    #ifdef KERNEL_STATIC
    #include COMPARE_M
    #endif
  }
}

// _aux1: Agile 2010 AES-128-CBC verification (from m09500)

KERNEL_FQ KERNEL_FA void m37011_aux1 (KERN_ATTR_TMPS_ESALT (office_open_tmp_t, office_open_t))
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

  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  w0[0] = l32_from_64_S (tmps[gid].out[0]);
  w0[1] = l32_from_64_S (tmps[gid].out[1]);
  w0[2] = l32_from_64_S (tmps[gid].out[2]);
  w0[3] = l32_from_64_S (tmps[gid].out[3]);
  w1[0] = l32_from_64_S (tmps[gid].out[4]);
  w1[1] = encryptedVerifierHashInputBlockKey[0];
  w1[2] = encryptedVerifierHashInputBlockKey[1];
  w1[3] = 0;
  w2[0] = 0;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;
  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = 0;

  sha1_ctx_t ctx;

  sha1_init (&ctx);

  sha1_update_64 (&ctx, w0, w1, w2, w3, 20 + 8);

  sha1_final (&ctx);

  u32 digest0[4];

  digest0[0] = ctx.h[0];
  digest0[1] = ctx.h[1];
  digest0[2] = ctx.h[2];
  digest0[3] = ctx.h[3];

  w0[0] = l32_from_64_S (tmps[gid].out[0]);
  w0[1] = l32_from_64_S (tmps[gid].out[1]);
  w0[2] = l32_from_64_S (tmps[gid].out[2]);
  w0[3] = l32_from_64_S (tmps[gid].out[3]);
  w1[0] = l32_from_64_S (tmps[gid].out[4]);
  w1[1] = encryptedVerifierHashValueBlockKey[0];
  w1[2] = encryptedVerifierHashValueBlockKey[1];
  w1[3] = 0;
  w2[0] = 0;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;
  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = 0;

  sha1_init (&ctx);

  sha1_update_64 (&ctx, w0, w1, w2, w3, 20 + 8);

  sha1_final (&ctx);

  u32 digest1[4];

  digest1[0] = ctx.h[0];
  digest1[1] = ctx.h[1];
  digest1[2] = ctx.h[2];
  digest1[3] = ctx.h[3];

  u32 ukey[4];

  ukey[0] = digest0[0];
  ukey[1] = digest0[1];
  ukey[2] = digest0[2];
  ukey[3] = digest0[3];

  u32 ks[44];

  AES128_set_decrypt_key (ks, ukey, s_te0, s_te1, s_te2, s_te3, s_td0, s_td1, s_td2, s_td3);

  const u32 digest_cur = DIGESTS_OFFSET_HOST + LOOP_POS;

  u32 data[4];

  data[0] = esalt_bufs[digest_cur].encryptedVerifier[0];
  data[1] = esalt_bufs[digest_cur].encryptedVerifier[1];
  data[2] = esalt_bufs[digest_cur].encryptedVerifier[2];
  data[3] = esalt_bufs[digest_cur].encryptedVerifier[3];

  u32 out[4];

  AES128_decrypt (ks, data, out, s_td0, s_td1, s_td2, s_td3, s_td4);

  out[0] ^= salt_bufs[SALT_POS_HOST].salt_buf[0];
  out[1] ^= salt_bufs[SALT_POS_HOST].salt_buf[1];
  out[2] ^= salt_bufs[SALT_POS_HOST].salt_buf[2];
  out[3] ^= salt_bufs[SALT_POS_HOST].salt_buf[3];

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

  sha1_init (&ctx);

  sha1_update_64 (&ctx, w0, w1, w2, w3, 16);

  sha1_final (&ctx);

  u32 digest[4];

  digest[0] = ctx.h[0];
  digest[1] = ctx.h[1];
  digest[2] = ctx.h[2];
  digest[3] = ctx.h[3];

  ukey[0] = digest1[0];
  ukey[1] = digest1[1];
  ukey[2] = digest1[2];
  ukey[3] = digest1[3];

  AES128_set_encrypt_key (ks, ukey, s_te0, s_te1, s_te2, s_te3);

  data[0] = digest[0] ^ salt_bufs[SALT_POS_HOST].salt_buf[0];
  data[1] = digest[1] ^ salt_bufs[SALT_POS_HOST].salt_buf[1];
  data[2] = digest[2] ^ salt_bufs[SALT_POS_HOST].salt_buf[2];
  data[3] = digest[3] ^ salt_bufs[SALT_POS_HOST].salt_buf[3];

  AES128_encrypt (ks, data, out, s_te0, s_te1, s_te2, s_te3, s_te4);

  const u32 r0 = out[0];
  const u32 r1 = out[1];
  const u32 r2 = out[2];
  const u32 r3 = out[3];

  #define il_pos 0

  #ifdef KERNEL_STATIC
  #include COMPARE_M
  #endif
}

// _aux2: Agile 3DES-112-CBC verification (2-key Triple DES)

KERNEL_FQ KERNEL_FA void m37011_aux2 (KERN_ATTR_TMPS_ESALT (office_open_tmp_t, office_open_t))
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

  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  w0[0] = l32_from_64_S (tmps[gid].out[0]);
  w0[1] = l32_from_64_S (tmps[gid].out[1]);
  w0[2] = l32_from_64_S (tmps[gid].out[2]);
  w0[3] = l32_from_64_S (tmps[gid].out[3]);
  w1[0] = l32_from_64_S (tmps[gid].out[4]);
  w1[1] = encryptedVerifierHashInputBlockKey[0];
  w1[2] = encryptedVerifierHashInputBlockKey[1];
  w1[3] = 0;
  w2[0] = 0;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;
  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = 0;

  sha1_ctx_t ctx;

  sha1_init (&ctx);

  sha1_update_64 (&ctx, w0, w1, w2, w3, 20 + 8);

  sha1_final (&ctx);

  u32 digest0[5];

  digest0[0] = ctx.h[0];
  digest0[1] = ctx.h[1];
  digest0[2] = ctx.h[2];
  digest0[3] = ctx.h[3];
  digest0[4] = ctx.h[4];

  w0[0] = l32_from_64_S (tmps[gid].out[0]);
  w0[1] = l32_from_64_S (tmps[gid].out[1]);
  w0[2] = l32_from_64_S (tmps[gid].out[2]);
  w0[3] = l32_from_64_S (tmps[gid].out[3]);
  w1[0] = l32_from_64_S (tmps[gid].out[4]);
  w1[1] = encryptedVerifierHashValueBlockKey[0];
  w1[2] = encryptedVerifierHashValueBlockKey[1];
  w1[3] = 0;
  w2[0] = 0;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;
  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = 0;

  sha1_init (&ctx);

  sha1_update_64 (&ctx, w0, w1, w2, w3, 20 + 8);

  sha1_final (&ctx);

  u32 digest1[5];

  digest1[0] = ctx.h[0];
  digest1[1] = ctx.h[1];
  digest1[2] = ctx.h[2];
  digest1[3] = ctx.h[3];
  digest1[4] = ctx.h[4];

  // 3DES key: K1 = bytes 0-7, K2 = bytes 8-15
  // For 3-key (key_bits=192): K3 = bytes 16-23 (h[4] + 0x36 pad for SHA-1)
  // For 2-key (key_bits=128): K3 = K1

  const u32 key_bits = esalt_bufs[DIGESTS_OFFSET_HOST].key_bits;

  u32 K1c[16], K1d[16], K2c[16], K2d[16], K3c[16], K3d[16];

  _des_crypt_keysetup (hc_swap32_S (digest0[0]), hc_swap32_S (digest0[1]), K1c, K1d, s_skb);
  _des_crypt_keysetup (hc_swap32_S (digest0[2]), hc_swap32_S (digest0[3]), K2c, K2d, s_skb);

  if (key_bits >= 192)
  {
    _des_crypt_keysetup (hc_swap32_S (digest0[4]), hc_swap32_S (0x36363636), K3c, K3d, s_skb);
  }
  else
  {
    for (u32 i = 0; i < 16; i++) { K3c[i] = K1c[i]; K3d[i] = K1d[i]; }
  }

  const u32 digest_cur = DIGESTS_OFFSET_HOST + LOOP_POS;

  // swap ciphertext and IV from BE (module parser stores BE) to LE for DES

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

  // SHA-1 of decrypted verifier (pt is now BE for SHA-1)

  w0[0] = pt[0];
  w0[1] = pt[1];
  w0[2] = pt[2];
  w0[3] = pt[3];
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

  sha1_init (&ctx);

  sha1_update_64 (&ctx, w0, w1, w2, w3, 16);

  sha1_final (&ctx);

  // re-encrypt with verifier-value key

  _des_crypt_keysetup (hc_swap32_S (digest1[0]), hc_swap32_S (digest1[1]), K1c, K1d, s_skb);
  _des_crypt_keysetup (hc_swap32_S (digest1[2]), hc_swap32_S (digest1[3]), K2c, K2d, s_skb);

  if (key_bits >= 192)
  {
    _des_crypt_keysetup (hc_swap32_S (digest1[4]), hc_swap32_S (0x36363636), K3c, K3d, s_skb);
  }
  else
  {
    for (u32 i = 0; i < 16; i++) { K3c[i] = K1c[i]; K3d[i] = K1d[i]; }
  }

  // 3DES-EDE CBC encrypt block 0: E(K1) -> D(K2) -> E(K3)

  u32 enc[4];

  des_in[0] = hc_swap32_S (ctx.h[0]) ^ iv0;
  des_in[1] = hc_swap32_S (ctx.h[1]) ^ iv1;

  _des_crypt_encrypt (des_out, des_in, K1c, K1d, s_SPtrans);
  _des_crypt_decrypt (des_tmp, des_out, K2c, K2d, s_SPtrans);
  _des_crypt_encrypt (des_out, des_tmp, K3c, K3d, s_SPtrans);

  enc[0] = des_out[0];
  enc[1] = des_out[1];

  // 3DES-EDE CBC encrypt block 1

  des_in[0] = hc_swap32_S (ctx.h[2]) ^ enc[0];
  des_in[1] = hc_swap32_S (ctx.h[3]) ^ enc[1];

  _des_crypt_encrypt (des_out, des_in, K1c, K1d, s_SPtrans);
  _des_crypt_decrypt (des_tmp, des_out, K2c, K2d, s_SPtrans);
  _des_crypt_encrypt (des_out, des_tmp, K3c, K3d, s_SPtrans);

  enc[2] = des_out[0];
  enc[3] = des_out[1];

  // swap DES output (LE) back to BE for digest comparison
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

KERNEL_FQ KERNEL_FA void m37011_aux3 (KERN_ATTR_TMPS_ESALT (office_open_tmp_t, office_open_t))
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

  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  w0[0] = l32_from_64_S (tmps[gid].out[0]);
  w0[1] = l32_from_64_S (tmps[gid].out[1]);
  w0[2] = l32_from_64_S (tmps[gid].out[2]);
  w0[3] = l32_from_64_S (tmps[gid].out[3]);
  w1[0] = l32_from_64_S (tmps[gid].out[4]);
  w1[1] = encryptedVerifierHashInputBlockKey[0];
  w1[2] = encryptedVerifierHashInputBlockKey[1];
  w1[3] = 0;
  w2[0] = 0;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;
  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = 0;

  sha1_ctx_t ctx;

  sha1_init (&ctx);

  sha1_update_64 (&ctx, w0, w1, w2, w3, 20 + 8);

  sha1_final (&ctx);

  u32 digest0[2];

  digest0[0] = ctx.h[0];
  digest0[1] = ctx.h[1];

  w0[0] = l32_from_64_S (tmps[gid].out[0]);
  w0[1] = l32_from_64_S (tmps[gid].out[1]);
  w0[2] = l32_from_64_S (tmps[gid].out[2]);
  w0[3] = l32_from_64_S (tmps[gid].out[3]);
  w1[0] = l32_from_64_S (tmps[gid].out[4]);
  w1[1] = encryptedVerifierHashValueBlockKey[0];
  w1[2] = encryptedVerifierHashValueBlockKey[1];
  w1[3] = 0;
  w2[0] = 0;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;
  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = 0;

  sha1_init (&ctx);

  sha1_update_64 (&ctx, w0, w1, w2, w3, 20 + 8);

  sha1_final (&ctx);

  u32 digest1[2];

  digest1[0] = ctx.h[0];
  digest1[1] = ctx.h[1];

  // DES key = first 8 bytes of derived key

  u32 Kc[16], Kd[16];

  _des_crypt_keysetup (hc_swap32_S (digest0[0]), hc_swap32_S (digest0[1]), Kc, Kd, s_skb);

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

  // DES-CBC decrypt block 0

  des_in[0] = ct[0];
  des_in[1] = ct[1];

  _des_crypt_decrypt (des_out, des_in, Kc, Kd, s_SPtrans);

  u32 pt[4];

  pt[0] = hc_swap32_S (des_out[0] ^ iv0);
  pt[1] = hc_swap32_S (des_out[1] ^ iv1);

  // DES-CBC decrypt block 1

  des_in[0] = ct[2];
  des_in[1] = ct[3];

  _des_crypt_decrypt (des_out, des_in, Kc, Kd, s_SPtrans);

  pt[2] = hc_swap32_S (des_out[0] ^ ct[0]);
  pt[3] = hc_swap32_S (des_out[1] ^ ct[1]);

  // SHA-1 of decrypted verifier (pt is BE for SHA-1)

  w0[0] = pt[0];
  w0[1] = pt[1];
  w0[2] = pt[2];
  w0[3] = pt[3];
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

  sha1_init (&ctx);

  sha1_update_64 (&ctx, w0, w1, w2, w3, 16);

  sha1_final (&ctx);

  // re-encrypt with verifier-value key

  _des_crypt_keysetup (hc_swap32_S (digest1[0]), hc_swap32_S (digest1[1]), Kc, Kd, s_skb);

  // DES-CBC encrypt block 0

  u32 enc[4];

  des_in[0] = hc_swap32_S (ctx.h[0]) ^ iv0;
  des_in[1] = hc_swap32_S (ctx.h[1]) ^ iv1;

  _des_crypt_encrypt (des_out, des_in, Kc, Kd, s_SPtrans);

  enc[0] = des_out[0];
  enc[1] = des_out[1];

  // DES-CBC encrypt block 1

  des_in[0] = hc_swap32_S (ctx.h[2]) ^ enc[0];
  des_in[1] = hc_swap32_S (ctx.h[3]) ^ enc[1];

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

KERNEL_FQ KERNEL_FA void m37011_aux4 (KERN_ATTR_TMPS_ESALT (office_open_tmp_t, office_open_t))
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

  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  w0[0] = l32_from_64_S (tmps[gid].out[0]);
  w0[1] = l32_from_64_S (tmps[gid].out[1]);
  w0[2] = l32_from_64_S (tmps[gid].out[2]);
  w0[3] = l32_from_64_S (tmps[gid].out[3]);
  w1[0] = l32_from_64_S (tmps[gid].out[4]);
  w1[1] = encryptedVerifierHashInputBlockKey[0];
  w1[2] = encryptedVerifierHashInputBlockKey[1];
  w1[3] = 0;
  w2[0] = 0;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;
  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = 0;

  sha1_ctx_t ctx;

  sha1_init (&ctx);

  sha1_update_64 (&ctx, w0, w1, w2, w3, 20 + 8);

  sha1_final (&ctx);

  // DESX key = 24 bytes: DES key (8) + K_post (8) + K_pre (8)
  // SHA-1 produces 20 bytes; pad to 24 with 0x36

  u32 dkey0[2], kpost0[2], kpre0[2];

  dkey0[0] = ctx.h[0];
  dkey0[1] = ctx.h[1];
  kpost0[0] = ctx.h[2];
  kpost0[1] = ctx.h[3];
  kpre0[0] = ctx.h[4];
  kpre0[1] = 0x36363636;

  w0[0] = l32_from_64_S (tmps[gid].out[0]);
  w0[1] = l32_from_64_S (tmps[gid].out[1]);
  w0[2] = l32_from_64_S (tmps[gid].out[2]);
  w0[3] = l32_from_64_S (tmps[gid].out[3]);
  w1[0] = l32_from_64_S (tmps[gid].out[4]);
  w1[1] = encryptedVerifierHashValueBlockKey[0];
  w1[2] = encryptedVerifierHashValueBlockKey[1];
  w1[3] = 0;
  w2[0] = 0;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;
  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = 0;

  sha1_init (&ctx);

  sha1_update_64 (&ctx, w0, w1, w2, w3, 20 + 8);

  sha1_final (&ctx);

  u32 dkey1[2], kpost1[2], kpre1[2];

  dkey1[0] = ctx.h[0];
  dkey1[1] = ctx.h[1];
  kpost1[0] = ctx.h[2];
  kpost1[1] = ctx.h[3];
  kpre1[0] = ctx.h[4];
  kpre1[1] = 0x36363636;

  // DES key setup for verifier-input key

  u32 Kc[16], Kd[16];

  // Swap keys from SHA-1 BE to DES LE
  // DESX key split (CNG order): K1(0-7)=DES, K2(8-15)=pre-whiten, K3(16-23)=post-whiten
  // Decrypt: pt = DES_D(K1, ct XOR K3) XOR K2 XOR IV
  _des_crypt_keysetup (hc_swap32_S (dkey0[0]), hc_swap32_S (dkey0[1]), Kc, Kd, s_skb);

  // kpost0 = h[2..3] = bytes 8-15 = K2 (pre-whiten: XOR with DES output)
  // kpre0  = h[4]+pad = bytes 16-23 = K3 (post-whiten: XOR with ciphertext)
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

  // DESX-CBC decrypt block 0: DES_D(ct ^ K_post) ^ K_pre, then CBC XOR IV

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

  // SHA-1 of decrypted verifier (pt is BE for SHA-1)

  w0[0] = pt[0];
  w0[1] = pt[1];
  w0[2] = pt[2];
  w0[3] = pt[3];
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

  sha1_init (&ctx);

  sha1_update_64 (&ctx, w0, w1, w2, w3, 16);

  sha1_final (&ctx);

  // re-encrypt with verifier-value key

  _des_crypt_keysetup (hc_swap32_S (dkey1[0]), hc_swap32_S (dkey1[1]), Kc, Kd, s_skb);

  u32 pre_w1[2], post_w1[2];
  pre_w1[0]  = hc_swap32_S (kpost1[0]);
  pre_w1[1]  = hc_swap32_S (kpost1[1]);
  post_w1[0] = hc_swap32_S (kpre1[0]);
  post_w1[1] = hc_swap32_S (kpre1[1]);

  // DESX-CBC encrypt block 0: K_post ^ DES_E((pt ^ IV) ^ K_pre)

  u32 enc[4];

  des_in[0] = hc_swap32_S (ctx.h[0]) ^ iv0 ^ pre_w1[0];
  des_in[1] = hc_swap32_S (ctx.h[1]) ^ iv1 ^ pre_w1[1];

  _des_crypt_encrypt (des_out, des_in, Kc, Kd, s_SPtrans);

  enc[0] = des_out[0] ^ post_w1[0];
  enc[1] = des_out[1] ^ post_w1[1];

  // DESX-CBC encrypt block 1

  des_in[0] = hc_swap32_S (ctx.h[2]) ^ enc[0] ^ pre_w1[0];
  des_in[1] = hc_swap32_S (ctx.h[3]) ^ enc[1] ^ pre_w1[1];

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

KERNEL_FQ KERNEL_FA void m37011_aux5 (KERN_ATTR_TMPS_ESALT (office_open_tmp_t, office_open_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  const u32 encryptedVerifierHashInputBlockKey[2] = { 0xfea7d276, 0x3b4b9e79 };
  const u32 encryptedVerifierHashValueBlockKey[2] = { 0xd7aa0f6d, 0x3061344e };

  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  w0[0] = l32_from_64_S (tmps[gid].out[0]);
  w0[1] = l32_from_64_S (tmps[gid].out[1]);
  w0[2] = l32_from_64_S (tmps[gid].out[2]);
  w0[3] = l32_from_64_S (tmps[gid].out[3]);
  w1[0] = l32_from_64_S (tmps[gid].out[4]);
  w1[1] = encryptedVerifierHashInputBlockKey[0];
  w1[2] = encryptedVerifierHashInputBlockKey[1];
  w1[3] = 0;
  w2[0] = 0;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;
  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = 0;

  sha1_ctx_t ctx;

  sha1_init (&ctx);

  sha1_update_64 (&ctx, w0, w1, w2, w3, 20 + 8);

  sha1_final (&ctx);

  u32 digest0[4];

  digest0[0] = ctx.h[0];
  digest0[1] = ctx.h[1];
  digest0[2] = ctx.h[2];
  digest0[3] = ctx.h[3];

  w0[0] = l32_from_64_S (tmps[gid].out[0]);
  w0[1] = l32_from_64_S (tmps[gid].out[1]);
  w0[2] = l32_from_64_S (tmps[gid].out[2]);
  w0[3] = l32_from_64_S (tmps[gid].out[3]);
  w1[0] = l32_from_64_S (tmps[gid].out[4]);
  w1[1] = encryptedVerifierHashValueBlockKey[0];
  w1[2] = encryptedVerifierHashValueBlockKey[1];
  w1[3] = 0;
  w2[0] = 0;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;
  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = 0;

  sha1_init (&ctx);

  sha1_update_64 (&ctx, w0, w1, w2, w3, 20 + 8);

  sha1_final (&ctx);

  u32 digest1[4];

  digest1[0] = ctx.h[0];
  digest1[1] = ctx.h[1];
  digest1[2] = ctx.h[2];
  digest1[3] = ctx.h[3];

  // RC2-128 key setup from verifier-input key (16 bytes, 128 effective bits)

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

  // RC2-CBC decrypt block 0 (8 bytes)

  rc2_in[0] = ct[0];
  rc2_in[1] = ct[1];

  rc2_decrypt (xk0, rc2_in, rc2_out);

  u32 pt[4];

  pt[0] = rc2_out[0] ^ salt_bufs[SALT_POS_HOST].salt_buf[0];
  pt[1] = rc2_out[1] ^ salt_bufs[SALT_POS_HOST].salt_buf[1];

  // RC2-CBC decrypt block 1

  rc2_in[0] = ct[2];
  rc2_in[1] = ct[3];

  rc2_decrypt (xk0, rc2_in, rc2_out);

  pt[2] = rc2_out[0] ^ ct[0];
  pt[3] = rc2_out[1] ^ ct[1];

  // SHA-1 of decrypted verifier

  w0[0] = pt[0];
  w0[1] = pt[1];
  w0[2] = pt[2];
  w0[3] = pt[3];
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

  sha1_init (&ctx);

  sha1_update_64 (&ctx, w0, w1, w2, w3, 16);

  sha1_final (&ctx);

  // RC2-128 key setup from verifier-value key

  u32 xk1[64];

  rc2_key_setup (xk1, digest1, 16, 128);

  // RC2-CBC encrypt block 0

  u32 enc[4];

  rc2_in[0] = ctx.h[0] ^ salt_bufs[SALT_POS_HOST].salt_buf[0];
  rc2_in[1] = ctx.h[1] ^ salt_bufs[SALT_POS_HOST].salt_buf[1];

  rc2_encrypt (xk1, rc2_in, rc2_out);

  enc[0] = rc2_out[0];
  enc[1] = rc2_out[1];

  // RC2-CBC encrypt block 1

  rc2_in[0] = ctx.h[2] ^ enc[0];
  rc2_in[1] = ctx.h[3] ^ enc[1];

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
