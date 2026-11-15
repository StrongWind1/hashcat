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
#endif

#define COMPARE_S M2S(INCLUDE_PATH/inc_comp_single.cl)
#define COMPARE_M M2S(INCLUDE_PATH/inc_comp_multi.cl)

typedef struct pbkdf2_sha1_tmp
{
  u32  ipad[5];
  u32  opad[5];

  u32  dgst[32];
  u32  out[32];

} pbkdf2_sha1_tmp_t;

#define ZIP2_DATA_MAX (8 * 1024 * 1024)

#define ZIP2_VERIFY_NONE   0
#define ZIP2_VERIFY_HMAC   1
#define ZIP2_VERIFY_PREFIX 2
#define ZIP2_VERIFY_MAGIC  3

typedef struct zip2
{
  u32 mode;
  u32 salt_len;
  u32 salt_buf[4];
  u32 verify_bytes;
  u32 auth_buf[4];
  u32 method;
  u32 packed;
  u32 packed_hi;
  u32 verify;
  u32 magic_len;
  u32 magic[4];
  u32 magic_mask[4];
  u32 digest[4];
  u32 data_len;
  u32 data_buf[ZIP2_DATA_MAX / 4];

} zip2_t;

// A line that carries only the start of a long entry is tested by decrypting that start and
// inflating it. The decoder reads its input a byte at a time through this, so nothing larger than
// one cipher block is ever held in private memory.

typedef struct zip2_ctr
{
  u32 ks[60];
  u32 mode;
  u32 counter;
  u32 used;
  u32 block[4];

  SHM_TYPE u32 *s_te0;
  SHM_TYPE u32 *s_te1;
  SHM_TYPE u32 *s_te2;
  SHM_TYPE u32 *s_te3;
  SHM_TYPE u32 *s_te4;

} zip2_ctr_t;

#define INFLATE_INPUT_FILTER zip2_ctr_byte

#include M2S(INCLUDE_PATH/inc_zip_inflate.cl)

// WinZip counts blocks from 1 and stores the counter little endian in the first bytes of the block

DECLSPEC void zip2_ctr_next (PRIVATE_AS zip2_ctr_t *ctr)
{
  ctr->counter++;

  u32 in[4];

  in[0] = hc_swap32_S (ctr->counter);
  in[1] = 0;
  in[2] = 0;
  in[3] = 0;

  if (ctr->mode == 1)
  {
    AES128_encrypt (ctr->ks, in, ctr->block, ctr->s_te0, ctr->s_te1, ctr->s_te2, ctr->s_te3, ctr->s_te4);
  }
  else if (ctr->mode == 2)
  {
    AES192_encrypt (ctr->ks, in, ctr->block, ctr->s_te0, ctr->s_te1, ctr->s_te2, ctr->s_te3, ctr->s_te4);
  }
  else
  {
    AES256_encrypt (ctr->ks, in, ctr->block, ctr->s_te0, ctr->s_te1, ctr->s_te2, ctr->s_te3, ctr->s_te4);
  }

  ctr->used = 0;
}

DECLSPEC mz_uint8 zip2_ctr_byte (const mz_uint8 c, mz_streamp pStream)
{
  PRIVATE_AS zip2_ctr_t *ctr = (PRIVATE_AS zip2_ctr_t *) pStream->opaque;

  if (ctr->used == 16) zip2_ctr_next (ctr);

  const u32 pos = ctr->used;

  ctr->used = pos + 1;

  const u32 k = (ctr->block[pos / 4] >> (24 - ((pos & 3) * 8))) & 0xff;

  return (mz_uint8) (c ^ k);
}

DECLSPEC void hmac_sha1_run_V (PRIVATE_AS u32x *w0, PRIVATE_AS u32x *w1, PRIVATE_AS u32x *w2, PRIVATE_AS u32x *w3, PRIVATE_AS u32x *ipad, PRIVATE_AS u32x *opad, PRIVATE_AS u32x *digest)
{
  digest[0] = ipad[0];
  digest[1] = ipad[1];
  digest[2] = ipad[2];
  digest[3] = ipad[3];
  digest[4] = ipad[4];

  sha1_transform_vector (w0, w1, w2, w3, digest);

  w0[0] = digest[0];
  w0[1] = digest[1];
  w0[2] = digest[2];
  w0[3] = digest[3];
  w1[0] = digest[4];
  w1[1] = 0x80000000;
  w1[2] = 0;
  w1[3] = 0;
  w2[0] = 0;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;
  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = (64 + 20) * 8;

  digest[0] = opad[0];
  digest[1] = opad[1];
  digest[2] = opad[2];
  digest[3] = opad[3];
  digest[4] = opad[4];

  sha1_transform_vector (w0, w1, w2, w3, digest);
}

KERNEL_FQ KERNEL_FA void m46200_init (KERN_ATTR_TMPS_ESALT (pbkdf2_sha1_tmp_t, zip2_t))
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  sha1_hmac_ctx_t sha1_hmac_ctx;

  sha1_hmac_init_global_swap (&sha1_hmac_ctx, pws[gid].i, pws[gid].pw_len);

  tmps[gid].ipad[0] = sha1_hmac_ctx.ipad.h[0];
  tmps[gid].ipad[1] = sha1_hmac_ctx.ipad.h[1];
  tmps[gid].ipad[2] = sha1_hmac_ctx.ipad.h[2];
  tmps[gid].ipad[3] = sha1_hmac_ctx.ipad.h[3];
  tmps[gid].ipad[4] = sha1_hmac_ctx.ipad.h[4];

  tmps[gid].opad[0] = sha1_hmac_ctx.opad.h[0];
  tmps[gid].opad[1] = sha1_hmac_ctx.opad.h[1];
  tmps[gid].opad[2] = sha1_hmac_ctx.opad.h[2];
  tmps[gid].opad[3] = sha1_hmac_ctx.opad.h[3];
  tmps[gid].opad[4] = sha1_hmac_ctx.opad.h[4];

  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  w0[0] = hc_swap32_S (esalt_bufs[DIGESTS_OFFSET_HOST].salt_buf[0]);
  w0[1] = hc_swap32_S (esalt_bufs[DIGESTS_OFFSET_HOST].salt_buf[1]);
  w0[2] = hc_swap32_S (esalt_bufs[DIGESTS_OFFSET_HOST].salt_buf[2]);
  w0[3] = hc_swap32_S (esalt_bufs[DIGESTS_OFFSET_HOST].salt_buf[3]);
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

  sha1_hmac_update_64 (&sha1_hmac_ctx, w0, w1, w2, w3, esalt_bufs[DIGESTS_OFFSET_HOST].salt_len);

  const u32 mode = esalt_bufs[DIGESTS_OFFSET_HOST].mode;

  int iter_start;
  int iter_stop;

  switch (mode)
  {
    case 1: iter_start  = 0;
            iter_stop   = 2;
            break;
    case 2: iter_start  = 1;
            iter_stop   = 3;
            break;
    case 3: iter_start  = 1;
            iter_stop   = 4;
            break;
  }

  // the cipher key is the first part of the derived key, and only a line that decrypts needs it

  if (esalt_bufs[DIGESTS_OFFSET_HOST].verify >= ZIP2_VERIFY_PREFIX) iter_start = 0;

  for (int i = iter_stop - 1, j = iter_stop; i >= iter_start; i--, j--)
  {
    sha1_hmac_ctx_t sha1_hmac_ctx2 = sha1_hmac_ctx;

    w0[0] = j;
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

    sha1_hmac_update_64 (&sha1_hmac_ctx2, w0, w1, w2, w3, 4);

    sha1_hmac_final (&sha1_hmac_ctx2);

    const u32 i5 = i * 5;

    tmps[gid].dgst[i5 + 0] = sha1_hmac_ctx2.opad.h[0];
    tmps[gid].dgst[i5 + 1] = sha1_hmac_ctx2.opad.h[1];
    tmps[gid].dgst[i5 + 2] = sha1_hmac_ctx2.opad.h[2];
    tmps[gid].dgst[i5 + 3] = sha1_hmac_ctx2.opad.h[3];
    tmps[gid].dgst[i5 + 4] = sha1_hmac_ctx2.opad.h[4];

    tmps[gid].out[i5 + 0] = tmps[gid].dgst[i5 + 0];
    tmps[gid].out[i5 + 1] = tmps[gid].dgst[i5 + 1];
    tmps[gid].out[i5 + 2] = tmps[gid].dgst[i5 + 2];
    tmps[gid].out[i5 + 3] = tmps[gid].dgst[i5 + 3];
    tmps[gid].out[i5 + 4] = tmps[gid].dgst[i5 + 4];
  }
}

KERNEL_FQ KERNEL_FA void m46200_loop (KERN_ATTR_TMPS_ESALT (pbkdf2_sha1_tmp_t, zip2_t))
{
  const u64 gid = get_global_id (0);

  if ((gid * VECT_SIZE) >= GID_CNT) return;

  u32x ipad[5];
  u32x opad[5];

  ipad[0] = packv (tmps, ipad, gid, 0);
  ipad[1] = packv (tmps, ipad, gid, 1);
  ipad[2] = packv (tmps, ipad, gid, 2);
  ipad[3] = packv (tmps, ipad, gid, 3);
  ipad[4] = packv (tmps, ipad, gid, 4);

  opad[0] = packv (tmps, opad, gid, 0);
  opad[1] = packv (tmps, opad, gid, 1);
  opad[2] = packv (tmps, opad, gid, 2);
  opad[3] = packv (tmps, opad, gid, 3);
  opad[4] = packv (tmps, opad, gid, 4);

  const u32 verify_bytes = esalt_bufs[DIGESTS_OFFSET_HOST].verify_bytes;

  const u32 mode = esalt_bufs[DIGESTS_OFFSET_HOST].mode;

  int iter_start;
  int iter_stop;

  switch (mode)
  {
    case 1: iter_start  = 0;
            iter_stop   = 2;
            break;
    case 2: iter_start  = 1;
            iter_stop   = 3;
            break;
    case 3: iter_start  = 1;
            iter_stop   = 4;
            break;
  }

  // the cipher key is the first part of the derived key, and only a line that decrypts needs it

  if (esalt_bufs[DIGESTS_OFFSET_HOST].verify >= ZIP2_VERIFY_PREFIX) iter_start = 0;

  for (int i = iter_stop - 1; i >= iter_start; i--)
  {
    const u32 i5 = i * 5;

    u32x dgst[5];
    u32x out[5];

    dgst[0] = packv (tmps, dgst, gid, i5 + 0);
    dgst[1] = packv (tmps, dgst, gid, i5 + 1);
    dgst[2] = packv (tmps, dgst, gid, i5 + 2);
    dgst[3] = packv (tmps, dgst, gid, i5 + 3);
    dgst[4] = packv (tmps, dgst, gid, i5 + 4);

    out[0] = packv (tmps, out, gid, i5 + 0);
    out[1] = packv (tmps, out, gid, i5 + 1);
    out[2] = packv (tmps, out, gid, i5 + 2);
    out[3] = packv (tmps, out, gid, i5 + 3);
    out[4] = packv (tmps, out, gid, i5 + 4);

    for (u32 j = 0; j < LOOP_CNT; j++)
    {
      u32x w0[4];
      u32x w1[4];
      u32x w2[4];
      u32x w3[4];

      w0[0] = dgst[0];
      w0[1] = dgst[1];
      w0[2] = dgst[2];
      w0[3] = dgst[3];
      w1[0] = dgst[4];
      w1[1] = 0x80000000;
      w1[2] = 0;
      w1[3] = 0;
      w2[0] = 0;
      w2[1] = 0;
      w2[2] = 0;
      w2[3] = 0;
      w3[0] = 0;
      w3[1] = 0;
      w3[2] = 0;
      w3[3] = (64 + 20) * 8;

      hmac_sha1_run_V (w0, w1, w2, w3, ipad, opad, dgst);

      out[0] ^= dgst[0];
      out[1] ^= dgst[1];
      out[2] ^= dgst[2];
      out[3] ^= dgst[3];
      out[4] ^= dgst[4];
    }

    // the block with the verifier is kept whether it matches or not, so the compare kernel reads
    // the verifier this candidate really produced

    unpackv (tmps, dgst, gid, i5 + 0, dgst[0]);
    unpackv (tmps, dgst, gid, i5 + 1, dgst[1]);
    unpackv (tmps, dgst, gid, i5 + 2, dgst[2]);
    unpackv (tmps, dgst, gid, i5 + 3, dgst[3]);
    unpackv (tmps, dgst, gid, i5 + 4, dgst[4]);

    unpackv (tmps, out, gid, i5 + 0, out[0]);
    unpackv (tmps, out, gid, i5 + 1, out[1]);
    unpackv (tmps, out, gid, i5 + 2, out[2]);
    unpackv (tmps, out, gid, i5 + 3, out[3]);
    unpackv (tmps, out, gid, i5 + 4, out[4]);

    if (i == iter_stop - 1) // 2 byte optimization check
    {
      if (mode == 1) if (MATCHES_NONE_VS ((out[3] >> 16), verify_bytes)) break;
      if (mode == 2) if (MATCHES_NONE_VS ((out[2] >> 16), verify_bytes)) break;
      if (mode == 3) if (MATCHES_NONE_VS ((out[1] >> 16), verify_bytes)) break;
    }
  }
}

KERNEL_FQ KERNEL_FA void m46200_comp (KERN_ATTR_TMPS_ESALT (pbkdf2_sha1_tmp_t, zip2_t))
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * aes shared
   */

  #ifdef REAL_SHM

  LOCAL_VK u32 s_te0[256];
  LOCAL_VK u32 s_te1[256];
  LOCAL_VK u32 s_te2[256];
  LOCAL_VK u32 s_te3[256];
  LOCAL_VK u32 s_te4[256];

  for (u32 i = lid; i < 256; i += lsz)
  {
    s_te0[i] = te0[i];
    s_te1[i] = te1[i];
    s_te2[i] = te2[i];
    s_te3[i] = te3[i];
    s_te4[i] = te4[i];
  }

  SYNC_THREADS ();

  #else

  CONSTANT_AS u32a *s_te0 = te0;
  CONSTANT_AS u32a *s_te1 = te1;
  CONSTANT_AS u32a *s_te2 = te2;
  CONSTANT_AS u32a *s_te3 = te3;
  CONSTANT_AS u32a *s_te4 = te4;

  #endif

  if (gid >= GID_CNT) return;

  const u32 mode   = esalt_bufs[DIGESTS_OFFSET_HOST].mode;
  const u32 verify = esalt_bufs[DIGESTS_OFFSET_HOST].verify;

  // The derived key is the cipher key, the authentication key and two bytes of verifier, in that
  // order, and each of the first two is as long as the cipher key.

  const u32 key_words = 2 + (mode * 2);

  const u32 got = tmps[gid].out[key_words * 2] >> 16;

  if (got != esalt_bufs[DIGESTS_OFFSET_HOST].verify_bytes) return;

  if (verify == ZIP2_VERIFY_HMAC)
  {
    u32 w0[4] = { 0 };
    u32 w1[4] = { 0 };
    u32 w2[4] = { 0 };
    u32 w3[4] = { 0 };

    for (u32 i = 0; i < key_words; i++)
    {
      const u32 word = tmps[gid].out[key_words + i];

      if (i < 4)
      {
        w0[i] = word;
      }
      else
      {
        w1[i - 4] = word;
      }
    }

    sha1_hmac_ctx_t ctx;

    sha1_hmac_init_64 (&ctx, w0, w1, w2, w3);

    sha1_hmac_update_global_swap (&ctx, esalt_bufs[DIGESTS_OFFSET_HOST].data_buf, esalt_bufs[DIGESTS_OFFSET_HOST].data_len);

    sha1_hmac_final (&ctx);

    // the authentication code is the first 10 bytes of the MAC

    if (hc_swap32_S (ctx.opad.h[0]) != esalt_bufs[DIGESTS_OFFSET_HOST].auth_buf[0]) return;
    if (hc_swap32_S (ctx.opad.h[1]) != esalt_bufs[DIGESTS_OFFSET_HOST].auth_buf[1]) return;

    if (hc_swap32_S (ctx.opad.h[2] & 0xffff0000) != esalt_bufs[DIGESTS_OFFSET_HOST].auth_buf[2]) return;
  }
  else if (verify >= ZIP2_VERIFY_PREFIX)
  {
    u32 ukey[8] = { 0 };

    for (u32 i = 0; i < key_words; i++) ukey[i] = tmps[gid].out[i];

    zip2_ctr_t ctr;

    ctr.mode    = mode;
    ctr.counter = 0;
    ctr.used    = 16;
    ctr.s_te0   = s_te0;
    ctr.s_te1   = s_te1;
    ctr.s_te2   = s_te2;
    ctr.s_te3   = s_te3;
    ctr.s_te4   = s_te4;

    if (mode == 1)
    {
      AES128_set_encrypt_key (ctr.ks, ukey, s_te0, s_te1, s_te2, s_te3);
    }
    else if (mode == 2)
    {
      AES192_set_encrypt_key (ctr.ks, ukey, s_te0, s_te1, s_te2, s_te3);
    }
    else
    {
      AES256_set_encrypt_key (ctr.ks, ukey, s_te0, s_te1, s_te2, s_te3);
    }

    if (verify == ZIP2_VERIFY_MAGIC)
    {
      // the signature a bzip2 or xz stream starts with fits in the first cipher block

      zip2_ctr_next (&ctr);

      const u32 magic_len = esalt_bufs[DIGESTS_OFFSET_HOST].magic_len;

      for (u32 i = 0; i < magic_len; i++)
      {
        const u32 shift = (i & 3) * 8;

        const u32 c    = (esalt_bufs[DIGESTS_OFFSET_HOST].data_buf[i / 4]   >> shift) & 0xff;
        const u32 want = (esalt_bufs[DIGESTS_OFFSET_HOST].magic[i / 4]      >> shift) & 0xff;
        const u32 mask = (esalt_bufs[DIGESTS_OFFSET_HOST].magic_mask[i / 4] >> shift) & 0xff;

        const u32 k = (ctr.block[i / 4] >> (24 - shift)) & 0xff;

        if ((((c ^ k) ^ want) & mask) != 0) return;
      }
    }
    else
    {
      u8 window[TINFL_LZ_DICT_SIZE];

      mz_stream infstream;

      inflate_state state;

      infstream.opaque    = (PRIVATE_AS void *) &ctr;
      infstream.avail_in  = esalt_bufs[DIGESTS_OFFSET_HOST].data_len;
      infstream.next_in   = (GLOBAL_AS const u8 *) esalt_bufs[DIGESTS_OFFSET_HOST].data_buf;
      infstream.avail_out = TINFL_LZ_DICT_SIZE;
      infstream.next_out  = window;

      mz_inflateInit2 (&infstream, -MAX_WBITS, &state);

      // mz_inflateInit2 () clears the user pointer along with the rest

      infstream.opaque = (PRIVATE_AS void *) &ctr;

      size_t in_bytes  = infstream.avail_in;
      size_t out_bytes = infstream.avail_out;

      const tinfl_status status = tinfl_decompress (&state.m_decomp, infstream.next_in, &in_bytes, infstream.next_out, infstream.next_out + infstream.window_out, &out_bytes, TINFL_FLAG_FLUSH_WINDOW | TINFL_FLAG_HAS_MORE_INPUT, &infstream);

      // the stream is cut short, so it has to be still running when the bytes run out

      if (status != TINFL_STATUS_NEEDS_MORE_INPUT) return;

      if (in_bytes != esalt_bufs[DIGESTS_OFFSET_HOST].data_len) return;
    }
  }

  const u32 r0 = esalt_bufs[DIGESTS_OFFSET_HOST].digest[0];
  const u32 r1 = esalt_bufs[DIGESTS_OFFSET_HOST].digest[1];
  const u32 r2 = esalt_bufs[DIGESTS_OFFSET_HOST].digest[2];
  const u32 r3 = esalt_bufs[DIGESTS_OFFSET_HOST].digest[3];

  #define il_pos 0

  #ifdef KERNEL_STATIC
  #include COMPARE_M
  #endif
}
