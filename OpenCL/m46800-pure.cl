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
#include M2S(INCLUDE_PATH/inc_hash_sha256.cl)
#endif

#define COMPARE_S M2S(INCLUDE_PATH/inc_comp_single.cl)
#define COMPARE_M M2S(INCLUDE_PATH/inc_comp_multi.cl)

typedef struct pbkdf2_sha256_tmp
{
  u32  ipad[8];
  u32  opad[8];

  u32  dgst[32];
  u32  out[32];

} pbkdf2_sha256_tmp_t;

// out[0..7] is the running PBKDF2 output. out[8..15] keeps it as it was after 2^lg2 iterations,
// which is the AES key, and out[16..23] as it was 16 iterations later, which is the hash key. The
// last 16 iterations give the password check value. A type 1 hash has no password check value, so
// the host hook is handed the two keys instead.

// One per hash. The host keeps more behind these words: what a type 1 line is written back from.

typedef struct rar5
{
  u32 iv[4];

  u32 type;
  u32 psw_check[2];

  u32 host_only[19]; // the struct is 104 bytes on the host

} rar5_t;

typedef struct rar5_hook
{
  u32 key[8];
  u32 hash_key[8];

  u32 hook_success;

} rar5_hook_t;

DECLSPEC void hmac_sha256_run_V (PRIVATE_AS u32x *w0, PRIVATE_AS u32x *w1, PRIVATE_AS u32x *w2, PRIVATE_AS u32x *w3, PRIVATE_AS u32x *ipad, PRIVATE_AS u32x *opad, PRIVATE_AS u32x *digest)
{
  digest[0] = ipad[0];
  digest[1] = ipad[1];
  digest[2] = ipad[2];
  digest[3] = ipad[3];
  digest[4] = ipad[4];
  digest[5] = ipad[5];
  digest[6] = ipad[6];
  digest[7] = ipad[7];

  sha256_transform_vector (w0, w1, w2, w3, digest);

  w0[0] = digest[0];
  w0[1] = digest[1];
  w0[2] = digest[2];
  w0[3] = digest[3];
  w1[0] = digest[4];
  w1[1] = digest[5];
  w1[2] = digest[6];
  w1[3] = digest[7];
  w2[0] = 0x80000000;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;
  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = (64 + 32) * 8;

  digest[0] = opad[0];
  digest[1] = opad[1];
  digest[2] = opad[2];
  digest[3] = opad[3];
  digest[4] = opad[4];
  digest[5] = opad[5];
  digest[6] = opad[6];
  digest[7] = opad[7];

  sha256_transform_vector (w0, w1, w2, w3, digest);
}

KERNEL_FQ KERNEL_FA void m46800_init (KERN_ATTR_TMPS_HOOKS_ESALT (pbkdf2_sha256_tmp_t, rar5_hook_t, rar5_t))
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  sha256_hmac_ctx_t sha256_hmac_ctx;

  sha256_hmac_init_global_swap (&sha256_hmac_ctx, pws[gid].i, pws[gid].pw_len);

  tmps[gid].ipad[0] = sha256_hmac_ctx.ipad.h[0];
  tmps[gid].ipad[1] = sha256_hmac_ctx.ipad.h[1];
  tmps[gid].ipad[2] = sha256_hmac_ctx.ipad.h[2];
  tmps[gid].ipad[3] = sha256_hmac_ctx.ipad.h[3];
  tmps[gid].ipad[4] = sha256_hmac_ctx.ipad.h[4];
  tmps[gid].ipad[5] = sha256_hmac_ctx.ipad.h[5];
  tmps[gid].ipad[6] = sha256_hmac_ctx.ipad.h[6];
  tmps[gid].ipad[7] = sha256_hmac_ctx.ipad.h[7];

  tmps[gid].opad[0] = sha256_hmac_ctx.opad.h[0];
  tmps[gid].opad[1] = sha256_hmac_ctx.opad.h[1];
  tmps[gid].opad[2] = sha256_hmac_ctx.opad.h[2];
  tmps[gid].opad[3] = sha256_hmac_ctx.opad.h[3];
  tmps[gid].opad[4] = sha256_hmac_ctx.opad.h[4];
  tmps[gid].opad[5] = sha256_hmac_ctx.opad.h[5];
  tmps[gid].opad[6] = sha256_hmac_ctx.opad.h[6];
  tmps[gid].opad[7] = sha256_hmac_ctx.opad.h[7];

  sha256_hmac_update_global (&sha256_hmac_ctx, salt_bufs[SALT_POS_HOST].salt_buf, salt_bufs[SALT_POS_HOST].salt_len);

  for (u32 i = 0, j = 1; i < 8; i += 8, j += 1)
  {
    sha256_hmac_ctx_t sha256_hmac_ctx2 = sha256_hmac_ctx;

    u32 w0[4];
    u32 w1[4];
    u32 w2[4];
    u32 w3[4];

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

    sha256_hmac_update_64 (&sha256_hmac_ctx2, w0, w1, w2, w3, 4);

    sha256_hmac_final (&sha256_hmac_ctx2);

    tmps[gid].dgst[i + 0] = sha256_hmac_ctx2.opad.h[0];
    tmps[gid].dgst[i + 1] = sha256_hmac_ctx2.opad.h[1];
    tmps[gid].dgst[i + 2] = sha256_hmac_ctx2.opad.h[2];
    tmps[gid].dgst[i + 3] = sha256_hmac_ctx2.opad.h[3];
    tmps[gid].dgst[i + 4] = sha256_hmac_ctx2.opad.h[4];
    tmps[gid].dgst[i + 5] = sha256_hmac_ctx2.opad.h[5];
    tmps[gid].dgst[i + 6] = sha256_hmac_ctx2.opad.h[6];
    tmps[gid].dgst[i + 7] = sha256_hmac_ctx2.opad.h[7];

    tmps[gid].out[i + 0] = tmps[gid].dgst[i + 0];
    tmps[gid].out[i + 1] = tmps[gid].dgst[i + 1];
    tmps[gid].out[i + 2] = tmps[gid].dgst[i + 2];
    tmps[gid].out[i + 3] = tmps[gid].dgst[i + 3];
    tmps[gid].out[i + 4] = tmps[gid].dgst[i + 4];
    tmps[gid].out[i + 5] = tmps[gid].dgst[i + 5];
    tmps[gid].out[i + 6] = tmps[gid].dgst[i + 6];
    tmps[gid].out[i + 7] = tmps[gid].dgst[i + 7];
  }

  // With a single iteration the AES key is the first block as it stands. The loop overwrites it
  // for every larger count.

  for (u32 i = 0; i < 8; i++)
  {
    tmps[gid].out[ 8 + i] = tmps[gid].out[i];
    tmps[gid].out[16 + i] = 0;
  }
}

KERNEL_FQ KERNEL_FA void m46800_loop (KERN_ATTR_TMPS_HOOKS_ESALT (pbkdf2_sha256_tmp_t, rar5_hook_t, rar5_t))
{
  const u64 gid = get_global_id (0);

  if ((gid * VECT_SIZE) >= GID_CNT) return;

  u32x ipad[8];
  u32x opad[8];

  ipad[0] = packv (tmps, ipad, gid, 0);
  ipad[1] = packv (tmps, ipad, gid, 1);
  ipad[2] = packv (tmps, ipad, gid, 2);
  ipad[3] = packv (tmps, ipad, gid, 3);
  ipad[4] = packv (tmps, ipad, gid, 4);
  ipad[5] = packv (tmps, ipad, gid, 5);
  ipad[6] = packv (tmps, ipad, gid, 6);
  ipad[7] = packv (tmps, ipad, gid, 7);

  opad[0] = packv (tmps, opad, gid, 0);
  opad[1] = packv (tmps, opad, gid, 1);
  opad[2] = packv (tmps, opad, gid, 2);
  opad[3] = packv (tmps, opad, gid, 3);
  opad[4] = packv (tmps, opad, gid, 4);
  opad[5] = packv (tmps, opad, gid, 5);
  opad[6] = packv (tmps, opad, gid, 6);
  opad[7] = packv (tmps, opad, gid, 7);

  // salt_iter is 2^lg2 + 31, the iterations left after the one init did. The output after the
  // iteration at these two positions is the AES key and the hash key.

  const u32 salt_iter = salt_bufs[SALT_POS_HOST].salt_iter;

  const u32 key_pos      = salt_iter - 33;
  const u32 hash_key_pos = salt_iter - 17;

  for (u32 i = 0; i < 8; i += 8)
  {
    u32x dgst[8];
    u32x out[8];

    dgst[0] = packv (tmps, dgst, gid, i + 0);
    dgst[1] = packv (tmps, dgst, gid, i + 1);
    dgst[2] = packv (tmps, dgst, gid, i + 2);
    dgst[3] = packv (tmps, dgst, gid, i + 3);
    dgst[4] = packv (tmps, dgst, gid, i + 4);
    dgst[5] = packv (tmps, dgst, gid, i + 5);
    dgst[6] = packv (tmps, dgst, gid, i + 6);
    dgst[7] = packv (tmps, dgst, gid, i + 7);

    out[0] = packv (tmps, out, gid, i + 0);
    out[1] = packv (tmps, out, gid, i + 1);
    out[2] = packv (tmps, out, gid, i + 2);
    out[3] = packv (tmps, out, gid, i + 3);
    out[4] = packv (tmps, out, gid, i + 4);
    out[5] = packv (tmps, out, gid, i + 5);
    out[6] = packv (tmps, out, gid, i + 6);
    out[7] = packv (tmps, out, gid, i + 7);

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
      w1[1] = dgst[5];
      w1[2] = dgst[6];
      w1[3] = dgst[7];
      w2[0] = 0x80000000;
      w2[1] = 0;
      w2[2] = 0;
      w2[3] = 0;
      w3[0] = 0;
      w3[1] = 0;
      w3[2] = 0;
      w3[3] = (64 + 32) * 8;

      hmac_sha256_run_V (w0, w1, w2, w3, ipad, opad, dgst);

      out[0] ^= dgst[0];
      out[1] ^= dgst[1];
      out[2] ^= dgst[2];
      out[3] ^= dgst[3];
      out[4] ^= dgst[4];
      out[5] ^= dgst[5];
      out[6] ^= dgst[6];
      out[7] ^= dgst[7];

      const u32 iter_pos = LOOP_POS + j;

      if (iter_pos == key_pos)
      {
        for (u32 k = 0; k < 8; k++)
        {
          unpackv (tmps, out, gid, 8 + k, out[k]);
        }
      }

      if (iter_pos == hash_key_pos)
      {
        for (u32 k = 0; k < 8; k++)
        {
          unpackv (tmps, out, gid, 16 + k, out[k]);
        }
      }
    }

    unpackv (tmps, dgst, gid, i + 0, dgst[0]);
    unpackv (tmps, dgst, gid, i + 1, dgst[1]);
    unpackv (tmps, dgst, gid, i + 2, dgst[2]);
    unpackv (tmps, dgst, gid, i + 3, dgst[3]);
    unpackv (tmps, dgst, gid, i + 4, dgst[4]);
    unpackv (tmps, dgst, gid, i + 5, dgst[5]);
    unpackv (tmps, dgst, gid, i + 6, dgst[6]);
    unpackv (tmps, dgst, gid, i + 7, dgst[7]);

    unpackv (tmps, out, gid, i + 0, out[0]);
    unpackv (tmps, out, gid, i + 1, out[1]);
    unpackv (tmps, out, gid, i + 2, out[2]);
    unpackv (tmps, out, gid, i + 3, out[3]);
    unpackv (tmps, out, gid, i + 4, out[4]);
    unpackv (tmps, out, gid, i + 5, out[5]);
    unpackv (tmps, out, gid, i + 6, out[6]);
    unpackv (tmps, out, gid, i + 7, out[7]);
  }
}

KERNEL_FQ KERNEL_FA void m46800_hook23 (KERN_ATTR_TMPS_HOOKS_ESALT (pbkdf2_sha256_tmp_t, rar5_hook_t, rar5_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  // Only a type 1 hash is verified on the host.

  if (salt_bufs[SALT_POS_HOST].salt_buf[4] != 1) return;

  for (u32 i = 0; i < 8; i++)
  {
    hooks[gid].key[i]      = tmps[gid].out[ 8 + i];
    hooks[gid].hash_key[i] = tmps[gid].out[16 + i];
  }

  hooks[gid].hook_success = 0;
}

KERNEL_FQ KERNEL_FA void m46800_comp (KERN_ATTR_TMPS_HOOKS_ESALT (pbkdf2_sha256_tmp_t, rar5_hook_t, rar5_t))
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  // Called once per hash of the salt group, with the hash's position in LOOP_POS.

  const u32 digest_pos = LOOP_POS;
  const u32 digest_cur = DIGESTS_OFFSET_HOST + digest_pos;

  // Type 1: the host hook decrypted the entry and compared its checksum.

  if (esalt_bufs[digest_cur].type == 1)
  {
    if (hooks[gid].hook_success == 1)
    {
      if (hc_atomic_inc (&hashes_shown[digest_cur]) == 0)
      {
        mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, digest_pos, digest_cur, gid, 0, 0, 0);
      }
    }

    return;
  }

  // Type 0: the 32 byte output folds down to the 8 byte password check value.

  const u32 outl = tmps[gid].out[0] ^ tmps[gid].out[2] ^ tmps[gid].out[4] ^ tmps[gid].out[6];
  const u32 outr = tmps[gid].out[1] ^ tmps[gid].out[3] ^ tmps[gid].out[5] ^ tmps[gid].out[7];

  if (outl == esalt_bufs[digest_cur].psw_check[0] && outr == esalt_bufs[digest_cur].psw_check[1])
  {
    if (hc_atomic_inc (&hashes_shown[digest_cur]) == 0)
    {
      mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, digest_pos, digest_cur, gid, 0, 0, 0);
    }
  }
}
