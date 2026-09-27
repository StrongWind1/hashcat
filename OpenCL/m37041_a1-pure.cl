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

KERNEL_FQ KERNEL_FA void m37041_mxx (KERN_ATTR_ESALT (office_rc4_t))
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


  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos++)
  {
    const u32 pw_len = pws[gid].pw_len;


    // candidate is a raw 5-byte key, not a password

    u32 key[4];

    key[0] = pws[gid].i[0];
    key[1] = pws[gid].i[1] & 0xff;
    key[2] = 0;
    key[3] = 0;

    rc4_init_128 (S, key, lid);

    u32 out[4];

    u8 j = rc4_next_16 (S, 0, 0, encryptedVerifier, out, lid);

    u32 w0[4];
    u32 w1[4];
    u32 w2[4];
    u32 w3[4];

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

    rc4_next_16 (S, 16, j, digest, out, lid);

    const u32 r0 = out[0];
    const u32 r1 = out[1];
    const u32 r2 = out[2];
    const u32 r3 = out[3];

    COMPARE_M_SCALAR (r0, r1, r2, r3);
  }
}

KERNEL_FQ KERNEL_FA void m37041_sxx (KERN_ATTR_ESALT (office_rc4_t))
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


    u32 key[4];

    key[0] = pws[gid].i[0];
    key[1] = pws[gid].i[1] & 0xff;
    key[2] = 0;
    key[3] = 0;

    rc4_init_128 (S, key, lid);

    u32 out[4];

    u8 j = rc4_next_16 (S, 0, 0, encryptedVerifier, out, lid);

    u32 w0[4];
    u32 w1[4];
    u32 w2[4];
    u32 w3[4];

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

    rc4_next_16 (S, 16, j, digest, out, lid);

    const u32 r0 = out[0];
    const u32 r1 = out[1];
    const u32 r2 = out[2];
    const u32 r3 = out[3];

    COMPARE_S_SCALAR (r0, r1, r2, r3);
  }
}
