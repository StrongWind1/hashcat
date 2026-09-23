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
#include M2S(INCLUDE_PATH/inc_rp.h)
#include M2S(INCLUDE_PATH/inc_rp.cl)
#include M2S(INCLUDE_PATH/inc_scalar.cl)
#include M2S(INCLUDE_PATH/inc_hash_sha1.cl)
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

KERNEL_FQ KERNEL_FA void m37112_mxx (KERN_ATTR_RULES_ESALT (office_rc4_t))
{
  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  u32 salt_buf[4];

  salt_buf[0] = salt_bufs[SALT_POS_HOST].salt_buf[0];
  salt_buf[1] = salt_bufs[SALT_POS_HOST].salt_buf[1];
  salt_buf[2] = salt_bufs[SALT_POS_HOST].salt_buf[2];
  salt_buf[3] = salt_bufs[SALT_POS_HOST].salt_buf[3];

  COPY_PW (pws[gid]);

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos++)
  {
    pw_t tmp = PASTE_PW;

    tmp.pw_len = apply_rules (rules_buf[il_pos].cmds, tmp.i, tmp.pw_len);

    // SHA-1(salt || UTF16LE(pw))

    u32 w0[4];
    u32 w1[4];
    u32 w2[4];
    u32 w3[4];

    // the password is already UTF16LE from PT_UTF16LE

    const u32 pw_salt_len = (tmp.pw_len) + 16;

    w3[3] = pw_salt_len * 8;
    w3[2] = 0;

    // build message: salt(16) || UTF16LE(pw)
    // salt is in native byte order, pw needs byte-swap for SHA-1 (BE)

    w0[0] = salt_buf[0];
    w0[1] = salt_buf[1];
    w0[2] = salt_buf[2];
    w0[3] = salt_buf[3];

    // place pw after salt (offset 16 bytes = 4 words)
    // pw words need hc_swap32 for SHA-1

    const u32 pw_words = (tmp.pw_len + 3) / 4;

    w1[0] = (pw_words >= 1) ? hc_swap32_S (tmp.i[0]) : 0;
    w1[1] = (pw_words >= 2) ? hc_swap32_S (tmp.i[1]) : 0;
    w1[2] = (pw_words >= 3) ? hc_swap32_S (tmp.i[2]) : 0;
    w1[3] = (pw_words >= 4) ? hc_swap32_S (tmp.i[3]) : 0;
    w2[0] = (pw_words >= 5) ? hc_swap32_S (tmp.i[4]) : 0;
    w2[1] = (pw_words >= 6) ? hc_swap32_S (tmp.i[5]) : 0;
    w2[2] = (pw_words >= 7) ? hc_swap32_S (tmp.i[6]) : 0;
    w2[3] = (pw_words >= 8) ? hc_swap32_S (tmp.i[7]) : 0;
    w3[0] = 0;
    w3[1] = 0;

    // add padding after message
    // pw_salt_len is 16 + pw_len, max pw_len is 30 (15 chars * 2), so max is 46 < 55, fits in one block

    switch (pw_salt_len)
    {
      // padding positions for lengths 16..46
      // byte pw_salt_len gets 0x80 in BE format
      default:
      {
        // generic: use SHA-1 context API instead

        u32 pass_hash[5];

        pass_hash[0] = SHA1M_A;
        pass_hash[1] = SHA1M_B;
        pass_hash[2] = SHA1M_C;
        pass_hash[3] = SHA1M_D;
        pass_hash[4] = SHA1M_E;

        sha1_ctx_t ctx;

        sha1_init (&ctx);

        sha1_update_global_swap (&ctx, salt_bufs[SALT_POS_HOST].salt_buf, 16);

        // password is in LE from PT_UTF16LE, swap for SHA-1
        u32 pw_be[16] = { 0 };
        for (u32 i = 0; (i < pw_words) && (i < 16); i++)
        {
          pw_be[i] = hc_swap32_S (tmp.i[i]);
        }

        sha1_update (&ctx, pw_be, tmp.pw_len);

        sha1_final (&ctx);

        pass_hash[0] = ctx.h[0];
        pass_hash[1] = ctx.h[1];
        pass_hash[2] = ctx.h[2];
        pass_hash[3] = ctx.h[3];
        pass_hash[4] = ctx.h[4];

        // SHA-1(H0 || LE32(0))

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

        // truncate to 5 bytes (40-bit key) and compare against rc4key

        const u32 r0 = hc_swap32_S (digest[0]);
        const u32 r1 = hc_swap32_S (digest[1]) & 0xff;
        const u32 r2 = 0;
        const u32 r3 = 0;

        COMPARE_M_SCALAR (r0, r1, r2, r3);

        break;
      }
    }
  }
}

KERNEL_FQ KERNEL_FA void m37112_sxx (KERN_ATTR_RULES_ESALT (office_rc4_t))
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

  COPY_PW (pws[gid]);

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos++)
  {
    pw_t tmp = PASTE_PW;

    tmp.pw_len = apply_rules (rules_buf[il_pos].cmds, tmp.i, tmp.pw_len);

    // SHA-1(salt || UTF16LE(pw)) -> SHA-1(H0 || LE32(0)) -> truncate -> compare rc4key

    const u32 pw_words = (tmp.pw_len + 3) / 4;

    sha1_ctx_t ctx;

    sha1_init (&ctx);

    sha1_update_global_swap (&ctx, salt_bufs[SALT_POS_HOST].salt_buf, 16);

    u32 pw_be[16] = { 0 };
    for (u32 i = 0; (i < pw_words) && (i < 16); i++)
    {
      pw_be[i] = hc_swap32_S (tmp.i[i]);
    }

    sha1_update (&ctx, pw_be, tmp.pw_len);

    sha1_final (&ctx);

    u32 w0[4];
    u32 w1[4];
    u32 w2[4];
    u32 w3[4];

    w0[0] = ctx.h[0];
    w0[1] = ctx.h[1];
    w0[2] = ctx.h[2];
    w0[3] = ctx.h[3];
    w1[0] = ctx.h[4];
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

    const u32 r0 = hc_swap32_S (digest[0]);
    const u32 r1 = hc_swap32_S (digest[1]) & 0xff;
    const u32 r2 = 0;
    const u32 r3 = 0;

    COMPARE_S_SCALAR (r0, r1, r2, r3);
  }
}
