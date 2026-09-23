/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_hash_sha384.cl)
#endif

#define COMPARE_S M2S(INCLUDE_PATH/inc_comp_single.cl)
#define COMPARE_M M2S(INCLUDE_PATH/inc_comp_multi.cl)

typedef struct office_protect
{
  u32 hash_type;
  u32 kdf_type;

} office_protect_t;

typedef struct office_protect_tmp
{
  u64 out[8];

} office_protect_tmp_t;

KERNEL_FQ KERNEL_FA void m37231_init (KERN_ATTR_TMPS_ESALT (office_protect_tmp_t, office_protect_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  sha384_ctx_t ctx;

  sha384_init (&ctx);

  sha384_update_global_swap (&ctx, salt_bufs[SALT_POS_HOST].salt_buf, salt_bufs[SALT_POS_HOST].salt_len);

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

KERNEL_FQ KERNEL_FA void m37231_loop (KERN_ATTR_TMPS_ESALT (office_protect_tmp_t, office_protect_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  u64 t0 = tmps[gid].out[0];
  u64 t1 = tmps[gid].out[1];
  u64 t2 = tmps[gid].out[2];
  u64 t3 = tmps[gid].out[3];
  u64 t4 = tmps[gid].out[4];
  u64 t5 = tmps[gid].out[5];

  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];
  u32 w4[4];
  u32 w5[4];
  u32 w6[4];
  u32 w7[4];

  // counter APPENDED: SHA-384(H || BE32(j))
  // message = 48 + 4 = 52 bytes

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
  w7[3] = (48 + 4) * 8;

  for (u32 i = 0, j = LOOP_POS; i < LOOP_CNT; i++, j++)
  {
    w0[0] = h32_from_64_S (t0);
    w0[1] = l32_from_64_S (t0);
    w0[2] = h32_from_64_S (t1);
    w0[3] = l32_from_64_S (t1);
    w1[0] = h32_from_64_S (t2);
    w1[1] = l32_from_64_S (t2);
    w1[2] = h32_from_64_S (t3);
    w1[3] = l32_from_64_S (t3);
    w2[0] = h32_from_64_S (t4);
    w2[1] = l32_from_64_S (t4);
    w2[2] = h32_from_64_S (t5);
    w2[3] = l32_from_64_S (t5);
    w3[0] = hc_swap32_S (j);

    u64 digest[8];

    digest[0] = SHA384M_A;
    digest[1] = SHA384M_B;
    digest[2] = SHA384M_C;
    digest[3] = SHA384M_D;
    digest[4] = SHA384M_E;
    digest[5] = SHA384M_F;
    digest[6] = SHA384M_G;
    digest[7] = SHA384M_H;

    sha384_transform (w0, w1, w2, w3, w4, w5, w6, w7, digest);

    t0 = digest[0];
    t1 = digest[1];
    t2 = digest[2];
    t3 = digest[3];
    t4 = digest[4];
    t5 = digest[5];
  }

  tmps[gid].out[0] = t0;
  tmps[gid].out[1] = t1;
  tmps[gid].out[2] = t2;
  tmps[gid].out[3] = t3;
  tmps[gid].out[4] = t4;
  tmps[gid].out[5] = t5;
}

KERNEL_FQ KERNEL_FA void m37231_comp (KERN_ATTR_TMPS_ESALT (office_protect_tmp_t, office_protect_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  const u32 r0 = (u32) tmps[gid].out[0];
  const u32 r1 = (u32) tmps[gid].out[1];
  const u32 r2 = (u32) tmps[gid].out[2];
  const u32 r3 = (u32) tmps[gid].out[3];

  #define il_pos 0

  #ifdef KERNEL_STATIC
  #include COMPARE_M
  #endif
}
