/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_hash_md5.cl)
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

KERNEL_FQ KERNEL_FA void m37251_init (KERN_ATTR_TMPS_ESALT (office_protect_tmp_t, office_protect_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  md5_ctx_t ctx;

  md5_init (&ctx);

  md5_update_global (&ctx, salt_bufs[SALT_POS_HOST].salt_buf, salt_bufs[SALT_POS_HOST].salt_len);

  md5_update_global_utf16le (&ctx, pws[gid].i, pws[gid].pw_len);

  md5_final (&ctx);

  tmps[gid].out[0] = (u64) ctx.h[0];
  tmps[gid].out[1] = (u64) ctx.h[1];
  tmps[gid].out[2] = (u64) ctx.h[2];
  tmps[gid].out[3] = (u64) ctx.h[3];
  tmps[gid].out[4] = 0;
  tmps[gid].out[5] = 0;
  tmps[gid].out[6] = 0;
  tmps[gid].out[7] = 0;
}

KERNEL_FQ KERNEL_FA void m37251_loop (KERN_ATTR_TMPS_ESALT (office_protect_tmp_t, office_protect_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  u32 t0 = (u32) tmps[gid].out[0];
  u32 t1 = (u32) tmps[gid].out[1];
  u32 t2 = (u32) tmps[gid].out[2];
  u32 t3 = (u32) tmps[gid].out[3];

  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  // counter APPENDED: MD5(H || LE32(j))
  // message = 16 + 4 = 20 bytes
  // MD5 is little-endian: counter is j (no swap), padding is 0x80 at byte 20,
  // length goes to w3[2] (word 14)

  w0[0] = 0;
  w0[1] = 0;
  w0[2] = 0;
  w0[3] = 0;
  w1[0] = 0;
  w1[1] = 0x80;
  w1[2] = 0;
  w1[3] = 0;
  w2[0] = 0;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;
  w3[0] = 0;
  w3[1] = 0;
  w3[2] = (16 + 4) * 8;
  w3[3] = 0;

  for (u32 i = 0, j = LOOP_POS; i < LOOP_CNT; i++, j++)
  {
    w0[0] = t0;
    w0[1] = t1;
    w0[2] = t2;
    w0[3] = t3;
    w1[0] = j;

    u32 digest[4];

    digest[0] = MD5M_A;
    digest[1] = MD5M_B;
    digest[2] = MD5M_C;
    digest[3] = MD5M_D;

    md5_transform (w0, w1, w2, w3, digest);

    t0 = digest[0];
    t1 = digest[1];
    t2 = digest[2];
    t3 = digest[3];
  }

  tmps[gid].out[0] = (u64) t0;
  tmps[gid].out[1] = (u64) t1;
  tmps[gid].out[2] = (u64) t2;
  tmps[gid].out[3] = (u64) t3;
}

KERNEL_FQ KERNEL_FA void m37251_comp (KERN_ATTR_TMPS_ESALT (office_protect_tmp_t, office_protect_t))
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
