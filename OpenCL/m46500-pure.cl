/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

// RAR 1.5: a stream cipher keyed from the CRC32 of the password.
//
// The key is set up here. A stored entry small enough to sit in the esalt is decrypted and its
// CRC32 compared here as well. Anything else, a compressed or a larger entry, goes to the host
// hook with the key, where it is decrypted and unpacked.

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_checksum_crc.cl)
#endif

#define RARL_KERNEL_DATA 262144

// The hook record is all that crosses to the host and back for every candidate, so it is two
// words: the four 16 bit key words on the way out, and in word 0 the answer on the way back, 1 for
// a match.

typedef struct rar15_tmp
{
  u32 key[4];

} rar15_tmp_t;

typedef struct rar15_hook
{
  u32 word[2];

} rar15_hook_t;

typedef struct rar_legacy
{
  u32 type;
  u32 method;
  u32 crc32;
  u32 unpack_size;
  u32 data_len;
  u32 in_kernel;

  u32 data[RARL_KERNEL_DATA / 4];

} rar_legacy_t;

KERNEL_FQ KERNEL_FA void m46500_init (KERN_ATTR_TMPS_HOOKS_ESALT (rar15_tmp_t, rar15_hook_t, rar_legacy_t))
{
  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  // The CRC32 table, from the shared memory of the work group.

  #ifdef REAL_SHM

  LOCAL_VK u32 s_crc32tab[256];

  for (u32 i = lid; i < 256; i += lsz) s_crc32tab[i] = crc32tab[i];

  SYNC_THREADS ();

  #else

  CONSTANT_AS u32a *s_crc32tab = crc32tab;

  #endif

  if (gid >= GID_CNT) return;

  const u32 pw_len = pws[gid].pw_len;

  // The CRC32 of the password, without the final inversion, gives the first two key words.

  u32 psw_crc = 0xffffffff;

  u32 k2 = 0;
  u32 k3 = 0;

  for (u32 i = 0; i < pw_len; i++)
  {
    const u32 p = (pws[gid].i[i / 4] >> ((i & 3) * 8)) & 0xff;

    psw_crc = (psw_crc >> 8) ^ s_crc32tab[(psw_crc ^ p) & 0xff];

    k2 = (k2 ^ p ^ s_crc32tab[p]) & 0xffff;
    k3 = (k3 + p + (s_crc32tab[p] >> 16)) & 0xffff;
  }

  tmps[gid].key[0] = (psw_crc >>  0) & 0xffff;
  tmps[gid].key[1] = (psw_crc >> 16) & 0xffff;
  tmps[gid].key[2] = k2;
  tmps[gid].key[3] = k3;
}

KERNEL_FQ KERNEL_FA void m46500_loop (KERN_ATTR_TMPS_HOOKS_ESALT (rar15_tmp_t, rar15_hook_t, rar_legacy_t))
{
  // The cipher has no iterated key derivation.
}

KERNEL_FQ KERNEL_FA void m46500_hook23 (KERN_ATTR_TMPS_HOOKS_ESALT (rar15_tmp_t, rar15_hook_t, rar_legacy_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  // Only an entry the kernel does not verify itself goes to the host.

  if (esalt_bufs[DIGESTS_OFFSET_HOST].in_kernel == 1) return;

  hooks[gid].word[0] = tmps[gid].key[0] | (tmps[gid].key[1] << 16);
  hooks[gid].word[1] = tmps[gid].key[2] | (tmps[gid].key[3] << 16);
}

KERNEL_FQ KERNEL_FA void m46500_comp (KERN_ATTR_TMPS_HOOKS_ESALT (rar15_tmp_t, rar15_hook_t, rar_legacy_t))
{
  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  // The CRC32 table is read for every byte of the entry, so it is copied to where a device reads
  // it fastest, the shared memory of the work group.

  #ifdef REAL_SHM

  LOCAL_VK u32 s_crc32tab[256];

  for (u32 i = lid; i < 256; i += lsz) s_crc32tab[i] = crc32tab[i];

  SYNC_THREADS ();

  #else

  CONSTANT_AS u32a *s_crc32tab = crc32tab;

  #endif

  if (gid >= GID_CNT) return;

  u32 matched = 0;

  if (esalt_bufs[DIGESTS_OFFSET_HOST].in_kernel == 1)
  {
    u32 k0 = tmps[gid].key[0];
    u32 k1 = tmps[gid].key[1];
    u32 k2 = tmps[gid].key[2];
    u32 k3 = tmps[gid].key[3];

    const u32 len = esalt_bufs[DIGESTS_OFFSET_HOST].unpack_size;

    u32 crc = 0xffffffff;

    for (u32 i = 0; i < len; i++)
    {
      k0 = (k0 + 0x1234) & 0xffff;

      const u32 t = s_crc32tab[(k0 & 0x1fe) >> 1];

      k1 = (k1 ^ t) & 0xffff;
      k2 = (k2 - (t >> 16)) & 0xffff;
      k0 = (k0 ^ k2) & 0xffff;
      k3 = (((k3 >> 1) | (k3 << 15)) & 0xffff) ^ k1;
      k3 = ((k3 >> 1) | (k3 << 15)) & 0xffff;
      k0 = (k0 ^ k3) & 0xffff;

      const u32 enc = (esalt_bufs[DIGESTS_OFFSET_HOST].data[i / 4] >> ((i & 3) * 8)) & 0xff;

      const u32 dec = enc ^ (k0 >> 8);

      crc = (crc >> 8) ^ s_crc32tab[(crc ^ dec) & 0xff];
    }

    if ((crc ^ 0xffffffff) == esalt_bufs[DIGESTS_OFFSET_HOST].crc32) matched = 1;
  }
  else
  {
    matched = hooks[gid].word[0];
  }

  if (matched == 1)
  {
    if (hc_atomic_inc (&hashes_shown[DIGESTS_OFFSET_HOST]) == 0)
    {
      mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, 0, DIGESTS_OFFSET_HOST + 0, gid, 0, 0, 0);
    }
  }
}
