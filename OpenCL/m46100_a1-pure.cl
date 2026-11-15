/*

PKZIP Kernels for Hashcat (c) 2018, European Union

PKZIP Kernels for Hashcat has been developed by the Joint Research Centre of the European Commission.
It is released as open source software under the MIT License.

PKZIP Kernels for Hashcat makes use of two primary external components, which continue to be subject
to the terms and conditions stipulated in the respective licences they have been released under. These
external components include, but are not necessarily limited to, the following:

-----

1. Hashcat: MIT License

Copyright (c) 2015-2018 Jens Steube

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and
associated documentation files (the "Software"), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial
portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT
LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

-----

2. Miniz: MIT License

Copyright 2013-2014 RAD Game Tools and Valve Software
Copyright 2010-2014 Rich Geldreich and Tenacious Software LLC

All Rights Reserved.

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
documentation files (the "Software"), to deal in the Software without restriction, including without
limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
the Software, and to permit persons to whom the Software is furnished to do so, subject to the following
conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial
portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT
LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

-----

The European Union disclaims all liability related to or arising out of the use made by third parties of
any external components and dependencies which may be included with PKZIP Kernels for Hashcat.

-----

The MIT License

Copyright (c) 2018, EUROPEAN UNION

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
documentation files (the "Software"), to deal in the Software without restriction, including without
limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
the Software, and to permit persons to whom the Software is furnished to do so, subject to the following
conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial
portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT
LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

Author:              Sein Coray
Related publication: https://scitepress.org/PublicationsDetail.aspx?ID=KLPzPqStp5g=

*/

#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_simd.cl)
#include M2S(INCLUDE_PATH/inc_checksum_crc.cl)
#include M2S(INCLUDE_PATH/inc_zip_traditional.cl)

KERNEL_FQ KERNEL_FA void m46100_sxx (KERN_ATTR_ESALT (zip1_t))
{
  /**
   * modifier
   */

  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * shared
   */

  ZIP1_SHARED_DECL

  if (gid >= GID_CNT) return;

  /**
   * prefetch from global memory
   */

  const u32 check_cnt = esalt_bufs[DIGESTS_OFFSET_HOST].check_cnt;
  const u32 verify    = esalt_bufs[DIGESTS_OFFSET_HOST].verify;

  u32 key0base = 0x12345678;
  u32 key1base = 0x23456789;
  u32 key2base = 0x34567890;

  // -a 12 puts the base word inside the amplifier instead of beside it, so the base word does not
  // start the candidate and the state in front of it is what the loop below has to begin from.

  const u32 key0empty = key0base;
  const u32 key1empty = key1base;
  const u32 key2empty = key2base;

  update_key012_buf (key0base, key1base, key2base, pws[gid].i, pws[gid].pw_len, l_crc32tab);

  /**
   * loop: the headers of every candidate first, the data of the few that pass afterwards
   */

  u32 q_pos[ZIP1_QUEUE];
  u32 q_keys[ZIP1_QUEUE * 3];

  u32 next_pos = 0;

  while (next_pos < IL_CNT)
  {
    u32 q_cnt = 0;

    for (u32 n = 0; (n < ZIP1_ROUND) && (next_pos < IL_CNT) && (q_cnt < ZIP1_QUEUE); n++, next_pos += 1)
    {
      const u32 pos = next_pos;

      u32 key0init = key0base;
      u32 key1init = key1base;
      u32 key2init = key2base;

      if (COMBS_IS_MIDDLE)
      {
        // five pieces in a fixed order: mask, base word, mask, second word, mask, and the state the
        // base word produced on its own is no longer the state this continues from

        key0init = key0empty;
        key1init = key1empty;
        key2init = key2empty;

        update_key012_buf (key0init, key1init, key2init, COMBS_PRE  (pos).i, COMBS_PRE  (pos).pw_len, l_crc32tab);
        update_key012_buf (key0init, key1init, key2init, pws[gid].i,         pws[gid].pw_len,         l_crc32tab);
        update_key012_buf (key0init, key1init, key2init, COMBS_MID  (pos).i, COMBS_MID  (pos).pw_len, l_crc32tab);
        update_key012_buf (key0init, key1init, key2init, COMBS_WORD (pos).i, COMBS_WORD (pos).pw_len, l_crc32tab);
      }

      update_key012_buf (key0init, key1init, key2init, COMBS_POST (pos).i, COMBS_POST (pos).pw_len, l_crc32tab);

    if (zip1_headers (key0init, key1init, key2init, l_crc32tab, l_hot, check_cnt, &q_keys[q_cnt * 3]) == 1)
    {
      q_pos[q_cnt] = pos;

      q_cnt++;
    }
  }

    for (u32 q = 0; q < q_cnt; q++)
    {
      if (zip1_data (&q_keys[q * 3], &esalt_bufs[DIGESTS_OFFSET_HOST], l_crc32tab, l_hot, verify) == 0) continue;

      const u32 il_pos = q_pos[q];

      const u32 search[4] =
      {
        digests_buf[DIGESTS_OFFSET_HOST].digest_buf[0],
        digests_buf[DIGESTS_OFFSET_HOST].digest_buf[1],
        digests_buf[DIGESTS_OFFSET_HOST].digest_buf[2],
        digests_buf[DIGESTS_OFFSET_HOST].digest_buf[3]
      };

      const u32 r0 = esalt_bufs[DIGESTS_OFFSET_HOST].digest[0];
      const u32 r1 = esalt_bufs[DIGESTS_OFFSET_HOST].digest[1];
      const u32 r2 = esalt_bufs[DIGESTS_OFFSET_HOST].digest[2];
      const u32 r3 = esalt_bufs[DIGESTS_OFFSET_HOST].digest[3];

      COMPARE_S_SIMD (r0, r1, r2, r3);
    }
  }
}

KERNEL_FQ KERNEL_FA void m46100_mxx (KERN_ATTR_ESALT (zip1_t))
{
  /**
   * modifier
   */

  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * shared
   */

  ZIP1_SHARED_DECL

  if (gid >= GID_CNT) return;

  /**
   * prefetch from global memory
   */

  const u32 check_cnt = esalt_bufs[DIGESTS_OFFSET_HOST].check_cnt;
  const u32 verify    = esalt_bufs[DIGESTS_OFFSET_HOST].verify;

  u32 key0base = 0x12345678;
  u32 key1base = 0x23456789;
  u32 key2base = 0x34567890;

  // -a 12 puts the base word inside the amplifier instead of beside it, so the base word does not
  // start the candidate and the state in front of it is what the loop below has to begin from.

  const u32 key0empty = key0base;
  const u32 key1empty = key1base;
  const u32 key2empty = key2base;

  update_key012_buf (key0base, key1base, key2base, pws[gid].i, pws[gid].pw_len, l_crc32tab);

  /**
   * loop: the headers of every candidate first, the data of the few that pass afterwards
   */

  u32 q_pos[ZIP1_QUEUE];
  u32 q_keys[ZIP1_QUEUE * 3];

  u32 next_pos = 0;

  while (next_pos < IL_CNT)
  {
    u32 q_cnt = 0;

    for (u32 n = 0; (n < ZIP1_ROUND) && (next_pos < IL_CNT) && (q_cnt < ZIP1_QUEUE); n++, next_pos += 1)
    {
      const u32 pos = next_pos;

      u32 key0init = key0base;
      u32 key1init = key1base;
      u32 key2init = key2base;

      if (COMBS_IS_MIDDLE)
      {
        // five pieces in a fixed order: mask, base word, mask, second word, mask, and the state the
        // base word produced on its own is no longer the state this continues from

        key0init = key0empty;
        key1init = key1empty;
        key2init = key2empty;

        update_key012_buf (key0init, key1init, key2init, COMBS_PRE  (pos).i, COMBS_PRE  (pos).pw_len, l_crc32tab);
        update_key012_buf (key0init, key1init, key2init, pws[gid].i,         pws[gid].pw_len,         l_crc32tab);
        update_key012_buf (key0init, key1init, key2init, COMBS_MID  (pos).i, COMBS_MID  (pos).pw_len, l_crc32tab);
        update_key012_buf (key0init, key1init, key2init, COMBS_WORD (pos).i, COMBS_WORD (pos).pw_len, l_crc32tab);
      }

      update_key012_buf (key0init, key1init, key2init, COMBS_POST (pos).i, COMBS_POST (pos).pw_len, l_crc32tab);

    if (zip1_headers (key0init, key1init, key2init, l_crc32tab, l_hot, check_cnt, &q_keys[q_cnt * 3]) == 1)
    {
      q_pos[q_cnt] = pos;

      q_cnt++;
    }
  }

    for (u32 q = 0; q < q_cnt; q++)
    {
      if (zip1_data (&q_keys[q * 3], &esalt_bufs[DIGESTS_OFFSET_HOST], l_crc32tab, l_hot, verify) == 0) continue;

      const u32 il_pos = q_pos[q];

      const u32 r0 = esalt_bufs[DIGESTS_OFFSET_HOST].digest[0];
      const u32 r1 = esalt_bufs[DIGESTS_OFFSET_HOST].digest[1];
      const u32 r2 = esalt_bufs[DIGESTS_OFFSET_HOST].digest[2];
      const u32 r3 = esalt_bufs[DIGESTS_OFFSET_HOST].digest[3];

      COMPARE_M_SIMD (r0, r1, r2, r3);
    }
  }
}
