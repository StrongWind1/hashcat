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

KERNEL_FQ KERNEL_FA void m46100_sxx (KERN_ATTR_VECTOR_ESALT (zip1_t))
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

  /**
   * base
   */

  const u32 pw_len = pws[gid].pw_len;

  u32 w[64] = { 0 };

  for (u32 i = 0, idx = 0; i < pw_len; i += 4, idx += 1)
  {
    w[idx] = pws[gid].i[idx];
  }

  const u32 w0l = w[0];

  /**
   * loop: the headers of every candidate first, the data of the few that pass afterwards
   */

  u32 q_pos[ZIP1_QUEUE];
  u32 q_keys[ZIP1_QUEUE * 3];

  u32 next_pos = 0;

  while (next_pos < IL_CNT)
  {
    u32 q_cnt = 0;

    for (u32 n = 0; (n < ZIP1_ROUND) && (next_pos < IL_CNT) && (q_cnt < ZIP1_QUEUE); n++, next_pos += VECT_SIZE)
    {
      const u32 pos = next_pos;

      const u32 w0r = words_buf_r[pos / VECT_SIZE];

      w[0] = w0l | w0r;

      u32 key0init = 0x12345678;
      u32 key1init = 0x23456789;
      u32 key2init = 0x34567890;

      update_key012_buf (key0init, key1init, key2init, w, pw_len, l_crc32tab);

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

KERNEL_FQ KERNEL_FA void m46100_mxx (KERN_ATTR_VECTOR_ESALT (zip1_t))
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

  /**
   * base
   */

  const u32 pw_len = pws[gid].pw_len;

  u32 w[64] = { 0 };

  for (u32 i = 0, idx = 0; i < pw_len; i += 4, idx += 1)
  {
    w[idx] = pws[gid].i[idx];
  }

  const u32 w0l = w[0];

  /**
   * loop: the headers of every candidate first, the data of the few that pass afterwards
   */

  u32 q_pos[ZIP1_QUEUE];
  u32 q_keys[ZIP1_QUEUE * 3];

  u32 next_pos = 0;

  while (next_pos < IL_CNT)
  {
    u32 q_cnt = 0;

    for (u32 n = 0; (n < ZIP1_ROUND) && (next_pos < IL_CNT) && (q_cnt < ZIP1_QUEUE); n++, next_pos += VECT_SIZE)
    {
      const u32 pos = next_pos;

      const u32 w0r = words_buf_r[pos / VECT_SIZE];

      w[0] = w0l | w0r;

      u32 key0init = 0x12345678;
      u32 key1init = 0x23456789;
      u32 key2init = 0x34567890;

      update_key012_buf (key0init, key1init, key2init, w, pw_len, l_crc32tab);

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
