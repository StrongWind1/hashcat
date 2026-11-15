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

#ifndef INC_ZIP_TRADITIONAL_CL
#define INC_ZIP_TRADITIONAL_CL

// Shared by the four kernels of mode 46100. A line carries the 12 byte encryption header of up to
// eight members with the value its last one or two bytes decrypt to, and the data of the first of
// them. The headers are tested first, then the data: a stored member by its CRC-32, a deflated one
// by inflating it, and a member whose stream starts with a fixed signature by that signature.

#define ZIP1_CHECK_MAX 8
#define ZIP1_DATA_MAX  (4 * 1024 * 1024)
#define ZIP1_HOT_DATA  8

// What every candidate needs sits in one block the work group copies into shared memory: the
// headers, the first bytes of the data, and for each header the mask and the two values its last
// bytes may decrypt to.

#define ZIP1_HOT_HEAD  0
#define ZIP1_HOT_FIRST (ZIP1_CHECK_MAX * 3)
#define ZIP1_HOT_MASK  (ZIP1_HOT_FIRST + ZIP1_HOT_DATA)
#define ZIP1_HOT_A     (ZIP1_HOT_MASK + ZIP1_CHECK_MAX)
#define ZIP1_HOT_B     (ZIP1_HOT_A + ZIP1_CHECK_MAX)
#define ZIP1_HOT_WORDS (ZIP1_HOT_B + ZIP1_CHECK_MAX)

// A candidate that passes the headers waits here until the thread has been through its other
// candidates. One byte of check lets one candidate in 256 through, and a GPU runs a thread in
// step with its neighbours: testing the data on the spot would stop all of them every time any
// one of them had a survivor.

#define ZIP1_QUEUE 16

// Every thread goes through the same number of candidates before it turns to its queue, so the
// threads of a work group reach that point together and test their survivors side by side. 512
// candidates leave two in a queue on average; a queue that fills up first ends the round early.

#define ZIP1_ROUND 512

#define ZIP1_VERIFY_NONE    0
#define ZIP1_VERIFY_STORED  1
#define ZIP1_VERIFY_INFLATE 2
#define ZIP1_VERIFY_PREFIX  3
#define ZIP1_VERIFY_MAGIC   4

#define TMPSIZ TINFL_LZ_DICT_SIZE

#define CRC32(x,c,t) (((x) >> 8) ^ (t)[((x) ^ (c)) & 0xff])
#define MSB(x)       ((x) >> 24)
#define CONST        0x08088405

#define update_key012(k0,k1,k2,c,t)           \
{                                             \
  (k0) = CRC32 ((k0), c, (t));                \
  (k1) = ((k1) + ((k0) & 0xff)) * CONST + 1;  \
  (k2) = CRC32 ((k2), MSB (k1), (t));         \
}

#define update_key012_buf(k0,k1,k2,buf,len,t)                                               \
{                                                                                           \
  const u32 blen = (len);                                                                   \
                                                                                            \
  for (u32 bi = 0, bj = 0; bi < blen; bi += 4, bj += 1)                                     \
  {                                                                                         \
    if (blen >= (bi + 1)) update_key012 (k0, k1, k2, unpack_v8a_from_v32_S ((buf)[bj]), t); \
    if (blen >= (bi + 2)) update_key012 (k0, k1, k2, unpack_v8b_from_v32_S ((buf)[bj]), t); \
    if (blen >= (bi + 3)) update_key012 (k0, k1, k2, unpack_v8c_from_v32_S ((buf)[bj]), t); \
    if (blen >= (bi + 4)) update_key012 (k0, k1, k2, unpack_v8d_from_v32_S ((buf)[bj]), t); \
  }                                                                                         \
}

#define update_key3(k2,k3)                  \
{                                           \
  const u32 temp = ((k2) & 0xffff) | 3;     \
                                            \
  (k3) = ((temp * (temp ^ 1)) >> 8) & 0xff; \
}

typedef struct zip1
{
  u32 hot[ZIP1_HOT_WORDS];
  u32 check_cnt;
  u32 verify;
  u32 method;
  u32 crc32;
  u32 unpacked;
  u32 unpacked_hi;
  u32 packed;
  u32 packed_hi;
  u32 data_len;
  u32 magic_len;
  u32 magic[ZIP1_HOT_DATA];
  u32 magic_mask[ZIP1_HOT_DATA];
  u32 digest[4];
  u32 data[ZIP1_DATA_MAX / 4];

} zip1_t;

// The module asks for the decoder only when a line that is loaded holds a deflate stream. A
// kernel without it is several times faster on everything else.

#ifdef ZIP1_INFLATE

#define CRC32_IN_INFLATE

#include M2S(INCLUDE_PATH/inc_zip_inflate.cl)

typedef struct {
    u8  op;          /* operation, extra bits, table bits */
    u8  bits;        /* bits in this part of the code */
    u16 val;         /* offset in table or code value */
} code;

CONSTANT_VK code lenfix[512] = {
    {96,7,0},{0,8,80},{0,8,16},{20,8,115},{18,7,31},{0,8,112},{0,8,48},
    {0,9,192},{16,7,10},{0,8,96},{0,8,32},{0,9,160},{0,8,0},{0,8,128},
    {0,8,64},{0,9,224},{16,7,6},{0,8,88},{0,8,24},{0,9,144},{19,7,59},
    {0,8,120},{0,8,56},{0,9,208},{17,7,17},{0,8,104},{0,8,40},{0,9,176},
    {0,8,8},{0,8,136},{0,8,72},{0,9,240},{16,7,4},{0,8,84},{0,8,20},
    {21,8,227},{19,7,43},{0,8,116},{0,8,52},{0,9,200},{17,7,13},{0,8,100},
    {0,8,36},{0,9,168},{0,8,4},{0,8,132},{0,8,68},{0,9,232},{16,7,8},
    {0,8,92},{0,8,28},{0,9,152},{20,7,83},{0,8,124},{0,8,60},{0,9,216},
    {18,7,23},{0,8,108},{0,8,44},{0,9,184},{0,8,12},{0,8,140},{0,8,76},
    {0,9,248},{16,7,3},{0,8,82},{0,8,18},{21,8,163},{19,7,35},{0,8,114},
    {0,8,50},{0,9,196},{17,7,11},{0,8,98},{0,8,34},{0,9,164},{0,8,2},
    {0,8,130},{0,8,66},{0,9,228},{16,7,7},{0,8,90},{0,8,26},{0,9,148},
    {20,7,67},{0,8,122},{0,8,58},{0,9,212},{18,7,19},{0,8,106},{0,8,42},
    {0,9,180},{0,8,10},{0,8,138},{0,8,74},{0,9,244},{16,7,5},{0,8,86},
    {0,8,22},{64,8,0},{19,7,51},{0,8,118},{0,8,54},{0,9,204},{17,7,15},
    {0,8,102},{0,8,38},{0,9,172},{0,8,6},{0,8,134},{0,8,70},{0,9,236},
    {16,7,9},{0,8,94},{0,8,30},{0,9,156},{20,7,99},{0,8,126},{0,8,62},
    {0,9,220},{18,7,27},{0,8,110},{0,8,46},{0,9,188},{0,8,14},{0,8,142},
    {0,8,78},{0,9,252},{96,7,0},{0,8,81},{0,8,17},{21,8,131},{18,7,31},
    {0,8,113},{0,8,49},{0,9,194},{16,7,10},{0,8,97},{0,8,33},{0,9,162},
    {0,8,1},{0,8,129},{0,8,65},{0,9,226},{16,7,6},{0,8,89},{0,8,25},
    {0,9,146},{19,7,59},{0,8,121},{0,8,57},{0,9,210},{17,7,17},{0,8,105},
    {0,8,41},{0,9,178},{0,8,9},{0,8,137},{0,8,73},{0,9,242},{16,7,4},
    {0,8,85},{0,8,21},{16,8,258},{19,7,43},{0,8,117},{0,8,53},{0,9,202},
    {17,7,13},{0,8,101},{0,8,37},{0,9,170},{0,8,5},{0,8,133},{0,8,69},
    {0,9,234},{16,7,8},{0,8,93},{0,8,29},{0,9,154},{20,7,83},{0,8,125},
    {0,8,61},{0,9,218},{18,7,23},{0,8,109},{0,8,45},{0,9,186},{0,8,13},
    {0,8,141},{0,8,77},{0,9,250},{16,7,3},{0,8,83},{0,8,19},{21,8,195},
    {19,7,35},{0,8,115},{0,8,51},{0,9,198},{17,7,11},{0,8,99},{0,8,35},
    {0,9,166},{0,8,3},{0,8,131},{0,8,67},{0,9,230},{16,7,7},{0,8,91},
    {0,8,27},{0,9,150},{20,7,67},{0,8,123},{0,8,59},{0,9,214},{18,7,19},
    {0,8,107},{0,8,43},{0,9,182},{0,8,11},{0,8,139},{0,8,75},{0,9,246},
    {16,7,5},{0,8,87},{0,8,23},{64,8,0},{19,7,51},{0,8,119},{0,8,55},
    {0,9,206},{17,7,15},{0,8,103},{0,8,39},{0,9,174},{0,8,7},{0,8,135},
    {0,8,71},{0,9,238},{16,7,9},{0,8,95},{0,8,31},{0,9,158},{20,7,99},
    {0,8,127},{0,8,63},{0,9,222},{18,7,27},{0,8,111},{0,8,47},{0,9,190},
    {0,8,15},{0,8,143},{0,8,79},{0,9,254},{96,7,0},{0,8,80},{0,8,16},
    {20,8,115},{18,7,31},{0,8,112},{0,8,48},{0,9,193},{16,7,10},{0,8,96},
    {0,8,32},{0,9,161},{0,8,0},{0,8,128},{0,8,64},{0,9,225},{16,7,6},
    {0,8,88},{0,8,24},{0,9,145},{19,7,59},{0,8,120},{0,8,56},{0,9,209},
    {17,7,17},{0,8,104},{0,8,40},{0,9,177},{0,8,8},{0,8,136},{0,8,72},
    {0,9,241},{16,7,4},{0,8,84},{0,8,20},{21,8,227},{19,7,43},{0,8,116},
    {0,8,52},{0,9,201},{17,7,13},{0,8,100},{0,8,36},{0,9,169},{0,8,4},
    {0,8,132},{0,8,68},{0,9,233},{16,7,8},{0,8,92},{0,8,28},{0,9,153},
    {20,7,83},{0,8,124},{0,8,60},{0,9,217},{18,7,23},{0,8,108},{0,8,44},
    {0,9,185},{0,8,12},{0,8,140},{0,8,76},{0,9,249},{16,7,3},{0,8,82},
    {0,8,18},{21,8,163},{19,7,35},{0,8,114},{0,8,50},{0,9,197},{17,7,11},
    {0,8,98},{0,8,34},{0,9,165},{0,8,2},{0,8,130},{0,8,66},{0,9,229},
    {16,7,7},{0,8,90},{0,8,26},{0,9,149},{20,7,67},{0,8,122},{0,8,58},
    {0,9,213},{18,7,19},{0,8,106},{0,8,42},{0,9,181},{0,8,10},{0,8,138},
    {0,8,74},{0,9,245},{16,7,5},{0,8,86},{0,8,22},{64,8,0},{19,7,51},
    {0,8,118},{0,8,54},{0,9,205},{17,7,15},{0,8,102},{0,8,38},{0,9,173},
    {0,8,6},{0,8,134},{0,8,70},{0,9,237},{16,7,9},{0,8,94},{0,8,30},
    {0,9,157},{20,7,99},{0,8,126},{0,8,62},{0,9,221},{18,7,27},{0,8,110},
    {0,8,46},{0,9,189},{0,8,14},{0,8,142},{0,8,78},{0,9,253},{96,7,0},
    {0,8,81},{0,8,17},{21,8,131},{18,7,31},{0,8,113},{0,8,49},{0,9,195},
    {16,7,10},{0,8,97},{0,8,33},{0,9,163},{0,8,1},{0,8,129},{0,8,65},
    {0,9,227},{16,7,6},{0,8,89},{0,8,25},{0,9,147},{19,7,59},{0,8,121},
    {0,8,57},{0,9,211},{17,7,17},{0,8,105},{0,8,41},{0,9,179},{0,8,9},
    {0,8,137},{0,8,73},{0,9,243},{16,7,4},{0,8,85},{0,8,21},{16,8,258},
    {19,7,43},{0,8,117},{0,8,53},{0,9,203},{17,7,13},{0,8,101},{0,8,37},
    {0,9,171},{0,8,5},{0,8,133},{0,8,69},{0,9,235},{16,7,8},{0,8,93},
    {0,8,29},{0,9,155},{20,7,83},{0,8,125},{0,8,61},{0,9,219},{18,7,23},
    {0,8,109},{0,8,45},{0,9,187},{0,8,13},{0,8,141},{0,8,77},{0,9,251},
    {16,7,3},{0,8,83},{0,8,19},{21,8,195},{19,7,35},{0,8,115},{0,8,51},
    {0,9,199},{17,7,11},{0,8,99},{0,8,35},{0,9,167},{0,8,3},{0,8,131},
    {0,8,67},{0,9,231},{16,7,7},{0,8,91},{0,8,27},{0,9,151},{20,7,67},
    {0,8,123},{0,8,59},{0,9,215},{18,7,19},{0,8,107},{0,8,43},{0,9,183},
    {0,8,11},{0,8,139},{0,8,75},{0,9,247},{16,7,5},{0,8,87},{0,8,23},
    {64,8,0},{19,7,51},{0,8,119},{0,8,55},{0,9,207},{17,7,15},{0,8,103},
    {0,8,39},{0,9,175},{0,8,7},{0,8,135},{0,8,71},{0,9,239},{16,7,9},
    {0,8,95},{0,8,31},{0,9,159},{20,7,99},{0,8,127},{0,8,63},{0,9,223},
    {18,7,27},{0,8,111},{0,8,47},{0,9,191},{0,8,15},{0,8,143},{0,8,79},
    {0,9,255}
};

CONSTANT_VK code distfix[32] = {
    {16,5,1},{23,5,257},{19,5,17},{27,5,4097},{17,5,5},{25,5,1025},
    {21,5,65},{29,5,16385},{16,5,3},{24,5,513},{20,5,33},{28,5,8193},
    {18,5,9},{26,5,2049},{22,5,129},{64,5,0},{16,5,2},{23,5,385},
    {19,5,25},{27,5,6145},{17,5,7},{25,5,1537},{21,5,97},{29,5,24577},
    {16,5,4},{24,5,769},{20,5,49},{28,5,12289},{18,5,13},{26,5,3073},
    {22,5,193},{64,5,0}
};

// hashcat-patched: Metal refuses a pointer that does not name its address space, and everything these
// two walk lives in private memory.

DECLSPEC int check_inflate_code2 (PRIVATE_AS u8 *next)
{
  u32 bits, hold, thisget, have, i;
  int left;
  u32 ncode;
  u32 ncount[2];  // ends up being an array of 8 u8 count values.  But we can clear it, and later 'check' it with 2 u32 instructions.
  PRIVATE_AS u8 *count;    // this will point to ncount array. NOTE, this is alignment required 'safe' for Sparc systems or others requiring alignment.
  hold = *next + (((u32) next[1]) << 8) + (((u32) next[2]) << 16) + (((u32) next[3]) << 24);
  next += 3;  // we pre-increment when pulling it in the loop, thus we need to be 1 byte back.
  hold >>= 3;  // we already processed 3 bits
  count = (PRIVATE_AS u8 *) ncount;

  if (257 + (hold & 0x1F) > 286)
  {
    return 0;  // nlen, but we do not use it.
  }
  hold >>= 5;
  if (1 + (hold & 0x1F) > 30)
  {
    return 0;    // ndist, but we do not use it.
  }
  hold >>= 5;
  ncode = 4 + (hold & 0xF);
  hold >>= 4;

  // we have 15 bits left.
  hold += ((u32)(*++next)) << 15;
  hold += ((u32)(*++next)) << 23;
  // we now have 31 bits.  We need to know this for the loop below.
  bits = 31;

  // We have 31 bits now, in accum.  If we are processing 19 codes, we do 7, then have 10 bits.
  // Add 16 more and have 26, then use 21, have 5.  Then load 16 more, then eat 15 of them.
  have = 0;

  ncount[0] = ncount[1] = 0;
  for (;;)
  {
    if (have+7>ncode)
    {
      thisget = ncode-have;
    }
    else
    {
      thisget = 7;
    }
    have += thisget;
    bits -= thisget*3;
    while (thisget--)
    {
      ++count[hold&7];
      hold>>=3;
    }
    if (have == ncode)
    {
      break;
    }
    hold += ((u32)(*++next)) << bits;
    bits += 8;
    hold += ((u32)(*++next)) << bits;
    bits += 8;
  }
  count[0] = 0;
  if (!ncount[0] && !ncount[1])
  {
    return 0;
  }

  left = 1;
  for (i = 1; i <= 7; ++i)
  {
    left <<= 1;
    left -= count[i];
    if (left < 0)
    {
      return 0;
    }
  }
  if (left > 0)
  {
    return 0;
  }

  return 1;
}


DECLSPEC int check_inflate_code1 (PRIVATE_AS u8 *next, int left)
{
  u32 whave = 0, op, bits, hold,len;
  code here1;

  hold = *next + (((u32) next[1]) << 8) + (((u32) next[2]) << 16) + (((u32) next[3]) << 24);
  next += 3; // we pre-increment when pulling it in the loop, thus we need to be 1 byte back.
  left -= 4;
  hold >>= 3;  // we already processed 3 bits
  bits = 32-3;
  for (;;)
  {
    if (bits < 15)
    {
      if (left < 2)
      {
        return 1;  // we are out of bytes.  Return we had no error.
      }
      left -= 2;
      hold += (u32)(*++next) << bits;
      bits += 8;
      hold += (u32)(*++next) << bits;
      bits += 8;
    }
    here1=lenfix[hold & 0x1FF];
    op = (unsigned)(here1.bits);
    hold >>= op;
    bits -= op;
    op = (unsigned)(here1.op);
    if (op == 0)
    {
      ++whave;
    }
    else if (op & 16)
    {
      len = (unsigned)(here1.val);
      op &= 15;
      if (op)
      {
        if (bits < op)
        {
          if (!left)
          {
            return 1;
          }
          --left;
          hold += (u32)(*++next) << bits;
          bits += 8;
        }
        len += (unsigned)hold & ((1U << op) - 1);
        hold >>= op;
        bits -= op;
      }
      if (bits < 15)
      {
        if (left < 2)
        {
          return 1;
        }
        left -= 2;
        hold += (u32)(*++next) << bits;
        bits += 8;
        hold += (u32)(*++next) << bits;
        bits += 8;
      }
      code here2 = distfix[hold & 0x1F];
      op = (unsigned)(here2.bits);
      hold >>= op;
      bits -= op;
      op = (unsigned)(here2.op);
      if (op & 16) /* distance base */
      {
        u32 dist = (unsigned)(here2.val);
        op &= 15;
        if (bits < op)
        {
          if (!left)
          {
            return 1;
          }
          --left;
          hold += (u32)(*++next) << bits;
          bits += 8;
          if (bits < op)
          {
            if (!left)
            {
              return 1;
            }
            --left;
            hold += (u32)(*++next) << bits;
            bits += 8;
          }
        }
        dist += (unsigned)hold & ((1U << op) - 1);
        if (dist > whave)
        {
          return 0;
        }
        hold >>= op;
        bits -= op;

        whave += len;
      }
      else
      {
        return 0;
      }
    }
    else if (op & 32)
    {
      if (left == 0)
      {
        return 1;
      }
      return 0;
    }
    else
    {
      return 0;
    }
  }
}

#endif

// The association attack reads the head of the line straight from global memory, every other
// attack from the copy the work group shares.

#if ATTACK_MODE == 9
#define ZIP1_HOT_AS GLOBAL_AS const
#else
#define ZIP1_HOT_AS LOCAL_AS
#endif

#define ZIP1_HOT_BYTE(w,i) (((w)[(i) / 4] >> (((i) & 3) * 8)) & 0xff)

#ifdef ZIP1_INFLATE

DECLSPEC int zip1_inflate (GLOBAL_AS const zip1_t *z, const u32 key0, const u32 key1, const u32 key2, LOCAL_AS u32 *l_crc32tab, const u32 prefix)
{
  u8 tmp[TMPSIZ];

  mz_stream infstream;

  inflate_state state;

  infstream.opaque    = Z_NULL;
  infstream.avail_in  = z->data_len;
  infstream.next_in   = (GLOBAL_AS const u8 *) z->data;
  infstream.avail_out = TMPSIZ;
  infstream.next_out  = tmp;
  infstream.key0      = key0;
  infstream.key1      = key1;
  infstream.key2      = key2;
  infstream.crc32     = 0xffffffff;
  infstream.crc32tab  = l_crc32tab;

  mz_inflateInit2 (&infstream, -MAX_WBITS, &state);

  size_t in_bytes  = infstream.avail_in;
  size_t out_bytes = infstream.avail_out;

  mz_uint decomp_flags = TINFL_FLAG_FLUSH_WINDOW;

  if (prefix == 1) decomp_flags |= TINFL_FLAG_HAS_MORE_INPUT;

  const tinfl_status status = tinfl_decompress (&state.m_decomp, infstream.next_in, &in_bytes, infstream.next_out, infstream.next_out + infstream.window_out, &out_bytes, decomp_flags, &infstream);

  if (prefix == 1)
  {
    // a stream cut short has to still be running when the bytes run out

    if (status != TINFL_STATUS_NEEDS_MORE_INPUT) return 0;

    if (in_bytes != z->data_len) return 0;

    return 1;
  }

  if (status != TINFL_STATUS_DONE) return 0;

  for (u32 i = 0; i < (u32) out_bytes; i++)
  {
    infstream.crc32 = CRC32 (infstream.crc32, tmp[infstream.window_out + i], l_crc32tab);
  }

  infstream.total_out += out_bytes;

  if (infstream.total_out != z->unpacked) return 0;

  if (~infstream.crc32 != z->crc32) return 0;

  return 1;
}

#endif

// The cheap half: decrypt the header of every member the line names and compare its end. The
// member whose data the line carries comes first, and the state behind its header is what the
// data continues from, so that state is handed back.

DECLSPEC int zip1_headers (const u32 key0init, const u32 key1init, const u32 key2init, LOCAL_AS u32 *l_crc32tab, ZIP1_HOT_AS u32 *hot, const u32 check_cnt, PRIVATE_AS u32 *saved)
{
  u32 key3;
  u32 plain;

  for (u32 idx = 0; idx < check_cnt; idx++)
  {
    u32 key0 = key0init;
    u32 key1 = key1init;
    u32 key2 = key2init;

    const u32 w0 = hot[ZIP1_HOT_HEAD + (idx * 3) + 0];
    const u32 w1 = hot[ZIP1_HOT_HEAD + (idx * 3) + 1];
    const u32 w2 = hot[ZIP1_HOT_HEAD + (idx * 3) + 2];

    update_key3 (key2, key3); plain = unpack_v8a_from_v32_S (w0) ^ key3; update_key012 (key0, key1, key2, plain, l_crc32tab);
    update_key3 (key2, key3); plain = unpack_v8b_from_v32_S (w0) ^ key3; update_key012 (key0, key1, key2, plain, l_crc32tab);
    update_key3 (key2, key3); plain = unpack_v8c_from_v32_S (w0) ^ key3; update_key012 (key0, key1, key2, plain, l_crc32tab);
    update_key3 (key2, key3); plain = unpack_v8d_from_v32_S (w0) ^ key3; update_key012 (key0, key1, key2, plain, l_crc32tab);
    update_key3 (key2, key3); plain = unpack_v8a_from_v32_S (w1) ^ key3; update_key012 (key0, key1, key2, plain, l_crc32tab);
    update_key3 (key2, key3); plain = unpack_v8b_from_v32_S (w1) ^ key3; update_key012 (key0, key1, key2, plain, l_crc32tab);
    update_key3 (key2, key3); plain = unpack_v8c_from_v32_S (w1) ^ key3; update_key012 (key0, key1, key2, plain, l_crc32tab);
    update_key3 (key2, key3); plain = unpack_v8d_from_v32_S (w1) ^ key3; update_key012 (key0, key1, key2, plain, l_crc32tab);
    update_key3 (key2, key3); plain = unpack_v8a_from_v32_S (w2) ^ key3; update_key012 (key0, key1, key2, plain, l_crc32tab);
    update_key3 (key2, key3); plain = unpack_v8b_from_v32_S (w2) ^ key3; update_key012 (key0, key1, key2, plain, l_crc32tab);

    update_key3 (key2, key3);

    const u32 lo = unpack_v8c_from_v32_S (w2) ^ key3;

    update_key012 (key0, key1, key2, lo, l_crc32tab);

    update_key3 (key2, key3);

    const u32 hi = unpack_v8d_from_v32_S (w2) ^ key3;

    update_key012 (key0, key1, key2, hi, l_crc32tab);

    const u32 got  = lo | (hi << 8);
    const u32 mask = hot[ZIP1_HOT_MASK + idx];

    if ((((got ^ hot[ZIP1_HOT_A + idx]) & mask) != 0) && (((got ^ hot[ZIP1_HOT_B + idx]) & mask) != 0)) return 0;

    if (idx == 0)
    {
      saved[0] = key0;
      saved[1] = key1;
      saved[2] = key2;
    }
  }

  return 1;
}

// The expensive half: the data of the first member, from the state behind its header.

DECLSPEC int zip1_data (PRIVATE_AS const u32 *saved, GLOBAL_AS const zip1_t *z, LOCAL_AS u32 *l_crc32tab, ZIP1_HOT_AS u32 *hot, const u32 verify)
{
  if (verify == ZIP1_VERIFY_NONE) return 1;

  u32 key0 = saved[0];
  u32 key1 = saved[1];
  u32 key2 = saved[2];
  u32 key3;
  u32 plain;

  const u32 data_len = z->data_len;

  if (verify == ZIP1_VERIFY_STORED)
  {
    u32 crc = 0xffffffff;

    const u32 words = data_len / 4;

    for (u32 j = 0; j < words; j++)
    {
      const u32 next = z->data[j];

      update_key3 (key2, key3); plain = unpack_v8a_from_v32_S (next) ^ key3; update_key012 (key0, key1, key2, plain, l_crc32tab); crc = CRC32 (crc, plain, l_crc32tab);
      update_key3 (key2, key3); plain = unpack_v8b_from_v32_S (next) ^ key3; update_key012 (key0, key1, key2, plain, l_crc32tab); crc = CRC32 (crc, plain, l_crc32tab);
      update_key3 (key2, key3); plain = unpack_v8c_from_v32_S (next) ^ key3; update_key012 (key0, key1, key2, plain, l_crc32tab); crc = CRC32 (crc, plain, l_crc32tab);
      update_key3 (key2, key3); plain = unpack_v8d_from_v32_S (next) ^ key3; update_key012 (key0, key1, key2, plain, l_crc32tab); crc = CRC32 (crc, plain, l_crc32tab);
    }

    const u32 left = data_len & 3;

    if (left != 0)
    {
      u32 next = z->data[words];

      for (u32 i = 0; i < left; i++)
      {
        update_key3 (key2, key3); plain = (next & 0xff) ^ key3; update_key012 (key0, key1, key2, plain, l_crc32tab); crc = CRC32 (crc, plain, l_crc32tab);

        next >>= 8;
      }
    }

    if (~crc != z->crc32) return 0;

    return 1;
  }

  // everything else looks at the first bytes of the stream before anything expensive happens

  u8 head[ZIP1_HOT_DATA * 4];

  for (u32 i = 0; i < (ZIP1_HOT_DATA * 4); i++)
  {
    const u32 c = ZIP1_HOT_BYTE (hot + ZIP1_HOT_FIRST, i);

    update_key3 (key2, key3); plain = c ^ key3; update_key012 (key0, key1, key2, plain, l_crc32tab);

    head[i] = (u8) plain;
  }

  if (verify == ZIP1_VERIFY_MAGIC)
  {
    const u32 magic_len = z->magic_len;

    for (u32 i = 0; i < magic_len; i++)
    {
      const u32 want = ZIP1_HOT_BYTE (z->magic, i);
      const u32 mask = ZIP1_HOT_BYTE (z->magic_mask, i);

      if ((((u32) head[i] ^ want) & mask) != 0) return 0;
    }

    return 1;
  }

  #ifdef ZIP1_INFLATE

  // a deflate block of type 3 does not exist

  if ((head[0] & 6) == 6) return 0;

  if (data_len >= 24)
  {
    if (((head[0] & 6) == 2) && (check_inflate_code1 (head, 24) == 0)) return 0;
    if (((head[0] & 6) == 4) && (check_inflate_code2 (head)     == 0)) return 0;
  }

  const u32 prefix = (verify == ZIP1_VERIFY_PREFIX) ? 1 : 0;

  return zip1_inflate (z, saved[0], saved[1], saved[2], l_crc32tab, prefix);

  #else

  return 0;

  #endif
}

// Every kernel starts the same way: the CRC table and the head of the line go into memory the
// work group shares.

#define ZIP1_SHARED_DECL                                \
  LOCAL_VK u32 l_crc32tab[256];                         \
  LOCAL_VK u32 l_hot[ZIP1_HOT_WORDS];                   \
  for (u64 i = lid; i < 256; i += lsz)                  \
  {                                                     \
    l_crc32tab[i] = crc32tab[i];                        \
  }                                                     \
  SYNC_THREADS ();                                      \
  for (u64 i = lid; i < ZIP1_HOT_WORDS; i += lsz)       \
  {                                                     \
    l_hot[i] = esalt_bufs[DIGESTS_OFFSET_HOST].hot[i];  \
  }                                                     \
  SYNC_THREADS ();

#endif
