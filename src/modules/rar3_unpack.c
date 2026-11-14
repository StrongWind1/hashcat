/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

// The RAR3 decompressor module 46700 verifies a compressed entry with. Included the way
// rar3_decode.c is: one translation unit, nothing exported.
//
// It follows UnRAR 7.3.2 (unpack30.cpp, the standard filters in rarvm.cpp and the Huffman table
// code in unpack.cpp), written out in C for a hook that needs one thing from it: the CRC32 of what
// a candidate password unpacks to. The PPM model is the PPMd var.H implementation published with
// 7-Zip that hashcat already carries.
//
// UnRAR's license, paragraph 2, which has to accompany code derived from its source:
//
//   UnRAR source code may be used in any software to handle
//   RAR archives without limitations free of charge, but cannot be
//   used to develop RAR (WinRAR) compatible archiver and to
//   re-create RAR compression algorithm, which is proprietary.
//   Distribution of modified UnRAR source code in separate form
//   or as a part of other software is permitted, provided that
//   full text of this paragraph, starting from "UnRAR source code"
//   words, is included in license, or in documentation if license
//   is not available, and in source code comments of resulting package.
//
// The full license is in docs/license_libs/UNRAR_LICENSE.txt.
//
// Unlike rar3_decode.c it takes a stream the way any RAR 2.9 to 4.x release writes it: LZ and PPM
// blocks in any order, filter records anywhere in the stream with positions relative to where they
// appear, filters applied one after another to the same block, and a 4 MiB dictionary.

#include "rar3/ppmd7/Ppmd7.c"
#include "rar3/ppmd7/Ppmd7aDec.c"

// The alphabet sizes: literals and match codes, distances, low distance bits, repeat lengths, and
// the code the tables themselves are written in.

#define RAR29_NC  299
#define RAR29_DC   60
#define RAR29_LDC  17
#define RAR29_RC   28
#define RAR29_BC   20

#define RAR29_TABLE_SIZE (RAR29_NC + RAR29_DC + RAR29_RC + RAR29_LDC)

#define RAR29_LOW_DIST_REP_COUNT 16

// RAR3 dictionaries go up to 4 MiB.

#define RAR29_WIN_SIZE 0x400000
#define RAR29_WIN_MASK (RAR29_WIN_SIZE - 1)

// A filter works on a copy of its block in the memory of RAR's filter VM, which is this large.

#define RAR29_VM_MEMSIZE 0x40000
#define RAR29_VM_MEMMASK (RAR29_VM_MEMSIZE - 1)

#define RAR29_FILTERS_MAX 8192

#define RAR29_FILTER_NONE    0
#define RAR29_FILTER_E8      1
#define RAR29_FILTER_E8E9    2
#define RAR29_FILTER_ITANIUM 3
#define RAR29_FILTER_DELTA   4
#define RAR29_FILTER_RGB     5
#define RAR29_FILTER_AUDIO   6

static u32  rar29_crc32tab[256];
static bool rar29_crc32tab_ready = false;

static void rar29_crc32_init (void)
{
  if (rar29_crc32tab_ready == true) return;

  for (u32 i = 0; i < 256; i++)
  {
    u32 c = i;

    for (u32 j = 0; j < 8; j++) c = ((c & 1) == 1) ? (0xEDB88320 ^ (c >> 1)) : (c >> 1);

    rar29_crc32tab[i] = c;
  }

  rar29_crc32tab_ready = true;
}

static u32 rar29_crc32 (const u32 start, const u8 *buf, const u64 len)
{
  u32 crc = start;

  for (u64 i = 0; i < len; i++) crc = (crc >> 8) ^ rar29_crc32tab[(crc ^ buf[i]) & 0xff];

  return crc;
}

typedef struct rar29_huff
{
  u32 max_num;
  u32 decode_len[16];
  u32 decode_pos[16];
  u16 decode_num[RAR29_NC];

} rar29_huff_t;

// A filter waiting for its block to be unpacked.

typedef struct rar29_filter
{
  u64 start;
  u32 length;
  u32 type;
  u32 r[7];

} rar29_filter_t;

// The buffers one hook thread keeps between candidates.

typedef struct rar29_buffers
{
  u8 *win;
  u8 *vm_mem;

  rar29_filter_t *stack;

  u8  *slot_type;
  u32 *slot_length;

  void *ppm_mem;
  u64   ppm_size;

} rar29_buffers_t;

typedef struct rar29_ctx rar29_ctx_t;

// PPMd reads the stream a byte at a time, from where the bit reader stands.

typedef struct rar29_byte_in
{
  IByteIn vt;

  rar29_ctx_t *ctx;

} rar29_byte_in_t;

// PPMd asks for its memory once per model reset, and is handed the buffer the thread already owns.

typedef struct rar29_arena
{
  ISzAlloc vt;

  rar29_buffers_t *buffers;

} rar29_arena_t;

struct rar29_ctx
{
  const u8 *in;
  u64       in_bits;
  u64       bit;

  rar29_buffers_t *buffers;

  // produced counts the bytes unpacked into the window, written those that reached the CRC32
  // after their filters ran.

  u64 produced;
  u64 written;
  u64 dest_size;
  u32 crc;

  rar29_huff_t ld;
  rar29_huff_t dd;
  rar29_huff_t ldd;
  rar29_huff_t rd;
  rar29_huff_t bd;

  u8 old_table[RAR29_TABLE_SIZE];

  bool tables_read;
  bool block_ppm;

  u32 old_dist[4];
  u32 last_length;
  u32 prev_low_dist;
  u32 low_dist_rep_count;

  CPpmd7          ppmd;
  rar29_byte_in_t ppm_in;
  rar29_arena_t   ppm_arena;
  bool            ppm_ready;
  u32             ppm_esc;

  u32 slot_cnt;
  u32 last_filter;

  u32 stack_cnt;
  u32 stack_at;

  bool ran_off;
  bool failed;
  bool unsupported;
};

static void rar29_buffers_free (rar29_buffers_t *b)
{
  hcfree (b->win);
  hcfree (b->vm_mem);
  hcfree (b->stack);
  hcfree (b->slot_type);
  hcfree (b->slot_length);
  hcfree (b->ppm_mem);

  memset (b, 0, sizeof (rar29_buffers_t));
}

static bool rar29_buffers_ready (rar29_buffers_t *b)
{
  if (b->win         == NULL) b->win         = (u8 *) hcmalloc (RAR29_WIN_SIZE);
  if (b->vm_mem      == NULL) b->vm_mem      = (u8 *) hcmalloc (RAR29_VM_MEMSIZE + 4);
  if (b->stack       == NULL) b->stack       = (rar29_filter_t *) hccalloc (RAR29_FILTERS_MAX, sizeof (rar29_filter_t));
  if (b->slot_type   == NULL) b->slot_type   = (u8 *) hcmalloc (RAR29_FILTERS_MAX + 1);
  if (b->slot_length == NULL) b->slot_length = (u32 *) hccalloc (RAR29_FILTERS_MAX + 1, sizeof (u32));

  if (b->win         == NULL) return false;
  if (b->vm_mem      == NULL) return false;
  if (b->stack       == NULL) return false;
  if (b->slot_type   == NULL) return false;
  if (b->slot_length == NULL) return false;

  return true;
}

static void *rar29_arena_alloc (ISzAllocPtr pp, size_t size)
{
  rar29_arena_t *p = (rar29_arena_t *) pp;

  rar29_buffers_t *b = p->buffers;

  if (b->ppm_size >= (u64) size) return b->ppm_mem;

  hcfree (b->ppm_mem);

  b->ppm_mem  = hcmalloc (size);
  b->ppm_size = (b->ppm_mem == NULL) ? 0 : (u64) size;

  return b->ppm_mem;
}

static void rar29_arena_free (MAYBE_UNUSED ISzAllocPtr pp, MAYBE_UNUSED void *address)
{
  // The buffer outlives the model and is freed with the thread's other buffers.
}

// The next 16 bits, zero filled past the end of the input.

static u32 rar29_getbits (const rar29_ctx_t *ctx)
{
  const u64 byte = ctx->bit >> 3;
  const u64 size = ctx->in_bits >> 3;

  u32 v = 0;

  if (byte + 0 < size) v |= (u32) ctx->in[byte + 0] << 16;
  if (byte + 1 < size) v |= (u32) ctx->in[byte + 1] <<  8;
  if (byte + 2 < size) v |= (u32) ctx->in[byte + 2] <<  0;

  const u32 bits = (v >> (8 - (ctx->bit & 7))) & 0xffff;

  return bits;
}

static void rar29_addbits (rar29_ctx_t *ctx, const u32 count)
{
  ctx->bit += count;

  if (ctx->bit > ctx->in_bits) ctx->ran_off = true;
}

static Byte rar29_byte_in_read (IByteInPtr pp)
{
  rar29_byte_in_t *p = Z7_CONTAINER_FROM_VTBL (pp, rar29_byte_in_t, vt);

  rar29_ctx_t *ctx = p->ctx;

  const u64 byte = ctx->bit >> 3;

  ctx->bit += 8;

  if (ctx->bit > ctx->in_bits)
  {
    ctx->ran_off = true;

    return 0;
  }

  const Byte b = ctx->in[byte];

  return b;
}

// A set of code lengths that claims more of the code space than there is describes no Huffman
// code. No packer writes one, and a wrong key produces one almost every time, so it is the
// cheapest way to turn a candidate down before anything is unpacked.

static bool rar29_code_fits (const u8 *lengths, const u32 size)
{
  u32 used = 0;

  for (u32 i = 0; i < size; i++)
  {
    const u32 length = lengths[i] & 0xf;

    if (length != 0) used += 0x8000 >> length;
  }

  const bool fits = (used <= 0x8000);

  return fits;
}

static void rar29_make_tables (const u8 *lengths, rar29_huff_t *dec, const u32 size)
{
  dec->max_num = size;

  u32 count[16];

  memset (count, 0, sizeof (count));

  for (u32 i = 0; i < size; i++) count[lengths[i] & 0xf]++;

  count[0] = 0;

  memset (dec->decode_num, 0, size * sizeof (dec->decode_num[0]));

  dec->decode_pos[0] = 0;
  dec->decode_len[0] = 0;

  u32 upper_limit = 0;

  for (u32 i = 1; i < 16; i++)
  {
    upper_limit += count[i];

    dec->decode_len[i] = upper_limit << (16 - i);

    upper_limit *= 2;

    dec->decode_pos[i] = dec->decode_pos[i - 1] + count[i - 1];
  }

  u32 copy_pos[16];

  memcpy (copy_pos, dec->decode_pos, sizeof (copy_pos));

  for (u32 i = 0; i < size; i++)
  {
    const u32 len = lengths[i] & 0xf;

    if (len == 0) continue;

    const u32 pos = copy_pos[len];

    copy_pos[len]++;

    if (pos < size) dec->decode_num[pos] = (u16) i;
  }
}

static u32 rar29_decode_number (rar29_ctx_t *ctx, const rar29_huff_t *dec)
{
  const u32 bit_field = rar29_getbits (ctx) & 0xfffe;

  u32 bits = 15;

  for (u32 i = 1; i < 15; i++)
  {
    if (bit_field < dec->decode_len[i])
    {
      bits = i;

      break;
    }
  }

  rar29_addbits (ctx, bits);

  const u32 dist = (bit_field - dec->decode_len[bits - 1]) >> (16 - bits);

  u32 pos = dec->decode_pos[bits] + dist;

  if (pos >= dec->max_num) pos = 0;

  const u32 number = dec->decode_num[pos];

  return number;
}

// ---- filters ----

static u32 rar29_itanium_getbits (const u8 *data, const u32 bit_pos, const u32 bit_count)
{
  const u32 addr = bit_pos / 8;
  const u32 bit  = bit_pos & 7;

  u32 field = (u32) data[addr + 0] | ((u32) data[addr + 1] << 8) | ((u32) data[addr + 2] << 16) | ((u32) data[addr + 3] << 24);

  field >>= bit;

  const u32 value = field & (0xffffffff >> (32 - bit_count));

  return value;
}

static void rar29_itanium_setbits (u8 *data, const u32 value, const u32 bit_pos, const u32 bit_count)
{
  const u32 addr = bit_pos / 8;
  const u32 bit  = bit_pos & 7;

  u32 and_mask = 0xffffffff >> (32 - bit_count);

  and_mask = ~(and_mask << bit);

  u32 field = value << bit;

  for (u32 i = 0; i < 4; i++)
  {
    data[addr + i] &= (u8) and_mask;
    data[addr + i] |= (u8) field;

    and_mask = (and_mask >> 8) | 0xff000000;

    field >>= 8;
  }
}

static u32 rar29_abs (const i32 v)
{
  const u32 magnitude = (v >= 0) ? (u32) v : (u32) (0 - v);

  return magnitude;
}

// Runs one standard filter over the block in mem, with the registers in r: r[4] is the block
// length and r[6] the position of the block in the file. Returns false when the filter refuses
// the block, in which case UnRAR passes it on untouched.

static bool rar29_run_filter (u8 *mem, const u32 type, const u32 *r)
{
  const u32 data_size = r[4];

  if ((type == RAR29_FILTER_E8) || (type == RAR29_FILTER_E8E9))
  {
    if ((data_size > RAR29_VM_MEMSIZE) || (data_size < 4)) return false;

    const u32 file_offset = r[6];
    const u32 file_size   = 0x1000000;

    const u8 cmp2 = (type == RAR29_FILTER_E8E9) ? 0xe9 : 0xe8;

    for (u32 cur = 0; cur < data_size - 4; )
    {
      const u8 byte = mem[cur];

      cur++;

      if ((byte != 0xe8) && (byte != cmp2)) continue;

      const u32 offset = cur + file_offset;

      const u32 addr = (u32) mem[cur + 0] | ((u32) mem[cur + 1] << 8) | ((u32) mem[cur + 2] << 16) | ((u32) mem[cur + 3] << 24);

      u32  put   = addr;
      bool write = false;

      if ((addr & 0x80000000) != 0)
      {
        if (((addr + offset) & 0x80000000) == 0)
        {
          put   = addr + file_size;
          write = true;
        }
      }
      else if (((addr - file_size) & 0x80000000) != 0)
      {
        put   = addr - offset;
        write = true;
      }

      if (write == true)
      {
        mem[cur + 0] = (u8) (put >>  0);
        mem[cur + 1] = (u8) (put >>  8);
        mem[cur + 2] = (u8) (put >> 16);
        mem[cur + 3] = (u8) (put >> 24);
      }

      cur += 4;
    }

    return true;
  }

  if (type == RAR29_FILTER_ITANIUM)
  {
    static const u8 masks[16] = { 4, 4, 6, 6, 0, 0, 7, 7, 4, 4, 0, 0, 4, 4, 0, 0 };

    if ((data_size > RAR29_VM_MEMSIZE) || (data_size < 21)) return false;

    u32 file_offset = r[6] >> 4;

    for (u32 cur = 0; cur < data_size - 21; cur += 16, file_offset++)
    {
      u8 *data = &mem[cur];

      const u32 low = data[0] & 0x1f;

      if (low < 0x10) continue;

      const u8 cmd_mask = masks[low - 0x10];

      for (u32 i = 0; i <= 2; i++)
      {
        if ((cmd_mask & (1 << i)) == 0) continue;

        const u32 start_pos = (i * 41) + 5;

        const u32 op_type = rar29_itanium_getbits (data, start_pos + 37, 4);

        if (op_type != 5) continue;

        const u32 offset = rar29_itanium_getbits (data, start_pos + 13, 20);

        rar29_itanium_setbits (data, (offset - file_offset) & 0xfffff, start_pos + 13, 20);
      }
    }

    return true;
  }

  if (type == RAR29_FILTER_DELTA)
  {
    const u32 channels = r[0];

    if ((data_size > RAR29_VM_MEMSIZE / 2) || (channels > 1024) || (channels == 0)) return false;

    const u32 border = data_size * 2;

    u32 src_pos = 0;

    for (u32 channel = 0; channel < channels; channel++)
    {
      u8 prev = 0;

      for (u32 dest_pos = data_size + channel; dest_pos < border; dest_pos += channels, src_pos++)
      {
        prev = (u8) (prev - mem[src_pos]);

        mem[dest_pos] = prev;
      }
    }

    return true;
  }

  if (type == RAR29_FILTER_RGB)
  {
    const u32 width = r[0] - 3;
    const u32 pos_r = r[1];

    if ((data_size > RAR29_VM_MEMSIZE / 2) || (data_size < 3) || (width > data_size) || (pos_r > 2)) return false;

    u8 *dest = &mem[data_size];

    u32 src_pos = 0;

    for (u32 channel = 0; channel < 3; channel++)
    {
      u32 prev = 0;

      for (u32 i = channel; i < data_size; i += 3, src_pos++)
      {
        u32 predicted = prev;

        if (i >= width + 3)
        {
          const u32 upper      = dest[i - width];
          const u32 upper_left = dest[i - width - 3];

          predicted = prev + upper - upper_left;

          const u32 pa = rar29_abs ((i32) (predicted - prev));
          const u32 pb = rar29_abs ((i32) (predicted - upper));
          const u32 pc = rar29_abs ((i32) (predicted - upper_left));

          if ((pa <= pb) && (pa <= pc))
          {
            predicted = prev;
          }
          else if (pb <= pc)
          {
            predicted = upper;
          }
          else
          {
            predicted = upper_left;
          }
        }

        dest[i] = (u8) (predicted - mem[src_pos]);

        prev = dest[i];
      }
    }

    for (u32 i = pos_r; i + 2 < data_size; i += 3)
    {
      const u8 g = dest[i + 1];

      dest[i + 0] = (u8) (dest[i + 0] + g);
      dest[i + 2] = (u8) (dest[i + 2] + g);
    }

    return true;
  }

  if (type == RAR29_FILTER_AUDIO)
  {
    const u32 channels = r[0];

    if ((data_size > RAR29_VM_MEMSIZE / 2) || (channels > 128) || (channels == 0)) return false;

    u8 *dest = &mem[data_size];

    u32 src_pos = 0;

    for (u32 channel = 0; channel < channels; channel++)
    {
      u32 prev_byte  = 0;
      u32 prev_delta = 0;

      u32 dif[7];

      memset (dif, 0, sizeof (dif));

      i32 d1 = 0;
      i32 d2 = 0;
      i32 d3 = 0;

      i32 k1 = 0;
      i32 k2 = 0;
      i32 k3 = 0;

      for (u32 i = channel, byte_count = 0; i < data_size; i += channels, byte_count++, src_pos++)
      {
        d3 = d2;
        d2 = (i32) prev_delta - d1;
        d1 = (i32) prev_delta;

        u32 predicted = (8 * prev_byte) + (u32) (k1 * d1) + (u32) (k2 * d2) + (u32) (k3 * d3);

        predicted = (predicted >> 3) & 0xff;

        const u32 cur_byte = mem[src_pos];

        predicted -= cur_byte;

        dest[i] = (u8) predicted;

        prev_delta = (u32) (i32) (i8) (predicted - prev_byte);
        prev_byte  = predicted;

        i32 d = (i8) cur_byte;

        d = (i32) ((u32) d << 3);

        dif[0] += rar29_abs (d);
        dif[1] += rar29_abs (d - d1);
        dif[2] += rar29_abs (d + d1);
        dif[3] += rar29_abs (d - d2);
        dif[4] += rar29_abs (d + d2);
        dif[5] += rar29_abs (d - d3);
        dif[6] += rar29_abs (d + d3);

        if ((byte_count & 0x1f) != 0) continue;

        u32 min_dif     = dif[0];
        u32 num_min_dif = 0;

        dif[0] = 0;

        for (u32 j = 1; j < 7; j++)
        {
          if (dif[j] < min_dif)
          {
            min_dif     = dif[j];
            num_min_dif = j;
          }

          dif[j] = 0;
        }

        switch (num_min_dif)
        {
          case 1: if (k1 >= -16) k1--; break;
          case 2: if (k1 <   16) k1++; break;
          case 3: if (k2 >= -16) k2--; break;
          case 4: if (k2 <   16) k2++; break;
          case 5: if (k3 >= -16) k3--; break;
          case 6: if (k3 <   16) k3++; break;
        }
      }
    }

    return true;
  }

  return false;
}

static void rar29_sum_window (rar29_ctx_t *ctx, const u64 from, const u64 to)
{
  u64 at = from;

  while (at < to)
  {
    const u64 off  = at & RAR29_WIN_MASK;
    const u64 take = MIN (to - at, RAR29_WIN_SIZE - off);

    ctx->crc = rar29_crc32 (ctx->crc, &ctx->buffers->win[off], take);

    at += take;
  }
}

// Hands unpacked bytes to the CRC32, running each filter over its block once the block is
// complete. Bytes in front of an incomplete block wait in the window.

static void rar29_flush (rar29_ctx_t *ctx)
{
  rar29_filter_t *stack = ctx->buffers->stack;

  u8 *mem = ctx->buffers->vm_mem;

  while (ctx->stack_at < ctx->stack_cnt)
  {
    const rar29_filter_t *flt = &stack[ctx->stack_at];

    if (flt->start < ctx->written)
    {
      // A filter over bytes that already reached the CRC32.

      ctx->failed = true;

      return;
    }

    if (flt->start >= ctx->produced) break;

    if (flt->start > ctx->written)
    {
      rar29_sum_window (ctx, ctx->written, flt->start);

      ctx->written = flt->start;
    }

    if (ctx->produced < flt->start + flt->length) return;

    // A custom program: UnRAR no longer runs those either, and the bytes would reach the CRC32
    // untransformed.

    if (flt->type == RAR29_FILTER_NONE)
    {
      ctx->unsupported = true;
      ctx->failed      = true;

      return;
    }

    for (u32 i = 0; i < flt->length; i++) mem[i] = ctx->buffers->win[(flt->start + i) & RAR29_WIN_MASK];

    u8 *out      = mem;
    u32 out_size = 0;

    const u64 block_start  = flt->start;
    const u32 block_length = flt->length;

    // Filters given for the same block run one after another, each on the output of the last.

    while (true)
    {
      const rar29_filter_t *cur = &stack[ctx->stack_at];

      u32 r[7];

      memcpy (r, cur->r, sizeof (r));

      r[6] = (u32) ctx->written;

      const bool ok = rar29_run_filter (mem, cur->type, r);

      out_size = cur->length & RAR29_VM_MEMMASK;

      const bool moved = ((cur->type == RAR29_FILTER_DELTA) || (cur->type == RAR29_FILTER_RGB) || (cur->type == RAR29_FILTER_AUDIO));

      out = mem;

      if ((moved == true) && (ok == true) && ((2 * out_size) <= RAR29_VM_MEMSIZE)) out = &mem[out_size];

      ctx->stack_at++;

      if (ctx->stack_at >= ctx->stack_cnt) break;

      const rar29_filter_t *next = &stack[ctx->stack_at];

      if (next->start  != block_start) break;
      if (next->length != out_size)    break;

      if (next->type == RAR29_FILTER_NONE)
      {
        ctx->unsupported = true;
        ctx->failed      = true;

        return;
      }

      if (out != mem) memmove (mem, out, out_size);
    }

    ctx->crc = rar29_crc32 (ctx->crc, out, out_size);

    ctx->written = block_start + block_length;
  }

  if (ctx->stack_at == ctx->stack_cnt)
  {
    ctx->stack_at  = 0;
    ctx->stack_cnt = 0;
  }

  u64 to = ctx->produced;

  if (ctx->stack_cnt > 0) to = MIN (to, stack[ctx->stack_at].start);

  if (to > ctx->written)
  {
    rar29_sum_window (ctx, ctx->written, to);

    ctx->written = to;
  }
}

static void rar29_emit (rar29_ctx_t *ctx, const u8 byte)
{
  if (ctx->produced >= ctx->dest_size)
  {
    ctx->failed = true;

    return;
  }

  // Bytes that have not reached the CRC32 yet are about to be overwritten.

  if (ctx->produced - ctx->written >= RAR29_WIN_SIZE)
  {
    rar29_flush (ctx);

    if (ctx->produced - ctx->written >= RAR29_WIN_SIZE)
    {
      ctx->failed = true;

      return;
    }
  }

  ctx->buffers->win[ctx->produced & RAR29_WIN_MASK] = byte;

  ctx->produced++;
}

// A match that reaches before the first byte of the file reads zeros, as UnRAR does for a file
// that does not continue a solid stream.

static void rar29_copy (rar29_ctx_t *ctx, const u32 length, const u32 dist)
{
  if (ctx->produced + length > ctx->dest_size)
  {
    ctx->failed = true;

    return;
  }

  const bool before = ((dist == 0) || (dist > RAR29_WIN_SIZE) || (dist > ctx->produced));

  for (u32 i = 0; (i < length) && (ctx->failed == false); i++)
  {
    const u8 byte = (before == true) ? 0 : ctx->buffers->win[(ctx->produced - dist) & RAR29_WIN_MASK];

    rar29_emit (ctx, byte);
  }
}

// ---- filter records ----

// A filter record is read out of the stream first and then parsed, with a bit reader of its own.

typedef struct rar29_code
{
  const u8 *buf;
  u32       size;
  u32       bit;

} rar29_code_t;

static u32 rar29_code_getbits (const rar29_code_t *code)
{
  const u32 byte = code->bit >> 3;

  u32 v = 0;

  if (byte + 0 < code->size) v |= (u32) code->buf[byte + 0] << 16;
  if (byte + 1 < code->size) v |= (u32) code->buf[byte + 1] <<  8;
  if (byte + 2 < code->size) v |= (u32) code->buf[byte + 2] <<  0;

  const u32 bits = (v >> (8 - (code->bit & 7))) & 0xffff;

  return bits;
}

static u32 rar29_code_read_data (rar29_code_t *code)
{
  u32 data = rar29_code_getbits (code);

  switch (data & 0xc000)
  {
    case 0x0000:

      code->bit += 6;

      data = (data >> 10) & 0xf;

      break;

    case 0x4000:

      if ((data & 0x3c00) == 0)
      {
        data = 0xffffff00 | ((data >> 2) & 0xff);

        code->bit += 14;
      }
      else
      {
        data = (data >> 6) & 0xff;

        code->bit += 10;
      }

      break;

    case 0x8000:

      code->bit += 2;

      data = rar29_code_getbits (code);

      code->bit += 16;

      break;

    default:

      code->bit += 2;

      data = rar29_code_getbits (code) << 16;

      code->bit += 16;

      data |= rar29_code_getbits (code);

      code->bit += 16;

      break;
  }

  return data;
}

// Which of the 6 standard filters a program is, by its length and CRC32.

static u32 rar29_filter_of (const u8 *program, const u32 size)
{
  u8 xor_sum = 0;

  for (u32 i = 1; i < size; i++) xor_sum ^= program[i];

  if (xor_sum != program[0]) return RAR29_FILTER_NONE;

  const u32 crc = rar29_crc32 (0xffffffff, program, size) ^ 0xffffffff;

  if ((size ==  53) && (crc == 0xad576887)) return RAR29_FILTER_E8;
  if ((size ==  57) && (crc == 0x3cd7e57e)) return RAR29_FILTER_E8E9;
  if ((size == 120) && (crc == 0x3769893f)) return RAR29_FILTER_ITANIUM;
  if ((size ==  29) && (crc == 0x0e06077d)) return RAR29_FILTER_DELTA;
  if ((size == 149) && (crc == 0x1c2c5dc8)) return RAR29_FILTER_RGB;
  if ((size == 216) && (crc == 0xbc85e701)) return RAR29_FILTER_AUDIO;

  return RAR29_FILTER_NONE;
}

static bool rar29_add_vm_code (rar29_ctx_t *ctx, const u32 first_byte, const u8 *buf, const u32 size)
{
  rar29_buffers_t *b = ctx->buffers;

  rar29_code_t code;

  code.buf  = buf;
  code.size = size;
  code.bit  = 0;

  u32 filt_pos = ctx->last_filter;

  if ((first_byte & 0x80) != 0)
  {
    filt_pos = rar29_code_read_data (&code);

    if (filt_pos == 0)
    {
      // Forget every filter seen so far.

      ctx->slot_cnt    = 0;
      ctx->last_filter = 0;
      ctx->stack_cnt   = 0;
      ctx->stack_at    = 0;
    }
    else
    {
      filt_pos--;
    }
  }

  if (filt_pos > ctx->slot_cnt) return false;

  ctx->last_filter = filt_pos;

  const bool new_filter = (filt_pos == ctx->slot_cnt);

  if (new_filter == true)
  {
    if (filt_pos >= RAR29_FILTERS_MAX) return false;

    b->slot_type[filt_pos]   = RAR29_FILTER_NONE;
    b->slot_length[filt_pos] = 0;

    ctx->slot_cnt++;
  }

  if (ctx->stack_cnt >= RAR29_FILTERS_MAX)
  {
    rar29_flush (ctx);

    if (ctx->stack_cnt >= RAR29_FILTERS_MAX) return false;
  }

  rar29_filter_t flt;

  memset (&flt, 0, sizeof (flt));

  u32 block_start = rar29_code_read_data (&code);

  if ((first_byte & 0x40) != 0) block_start += 258;

  // The position counts from where the record stands in the unpacked data.

  flt.start = ctx->produced + block_start;

  if ((first_byte & 0x20) != 0)
  {
    flt.length = rar29_code_read_data (&code);

    b->slot_length[filt_pos] = flt.length;
  }
  else
  {
    flt.length = b->slot_length[filt_pos];
  }

  flt.r[4] = flt.length;

  if ((first_byte & 0x10) != 0)
  {
    const u32 init_mask = rar29_code_getbits (&code) >> 9;

    code.bit += 7;

    for (u32 i = 0; i < 7; i++)
    {
      if ((init_mask & (1 << i)) != 0) flt.r[i] = rar29_code_read_data (&code);
    }
  }

  if (new_filter == true)
  {
    const u32 program_size = rar29_code_read_data (&code);

    if ((program_size >= 0x10000) || (program_size == 0)) return false;

    const u32 program_at = code.bit >> 3;

    if (program_at + program_size > size) return false;

    // UnRAR reads the program through its bit reader, so it need not start on a byte.

    u8 program[256];

    if (program_size <= sizeof (program))
    {
      for (u32 i = 0; i < program_size; i++)
      {
        program[i] = (u8) (rar29_code_getbits (&code) >> 8);

        code.bit += 8;
      }

      b->slot_type[filt_pos] = (u8) rar29_filter_of (program, program_size);
    }
  }

  // A filter longer than the VM memory is not something RAR writes.

  if (flt.length > RAR29_VM_MEMSIZE) return false;

  flt.type = b->slot_type[filt_pos];

  b->stack[ctx->stack_cnt] = flt;

  ctx->stack_cnt++;

  return true;
}

static bool rar29_ppm_char (rar29_ctx_t *ctx, u32 *out)
{
  const i32 sym = (i32) Ppmd7a_DecodeSymbol (&ctx->ppmd);

  if ((sym < 0) || (ctx->ran_off == true)) return false;

  *out = (u32) sym;

  return true;
}

// Reads a filter record out of the LZ stream or, when ppm is set, out of the PPM stream.

static bool rar29_read_vm_code (rar29_ctx_t *ctx, const bool ppm)
{
  // The longest record a 16 bit length can announce.

  static __thread u8 buf[0x10000];

  u32 next[3];

  for (u32 i = 0; i < 3; i++) next[i] = 0;

  if (ppm == true)
  {
    if (rar29_ppm_char (ctx, &next[0]) == false) return false;
  }
  else
  {
    next[0] = rar29_getbits (ctx) >> 8;

    rar29_addbits (ctx, 8);
  }

  const u32 first_byte = next[0];

  u32 length = (first_byte & 7) + 1;

  if (length == 7)
  {
    if (ppm == true)
    {
      if (rar29_ppm_char (ctx, &next[1]) == false) return false;
    }
    else
    {
      next[1] = rar29_getbits (ctx) >> 8;

      rar29_addbits (ctx, 8);
    }

    length = next[1] + 7;
  }
  else if (length == 8)
  {
    if (ppm == true)
    {
      if (rar29_ppm_char (ctx, &next[1]) == false) return false;
      if (rar29_ppm_char (ctx, &next[2]) == false) return false;

      length = (next[1] * 256) + next[2];
    }
    else
    {
      length = rar29_getbits (ctx);

      rar29_addbits (ctx, 16);
    }
  }

  if (length == 0) return false;

  for (u32 i = 0; i < length; i++)
  {
    if (ppm == true)
    {
      u32 ch = 0;

      if (rar29_ppm_char (ctx, &ch) == false) return false;

      buf[i] = (u8) ch;
    }
    else
    {
      buf[i] = (u8) (rar29_getbits (ctx) >> 8);

      rar29_addbits (ctx, 8);
    }
  }

  if (ctx->ran_off == true) return false;

  const bool ok = rar29_add_vm_code (ctx, first_byte, buf, length);

  return ok;
}

// ---- blocks ----

static bool rar29_ppm_init (rar29_ctx_t *ctx)
{
  const u32 flags = rar29_byte_in_read (&ctx->ppm_in.vt);

  const bool reset = ((flags & 0x20) != 0);

  u32 max_mb = 0;

  if (reset == true)
  {
    max_mb = rar29_byte_in_read (&ctx->ppm_in.vt);
  }
  else
  {
    // A block that continues a model needs one to continue.

    if (ctx->ppm_ready == false) return false;
  }

  if ((flags & 0x40) != 0) ctx->ppm_esc = rar29_byte_in_read (&ctx->ppm_in.vt);

  ctx->ppmd.rc.dec.Stream = &ctx->ppm_in.vt;

  if (Ppmd7a_RangeDec_Init (&ctx->ppmd.rc.dec) == False) return false;

  if (ctx->ran_off == true) return false;

  if (reset == true)
  {
    u32 max_order = (flags & 0x1f) + 1;

    if (max_order > 16) max_order = 16 + ((max_order - 16) * 3);

    if (max_order == 1) return false;

    if (Ppmd7_Alloc (&ctx->ppmd, (UInt32) (max_mb + 1) << 20, &ctx->ppm_arena.vt) == False) return false;

    Ppmd7_Init (&ctx->ppmd, max_order);

    ctx->ppm_ready = true;
  }

  return true;
}

static bool rar29_read_tables (rar29_ctx_t *ctx)
{
  u8 bit_length[RAR29_BC];
  u8 table[RAR29_TABLE_SIZE];

  rar29_addbits (ctx, (u32) ((8 - (ctx->bit & 7)) & 7));

  const u32 bit_field = rar29_getbits (ctx);

  if ((bit_field & 0x8000) != 0)
  {
    ctx->block_ppm = true;

    const bool ok = rar29_ppm_init (ctx);

    return ok;
  }

  ctx->block_ppm = false;

  ctx->prev_low_dist      = 0;
  ctx->low_dist_rep_count = 0;

  if ((bit_field & 0x4000) == 0) memset (ctx->old_table, 0, sizeof (ctx->old_table));

  rar29_addbits (ctx, 2);

  for (u32 i = 0; i < RAR29_BC; i++)
  {
    const u32 length = (rar29_getbits (ctx) >> 12) & 0xf;

    rar29_addbits (ctx, 4);

    if (length != 15)
    {
      bit_length[i] = (u8) length;

      continue;
    }

    const u32 zero_count = (rar29_getbits (ctx) >> 12) & 0xf;

    rar29_addbits (ctx, 4);

    if (zero_count == 0)
    {
      bit_length[i] = 15;

      continue;
    }

    for (u32 j = 0; (j < zero_count + 2) && (i < RAR29_BC); j++, i++) bit_length[i] = 0;

    i--;
  }

  if (rar29_code_fits (bit_length, RAR29_BC) == false) return false;

  rar29_make_tables (bit_length, &ctx->bd, RAR29_BC);

  for (u32 i = 0; i < RAR29_TABLE_SIZE; )
  {
    if (ctx->ran_off == true) return false;

    const u32 number = rar29_decode_number (ctx, &ctx->bd);

    if (number < 16)
    {
      table[i] = (u8) ((number + ctx->old_table[i]) & 0xf);

      i++;

      continue;
    }

    u32 n = 0;

    if ((number == 16) || (number == 18))
    {
      n = (rar29_getbits (ctx) >> 13) + 3;

      rar29_addbits (ctx, 3);
    }
    else
    {
      n = (rar29_getbits (ctx) >> 9) + 11;

      rar29_addbits (ctx, 7);
    }

    if (number < 18)
    {
      // There is nothing to repeat at the first position.

      if (i == 0) return false;

      for (u32 j = 0; (j < n) && (i < RAR29_TABLE_SIZE); j++, i++) table[i] = table[i - 1];
    }
    else
    {
      for (u32 j = 0; (j < n) && (i < RAR29_TABLE_SIZE); j++, i++) table[i] = 0;
    }
  }

  if (ctx->ran_off == true) return false;

  ctx->tables_read = true;

  if (rar29_code_fits (&table[0], RAR29_NC) == false) return false;

  rar29_make_tables (&table[0],                               &ctx->ld,  RAR29_NC);
  if (rar29_code_fits (&table[RAR29_NC], RAR29_DC) == false) return false;

  rar29_make_tables (&table[RAR29_NC],                        &ctx->dd,  RAR29_DC);
  if (rar29_code_fits (&table[RAR29_NC + RAR29_DC], RAR29_LDC) == false) return false;

  rar29_make_tables (&table[RAR29_NC + RAR29_DC],             &ctx->ldd, RAR29_LDC);
  if (rar29_code_fits (&table[RAR29_NC + RAR29_DC + RAR29_LDC], RAR29_RC) == false) return false;

  rar29_make_tables (&table[RAR29_NC + RAR29_DC + RAR29_LDC], &ctx->rd,  RAR29_RC);

  memcpy (ctx->old_table, table, sizeof (ctx->old_table));

  return true;
}

// One step of a PPM block. Returns false when the file or the stream ends.

static bool rar29_step_ppm (rar29_ctx_t *ctx)
{
  u32 ch = 0;

  if (rar29_ppm_char (ctx, &ch) == false)
  {
    ctx->failed = true;

    return false;
  }

  if (ch != ctx->ppm_esc)
  {
    rar29_emit (ctx, (u8) ch);

    return true;
  }

  u32 next = 0;

  if (rar29_ppm_char (ctx, &next) == false)
  {
    ctx->failed = true;

    return false;
  }

  // 0 ends the PPM block, 2 ends the file, 3 is a filter record, 4 a match and 5 a run of the
  // last byte. Anything else is the escape character itself.

  if (next == 0)
  {
    const bool ok = rar29_read_tables (ctx);

    if (ok == false) ctx->failed = true;

    return ok;
  }

  if (next == 2) return false;

  if (next == 3)
  {
    const bool ok = rar29_read_vm_code (ctx, true);

    if (ok == false) ctx->failed = true;

    return ok;
  }

  if (next == 4)
  {
    u32 dist   = 0;
    u32 length = 0;

    for (u32 i = 0; i < 4; i++)
    {
      u32 c = 0;

      if (rar29_ppm_char (ctx, &c) == false)
      {
        ctx->failed = true;

        return false;
      }

      if (i == 3)
      {
        length = c;
      }
      else
      {
        dist = (dist << 8) + c;
      }
    }

    rar29_copy (ctx, length + 32, dist + 2);

    return true;
  }

  if (next == 5)
  {
    u32 length = 0;

    if (rar29_ppm_char (ctx, &length) == false)
    {
      ctx->failed = true;

      return false;
    }

    rar29_copy (ctx, length + 4, 1);

    return true;
  }

  rar29_emit (ctx, (u8) ch);

  return true;
}

static void rar29_insert_old_dist (rar29_ctx_t *ctx, const u32 dist)
{
  ctx->old_dist[3] = ctx->old_dist[2];
  ctx->old_dist[2] = ctx->old_dist[1];
  ctx->old_dist[1] = ctx->old_dist[0];
  ctx->old_dist[0] = dist;
}

// One step of an LZ block. Returns false when the file or the stream ends.

static bool rar29_step_lz (rar29_ctx_t *ctx)
{
  static const u8 ldecode[]  = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 10, 12, 14, 16, 20, 24, 28, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224 };
  static const u8 lbits[]    = { 0, 0, 0, 0, 0, 0, 0, 0, 1,  1,  1,  1,  2,  2,  2,  2,  3,  3,  3,  3,  4,  4,  4,   4,   5,   5,   5,   5 };
  static const u8 sddecode[] = { 0, 4, 8, 16, 32, 64, 128, 192 };
  static const u8 sdbits[]   = { 2, 2, 3,  4,  5,  6,   6,   6 };

  // 60 distance slots: 4 with no extra bits, then pairs with 1 to 15 bits, 14 with 16 bits and 12
  // with 18.

  static const u8 dbit_counts[] = { 4, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 14, 0, 12 };

  static __thread u32  ddecode[RAR29_DC];
  static __thread u8   dbits[RAR29_DC];
  static __thread bool dtables_ready = false;

  if (dtables_ready == false)
  {
    u32 dist = 0;
    u32 slot = 0;

    for (u32 bit_length = 0; bit_length < 19; bit_length++)
    {
      for (u32 j = 0; j < dbit_counts[bit_length]; j++, slot++, dist += (1u << bit_length))
      {
        ddecode[slot] = dist;
        dbits[slot]   = (u8) bit_length;
      }
    }

    dtables_ready = true;
  }

  u32 number = rar29_decode_number (ctx, &ctx->ld);

  if (number < 256)
  {
    rar29_emit (ctx, (u8) number);

    return true;
  }

  if (number >= 271)
  {
    number -= 271;

    u32 length = ldecode[number] + 3;

    const u32 length_bits = lbits[number];

    if (length_bits > 0)
    {
      length += rar29_getbits (ctx) >> (16 - length_bits);

      rar29_addbits (ctx, length_bits);
    }

    const u32 dist_number = rar29_decode_number (ctx, &ctx->dd);

    if (dist_number >= RAR29_DC)
    {
      ctx->failed = true;

      return false;
    }

    u32 dist = ddecode[dist_number] + 1;

    const u32 bits = dbits[dist_number];

    if (bits > 0)
    {
      if (dist_number > 9)
      {
        if (bits > 4)
        {
          dist += (rar29_getbits (ctx) >> (20 - bits)) << 4;

          rar29_addbits (ctx, bits - 4);
        }

        if (ctx->low_dist_rep_count > 0)
        {
          ctx->low_dist_rep_count--;

          dist += ctx->prev_low_dist;
        }
        else
        {
          const u32 low_dist = rar29_decode_number (ctx, &ctx->ldd);

          if (low_dist == 16)
          {
            ctx->low_dist_rep_count = RAR29_LOW_DIST_REP_COUNT - 1;

            dist += ctx->prev_low_dist;
          }
          else
          {
            dist += low_dist;

            ctx->prev_low_dist = low_dist;
          }
        }
      }
      else
      {
        dist += rar29_getbits (ctx) >> (16 - bits);

        rar29_addbits (ctx, bits);
      }
    }

    if (dist >= 0x2000)
    {
      length++;

      if (dist >= 0x40000) length++;
    }

    rar29_insert_old_dist (ctx, dist);

    ctx->last_length = length;

    rar29_copy (ctx, length, dist);

    return true;
  }

  if (number == 256)
  {
    // The end of a block: either new tables follow, or the file ends here.

    const u32 bit_field = rar29_getbits (ctx);

    if ((bit_field & 0x8000) != 0)
    {
      rar29_addbits (ctx, 1);

      const bool ok = rar29_read_tables (ctx);

      if (ok == false) ctx->failed = true;

      return ok;
    }

    rar29_addbits (ctx, 2);

    return false;
  }

  if (number == 257)
  {
    const bool ok = rar29_read_vm_code (ctx, false);

    if (ok == false) ctx->failed = true;

    return ok;
  }

  if (number == 258)
  {
    if (ctx->last_length != 0) rar29_copy (ctx, ctx->last_length, ctx->old_dist[0]);

    return true;
  }

  if (number < 263)
  {
    const u32 dist_num = number - 259;

    const u32 dist = ctx->old_dist[dist_num];

    for (u32 i = dist_num; i > 0; i--) ctx->old_dist[i] = ctx->old_dist[i - 1];

    ctx->old_dist[0] = dist;

    const u32 length_number = rar29_decode_number (ctx, &ctx->rd);

    if (length_number >= RAR29_RC)
    {
      ctx->failed = true;

      return false;
    }

    u32 length = ldecode[length_number] + 2;

    const u32 bits = lbits[length_number];

    if (bits > 0)
    {
      length += rar29_getbits (ctx) >> (16 - bits);

      rar29_addbits (ctx, bits);
    }

    ctx->last_length = length;

    rar29_copy (ctx, length, dist);

    return true;
  }

  number -= 263;

  u32 dist = sddecode[number] + 1;

  const u32 bits = sdbits[number];

  if (bits > 0)
  {
    dist += rar29_getbits (ctx) >> (16 - bits);

    rar29_addbits (ctx, bits);
  }

  rar29_insert_old_dist (ctx, dist);

  ctx->last_length = 2;

  rar29_copy (ctx, 2, dist);

  return true;
}

// The 4 bits at a bit position, most significant bit first.

static u32 rar29_nibble (const u8 *in, const u32 bit)
{
  const u32 byte = bit >> 3;

  const u32 pair = ((u32) in[byte + 0] << 8) | (u32) in[byte + 1];

  const u32 nibble = (pair >> (12 - (bit & 7))) & 0xf;

  return nibble;
}

// Whether the first decrypted block can start a RAR3 stream. The first 16 bytes are enough to
// ask this, and it turns away nearly every wrong password before anything else is decrypted.
//
// A PPM block that opens a file has to reset its model. An LZ block cannot keep a table it does
// not have yet, and the 20 code lengths of its pre-table have to form a complete prefix code. The
// LZ test is implemented similar to the check_huffman () function from John The Ripper, with
// permission from magnum and JtR.

static bool rar29_first_block_ok (const u8 *in)
{
  if ((in[0] & 0x80) != 0)
  {
    const bool reset = ((in[0] & 0x20) != 0);

    return reset;
  }

  if ((in[0] & 0x40) != 0) return false;

  // The pre-table is 20 code lengths of 4 bits behind the 2 flag bits, with a length of 15
  // followed by a 4 bit count of zero lengths. A table that runs past the 16 bytes is left to the
  // decoder.

  u8 bit_length[RAR29_BC];

  u32 bit = 2;

  for (u32 i = 0; i < RAR29_BC; i++)
  {
    if (bit + 20 > 128) return true;

    const u32 length = rar29_nibble (in, bit);

    bit += 4;

    if (length != 15)
    {
      bit_length[i] = (u8) length;

      continue;
    }

    const u32 zero_count = rar29_nibble (in, bit);

    bit += 4;

    if (zero_count == 0)
    {
      bit_length[i] = 15;

      continue;
    }

    for (u32 j = 0; (j < zero_count + 2) && (i < RAR29_BC); j++, i++) bit_length[i] = 0;

    i--;
  }

  u32 count[16];

  memset (count, 0, sizeof (count));

  for (u32 i = 0; i < RAR29_BC; i++) count[bit_length[i]]++;

  count[0] = 0;

  u32 used = 0;

  for (u32 i = 1; i < 16; i++) used += count[i] << (15 - i);

  // Complete means the codes fill the code space exactly.

  const bool complete = (used == 0x8000);

  return complete;
}

// Unpacks one RAR3 file that does not continue a solid stream. Returns true when the stream
// produced exactly unpack_size bytes, with their CRC32 in *crc32. *ran_off says the stream asked
// for more input than it was given, which is the cue to decrypt the rest. *unsupported says the
// stream uses a filter this decoder does not implement.

static bool rar29_unpack (rar29_buffers_t *buffers, const u8 *in, const u64 pack_size, const u64 unpack_size, u32 *crc32, bool *ran_off, bool *unsupported)
{
  // Too large for the hook thread's stack, so it lives in static storage per thread.

  static __thread rar29_ctx_t ctx;

  memset (&ctx, 0, sizeof (ctx));

  rar29_crc32_init ();

  ctx.in        = in;
  ctx.in_bits   = pack_size * 8;
  ctx.buffers   = buffers;
  ctx.dest_size = unpack_size;
  ctx.crc       = 0xffffffff;
  ctx.ppm_esc   = 2;

  ctx.ppm_in.vt.Read = rar29_byte_in_read;
  ctx.ppm_in.ctx     = &ctx;

  ctx.ppm_arena.vt.Alloc = rar29_arena_alloc;
  ctx.ppm_arena.vt.Free  = rar29_arena_free;
  ctx.ppm_arena.buffers  = buffers;

  Ppmd7_Construct (&ctx.ppmd);

  *crc32       = 0;
  *ran_off     = false;
  *unsupported = false;

  bool more = rar29_read_tables (&ctx);

  if (more == false) ctx.failed = true;

  while (more == true)
  {
    if (ctx.ran_off == true) break;
    if (ctx.failed  == true) break;

    if (ctx.block_ppm == true)
    {
      more = rar29_step_ppm (&ctx);
    }
    else
    {
      more = rar29_step_lz (&ctx);
    }
  }

  *ran_off     = ctx.ran_off;
  *unsupported = ctx.unsupported;

  if (ctx.failed == true) return false;

  rar29_flush (&ctx);

  *unsupported = ctx.unsupported;

  if (ctx.failed == true) return false;

  *crc32 = ctx.crc ^ 0xffffffff;

  const bool complete = ((ctx.produced == ctx.dest_size) && (ctx.written == ctx.dest_size));

  return complete;
}
