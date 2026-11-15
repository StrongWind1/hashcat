/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

// What the coders of a 7z folder do to the data once it has been decrypted, for the modules that
// read 7z lines. It is included by a module as one translation unit, the way rar3_decode.c is.
//
// LZMA, LZMA2, PPMd, BCJ2, the branch converters and Delta are the decoders of 7-Zip itself, which
// its author placed in the public domain. They sit unchanged in sevenzip/ and ORIGIN.txt there
// says where each file came from. Deflate, Deflate64 and BZip2 are written for this file, because
// 7-Zip decodes them in C++ under another licence. Zstandard goes to the library hashcat loads.

#include "sevenzip/LzmaDec.c"
#include "sevenzip/Lzma2Dec.c"
#include "sevenzip/Bcj2.c"
#include "sevenzip/Bra.c"
#include "sevenzip/Bra86.c"
#include "sevenzip/Delta.c"
#include "sevenzip/Ppmd7.c"
#include "sevenzip/Ppmd7Dec.c"

// How a decoder stopped.

#define SZ_DONE  0 // the bytes asked for are there
#define SZ_END   1 // the stream ended, and ended properly, before that
#define SZ_SHORT 2 // the input ran out, and nothing was wrong with it up to there
#define SZ_BAD   3 // this is not such a stream

// The coders a line may name.

#define SZ_KIND_NONE      0
#define SZ_KIND_LZMA      1
#define SZ_KIND_LZMA2     2
#define SZ_KIND_PPMD      3
#define SZ_KIND_DEFLATE   4
#define SZ_KIND_DEFLATE64 5
#define SZ_KIND_BZIP2     6
#define SZ_KIND_ZSTD      7
#define SZ_KIND_DELTA     8
#define SZ_KIND_X86       9
#define SZ_KIND_PPC       10
#define SZ_KIND_IA64      11
#define SZ_KIND_ARM       12
#define SZ_KIND_ARMT      13
#define SZ_KIND_SPARC     14
#define SZ_KIND_ARM64     15
#define SZ_KIND_RISCV     16
#define SZ_KIND_SWAP2     17
#define SZ_KIND_SWAP4     18
#define SZ_KIND_BCJ2      19

#define SZ_KIND_IS_PACKER(k) (((k) >= SZ_KIND_LZMA)  && ((k) <= SZ_KIND_ZSTD))
#define SZ_KIND_IS_FILTER(k) (((k) >= SZ_KIND_DELTA) && ((k) <= SZ_KIND_SWAP4))

// A PPMd model is allocated in one piece of the size the archive names. 7-Zip takes up to 4 GiB
// less a few bytes. Every hook thread keeps one, so the limit here is lower.

#define SZ_PPMD_MEM_MAX (256u * 1024 * 1024)

#define SZ_BZIP2_BLOCK_MAX 900000
#define SZ_BZIP2_SELECTORS 18002
#define SZ_BZIP2_GROUPS    6
#define SZ_BZIP2_SYMBOLS   258
#define SZ_BZIP2_CODE_MAX  20

typedef struct sz_coder_id
{
  u32 kind;
  u32 id_len;
  u8  id[4];

} sz_coder_id_t;

static const sz_coder_id_t SZ_CODER_IDS[] =
{
  { SZ_KIND_LZMA,      3, { 0x03, 0x01, 0x01, 0x00 } },
  { SZ_KIND_LZMA2,     1, { 0x21, 0x00, 0x00, 0x00 } },
  { SZ_KIND_PPMD,      3, { 0x03, 0x04, 0x01, 0x00 } },
  { SZ_KIND_DEFLATE,   3, { 0x04, 0x01, 0x08, 0x00 } },
  { SZ_KIND_DEFLATE64, 3, { 0x04, 0x01, 0x09, 0x00 } },
  { SZ_KIND_BZIP2,     3, { 0x04, 0x02, 0x02, 0x00 } },
  { SZ_KIND_ZSTD,      4, { 0x04, 0xf7, 0x11, 0x01 } },
  { SZ_KIND_DELTA,     1, { 0x03, 0x00, 0x00, 0x00 } },
  { SZ_KIND_X86,       4, { 0x03, 0x03, 0x01, 0x03 } },
  { SZ_KIND_PPC,       4, { 0x03, 0x03, 0x02, 0x05 } },
  { SZ_KIND_IA64,      4, { 0x03, 0x03, 0x04, 0x01 } },
  { SZ_KIND_ARM,       4, { 0x03, 0x03, 0x05, 0x01 } },
  { SZ_KIND_ARMT,      4, { 0x03, 0x03, 0x07, 0x01 } },
  { SZ_KIND_SPARC,     4, { 0x03, 0x03, 0x08, 0x05 } },
  { SZ_KIND_ARM64,     1, { 0x0a, 0x00, 0x00, 0x00 } },
  { SZ_KIND_RISCV,     1, { 0x0b, 0x00, 0x00, 0x00 } },
  { SZ_KIND_SWAP2,     3, { 0x02, 0x03, 0x02, 0x00 } },
  { SZ_KIND_SWAP4,     3, { 0x02, 0x03, 0x04, 0x00 } },
  { SZ_KIND_BCJ2,      4, { 0x03, 0x03, 0x01, 0x1b } },
};

static u32 sz_kind_of (const u8 *id, const u32 id_len)
{
  for (size_t i = 0; i < sizeof (SZ_CODER_IDS) / sizeof (SZ_CODER_IDS[0]); i++)
  {
    if (SZ_CODER_IDS[i].id_len != id_len) continue;

    if (memcmp (SZ_CODER_IDS[i].id, id, id_len) == 0) return SZ_CODER_IDS[i].kind;
  }

  return SZ_KIND_NONE;
}

static const sz_coder_id_t *sz_id_of (const u32 kind)
{
  for (size_t i = 0; i < sizeof (SZ_CODER_IDS) / sizeof (SZ_CODER_IDS[0]); i++)
  {
    if (SZ_CODER_IDS[i].kind == kind) return &SZ_CODER_IDS[i];
  }

  return NULL;
}

// What one hook thread keeps between candidates, so that nothing large is allocated for each.

typedef struct sz_mem
{
  CPpmd7 ppmd;
  u32    ppmd_mem;
  bool   ppmd_ready;

  u32   *bz_tt;
  u8    *bz_selector;
  bool   bz_crc_ready;
  u32    bz_crc[256];

} sz_mem_t;

static void *sz_alloc (MAYBE_UNUSED ISzAllocPtr p, size_t size)
{
  return malloc (size);
}

static void sz_free (MAYBE_UNUSED ISzAllocPtr p, void *address)
{
  free (address);
}

static const ISzAlloc SZ_ALLOC = { sz_alloc, sz_free };

static void sz_mem_free (sz_mem_t *mem)
{
  if (mem->ppmd_ready == true) Ppmd7_Free (&mem->ppmd, &SZ_ALLOC);

  free (mem->bz_tt);
  free (mem->bz_selector);

  memset (mem, 0, sizeof (sz_mem_t));
}

/**
 * LZMA and LZMA2
 */

// With to_end the stream has to stop exactly where the output does: the range coder is back at
// zero and nothing is left over. That is what tells a real stream from one a wrong key produced
// when there is no checksum to ask.

static int sz_lzma_status (const SRes res, const ELzmaStatus status, const size_t produced, const size_t want)
{
  if (res == SZ_ERROR_INPUT_EOF) return SZ_SHORT;

  if (res != SZ_OK) return SZ_BAD;

  if (produced == want) return SZ_DONE;

  if (status == LZMA_STATUS_FINISHED_WITH_MARK) return SZ_END;

  if (status == LZMA_STATUS_NEEDS_MORE_INPUT) return SZ_SHORT;

  return SZ_BAD;
}

static int sz_lzma (const u8 *props, const u32 props_len, const u8 *in, const size_t in_len, u8 *out, const size_t want, const bool to_end, size_t *produced, size_t *consumed)
{
  *produced = 0;
  *consumed = 0;

  // 7-Zip takes properties that are longer than it needs and reads the start of them

  if (props_len < LZMA_PROPS_SIZE) return SZ_BAD;

  SizeT dst = want;
  SizeT src = in_len;

  ELzmaStatus status = LZMA_STATUS_NOT_SPECIFIED;

  const SRes res = LzmaDecode (out, &dst, in, &src, props, LZMA_PROPS_SIZE, (to_end == true) ? LZMA_FINISH_END : LZMA_FINISH_ANY, &status, &SZ_ALLOC);

  *produced = dst;
  *consumed = src;

  return sz_lzma_status (res, status, dst, want);
}

static int sz_lzma2 (const u8 *props, const u32 props_len, const u8 *in, const size_t in_len, u8 *out, const size_t want, const bool to_end, size_t *produced, size_t *consumed)
{
  *produced = 0;
  *consumed = 0;

  if ((props_len != 1) || (props[0] > 40)) return SZ_BAD;

  SizeT dst = want;
  SizeT src = in_len;

  ELzmaStatus status = LZMA_STATUS_NOT_SPECIFIED;

  const SRes res = Lzma2Decode (out, &dst, in, &src, props[0], (to_end == true) ? LZMA_FINISH_END : LZMA_FINISH_ANY, &status, &SZ_ALLOC);

  *produced = dst;
  *consumed = src;

  return sz_lzma_status (res, status, dst, want);
}

/**
 * PPMd
 */

typedef struct sz_byte_in
{
  IByteIn vt;

  const u8 *cur;
  const u8 *end;

  bool over;

} sz_byte_in_t;

static Byte sz_byte_in_read (IByteInPtr pp)
{
  sz_byte_in_t *p = Z7_CONTAINER_FROM_VTBL (pp, sz_byte_in_t, vt);

  if (p->cur != p->end) return *p->cur++;

  p->over = true;

  return 0;
}

static int sz_ppmd (sz_mem_t *mem, const u8 *props, const u32 props_len, const u8 *in, const size_t in_len, u8 *out, const size_t want, const bool to_end, size_t *produced, size_t *consumed)
{
  *produced = 0;
  *consumed = 0;

  if (props_len < 5) return SZ_BAD;

  const u32 order = props[0];
  const u32 size  = ((u32) props[1]) | ((u32) props[2] << 8) | ((u32) props[3] << 16) | ((u32) props[4] << 24);

  if ((order < PPMD7_MIN_ORDER) || (order > PPMD7_MAX_ORDER)) return SZ_BAD;

  if ((size < PPMD7_MIN_MEM_SIZE) || (size > SZ_PPMD_MEM_MAX)) return SZ_BAD;

  if ((mem->ppmd_ready == false) || (mem->ppmd_mem != size))
  {
    if (mem->ppmd_ready == false) Ppmd7_Construct (&mem->ppmd);

    mem->ppmd_ready = true;
    mem->ppmd_mem   = 0;

    if (Ppmd7_Alloc (&mem->ppmd, size, &SZ_ALLOC) == 0) return SZ_BAD;

    mem->ppmd_mem = size;
  }

  sz_byte_in_t stream;

  stream.vt.Read = sz_byte_in_read;
  stream.cur     = in;
  stream.end     = in + in_len;
  stream.over    = false;

  mem->ppmd.rc.dec.Stream = &stream.vt;

  if (Ppmd7z_RangeDec_Init (&mem->ppmd.rc.dec) == 0) return (stream.over == true) ? SZ_SHORT : SZ_BAD;

  if (stream.over == true) return SZ_SHORT;

  Ppmd7_Init (&mem->ppmd, order);

  size_t pos = 0;

  int rc = SZ_DONE;

  while (pos < want)
  {
    const int sym = Ppmd7z_DecodeSymbol (&mem->ppmd);

    if (stream.over == true) { rc = SZ_SHORT; break; }

    if (sym < 0) { rc = SZ_BAD; break; }

    out[pos++] = (u8) sym;
  }

  *produced = pos;
  *consumed = (size_t) (stream.cur - in);

  if ((rc == SZ_DONE) && (to_end == true))
  {
    if (Ppmd7z_RangeDec_IsFinishedOK (&mem->ppmd.rc.dec) == 0) return SZ_BAD;
  }

  return rc;
}

/**
 * Deflate and Deflate64
 */

typedef struct sz_bits
{
  const u8 *in;

  size_t len;
  size_t pos;

  u32 buf;
  u32 cnt;

  bool over;

} sz_bits_t;

// low bit first, as Deflate packs them

static u32 sz_bits_low (sz_bits_t *b, const u32 n)
{
  while (b->cnt < n)
  {
    u32 c = 0;

    if (b->pos < b->len)
    {
      c = b->in[b->pos++];
    }
    else
    {
      b->over = true;
    }

    b->buf |= c << b->cnt;
    b->cnt += 8;
  }

  const u32 v = b->buf & ((1u << n) - 1);

  b->buf >>= n;
  b->cnt  -= n;

  return v;
}

typedef struct sz_huff
{
  u16 count[16];
  u16 symbol[288];

} sz_huff_t;

// Returns how many codes of the longest length are unused: 0 for a complete set, more for one
// that leaves room, less for one that claims more room than there is.

static int sz_huff_build (sz_huff_t *h, const u8 *lens, const u32 n)
{
  memset (h->count, 0, sizeof (h->count));

  for (u32 i = 0; i < n; i++) h->count[lens[i]]++;

  if (h->count[0] == n) return 0;

  int left = 1;

  for (u32 len = 1; len < 16; len++)
  {
    left <<= 1;
    left  -= h->count[len];

    if (left < 0) return left;
  }

  u16 offs[16];

  offs[1] = 0;

  for (u32 len = 1; len < 15; len++) offs[len + 1] = offs[len] + h->count[len];

  for (u32 i = 0; i < n; i++)
  {
    if (lens[i] != 0) h->symbol[offs[lens[i]]++] = (u16) i;
  }

  return left;
}

static int sz_huff_decode (sz_bits_t *b, const sz_huff_t *h)
{
  int code  = 0;
  int first = 0;
  int index = 0;

  for (u32 len = 1; len < 16; len++)
  {
    code |= (int) sz_bits_low (b, 1);

    const int count = h->count[len];

    if (code - count < first) return h->symbol[index + (code - first)];

    index  += count;
    first  += count;
    first <<= 1;
    code  <<= 1;
  }

  return -1;
}

static const u16 SZ_LEN_BASE[29]  = { 3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258 };
static const u8  SZ_LEN_EXTRA[29] = { 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0 };
static const u32 SZ_DIST_BASE[32] = { 1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577, 32769, 49153 };
static const u8  SZ_DIST_EXTRA[32] = { 0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13, 14, 14 };

static const u8 SZ_CLEN_ORDER[19] = { 16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15 };

// Deflate64 differs in three places: the last length code takes 16 extra bits and starts at 3,
// two more distance codes reach back 64 KiB, and the window is that large.

static int sz_inflate (const u8 *in, const size_t in_len, u8 *out, const size_t want, const bool wide, size_t *produced, size_t *consumed)
{
  sz_bits_t b;

  memset (&b, 0, sizeof (b));

  b.in  = in;
  b.len = in_len;

  const u32 dist_codes = (wide == true) ? 32 : 30;
  const u32 window     = (wide == true) ? 65536 : 32768;

  size_t pos = 0;

  int rc = SZ_END;

  sz_huff_t lit;
  sz_huff_t dist;

  u8 lens[288 + 32];

  for (;;)
  {
    const u32 last = sz_bits_low (&b, 1);
    const u32 type = sz_bits_low (&b, 2);

    if (b.over == true) { rc = SZ_SHORT; break; }

    if (type == 3) { rc = SZ_BAD; break; }

    if (type == 0)
    {
      b.buf = 0;
      b.cnt = 0;

      const u32 len  = sz_bits_low (&b, 16);
      const u32 nlen = sz_bits_low (&b, 16);

      if (b.over == true) { rc = SZ_SHORT; break; }

      if (len != (~nlen & 0xffff)) { rc = SZ_BAD; break; }

      size_t n = len;

      if (n > in_len - b.pos) { n = in_len - b.pos; rc = SZ_SHORT; }
      if (n > want - pos)     { n = want - pos;     rc = SZ_DONE;  }

      memcpy (out + pos, in + b.pos, n);

      pos   += n;
      b.pos += n;

      if (n != len) break;

      if (pos == want) { rc = SZ_DONE; break; }

      if (last == 1) break;

      continue;
    }

    if (type == 1)
    {
      for (u32 i =   0; i < 144; i++) lens[i] = 8;
      for (u32 i = 144; i < 256; i++) lens[i] = 9;
      for (u32 i = 256; i < 280; i++) lens[i] = 7;
      for (u32 i = 280; i < 288; i++) lens[i] = 8;

      sz_huff_build (&lit, lens, 288);

      for (u32 i = 0; i < 32; i++) lens[i] = 5;

      sz_huff_build (&dist, lens, 32);
    }
    else
    {
      const u32 nlit  = sz_bits_low (&b, 5) + 257;
      const u32 ndist = sz_bits_low (&b, 5) + 1;
      const u32 nclen = sz_bits_low (&b, 4) + 4;

      if (b.over == true) { rc = SZ_SHORT; break; }

      if ((nlit > 286) || (ndist > dist_codes)) { rc = SZ_BAD; break; }

      u8 clens[19];

      memset (clens, 0, sizeof (clens));

      for (u32 i = 0; i < nclen; i++) clens[SZ_CLEN_ORDER[i]] = (u8) sz_bits_low (&b, 3);

      sz_huff_t clen;

      if (sz_huff_build (&clen, clens, 19) != 0) { rc = (b.over == true) ? SZ_SHORT : SZ_BAD; break; }

      u32 idx = 0;

      bool bad = false;

      while (idx < nlit + ndist)
      {
        const int sym = sz_huff_decode (&b, &clen);

        if (b.over == true) break;

        if (sym < 0) { bad = true; break; }

        if (sym < 16)
        {
          lens[idx++] = (u8) sym;

          continue;
        }

        u32 prev = 0;
        u32 rep  = 0;

        if (sym == 16)
        {
          if (idx == 0) { bad = true; break; }

          prev = lens[idx - 1];
          rep  = 3 + sz_bits_low (&b, 2);
        }
        else if (sym == 17)
        {
          rep = 3 + sz_bits_low (&b, 3);
        }
        else
        {
          rep = 11 + sz_bits_low (&b, 7);
        }

        if (idx + rep > nlit + ndist) { bad = true; break; }

        while (rep--) lens[idx++] = (u8) prev;
      }

      if (b.over == true) { rc = SZ_SHORT; break; }

      if ((bad == true) || (lens[256] == 0)) { rc = SZ_BAD; break; }

      // a set that leaves room is allowed only when it holds a single code

      int left = sz_huff_build (&lit, lens, nlit);

      if ((left < 0) || ((left > 0) && (nlit - lit.count[0] != 1))) { rc = SZ_BAD; break; }

      left = sz_huff_build (&dist, lens + nlit, ndist);

      if ((left < 0) || ((left > 0) && (ndist - dist.count[0] != 1))) { rc = SZ_BAD; break; }
    }

    bool stop = false;

    for (;;)
    {
      const int sym = sz_huff_decode (&b, &lit);

      if (b.over == true) { rc = SZ_SHORT; stop = true; break; }

      if (sym < 0) { rc = SZ_BAD; stop = true; break; }

      if (sym < 256)
      {
        out[pos++] = (u8) sym;

        if (pos == want) { rc = SZ_DONE; stop = true; break; }

        continue;
      }

      if (sym == 256) break;

      if (sym > 285) { rc = SZ_BAD; stop = true; break; }

      u32 len;

      if ((wide == true) && (sym == 285))
      {
        len = 3 + sz_bits_low (&b, 16);
      }
      else
      {
        len = SZ_LEN_BASE[sym - 257] + sz_bits_low (&b, SZ_LEN_EXTRA[sym - 257]);
      }

      const int dsym = sz_huff_decode (&b, &dist);

      if (b.over == true) { rc = SZ_SHORT; stop = true; break; }

      if ((dsym < 0) || ((u32) dsym >= dist_codes)) { rc = SZ_BAD; stop = true; break; }

      const u32 back = SZ_DIST_BASE[dsym] + sz_bits_low (&b, SZ_DIST_EXTRA[dsym]);

      if (b.over == true) { rc = SZ_SHORT; stop = true; break; }

      if ((back > pos) || (back > window)) { rc = SZ_BAD; stop = true; break; }

      size_t n = len;

      if (n > want - pos) n = want - pos;

      for (size_t i = 0; i < n; i++, pos++) out[pos] = out[pos - back];

      if (pos == want) { rc = SZ_DONE; stop = true; break; }
    }

    if (stop == true) break;

    if (last == 1) break;
  }

  *produced = pos;
  *consumed = b.pos - (b.cnt / 8);

  return rc;
}

/**
 * BZip2
 */

// high bit first, as BZip2 packs them

static u32 sz_bits_high (sz_bits_t *b, const u32 n)
{
  while (b->cnt < n)
  {
    u32 c = 0;

    if (b->pos < b->len)
    {
      c = b->in[b->pos++];
    }
    else
    {
      b->over = true;
    }

    b->buf  = (b->buf << 8) | c;
    b->cnt += 8;
  }

  const u32 v = (b->buf >> (b->cnt - n)) & ((1u << n) - 1);

  b->cnt -= n;

  return v;
}

typedef struct sz_bz_code
{
  u32 min_len;

  int limit[SZ_BZIP2_CODE_MAX + 2];
  int base[SZ_BZIP2_CODE_MAX + 2];
  u16 perm[SZ_BZIP2_SYMBOLS];

} sz_bz_code_t;

static void sz_bz_build (sz_bz_code_t *c, const u8 *lens, const u32 alpha)
{
  u32 min_len = SZ_BZIP2_CODE_MAX;
  u32 max_len = 1;

  for (u32 i = 0; i < alpha; i++)
  {
    if (lens[i] < min_len) min_len = lens[i];
    if (lens[i] > max_len) max_len = lens[i];
  }

  u32 pp = 0;

  for (u32 len = min_len; len <= max_len; len++)
  {
    for (u32 i = 0; i < alpha; i++)
    {
      if (lens[i] == len) c->perm[pp++] = (u16) i;
    }
  }

  int count[SZ_BZIP2_CODE_MAX + 2];

  memset (count, 0, sizeof (count));

  for (u32 i = 0; i < alpha; i++) count[lens[i]]++;

  int code  = 0;
  int index = 0;

  for (u32 len = min_len; len <= max_len; len++)
  {
    // limit is the largest code of this length, base turns a code into a position in perm

    c->base[len]  = index - code;
    code         += count[len];
    index        += count[len];
    c->limit[len] = code - 1;
    code        <<= 1;
  }

  c->limit[max_len + 1] = 0x7fffffff;
  c->base[max_len + 1]  = -0x40000000;
  c->min_len            = min_len;
}

static int sz_bunzip2 (sz_mem_t *mem, const u8 *in, const size_t in_len, u8 *out, const size_t want, size_t *produced, size_t *consumed)
{
  *produced = 0;
  *consumed = 0;

  if (mem->bz_tt == NULL)
  {
    mem->bz_tt       = (u32 *) malloc (SZ_BZIP2_BLOCK_MAX * sizeof (u32));
    mem->bz_selector = (u8 *)  malloc (SZ_BZIP2_SELECTORS);

    if ((mem->bz_tt == NULL) || (mem->bz_selector == NULL)) return SZ_BAD;
  }

  if (mem->bz_crc_ready == false)
  {
    for (u32 i = 0; i < 256; i++)
    {
      u32 c = i << 24;

      for (u32 k = 0; k < 8; k++) c = (c & 0x80000000) ? ((c << 1) ^ 0x04c11db7) : (c << 1);

      mem->bz_crc[i] = c;
    }

    mem->bz_crc_ready = true;
  }

  u32 *tt = mem->bz_tt;

  sz_bits_t b;

  memset (&b, 0, sizeof (b));

  b.in  = in;
  b.len = in_len;

  const u32 sig   = sz_bits_high (&b, 24);
  const u32 level = sz_bits_high (&b, 8);

  if (b.over == true) return SZ_SHORT;

  if ((sig != 0x425a68) || (level < '1') || (level > '9')) return SZ_BAD;

  const u32 block_max = (level - '0') * 100000;

  size_t pos = 0;

  int rc = SZ_END;

  for (;;)
  {
    const u32 magic_hi = sz_bits_high (&b, 24);
    const u32 magic_lo = sz_bits_high (&b, 24);

    if (b.over == true) { rc = SZ_SHORT; break; }

    if ((magic_hi == 0x177245) && (magic_lo == 0x385090))
    {
      sz_bits_high (&b, 16);
      sz_bits_high (&b, 16);

      if (b.over == true) rc = SZ_SHORT;

      break;
    }

    if ((magic_hi != 0x314159) || (magic_lo != 0x265359)) { rc = SZ_BAD; break; }

    const u32 block_crc = (sz_bits_high (&b, 16) << 16) | sz_bits_high (&b, 16);

    // a block whose bytes were shuffled, which no bzip2 of the last 30 years writes

    if (sz_bits_high (&b, 1) != 0) { rc = (b.over == true) ? SZ_SHORT : SZ_BAD; break; }

    const u32 orig = sz_bits_high (&b, 24);

    u8 seq[256];

    u32 nsym = 0;

    const u32 used = sz_bits_high (&b, 16);

    for (u32 i = 0; i < 16; i++)
    {
      if ((used & (0x8000 >> i)) == 0) continue;

      const u32 bits = sz_bits_high (&b, 16);

      for (u32 j = 0; j < 16; j++)
      {
        if (bits & (0x8000 >> j)) seq[nsym++] = (u8) ((i * 16) + j);
      }
    }

    const u32 groups    = sz_bits_high (&b, 3);
    const u32 selectors = sz_bits_high (&b, 15);

    if (b.over == true) { rc = SZ_SHORT; break; }

    if ((nsym == 0) || (groups < 2) || (groups > SZ_BZIP2_GROUPS) || (selectors < 1) || (selectors > SZ_BZIP2_SELECTORS)) { rc = SZ_BAD; break; }

    const u32 alpha = nsym + 2;

    u8 order[SZ_BZIP2_GROUPS];

    for (u32 i = 0; i < groups; i++) order[i] = (u8) i;

    bool bad = false;

    for (u32 i = 0; i < selectors; i++)
    {
      u32 j = 0;

      while (sz_bits_high (&b, 1) == 1)
      {
        j++;

        if (j >= groups) { bad = true; break; }
      }

      if ((bad == true) || (b.over == true)) break;

      const u8 v = order[j];

      for (; j > 0; j--) order[j] = order[j - 1];

      order[0] = v;

      mem->bz_selector[i] = v;
    }

    if (b.over == true) { rc = SZ_SHORT; break; }

    if (bad == true) { rc = SZ_BAD; break; }

    sz_bz_code_t codes[SZ_BZIP2_GROUPS];

    for (u32 g = 0; (g < groups) && (bad == false); g++)
    {
      u8 lens[SZ_BZIP2_SYMBOLS];

      u32 len = sz_bits_high (&b, 5);

      for (u32 i = 0; i < alpha; i++)
      {
        for (;;)
        {
          if ((len < 1) || (len > SZ_BZIP2_CODE_MAX)) { bad = true; break; }

          if (sz_bits_high (&b, 1) == 0) break;

          if (sz_bits_high (&b, 1) == 0) len++; else len--;

          if (b.over == true) break;
        }

        if ((bad == true) || (b.over == true)) break;

        lens[i] = (u8) len;
      }

      if ((bad == true) || (b.over == true)) break;

      sz_bz_build (&codes[g], lens, alpha);
    }

    if (b.over == true) { rc = SZ_SHORT; break; }

    if (bad == true) { rc = SZ_BAD; break; }

    // the symbols: runs of the byte at the front of the list, and positions in that list

    u8 mtf[256];

    for (u32 i = 0; i < nsym; i++) mtf[i] = seq[i];

    u32 freq[256];

    memset (freq, 0, sizeof (freq));

    u32 nblock = 0;
    u32 group  = 0;
    u32 left   = 0;
    u32 run    = 0;
    u32 weight = 1;

    const sz_bz_code_t *c = NULL;

    for (;;)
    {
      if (left == 0)
      {
        if (group >= selectors) { bad = true; break; }

        c    = &codes[mem->bz_selector[group++]];
        left = 50;
      }

      left--;

      u32 len  = c->min_len;
      int code = (int) sz_bits_high (&b, len);

      while (code > c->limit[len])
      {
        len++;

        if (len > SZ_BZIP2_CODE_MAX) break;

        code = (code << 1) | (int) sz_bits_high (&b, 1);
      }

      if (b.over == true) break;

      if (len > SZ_BZIP2_CODE_MAX) { bad = true; break; }

      const int where = code + c->base[len];

      if ((where < 0) || ((u32) where >= alpha)) { bad = true; break; }

      const u32 sym = c->perm[where];

      if (sym <= 1)
      {
        // a run length is written in bijective base 2, lowest digit first

        if (weight > 0x200000) { bad = true; break; }

        run    += weight << sym;
        weight <<= 1;

        continue;
      }

      if (run > 0)
      {
        if (run > block_max - nblock) { bad = true; break; }

        const u8 v = mtf[0];

        freq[v] += run;

        while (run--) tt[nblock++] = v;

        run    = 0;
        weight = 1;
      }

      if (sym == nsym + 1) break;

      if (nblock >= block_max) { bad = true; break; }

      const u32 at = sym - 1;
      const u8  v  = mtf[at];

      for (u32 j = at; j > 0; j--) mtf[j] = mtf[j - 1];

      mtf[0] = v;

      freq[v]++;

      tt[nblock++] = v;
    }

    if (b.over == true) { rc = SZ_SHORT; break; }

    if ((bad == true) || (orig >= nblock)) { rc = SZ_BAD; break; }

    // undo the sort: every entry gets the position of the byte that followed it

    u32 start[256];

    u32 sum = 0;

    for (u32 i = 0; i < 256; i++)
    {
      start[i] = sum;
      sum     += freq[i];
    }

    for (u32 i = 0; i < nblock; i++)
    {
      const u8 v = (u8) (tt[i] & 0xff);

      tt[start[v]++] |= i << 8;
    }

    // and read the block back, undoing the run length coding of the first stage on the way

    u32 at   = tt[orig] >> 8;
    u32 crc  = 0xffffffff;
    u32 same = 0;
    int prev = -1;

    bool cut = false;

    for (u32 i = 0; i < nblock; i++)
    {
      const u32 entry = tt[at];
      const u8  v     = (u8) (entry & 0xff);

      at = entry >> 8;

      if (same == 4)
      {
        // four equal bytes are followed by a count of more of them

        for (u32 k = 0; k < v; k++)
        {
          if (pos == want) { cut = true; break; }

          out[pos++] = (u8) prev;

          crc = (crc << 8) ^ mem->bz_crc[(crc >> 24) ^ (u8) prev];
        }

        if (cut == true) break;

        same = 0;
        prev = -1;

        continue;
      }

      if (pos == want) { cut = true; break; }

      out[pos++] = v;

      crc = (crc << 8) ^ mem->bz_crc[(crc >> 24) ^ v];

      if ((int) v == prev)
      {
        same++;
      }
      else
      {
        same = 1;
        prev = v;
      }
    }

    if (cut == true) { rc = SZ_DONE; break; }

    if (~crc != block_crc) { rc = SZ_BAD; break; }

    if (pos == want) { rc = SZ_DONE; break; }
  }

  *produced = pos;
  *consumed = b.pos - (b.cnt / 8);

  return rc;
}

/**
 * one coder
 */

// Unpack as much of a stream as is asked for. With to_end, what is asked for is all there is, and
// the stream has to end there.

static int sz_unpack (sz_mem_t *mem, const u32 kind, const u8 *props, const u32 props_len, const u8 *in, const size_t in_len, u8 *out, const size_t want, const bool to_end, size_t *produced, size_t *consumed)
{
  *produced = 0;
  *consumed = 0;

  switch (kind)
  {
    case SZ_KIND_LZMA:      return sz_lzma    (props, props_len, in, in_len, out, want, to_end, produced, consumed);
    case SZ_KIND_LZMA2:     return sz_lzma2   (props, props_len, in, in_len, out, want, to_end, produced, consumed);
    case SZ_KIND_PPMD:      return sz_ppmd    (mem, props, props_len, in, in_len, out, want, to_end, produced, consumed);
    case SZ_KIND_DEFLATE:   return sz_inflate (in, in_len, out, want, false, produced, consumed);
    case SZ_KIND_DEFLATE64: return sz_inflate (in, in_len, out, want, true,  produced, consumed);
    case SZ_KIND_BZIP2:     return sz_bunzip2 (mem, in, in_len, out, want, produced, consumed);
  }

  if (kind == SZ_KIND_ZSTD)
  {
    // the library says yes or no and not how far it came

    if (hc_zstd_decompress (in, in_len, out, want) == false) return SZ_BAD;

    *produced = want;
    *consumed = in_len;

    return SZ_DONE;
  }

  return SZ_BAD;
}

// A filter works where the data is. A branch converter leaves the last bytes alone when the
// instruction they start does not fit, which is what 7-Zip does at the end of a stream.

static bool sz_filter (const u32 kind, const u8 *props, const u32 props_len, u8 *data, const size_t len)
{
  u32 pc = 0;

  if (props_len == 4) pc = ((u32) props[0]) | ((u32) props[1] << 8) | ((u32) props[2] << 16) | ((u32) props[3] << 24);

  if (kind == SZ_KIND_DELTA)
  {
    if (props_len != 1) return false;

    Byte state[DELTA_STATE_SIZE];

    Delta_Init (state);

    Delta_Decode (state, (unsigned) props[0] + 1, data, len);

    return true;
  }

  if (kind == SZ_KIND_SWAP2)
  {
    for (size_t i = 0; i + 2 <= len; i += 2)
    {
      const u8 t = data[i];

      data[i + 0] = data[i + 1];
      data[i + 1] = t;
    }

    return true;
  }

  if (kind == SZ_KIND_SWAP4)
  {
    for (size_t i = 0; i + 4 <= len; i += 4)
    {
      const u8 t0 = data[i + 0];
      const u8 t1 = data[i + 1];

      data[i + 0] = data[i + 3];
      data[i + 1] = data[i + 2];
      data[i + 2] = t1;
      data[i + 3] = t0;
    }

    return true;
  }

  if ((props_len != 0) && (props_len != 4)) return false;

  if (kind == SZ_KIND_X86)
  {
    UInt32 state = Z7_BRANCH_CONV_ST_X86_STATE_INIT_VAL;

    z7_BranchConvSt_X86_Dec (data, len, pc, &state);

    return true;
  }

  switch (kind)
  {
    case SZ_KIND_PPC:   z7_BranchConv_PPC_Dec   (data, len, pc); return true;
    case SZ_KIND_IA64:  z7_BranchConv_IA64_Dec  (data, len, pc); return true;
    case SZ_KIND_ARM:   z7_BranchConv_ARM_Dec   (data, len, pc); return true;
    case SZ_KIND_ARMT:  z7_BranchConv_ARMT_Dec  (data, len, pc); return true;
    case SZ_KIND_SPARC: z7_BranchConv_SPARC_Dec (data, len, pc); return true;
    case SZ_KIND_ARM64: z7_BranchConv_ARM64_Dec (data, len, pc); return true;
    case SZ_KIND_RISCV: z7_BranchConv_RISCV_Dec (data, len, pc); return true;
  }

  return false;
}

// BCJ2 puts four streams back together: the code with its branch targets taken out, the targets
// of calls, the targets of jumps, and one bit for every branch that says whether it was taken out.

static int sz_bcj2 (const u8 *bufs[4], const size_t lens[4], u8 *out, const size_t want, const bool to_end, size_t *produced)
{
  CBcj2Dec dec;

  for (u32 i = 0; i < BCJ2_NUM_STREAMS; i++)
  {
    size_t len = lens[i];

    if (BCJ2_IS_32BIT_STREAM (i)) len &= ~(size_t) 3;

    dec.bufs[i] = bufs[i];
    dec.lims[i] = bufs[i] + len;
  }

  dec.dest    = out;
  dec.destLim = out + want;

  Bcj2Dec_Init (&dec);

  const SRes res = Bcj2Dec_Decode (&dec);

  *produced = (size_t) (dec.dest - out);

  if ((res != SZ_OK) || (dec.state == BCJ2_DEC_STATE_ERROR)) return SZ_BAD;

  if (*produced != want) return SZ_SHORT;

  if (to_end == true)
  {
    if (Bcj2Dec_IsMaybeFinished_code (&dec) == 0) return SZ_BAD;
  }

  return SZ_DONE;
}

// What the first cipher block of a stream has to look like for the coder that reads it. This
// costs one block of AES and turns away most wrong keys before anything is unpacked.

static bool sz_start_fits (const u32 kind, const u8 *p)
{
  switch (kind)
  {
    case SZ_KIND_LZMA:
    case SZ_KIND_PPMD:

      // both range coders start with a byte that is always zero

      return (p[0] == 0);

    case SZ_KIND_LZMA2:

      // the first chunk resets the dictionary: stored, or packed with new properties

      if (p[0] == 0x01) return true;

      if (p[0] < 0xe0) return false;

      return ((p[5] < 225) && (p[6] == 0));

    case SZ_KIND_DEFLATE:
    case SZ_KIND_DEFLATE64:

      if (((p[0] >> 1) & 3) == 3) return false;

      if (((p[0] >> 1) & 3) == 0) return ((p[1] ^ p[3]) == 0xff) && ((p[2] ^ p[4]) == 0xff);

      return true;

    case SZ_KIND_BZIP2:

      if ((p[0] != 'B') || (p[1] != 'Z') || (p[2] != 'h') || (p[3] < '1') || (p[3] > '9')) return false;

      if (memcmp (p + 4, "\x31\x41\x59\x26\x53\x59", 6) == 0) return true;

      return (memcmp (p + 4, "\x17\x72\x45\x38\x50\x90", 6) == 0);

    case SZ_KIND_ZSTD:

      return (memcmp (p, "\x28\xb5\x2f\xfd", 4) == 0);
  }

  return true;
}

/**
 * the header of an archive
 */

// An archive whose header is encrypted and has no checksum leaves one thing to test: whether
// what was decrypted is a header. 7-Zip tells a wrong password the same way. Every field is
// walked, and the walk has to end with the last byte.

typedef struct sz_rd
{
  const u8 *buf;

  size_t len;
  size_t pos;

  bool bad;

} sz_rd_t;

typedef struct sz_hdr_folder
{
  u32  coders;
  u32  files;
  bool crc;

} sz_hdr_folder_t;

static u8 sz_rd_byte (sz_rd_t *r)
{
  if (r->pos >= r->len)
  {
    r->bad = true;

    return 0;
  }

  return r->buf[r->pos++];
}

static u64 sz_rd_number (sz_rd_t *r)
{
  const u8 first = sz_rd_byte (r);

  u8  mask  = 0x80;
  u64 value = 0;

  for (u32 i = 0; i < 8; i++)
  {
    if ((first & mask) == 0) return value | ((u64) (first & (mask - 1)) << (8 * i));

    value |= (u64) sz_rd_byte (r) << (8 * i);

    mask >>= 1;
  }

  return value;
}

static void sz_rd_skip (sz_rd_t *r, const u64 count)
{
  if (count > r->len - r->pos)
  {
    r->bad = true;

    return;
  }

  r->pos += (size_t) count;
}

// A count of things that take at least one byte each cannot be larger than what is left.

static u64 sz_rd_count (sz_rd_t *r)
{
  const u64 count = sz_rd_number (r);

  if (count > r->len - r->pos) r->bad = true;

  return (r->bad == true) ? 0 : count;
}

static void sz_rd_digests (sz_rd_t *r, const u64 count)
{
  u64 defined = count;

  if (sz_rd_byte (r) == 0)
  {
    defined = 0;

    for (u64 i = 0; i < count; i += 8)
    {
      u8 bits = sz_rd_byte (r);

      // the bits past the count are not counted

      if (count - i < 8) bits &= (u8) (0xff00 >> (count - i));

      for (; bits != 0; bits &= (u8) (bits - 1)) defined++;

      if (r->bad == true) return;
    }
  }

  if (defined > (r->len - r->pos) / 4)
  {
    r->bad = true;

    return;
  }

  r->pos += (size_t) defined * 4;
}

static u32 sz_rd_folder (sz_rd_t *r)
{
  const u64 coders = sz_rd_number (r);

  if ((coders < 1) || (coders > 64))
  {
    r->bad = true;

    return 0;
  }

  u64 inputs = 0;

  for (u64 i = 0; i < coders; i++)
  {
    const u8 flags = sz_rd_byte (r);

    if (flags & 0xc0) r->bad = true;

    sz_rd_skip (r, flags & 0x0f);

    u64 in = 1;

    if (flags & 0x10)
    {
      in = sz_rd_number (r);

      if ((in < 1) || (in > 64)) r->bad = true;

      if (sz_rd_number (r) != 1) r->bad = true;
    }

    if (flags & 0x20) sz_rd_skip (r, sz_rd_number (r));

    if (r->bad == true) return 0;

    inputs += in;
  }

  for (u64 i = 0; i < coders - 1; i++)
  {
    if (sz_rd_number (r) >= inputs) r->bad = true;
    if (sz_rd_number (r) >= coders) r->bad = true;
  }

  if (inputs < coders)
  {
    r->bad = true;

    return 0;
  }

  const u64 packed = inputs - (coders - 1);

  if (packed > 1)
  {
    for (u64 i = 0; i < packed; i++)
    {
      if (sz_rd_number (r) >= inputs) r->bad = true;
    }
  }

  return (u32) coders;
}

static void sz_rd_streams (sz_rd_t *r)
{
  sz_hdr_folder_t *folders = NULL;

  u64 folder_cnt = 0;

  while (r->bad == false)
  {
    const u8 id = sz_rd_byte (r);

    if (id == 0x00) break;

    if (id == 0x06)
    {
      sz_rd_number (r);

      const u64 count = sz_rd_count (r);

      while (r->bad == false)
      {
        const u8 part = sz_rd_byte (r);

        if (part == 0x00) break;

        if (part == 0x09)
        {
          for (u64 i = 0; i < count; i++) sz_rd_number (r);
        }
        else if (part == 0x0a)
        {
          sz_rd_digests (r, count);
        }
        else
        {
          r->bad = true;
        }
      }
    }
    else if (id == 0x07)
    {
      if (sz_rd_byte (r) != 0x0b) r->bad = true;

      if (folders != NULL) r->bad = true;

      folder_cnt = sz_rd_count (r);

      if (sz_rd_byte (r) != 0x00) r->bad = true;

      if (r->bad == true) break;

      folders = (sz_hdr_folder_t *) calloc ((size_t) folder_cnt + 1, sizeof (sz_hdr_folder_t));

      if (folders == NULL)
      {
        r->bad = true;

        break;
      }

      for (u64 i = 0; (i < folder_cnt) && (r->bad == false); i++)
      {
        folders[i].coders = sz_rd_folder (r);
        folders[i].files  = 1;
      }

      while (r->bad == false)
      {
        const u8 part = sz_rd_byte (r);

        if (part == 0x00) break;

        if (part == 0x0c)
        {
          for (u64 i = 0; i < folder_cnt; i++)
          {
            for (u32 k = 0; k < folders[i].coders; k++) sz_rd_number (r);
          }
        }
        else if (part == 0x0a)
        {
          // which folders have one decides how many the files inside them still need

          const size_t at = r->pos;

          const u8 all = sz_rd_byte (r);

          for (u64 i = 0; (i < folder_cnt) && (r->bad == false); i++)
          {
            folders[i].crc = (all != 0) ? true : (((r->buf[(at + 1 + (i / 8) < r->len) ? at + 1 + (i / 8) : at] << (i & 7)) & 0x80) != 0);
          }

          r->pos = at;

          sz_rd_digests (r, folder_cnt);
        }
        else
        {
          r->bad = true;
        }
      }
    }
    else if (id == 0x08)
    {
      u8 part = sz_rd_byte (r);

      if (part == 0x0d)
      {
        for (u64 i = 0; i < folder_cnt; i++)
        {
          const u64 files = sz_rd_number (r);

          if (files > 0x7fffffff) r->bad = true;

          folders[i].files = (u32) files;
        }

        part = sz_rd_byte (r);
      }

      if (part == 0x09)
      {
        for (u64 i = 0; (i < folder_cnt) && (r->bad == false); i++)
        {
          for (u32 k = 1; (k < folders[i].files) && (r->bad == false); k++) sz_rd_number (r);
        }

        part = sz_rd_byte (r);
      }

      if (part == 0x0a)
      {
        u64 missing = 0;

        for (u64 i = 0; i < folder_cnt; i++)
        {
          if ((folders[i].files == 1) && (folders[i].crc == true)) continue;

          missing += folders[i].files;
        }

        sz_rd_digests (r, missing);

        part = sz_rd_byte (r);
      }

      if (part != 0x00) r->bad = true;
    }
    else
    {
      r->bad = true;
    }
  }

  free (folders);
}

static bool sz_header_valid (const u8 *buf, const size_t len)
{
  sz_rd_t r;

  r.buf = buf;
  r.len = len;
  r.pos = 0;
  r.bad = false;

  if (sz_rd_byte (&r) != 0x01) return false;

  while (r.bad == false)
  {
    const u8 id = sz_rd_byte (&r);

    if (id == 0x00) return (r.bad == false) && (r.pos == r.len);

    if (id == 0x02)
    {
      // properties of the archive

      while ((r.bad == false) && (sz_rd_byte (&r) != 0x00)) sz_rd_skip (&r, sz_rd_number (&r));
    }
    else if ((id == 0x03) || (id == 0x04))
    {
      sz_rd_streams (&r);
    }
    else if (id == 0x05)
    {
      // the files: a count, then properties, each with its kind and its size

      sz_rd_number (&r);

      while (r.bad == false)
      {
        const u8 kind = sz_rd_byte (&r);

        if (kind == 0x00) break;

        if ((kind < 0x0e) || (kind > 0x19)) r.bad = true;

        sz_rd_skip (&r, sz_rd_number (&r));
      }
    }
    else
    {
      r.bad = true;
    }
  }

  return false;
}
