/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

// RAR 1.5 and RAR 2.0: what modules 46500 and 46600 do on the host. Included the way
// rar3_decode.c is: one translation unit, nothing exported.
//
// The kernel sets the cipher up from the password. A small stored entry it also verifies itself.
// Every other entry comes here with the key the kernel derived, to be decrypted, unpacked if it
// is compressed, and compared with the CRC32 of the file.
//
// The ciphers and decompressors follow UnRAR 7.3.2 (crypt1.cpp, crypt2.cpp, unpack15.cpp,
// unpack20.cpp and the Huffman table code in unpack.cpp), written out in C for a hook that needs
// one thing from them: the CRC32 of what a candidate password unpacks to.
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

// The largest stored entry the kernel verifies itself, which a discrete GPU does many times faster
// than the host. It travels in the esalt, which every hash has at this size, so it is not the
// whole 4 MiB a line may carry.

#define RARL_KERNEL_DATA 262144

// The most encrypted data one hash line may carry. ArchiveWolf emits an entry whole up to this size
// and emits nothing above it, because a cut stream cannot be checked against the file CRC32.

#define RARL_DATA_MAX (4 * 1024 * 1024)

// RAR 2.0 dictionaries go up to 1 MiB. RAR 1.5 uses 64 KiB of the same window.

#define RARL_WIN_SIZE 0x100000
#define RARL_WIN_MASK (RARL_WIN_SIZE - 1)

static u32 rarl_crc32tab[256];
static bool rarl_crc32tab_ready = false;

static void rarl_crc32_init (void)
{
  if (rarl_crc32tab_ready == true) return;

  for (u32 i = 0; i < 256; i++)
  {
    u32 c = i;

    for (u32 j = 0; j < 8; j++) c = ((c & 1) == 1) ? (0xEDB88320 ^ (c >> 1)) : (c >> 1);

    rarl_crc32tab[i] = c;
  }

  rarl_crc32tab_ready = true;
}

static u32 rarl_crc32 (u32 crc, const u8 *buf, const u32 len)
{
  for (u32 i = 0; i < len; i++) crc = (crc >> 8) ^ rarl_crc32tab[(crc ^ buf[i]) & 0xff];

  return crc;
}

// ---- RAR 1.5 cipher (Crypt15), from the key the kernel set up ----

static void rarl_decrypt15 (const u32 *key, const u8 *in, u8 *out, const u32 len)
{
  u32 k0 = key[0];
  u32 k1 = key[1];
  u32 k2 = key[2];
  u32 k3 = key[3];

  for (u32 i = 0; i < len; i++)
  {
    k0 = (k0 + 0x1234) & 0xffff;

    const u32 t = rarl_crc32tab[(k0 & 0x1fe) >> 1];

    k1 = (k1 ^ t) & 0xffff;
    k2 = (k2 - (t >> 16)) & 0xffff;
    k0 = (k0 ^ k2) & 0xffff;
    k3 = (((k3 >> 1) | (k3 << 15)) & 0xffff) ^ k1;
    k3 = ((k3 >> 1) | (k3 << 15)) & 0xffff;
    k0 = (k0 ^ k3) & 0xffff;

    out[i] = in[i] ^ (u8) (k0 >> 8);
  }
}

// ---- RAR 2.0 cipher (DecryptBlock20), from the key and the table the kernel set up ----

#define RARL_ROL32(x,n) (((x) << (n)) | ((x) >> (32 - (n))))

#define RARL_SUBST(t,st) ( (u32) (st)[ (t)        & 0xff]        \
                         | ((u32) (st)[((t) >>  8) & 0xff] <<  8) \
                         | ((u32) (st)[((t) >> 16) & 0xff] << 16) \
                         | ((u32) (st)[((t) >> 24) & 0xff] << 24))

static u32 rarl_get4 (const u8 *b)
{
  const u32 v = (u32) b[0] | ((u32) b[1] << 8) | ((u32) b[2] << 16) | ((u32) b[3] << 24);

  return v;
}

static void rarl_put4 (const u32 v, u8 *b)
{
  b[0] = (u8) (v >>  0);
  b[1] = (u8) (v >>  8);
  b[2] = (u8) (v >> 16);
  b[3] = (u8) (v >> 24);
}

// The table every RAR 2.0 key starts from.

static const u8 rarl_init_subst20[256] =
{
  215, 19,149, 35, 73,197,192,205,249, 28, 16,119, 48,221,  2, 42,
  232,  1,177,233, 14, 88,219, 25,223,195,244, 90, 87,239,153,137,
  255,199,147, 70, 92, 66,246, 13,216, 40, 62, 29,217,230, 86,  6,
   71, 24,171,196,101,113,218,123, 93, 91,163,178,202, 67, 44,235,
  107,250, 75,234, 49,167,125,211, 83,114,157,144, 32,193,143, 36,
  158,124,247,187, 89,214,141, 47,121,228, 61,130,213,194,174,251,
   97,110, 54,229,115, 57,152, 94,105,243,212, 55,209,245, 63, 11,
  164,200, 31,156, 81,176,227, 21, 76, 99,139,188,127, 17,248, 51,
  207,120,189,210,  8,226, 41, 72,183,203,135,165,166, 60, 98,  7,
  122, 38,155,170, 69,172,252,238, 39,134, 59,128,236, 27,240, 80,
  131,  3, 85,206,145, 79,154,142,159,220,201,133, 74, 64, 20,129,
  224,185,138,103,173,182, 43, 34,254, 82,198,151,231,180, 58, 10,
  118, 26,102, 12, 50,132, 22,191,136,111,162,179, 45,  4,148,108,
  161, 56, 78,126,242,222, 15,175,146, 23, 33,241,181,190, 77,225,
    0, 46,169,186, 68, 95,237, 65, 53,208,253,168,  9, 18,100, 52,
  116,184,160, 96,109, 37, 30,106,140,104,150,  5,204,117,112, 84
};

// SetKey20, for the devices whose key the host sets up: the table is shuffled by the password,
// then the password itself is encrypted, which moves the key on. psw holds the password, zero
// filled to a multiple of 16 bytes.

static void rarl_set_key20 (const u8 *psw, const u32 pw_len, u32 *key, u8 *subst)
{
  memcpy (subst, rarl_init_subst20, 256);

  for (u32 j = 0; j < 256; j++)
  {
    for (u32 i = 0; i < pw_len; i += 2)
    {
      u32 n1 = rarl_crc32tab[(psw[i + 0] - j) & 0xff] & 0xff;

      const u32 n2 = rarl_crc32tab[(psw[i + 1] + j) & 0xff] & 0xff;

      for (u32 k = 1; n1 != n2; k++)
      {
        const u32 other = (n1 + i + k) & 0xff;

        const u8 tmp = subst[n1];

        subst[n1]    = subst[other];
        subst[other] = tmp;

        n1 = (n1 + 1) & 0xff;
      }
    }
  }

  key[0] = 0xD3A3B879;
  key[1] = 0x3F6D12F7;
  key[2] = 0x7515A235;
  key[3] = 0xA4E7F123;

  for (u32 off = 0; off < pw_len; off += 16)
  {
    u32 a = rarl_get4 (&psw[off +  0]) ^ key[0];
    u32 b = rarl_get4 (&psw[off +  4]) ^ key[1];
    u32 c = rarl_get4 (&psw[off +  8]) ^ key[2];
    u32 d = rarl_get4 (&psw[off + 12]) ^ key[3];

    for (u32 i = 0; i < 32; i++)
    {
      const u32 k = key[i & 3];

      u32 t = (c + RARL_ROL32 (d, 11)) ^ k;

      const u32 ta = a ^ RARL_SUBST (t, subst);

      t = (d ^ RARL_ROL32 (c, 17)) + k;

      const u32 tb = b ^ RARL_SUBST (t, subst);

      a = c;
      b = d;
      c = ta;
      d = tb;
    }

    u8 ct[16];

    rarl_put4 (c ^ key[0], &ct[ 0]);
    rarl_put4 (d ^ key[1], &ct[ 4]);
    rarl_put4 (a ^ key[2], &ct[ 8]);
    rarl_put4 (b ^ key[3], &ct[12]);

    for (u32 i = 0; i < 16; i += 4)
    {
      key[0] ^= rarl_crc32tab[ct[i + 0]];
      key[1] ^= rarl_crc32tab[ct[i + 1]];
      key[2] ^= rarl_crc32tab[ct[i + 2]];
      key[3] ^= rarl_crc32tab[ct[i + 3]];
    }
  }
}

// Decrypts len bytes, a multiple of 16. The key moves on with every ciphertext block.

static void rarl_decrypt20 (const u32 *key_in, const u8 *subst, const u8 *in, u8 *out, const u32 len)
{
  u32 key[4];

  key[0] = key_in[0];
  key[1] = key_in[1];
  key[2] = key_in[2];
  key[3] = key_in[3];

  for (u32 off = 0; off + 16 <= len; off += 16)
  {
    u8 ct[16];

    memcpy (ct, &in[off], 16);

    u32 a = rarl_get4 (&ct[ 0]) ^ key[0];
    u32 b = rarl_get4 (&ct[ 4]) ^ key[1];
    u32 c = rarl_get4 (&ct[ 8]) ^ key[2];
    u32 d = rarl_get4 (&ct[12]) ^ key[3];

    for (u32 i = 0; i < 32; i++)
    {
      const u32 k = key[(31 - i) & 3];

      u32 t = (c + RARL_ROL32 (d, 11)) ^ k;

      const u32 ta = a ^ RARL_SUBST (t, subst);

      t = (d ^ RARL_ROL32 (c, 17)) + k;

      const u32 tb = b ^ RARL_SUBST (t, subst);

      a = c;
      b = d;
      c = ta;
      d = tb;
    }

    rarl_put4 (c ^ key[0], &out[off +  0]);
    rarl_put4 (d ^ key[1], &out[off +  4]);
    rarl_put4 (a ^ key[2], &out[off +  8]);
    rarl_put4 (b ^ key[3], &out[off + 12]);

    for (u32 i = 0; i < 16; i += 4)
    {
      key[0] ^= rarl_crc32tab[ct[i + 0]];
      key[1] ^= rarl_crc32tab[ct[i + 1]];
      key[2] ^= rarl_crc32tab[ct[i + 2]];
      key[3] ^= rarl_crc32tab[ct[i + 3]];
    }
  }
}

// ---- bit input shared by both decompressors ----

typedef struct rarl_ctx
{
  const u8 *in;
  u64       in_bits;
  u64       bit;

  u8  *win;
  u64  produced;
  u64  dest_size;
  u32  crc;

  bool failed;

} rarl_ctx_t;

// The next 16 bits, zero filled past the end of the input.

static u32 rarl_getbits (const rarl_ctx_t *ctx)
{
  const u64 byte = ctx->bit >> 3;
  const u64 size = (ctx->in_bits + 7) >> 3;

  u32 v = 0;

  if (byte + 0 < size) v |= (u32) ctx->in[byte + 0] << 16;
  if (byte + 1 < size) v |= (u32) ctx->in[byte + 1] <<  8;
  if (byte + 2 < size) v |= (u32) ctx->in[byte + 2] <<  0;

  const u32 bits = (v >> (8 - (ctx->bit & 7))) & 0xffff;

  return bits;
}

static void rarl_addbits (rarl_ctx_t *ctx, const u32 count)
{
  ctx->bit += count;

  // A stream that asks for more bits than the entry holds was not written by RAR.

  if (ctx->bit > ctx->in_bits) ctx->failed = true;
}

static void rarl_emit (rarl_ctx_t *ctx, const u8 byte)
{
  if (ctx->produced >= ctx->dest_size)
  {
    ctx->failed = true;

    return;
  }

  ctx->win[ctx->produced & RARL_WIN_MASK] = byte;

  ctx->produced++;

  ctx->crc = (ctx->crc >> 8) ^ rarl_crc32tab[(ctx->crc ^ byte) & 0xff];
}

// A match that reaches before the first byte of the file reads the window as it was before
// unpacking began, which is zeros for a file that does not continue a solid stream.

static void rarl_copy (rarl_ctx_t *ctx, const u32 length, const u32 dist)
{
  if (ctx->produced + length > ctx->dest_size)
  {
    ctx->failed = true;

    return;
  }

  for (u32 i = 0; i < length; i++)
  {
    const bool before = ((dist == 0) || (dist > RARL_WIN_SIZE) || (dist > ctx->produced));

    const u8 byte = (before == true) ? 0 : ctx->win[(ctx->produced - dist) & RARL_WIN_MASK];

    rarl_emit (ctx, byte);
  }
}

// ---- Unpack15 ----

static const u32 rarl_dec_l1[]  = { 0x8000, 0xa000, 0xc000, 0xd000, 0xe000, 0xea00, 0xee00, 0xf000, 0xf200, 0xf200, 0xffff };
static const u32 rarl_pos_l1[]  = { 0, 0, 0, 2, 3, 5, 7, 11, 16, 20, 24, 32, 32 };
static const u32 rarl_dec_l2[]  = { 0xa000, 0xc000, 0xd000, 0xe000, 0xea00, 0xee00, 0xf000, 0xf200, 0xf240, 0xffff };
static const u32 rarl_pos_l2[]  = { 0, 0, 0, 0, 5, 7, 9, 13, 18, 22, 26, 34, 36 };
static const u32 rarl_dec_hf0[] = { 0x8000, 0xc000, 0xe000, 0xf200, 0xf200, 0xf200, 0xf200, 0xf200, 0xffff };
static const u32 rarl_pos_hf0[] = { 0, 0, 0, 0, 0, 8, 16, 24, 33, 33, 33, 33, 33 };
static const u32 rarl_dec_hf1[] = { 0x2000, 0xc000, 0xe000, 0xf000, 0xf200, 0xf200, 0xf7e0, 0xffff };
static const u32 rarl_pos_hf1[] = { 0, 0, 0, 0, 0, 0, 4, 44, 60, 76, 80, 80, 127 };
static const u32 rarl_dec_hf2[] = { 0x1000, 0x2400, 0x8000, 0xc000, 0xfa00, 0xffff, 0xffff, 0xffff };
static const u32 rarl_pos_hf2[] = { 0, 0, 0, 0, 0, 0, 2, 7, 53, 117, 233, 0, 0 };
static const u32 rarl_dec_hf3[] = { 0x0800, 0x2400, 0xee00, 0xfe80, 0xffff, 0xffff, 0xffff };
static const u32 rarl_pos_hf3[] = { 0, 0, 0, 0, 0, 0, 0, 2, 16, 218, 251, 0, 0 };
static const u32 rarl_dec_hf4[] = { 0xff00, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff };
static const u32 rarl_pos_hf4[] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 0, 0, 0 };

static const u8 rarl_short_len1[] = { 1, 3, 4, 4, 5, 6, 7, 8, 8, 4, 4, 5, 6, 6, 4, 0 };
static const u8 rarl_short_xor1[] = { 0x00, 0xa0, 0xd0, 0xe0, 0xf0, 0xf8, 0xfc, 0xfe, 0xff, 0xc0, 0x80, 0x90, 0x98, 0x9c, 0xb0 };
static const u8 rarl_short_len2[] = { 2, 3, 3, 3, 4, 4, 5, 6, 6, 4, 4, 5, 6, 6, 4, 0 };
static const u8 rarl_short_xor2[] = { 0x00, 0x40, 0x60, 0xa0, 0xd0, 0xe0, 0xf0, 0xf8, 0xfc, 0xc0, 0x80, 0x90, 0x98, 0x9c, 0xb0 };

typedef struct rarl_u15
{
  u16 ch_set[256];
  u16 ch_set_a[256];
  u16 ch_set_b[256];
  u16 ch_set_c[256];

  u8  n_to_pl[256];
  u8  n_to_pl_b[256];
  u8  n_to_pl_c[256];

  u32 avr_plc;
  u32 avr_plc_b;
  u32 avr_ln1;
  u32 avr_ln2;
  u32 avr_ln3;
  u32 max_dist3;
  u32 nhfb;
  u32 nlzb;
  u32 num_huf;
  u32 buf60;
  u32 st_mode;
  u32 l_count;
  u32 flag_buf;
  i32 flags_cnt;

  u32 old_dist[4];
  u32 old_dist_ptr;
  u32 last_dist;
  u32 last_length;

} rarl_u15_t;

static void rarl15_corr_huff (u16 *char_set, u8 *num_to_place)
{
  u32 pos = 0;

  for (u32 n = 0; n < 8; n++)
  {
    const u16 rank = (u16) (7 - n);

    for (u32 j = 0; j < 32; j++, pos++) char_set[pos] = (char_set[pos] & ~0xff) | rank;
  }

  memset (num_to_place, 0, 256);

  for (u32 rank = 0; rank < 7; rank++) num_to_place[rank] = (u8) ((7 - rank) * 32);
}

static u32 rarl15_decode_num (rarl_ctx_t *ctx, u32 start_pos, const u32 *dec_tab, const u32 *pos_tab)
{
  const u32 num = rarl_getbits (ctx) & 0xfff0;

  u32 i = 0;

  for (i = 0; dec_tab[i] <= num; i++) start_pos++;

  rarl_addbits (ctx, start_pos);

  const u32 base = (i > 0) ? dec_tab[i - 1] : 0;

  const u32 value = ((num - base) >> (16 - start_pos)) + pos_tab[start_pos];

  return value;
}

static void rarl15_remember (rarl_u15_t *u, const u32 dist, const u32 length)
{
  u->old_dist[u->old_dist_ptr] = dist;

  u->old_dist_ptr = (u->old_dist_ptr + 1) & 3;

  u->last_length = length;
  u->last_dist   = dist;
}

static void rarl15_get_flags_buf (rarl_ctx_t *ctx, rarl_u15_t *u)
{
  const u32 place = rarl15_decode_num (ctx, 5, rarl_dec_hf2, rarl_pos_hf2);

  // A corrupt stream can name a place past the table.

  if (place >= 256) return;

  u32 flags;
  u32 new_place;

  while (1)
  {
    flags = u->ch_set_c[place];

    new_place = u->n_to_pl_c[flags & 0xff]++;

    u->flag_buf = flags >> 8;

    flags++;

    if ((flags & 0xff) != 0) break;

    rarl15_corr_huff (u->ch_set_c, u->n_to_pl_c);
  }

  u->ch_set_c[place]     = u->ch_set_c[new_place];
  u->ch_set_c[new_place] = (u16) flags;
}

static void rarl15_short_lz (rarl_ctx_t *ctx, rarl_u15_t *u)
{
  u->num_huf = 0;

  u32 bit_field = rarl_getbits (ctx);

  if (u->l_count == 2)
  {
    rarl_addbits (ctx, 1);

    if (bit_field >= 0x8000)
    {
      rarl_copy (ctx, u->last_length, u->last_dist);

      return;
    }

    bit_field = (bit_field << 1) & 0xffff;

    u->l_count = 0;
  }

  bit_field >>= 8;

  const u8 *lens = (u->avr_ln1 < 37) ? rarl_short_len1 : rarl_short_len2;
  const u8 *xors = (u->avr_ln1 < 37) ? rarl_short_xor1 : rarl_short_xor2;
  const u32 buf  = (u->avr_ln1 < 37) ? 1 : 3;

  u32 length;

  for (length = 0; ; length++)
  {
    if (length >= 15)
    {
      ctx->failed = true;

      return;
    }

    const u32 len = (length == buf) ? (u->buf60 + 3) : lens[length];

    if (((bit_field ^ xors[length]) & (~(0xff >> len) & 0xff)) == 0)
    {
      rarl_addbits (ctx, len);

      break;
    }
  }

  if (length >= 9)
  {
    if (length == 9)
    {
      u->l_count++;

      rarl_copy (ctx, u->last_length, u->last_dist);

      return;
    }

    if (length == 14)
    {
      u->l_count = 0;

      length = rarl15_decode_num (ctx, 3, rarl_dec_l2, rarl_pos_l2) + 5;

      const u32 dist = (rarl_getbits (ctx) >> 1) | 0x8000;

      rarl_addbits (ctx, 15);

      u->last_length = length;
      u->last_dist   = dist;

      rarl_copy (ctx, length, dist);

      return;
    }

    u->l_count = 0;

    const u32 save_length = length;

    const u32 dist = u->old_dist[(u->old_dist_ptr - (length - 9)) & 3];

    length = rarl15_decode_num (ctx, 2, rarl_dec_l1, rarl_pos_l1) + 2;

    if ((length == 0x101) && (save_length == 10))
    {
      u->buf60 ^= 1;

      return;
    }

    if (dist > 256) length++;

    if (dist >= u->max_dist3) length++;

    rarl15_remember (u, dist, length);

    rarl_copy (ctx, length, dist);

    return;
  }

  u->l_count = 0;

  u->avr_ln1 += length;
  u->avr_ln1 -= u->avr_ln1 >> 4;

  const u32 place = rarl15_decode_num (ctx, 5, rarl_dec_hf2, rarl_pos_hf2) & 0xff;

  u32 dist = u->ch_set_a[place];

  if (place > 0)
  {
    const u16 last = u->ch_set_a[place - 1];

    u->ch_set_a[place]     = last;
    u->ch_set_a[place - 1] = (u16) dist;
  }

  length += 2;

  dist++;

  rarl15_remember (u, dist, length);

  rarl_copy (ctx, length, dist);
}

static void rarl15_long_lz (rarl_ctx_t *ctx, rarl_u15_t *u)
{
  u->num_huf = 0;

  u->nlzb += 16;

  if (u->nlzb > 0xff)
  {
    u->nlzb = 0x90;

    u->nhfb >>= 1;
  }

  const u32 old_avr2 = u->avr_ln2;

  u32 bit_field = rarl_getbits (ctx);

  u32 length;

  if (u->avr_ln2 >= 122)
  {
    length = rarl15_decode_num (ctx, 3, rarl_dec_l2, rarl_pos_l2);
  }
  else if (u->avr_ln2 >= 64)
  {
    length = rarl15_decode_num (ctx, 2, rarl_dec_l1, rarl_pos_l1);
  }
  else if (bit_field < 0x100)
  {
    length = bit_field;

    rarl_addbits (ctx, 16);
  }
  else
  {
    for (length = 0; ((bit_field << length) & 0x8000) == 0; length++);

    rarl_addbits (ctx, length + 1);
  }

  u->avr_ln2 += length;
  u->avr_ln2 -= u->avr_ln2 >> 5;

  u32 place;

  if      (u->avr_plc_b > 0x28ff) place = rarl15_decode_num (ctx, 5, rarl_dec_hf2, rarl_pos_hf2);
  else if (u->avr_plc_b > 0x06ff) place = rarl15_decode_num (ctx, 5, rarl_dec_hf1, rarl_pos_hf1);
  else                            place = rarl15_decode_num (ctx, 4, rarl_dec_hf0, rarl_pos_hf0);

  u->avr_plc_b += place;
  u->avr_plc_b -= u->avr_plc_b >> 8;

  const u32 idx = place & 0xff;

  u32 dist;
  u32 new_place;

  while (1)
  {
    dist = u->ch_set_b[idx];

    new_place = u->n_to_pl_b[dist & 0xff]++;

    dist++;

    if ((dist & 0xff) != 0) break;

    rarl15_corr_huff (u->ch_set_b, u->n_to_pl_b);
  }

  u->ch_set_b[idx]       = u->ch_set_b[new_place];
  u->ch_set_b[new_place] = (u16) dist;

  dist = ((dist & 0xff00) | (rarl_getbits (ctx) >> 8)) >> 1;

  rarl_addbits (ctx, 7);

  const u32 old_avr3 = u->avr_ln3;

  if ((length != 1) && (length != 4))
  {
    if ((length == 0) && (dist <= u->max_dist3))
    {
      u->avr_ln3++;
      u->avr_ln3 -= u->avr_ln3 >> 8;
    }
    else if (u->avr_ln3 > 0)
    {
      u->avr_ln3--;
    }
  }

  length += 3;

  if (dist >= u->max_dist3) length++;

  if (dist <= 256) length += 8;

  const bool far = ((old_avr3 > 0xb0) || ((u->avr_plc >= 0x2a00) && (old_avr2 < 0x40)));

  u->max_dist3 = (far == true) ? 0x7f00 : 0x2001;

  rarl15_remember (u, dist, length);

  rarl_copy (ctx, length, dist);
}

static void rarl15_huff_decode (rarl_ctx_t *ctx, rarl_u15_t *u)
{
  const u32 bit_field = rarl_getbits (ctx);

  u32 place;

  if      (u->avr_plc > 0x75ff) place = rarl15_decode_num (ctx, 8, rarl_dec_hf4, rarl_pos_hf4);
  else if (u->avr_plc > 0x5dff) place = rarl15_decode_num (ctx, 6, rarl_dec_hf3, rarl_pos_hf3);
  else if (u->avr_plc > 0x35ff) place = rarl15_decode_num (ctx, 5, rarl_dec_hf2, rarl_pos_hf2);
  else if (u->avr_plc > 0x0dff) place = rarl15_decode_num (ctx, 5, rarl_dec_hf1, rarl_pos_hf1);
  else                          place = rarl15_decode_num (ctx, 4, rarl_dec_hf0, rarl_pos_hf0);

  place &= 0xff;

  if (u->st_mode == 1)
  {
    if ((place == 0) && (bit_field > 0x0fff)) place = 0x100;

    if (place-- == 0)
    {
      const u32 field = rarl_getbits (ctx);

      rarl_addbits (ctx, 1);

      if ((field & 0x8000) != 0)
      {
        u->num_huf = 0;
        u->st_mode = 0;

        return;
      }

      const u32 length = ((field & 0x4000) != 0) ? 4 : 3;

      rarl_addbits (ctx, 1);

      u32 dist = rarl15_decode_num (ctx, 5, rarl_dec_hf2, rarl_pos_hf2);

      dist = (dist << 5) | (rarl_getbits (ctx) >> 11);

      rarl_addbits (ctx, 5);

      rarl_copy (ctx, length, dist);

      return;
    }
  }
  else
  {
    if ((u->num_huf >= 16) && (u->flags_cnt == 0)) u->st_mode = 1;

    u->num_huf++;
  }

  u->avr_plc += place;
  u->avr_plc -= u->avr_plc >> 8;

  u->nhfb += 16;

  if (u->nhfb > 0xff)
  {
    u->nhfb = 0x90;

    u->nlzb >>= 1;
  }

  const u32 idx = place & 0xff;

  rarl_emit (ctx, (u8) (u->ch_set[idx] >> 8));

  u32 cur;
  u32 new_place;

  while (1)
  {
    cur = u->ch_set[idx];

    new_place = u->n_to_pl[cur & 0xff]++;

    cur++;

    if ((cur & 0xff) <= 0xa1) break;

    rarl15_corr_huff (u->ch_set, u->n_to_pl);
  }

  u->ch_set[idx]       = u->ch_set[new_place];
  u->ch_set[new_place] = (u16) cur;
}

// Unpacks one RAR 1.5 file that does not continue a solid stream. Returns 1 when the stream
// produced exactly unpack_size bytes, with their CRC32 in *crc32.

static bool rarl_unpack15 (u8 *win, const u8 *in, const u32 pack_size, const u32 unpack_size, u32 *crc32)
{
  rarl_ctx_t ctx;

  memset (&ctx, 0, sizeof (ctx));

  ctx.in        = in;
  ctx.in_bits   = (u64) pack_size * 8;
  ctx.win       = win;
  ctx.dest_size = unpack_size;
  ctx.crc       = 0xffffffff;

  rarl_u15_t u;

  memset (&u, 0, sizeof (u));

  u.avr_plc   = 0x3500;
  u.max_dist3 = 0x2001;
  u.nhfb      = 0x80;
  u.nlzb      = 0x80;

  u.old_dist[0] = u.old_dist[1] = u.old_dist[2] = u.old_dist[3] = 0xffffffff;

  u.last_dist = 0xffffffff;

  for (u32 i = 0; i < 256; i++)
  {
    u.ch_set[i]   = (u16) (i << 8);
    u.ch_set_b[i] = (u16) (i << 8);
    u.ch_set_a[i] = (u16) i;
    u.ch_set_c[i] = (u16) (((0 - i) & 0xff) << 8);
  }

  rarl15_corr_huff (u.ch_set_b, u.n_to_pl_b);

  if (unpack_size > 0)
  {
    rarl15_get_flags_buf (&ctx, &u);

    u.flags_cnt = 8;
  }

  while ((ctx.produced < ctx.dest_size) && (ctx.failed == false))
  {
    if (u.st_mode == 1)
    {
      rarl15_huff_decode (&ctx, &u);

      continue;
    }

    if (--u.flags_cnt < 0)
    {
      rarl15_get_flags_buf (&ctx, &u);

      u.flags_cnt = 7;
    }

    if ((u.flag_buf & 0x80) != 0)
    {
      u.flag_buf = (u.flag_buf << 1) & 0xff;

      if (u.nlzb > u.nhfb) rarl15_long_lz (&ctx, &u); else rarl15_huff_decode (&ctx, &u);
    }
    else
    {
      u.flag_buf = (u.flag_buf << 1) & 0xff;

      if (--u.flags_cnt < 0)
      {
        rarl15_get_flags_buf (&ctx, &u);

        u.flags_cnt = 7;
      }

      if ((u.flag_buf & 0x80) != 0)
      {
        u.flag_buf = (u.flag_buf << 1) & 0xff;

        if (u.nlzb > u.nhfb) rarl15_huff_decode (&ctx, &u); else rarl15_long_lz (&ctx, &u);
      }
      else
      {
        u.flag_buf = (u.flag_buf << 1) & 0xff;

        rarl15_short_lz (&ctx, &u);
      }
    }
  }

  *crc32 = ctx.crc ^ 0xffffffff;

  const bool ok = ((ctx.failed == false) && (ctx.produced == ctx.dest_size));

  return ok;
}

// ---- Unpack20 ----

// The alphabet sizes: literals and match codes, distances, repeat lengths, the code the tables
// themselves are written in, and one audio channel.

#define RARL20_NC 298
#define RARL20_DC  48
#define RARL20_RC  28
#define RARL20_BC  19
#define RARL20_MC 257

typedef struct rarl_huff
{
  u32 max_num;
  u32 decode_len[16];
  u32 decode_pos[16];
  u16 decode_num[RARL20_NC];

} rarl_huff_t;

// A set of code lengths that claims more of the code space than there is describes no Huffman
// code. No packer writes one, and a wrong key produces one almost every time, so it is the
// cheapest way to turn a candidate down before anything is unpacked.

static bool rarl20_code_fits (const u8 *lengths, const u32 size)
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

static void rarl20_make_tables (const u8 *lengths, rarl_huff_t *dec, const u32 size)
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

    const u32 pos = copy_pos[len]++;

    if (pos < size) dec->decode_num[pos] = (u16) i;
  }
}

static u32 rarl20_decode_number (rarl_ctx_t *ctx, const rarl_huff_t *dec)
{
  const u32 bit_field = rarl_getbits (ctx) & 0xfffe;

  u32 bits = 15;

  for (u32 i = 1; i < 15; i++)
  {
    if (bit_field < dec->decode_len[i])
    {
      bits = i;

      break;
    }
  }

  rarl_addbits (ctx, bits);

  u32 dist = bit_field - dec->decode_len[bits - 1];

  dist >>= (16 - bits);

  u32 pos = dec->decode_pos[bits] + dist;

  if (pos >= dec->max_num) pos = 0;

  return dec->decode_num[pos];
}

typedef struct rarl_audio
{
  i32 k1;
  i32 k2;
  i32 k3;
  i32 k4;
  i32 k5;

  i32 d1;
  i32 d2;
  i32 d3;
  i32 d4;

  i32 last_delta;
  i32 last_char;

  u32 dif[11];
  u32 byte_count;

} rarl_audio_t;

typedef struct rarl_u20
{
  rarl_huff_t ld;
  rarl_huff_t dd;
  rarl_huff_t rd;
  rarl_huff_t bd;
  rarl_huff_t md[4];

  u8  old_table[RARL20_MC * 4];

  bool audio_block;
  u32 channels;
  u32 cur_channel;
  i32 channel_delta;

  rarl_audio_t aud[4];

  u32 old_dist[4];
  u32 old_dist_ptr;
  u32 last_dist;
  u32 last_length;

} rarl_u20_t;

static u32 rarl20_abs (const i32 v)
{
  const u32 magnitude = (v >= 0) ? (u32) v : (u32) (0 - v);

  return magnitude;
}

static u8 rarl20_decode_audio (rarl_u20_t *u, const i32 delta)
{
  rarl_audio_t *v = &u->aud[u->cur_channel];

  v->byte_count++;

  v->d4 = v->d3;
  v->d3 = v->d2;
  v->d2 = v->last_delta - v->d1;
  v->d1 = v->last_delta;

  i32 pch = 8 * v->last_char + v->k1 * v->d1 + v->k2 * v->d2 + v->k3 * v->d3 + v->k4 * v->d4 + v->k5 * u->channel_delta;

  pch = (pch >> 3) & 0xff;

  const u32 ch = (u32) (pch - delta);

  i32 d = (i8) delta;

  d = (i32) ((u32) d << 3);

  v->dif[0]  += rarl20_abs (d);
  v->dif[1]  += rarl20_abs (d - v->d1);
  v->dif[2]  += rarl20_abs (d + v->d1);
  v->dif[3]  += rarl20_abs (d - v->d2);
  v->dif[4]  += rarl20_abs (d + v->d2);
  v->dif[5]  += rarl20_abs (d - v->d3);
  v->dif[6]  += rarl20_abs (d + v->d3);
  v->dif[7]  += rarl20_abs (d - v->d4);
  v->dif[8]  += rarl20_abs (d + v->d4);
  v->dif[9]  += rarl20_abs (d - u->channel_delta);
  v->dif[10] += rarl20_abs (d + u->channel_delta);

  v->last_delta = (i8) (ch - (u32) v->last_char);

  u->channel_delta = v->last_delta;

  v->last_char = (i32) ch;

  if ((v->byte_count & 0x1f) == 0)
  {
    u32 min_dif     = v->dif[0];
    u32 num_min_dif = 0;

    v->dif[0] = 0;

    for (u32 i = 1; i < 11; i++)
    {
      if (v->dif[i] < min_dif)
      {
        min_dif     = v->dif[i];
        num_min_dif = i;
      }

      v->dif[i] = 0;
    }

    switch (num_min_dif)
    {
      case  1: if (v->k1 >= -16) v->k1--; break;
      case  2: if (v->k1 <   16) v->k1++; break;
      case  3: if (v->k2 >= -16) v->k2--; break;
      case  4: if (v->k2 <   16) v->k2++; break;
      case  5: if (v->k3 >= -16) v->k3--; break;
      case  6: if (v->k3 <   16) v->k3++; break;
      case  7: if (v->k4 >= -16) v->k4--; break;
      case  8: if (v->k4 <   16) v->k4++; break;
      case  9: if (v->k5 >= -16) v->k5--; break;
      case 10: if (v->k5 <   16) v->k5++; break;
    }
  }

  return (u8) ch;
}

static bool rarl20_read_tables (rarl_ctx_t *ctx, rarl_u20_t *u)
{
  u8 bit_length[RARL20_BC];
  u8 table[RARL20_MC * 4];

  const u32 bit_field = rarl_getbits (ctx);

  u->audio_block = ((bit_field & 0x8000) != 0);

  if ((bit_field & 0x4000) == 0) memset (u->old_table, 0, sizeof (u->old_table));

  rarl_addbits (ctx, 2);

  u32 table_size;

  if (u->audio_block == true)
  {
    u->channels = ((bit_field >> 12) & 3) + 1;

    if (u->cur_channel >= u->channels) u->cur_channel = 0;

    rarl_addbits (ctx, 2);

    table_size = RARL20_MC * u->channels;
  }
  else
  {
    table_size = RARL20_NC + RARL20_DC + RARL20_RC;
  }

  for (u32 i = 0; i < RARL20_BC; i++)
  {
    bit_length[i] = (u8) (rarl_getbits (ctx) >> 12);

    rarl_addbits (ctx, 4);
  }

  if (rarl20_code_fits (bit_length, RARL20_BC) == false) return false;

  rarl20_make_tables (bit_length, &u->bd, RARL20_BC);

  for (u32 i = 0; i < table_size; )
  {
    if (ctx->failed == true) return false;

    const u32 number = rarl20_decode_number (ctx, &u->bd);

    if (number < 16)
    {
      table[i] = (u8) ((number + u->old_table[i]) & 0xf);

      i++;
    }
    else if (number == 16)
    {
      const u32 n = (rarl_getbits (ctx) >> 14) + 3;

      rarl_addbits (ctx, 2);

      // There is nothing to repeat at the first position.

      if (i == 0) return false;

      for (u32 j = 0; (j < n) && (i < table_size); j++, i++) table[i] = table[i - 1];
    }
    else
    {
      u32 n;

      if (number == 17)
      {
        n = (rarl_getbits (ctx) >> 13) + 3;

        rarl_addbits (ctx, 3);
      }
      else
      {
        n = (rarl_getbits (ctx) >> 9) + 11;

        rarl_addbits (ctx, 7);
      }

      for (u32 j = 0; (j < n) && (i < table_size); j++, i++) table[i] = 0;
    }
  }

  if (ctx->failed == true) return false;

  if (u->audio_block == true)
  {
    for (u32 i = 0; i < u->channels; i++)
    {
      if (rarl20_code_fits (&table[i * RARL20_MC], RARL20_MC) == false) return false;

      rarl20_make_tables (&table[i * RARL20_MC], &u->md[i], RARL20_MC);
    }
  }
  else
  {
    if (rarl20_code_fits (&table[0], RARL20_NC) == false) return false;

    rarl20_make_tables (&table[0],                     &u->ld, RARL20_NC);
    if (rarl20_code_fits (&table[RARL20_NC], RARL20_DC) == false) return false;

    rarl20_make_tables (&table[RARL20_NC],             &u->dd, RARL20_DC);
    if (rarl20_code_fits (&table[RARL20_NC + RARL20_DC], RARL20_RC) == false) return false;

    rarl20_make_tables (&table[RARL20_NC + RARL20_DC], &u->rd, RARL20_RC);
  }

  memcpy (u->old_table, table, table_size);

  return true;
}

static void rarl20_copy (rarl_ctx_t *ctx, rarl_u20_t *u, const u32 length, const u32 dist)
{
  u->last_dist = dist;

  u->old_dist[u->old_dist_ptr] = dist;

  u->old_dist_ptr = (u->old_dist_ptr + 1) & 3;

  u->last_length = length;

  rarl_copy (ctx, length, dist);
}

// Unpacks one RAR 2.0 file that does not continue a solid stream. Returns 1 when the stream
// produced exactly unpack_size bytes, with their CRC32 in *crc32.

static bool rarl_unpack20 (u8 *win, const u8 *in, const u32 pack_size, const u32 unpack_size, u32 *crc32)
{
  static const u8  ldecode[]  = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 10, 12, 14, 16, 20, 24, 28, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224 };
  static const u8  lbits[]    = { 0, 0, 0, 0, 0, 0, 0, 0, 1,  1,  1,  1,  2,  2,  2,  2,  3,  3,  3,  3,  4,  4,  4,   4,   5,   5,   5,   5 };
  static const u32 ddecode[]  = { 0, 1, 2, 3, 4, 6, 8, 12, 16, 24, 32, 48, 64, 96, 128, 192, 256, 384, 512, 768, 1024, 1536, 2048, 3072, 4096, 6144, 8192, 12288, 16384, 24576, 32768, 49152, 65536, 98304, 131072, 196608, 262144, 327680, 393216, 458752, 524288, 589824, 655360, 720896, 786432, 851968, 917504, 983040 };
  static const u8  dbits[]    = { 0, 0, 0, 0, 1, 1, 2,  2,  3,  3,  4,  4,  5,  5,   6,   6,   7,   7,   8,   8,    9,    9,   10,   10,   11,   11,   12,    12,    13,    13,    14,    14,    15,    15,     16,     16,     16,     16,     16,     16,     16,     16,     16,     16,     16,     16,     16,     16 };
  static const u8  sddecode[] = { 0, 4, 8, 16, 32, 64, 128, 192 };
  static const u8  sdbits[]   = { 2, 2, 3,  4,  5,  6,   6,   6 };

  rarl_ctx_t ctx;

  memset (&ctx, 0, sizeof (ctx));

  ctx.in        = in;
  ctx.in_bits   = (u64) pack_size * 8;
  ctx.win       = win;
  ctx.dest_size = unpack_size;
  ctx.crc       = 0xffffffff;

  // Too large for the hook thread's stack next to the candidate buffers, so it lives in static
  // storage per thread.

  static __thread rarl_u20_t u;

  memset (&u, 0, sizeof (u));

  u.channels = 1;

  *crc32 = 0;

  if (rarl20_read_tables (&ctx, &u) == false) return false;

  while ((ctx.produced < ctx.dest_size) && (ctx.failed == false))
  {
    if (u.audio_block == true)
    {
      const u32 number = rarl20_decode_number (&ctx, &u.md[u.cur_channel]);

      if (number == 256)
      {
        if (rarl20_read_tables (&ctx, &u) == false) break;

        continue;
      }

      rarl_emit (&ctx, rarl20_decode_audio (&u, (i32) number));

      u.cur_channel++;

      if (u.cur_channel == u.channels) u.cur_channel = 0;

      continue;
    }

    u32 number = rarl20_decode_number (&ctx, &u.ld);

    if (number < 256)
    {
      rarl_emit (&ctx, (u8) number);

      continue;
    }

    if (number > 269)
    {
      number -= 270;

      u32 length = ldecode[number] + 3;

      u32 bits = lbits[number];

      if (bits > 0)
      {
        length += rarl_getbits (&ctx) >> (16 - bits);

        rarl_addbits (&ctx, bits);
      }

      const u32 dist_number = rarl20_decode_number (&ctx, &u.dd);

      u32 dist = ddecode[dist_number] + 1;

      bits = dbits[dist_number];

      if (bits > 0)
      {
        dist += rarl_getbits (&ctx) >> (16 - bits);

        rarl_addbits (&ctx, bits);
      }

      if (dist >= 0x2000)
      {
        length++;

        if (dist >= 0x40000) length++;
      }

      rarl20_copy (&ctx, &u, length, dist);

      continue;
    }

    if (number == 269)
    {
      if (rarl20_read_tables (&ctx, &u) == false) break;

      continue;
    }

    if (number == 256)
    {
      rarl20_copy (&ctx, &u, u.last_length, u.last_dist);

      continue;
    }

    if (number < 261)
    {
      const u32 dist = u.old_dist[(u.old_dist_ptr - (number - 256)) & 3];

      const u32 length_number = rarl20_decode_number (&ctx, &u.rd);

      u32 length = ldecode[length_number] + 2;

      const u32 bits = lbits[length_number];

      if (bits > 0)
      {
        length += rarl_getbits (&ctx) >> (16 - bits);

        rarl_addbits (&ctx, bits);
      }

      if (dist >= 0x101)
      {
        length++;

        if (dist >= 0x2000)
        {
          length++;

          if (dist >= 0x40000) length++;
        }
      }

      rarl20_copy (&ctx, &u, length, dist);

      continue;
    }

    number -= 261;

    u32 dist = sddecode[number] + 1;

    const u32 bits = sdbits[number];

    if (bits > 0)
    {
      dist += rarl_getbits (&ctx) >> (16 - bits);

      rarl_addbits (&ctx, bits);
    }

    rarl20_copy (&ctx, &u, 2, dist);
  }

  *crc32 = ctx.crc ^ 0xffffffff;

  const bool ok = ((ctx.failed == false) && (ctx.produced == ctx.dest_size));

  return ok;
}

// ---- what the two modules share beyond the algorithms ----

// The key as the kernel set it up: 4 words, and for RAR 2.0 the 256 byte substitution table as
// well. What goes to the host and comes back for every candidate is kept as small as each cipher
// allows: the hook buffer crosses the bus twice a batch, and at some million candidates a second
// its size decides the speed of a discrete GPU.

typedef struct rar15_tmp
{
  u32 key[4];

} rar15_tmp_t;

// For RAR 1.5 the record is two words. The four key words are 16 bits each and travel to the host
// as key[0] | key[1] << 16 and key[2] | key[3] << 16. The host answers in the same record: word 0
// becomes 1 for a match and 0 otherwise.

typedef struct rar15_hook
{
  u32 word[2];

} rar15_hook_t;

typedef struct rar20_tmp
{
  u32 key[4];
  u8  subst[256];

} rar20_tmp_t;

// pw and pw_len are only filled where the host sets the key up.

typedef struct rar20_hook
{
  u32 key[4];

  u32 hook_success;

  u8  subst[256];

  u32 pw[32];
  u32 pw_len;

} rar20_hook_t;

// One per hash, and what the kernel sees of it. in_kernel says the kernel verifies the entry
// itself, which it does for a stored one that fits data.

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

typedef struct rar_legacy_hook_salt
{
  // type is 15 for RAR 1.5 and 20 for RAR 2.0. method is 0x30 for a stored entry, 0x31 to 0x35
  // for a compressed one, and 0 when the hash line does not say. crc32 is that of the unpacked
  // file. data is the whole encrypted entry, data_len bytes of it, on the heap.

  u32 type;
  u32 method;
  u32 crc32;
  u32 unpack_size;
  u32 data_len;
  u32 in_kernel;

  u8 *data;

} rar_legacy_hook_salt_t;

// One decrypted copy of the entry and one window per hook thread, allocated on first use.

typedef struct rar_legacy_work
{
  u8 *plain;
  u8 *win;

} rar_legacy_work_t;

// Hook thread i of every device is handed the same one of these, and the devices run at the same
// time, so each device has a set of buffers of its own.

typedef struct rar_legacy_hook_extra
{
  rar_legacy_work_t work[DEVICES_MAX];

  // what --rar20-key-setup says, for the hooks, which are not handed the options

  u32 key_setup;

} rar_legacy_hook_extra_t;

static const char *SIGNATURE_RAR_LEGACY_STOP = "$/rar$";

// The size a stored entry of this unpacked size has in the archive. RAR 2.0 pads it to its 16
// byte block.

static u32 rarl_stored_len (const u32 type, const u32 unpack_size)
{
  const u32 stored_len = (type == 20) ? ((unpack_size + 15) & ~15u) : unpack_size;

  return stored_len;
}

// The RAR 2.0 key setup is some hundred thousand dependent byte swaps in a 256 byte table for
// every candidate. Left to itself, a discrete GPU does that in the kernel. An integrated one, which
// shares the memory of the host, is slower at it than the host threads are, so there the kernel
// hands the password over and the host sets the key up. --rar20-key-setup decides it by hand.

#define OPTION_RAR20_KEY_SETUP "rar20-key-setup"

#define RARL_KEY_SETUP_AUTO   0
#define RARL_KEY_SETUP_HOST   1
#define RARL_KEY_SETUP_DEVICE 2

MAYBE_UNUSED static const module_option_t *rarl_register_options (void)
{
  static const module_option_t options[] =
  {
    {
      .name         = OPTION_RAR20_KEY_SETUP,
      .type         = MODULE_OPTION_TYPE_U32,
      .flags        = MODULE_OPTION_FLAG_MAX,
      .max          = RARL_KEY_SETUP_DEVICE,
      .def          = RARL_KEY_SETUP_AUTO,
      .help_type    = "Num",
      .help         = "Where the RAR 2.0 key is set up: 0=auto, 1=host, 2=device",
      .help_example = "--rar20-key-setup=2",
    },
    { .name = NULL },
  };

  return options;
}

static bool rarl_host_key (const hc_device_param_t *device_param, const u32 key_setup)
{
  if (key_setup == RARL_KEY_SETUP_HOST)   return true;
  if (key_setup == RARL_KEY_SETUP_DEVICE) return false;

  const bool host_key = (device_param->device_host_unified_memory == 1);

  return host_key;
}

// Only the RAR 2.0 module calls this.

MAYBE_UNUSED static void rarl_hook12 (hc_device_param_t *device_param, const void *hook_extra_param, MAYBE_UNUSED const void *hook_salts_buf, MAYBE_UNUSED const u32 salt_pos, const u64 pw_pos)
{
  const rar_legacy_hook_extra_t *extra = (const rar_legacy_hook_extra_t *) hook_extra_param;

  if (rarl_host_key (device_param, extra->key_setup) == false) return;

  rar20_hook_t *hook_items = (rar20_hook_t *) device_param->hooks_buf;
  rar20_hook_t *hook_item  = &hook_items[pw_pos];

  const u32 pw_len = MIN (hook_item->pw_len, 127);

  u8 psw[128 + 16];

  memset (psw, 0, sizeof (psw));
  memcpy (psw, hook_item->pw, pw_len);

  rarl_crc32_init ();

  rarl_set_key20 (psw, pw_len, hook_item->key, hook_item->subst);
}

static void rarl_hook23 (hc_device_param_t *device_param, const void *hook_extra_param, const void *hook_salts_buf, const u32 salt_pos, const u64 pw_pos)
{
  const rar_legacy_hook_salt_t *salts = (const rar_legacy_hook_salt_t *) hook_salts_buf;
  const rar_legacy_hook_salt_t *rl    = &salts[salt_pos];

  // The kernel verified this one, and its hook buffer was never written.

  if (rl->in_kernel == 1) return;

  // The two ciphers have hook records of their own size. The key is taken out before the answer
  // goes in, because RAR 1.5 uses the same words for both.

  u32 key[4];

  const u8 *subst        = NULL;
  u32      *hook_success = NULL;

  if (rl->type == 20)
  {
    rar20_hook_t *hook_items = (rar20_hook_t *) device_param->hooks_buf;

    key[0] = hook_items[pw_pos].key[0];
    key[1] = hook_items[pw_pos].key[1];
    key[2] = hook_items[pw_pos].key[2];
    key[3] = hook_items[pw_pos].key[3];

    subst        = hook_items[pw_pos].subst;
    hook_success = &hook_items[pw_pos].hook_success;
  }
  else
  {
    rar15_hook_t *hook_items = (rar15_hook_t *) device_param->hooks_buf;

    key[0] = (hook_items[pw_pos].word[0] >>  0) & 0xffff;
    key[1] = (hook_items[pw_pos].word[0] >> 16) & 0xffff;
    key[2] = (hook_items[pw_pos].word[1] >>  0) & 0xffff;
    key[3] = (hook_items[pw_pos].word[1] >> 16) & 0xffff;

    hook_success = &hook_items[pw_pos].word[0];
  }

  *hook_success = 0;

  if (rl->data == NULL) return;

  if ((rl->data_len == 0) || (rl->data_len > RARL_DATA_MAX)) return;

  // The interface hands this over as const, but it belongs to this module and this hook thread.

  rar_legacy_hook_extra_t *shared = (rar_legacy_hook_extra_t *) hook_extra_param;

  rar_legacy_work_t *extra = &shared->work[device_param->device_id];

  if (extra->plain == NULL) extra->plain = (u8 *) hcmalloc (RARL_DATA_MAX + 16);
  if (extra->win   == NULL) extra->win   = (u8 *) hcmalloc (RARL_WIN_SIZE);

  if (extra->plain == NULL) return;
  if (extra->win   == NULL) return;

  rarl_crc32_init ();

  if (rl->type == 20)
  {
    rarl_decrypt20 (key, subst, rl->data, extra->plain, rl->data_len);
  }
  else
  {
    rarl_decrypt15 (key, rl->data, extra->plain, rl->data_len);
  }

  // A line that does not name the method is read as stored first, whenever the sizes fit one.

  const bool try_stored = ((rl->method == 0x30) || ((rl->method == 0) && (rl->data_len == rarl_stored_len (rl->type, rl->unpack_size))));

  if (try_stored == true)
  {
    const u32 stored_crc32 = rarl_crc32 (0xffffffff, extra->plain, rl->unpack_size) ^ 0xffffffff;

    if (stored_crc32 == rl->crc32)
    {
      *hook_success = 1;

      return;
    }
  }

  if (rl->method == 0x30) return;

  u32 crc32 = 0;

  bool ok = false;

  if (rl->type == 20)
  {
    ok = rarl_unpack20 (extra->win, extra->plain, rl->data_len, rl->unpack_size, &crc32);
  }
  else
  {
    ok = rarl_unpack15 (extra->win, extra->plain, rl->data_len, rl->unpack_size, &crc32);
  }

  if ((ok == true) && (crc32 == rl->crc32)) *hook_success = 1;
}

static bool rarl_hook_extra_param_term (void *hook_extra_param)
{
  rar_legacy_hook_extra_t *extra = (rar_legacy_hook_extra_t *) hook_extra_param;

  for (u32 d = 0; d < DEVICES_MAX; d++)
  {
    hcfree (extra->work[d].plain);
    hcfree (extra->work[d].win);

    extra->work[d].plain = NULL;
    extra->work[d].win   = NULL;
  }

  return true;
}

// How many candidates go to the device at once. A batch is not done before every candidate in it
// is verified, which means decrypting the whole entry for each: in the kernel for a stored entry
// it holds, on the host otherwise, where a compressed one is unpacked to its full size as well.
// The autotuner sees neither, and with an entry of some hundred kilobytes the batch it picks takes
// minutes. So the batch is sized from the entry that is the most work, with one allowance for
// what a device gets through and a smaller one for the host.
//
// A batch holds the processors of the device times its threads times the kernel accel. The threads
// are not settled when this is asked, so the most a backend has been seen to pick stands in for
// them, which only ever makes the batch smaller than meant.
//
// The answer is a tuning database row for this device: its name, the mode, the vector width, the
// kernel accel and the kernel loops, with A for a value left to the autotuner. accel_cap is the
// most the mode wants at any size, 0 for no such limit.

#define RARL_BATCH_BYTES   1000000000
#define RARL_KERNEL_BYTES  100000000000
#define RARL_BATCH_THREADS 64
#define RARL_ACCEL_ROW_MAX 1024

static char *rarl_extra_tuningdb_block (const user_options_t *user_options, const backend_ctx_t *backend_ctx, const hashes_t *hashes, const u32 device_id, const u32 accel_cap)
{
  const hc_device_param_t *device_param = &backend_ctx->devices_param[device_id];

  const rar_legacy_hook_salt_t *salts = (const rar_legacy_hook_salt_t *) hashes->hook_salts_buf;

  // The work for one candidate, in bytes read and written, and the smallest batch any entry asks
  // for.

  u64 batch = 0;

  for (u32 i = 0; i < hashes->salts_cnt; i++)
  {
    u64 work = salts[i].data_len;

    if (salts[i].method != 0x30) work += salts[i].unpack_size;

    if (work == 0) continue;

    const u64 allowance = (salts[i].in_kernel == 1) ? RARL_KERNEL_BYTES : RARL_BATCH_BYTES;

    const u64 wanted = MAX (allowance / work, 1);

    if ((batch == 0) || (wanted < batch)) batch = wanted;
  }

  // 0 stands for a value left to the autotuner.

  u32 kernel_accel = accel_cap;

  if (batch > 0)
  {
    const u64 per_accel = (u64) MAX (device_param->device_processors, 1) * RARL_BATCH_THREADS;

    const u64 accel = MAX (batch / per_accel, 1);

    // A row may name at most RARL_ACCEL_ROW_MAX. An entry small enough to ask for more is left to
    // the autotuner.

    if (accel < RARL_ACCEL_ROW_MAX) kernel_accel = (u32) accel;

    if ((accel_cap > 0) && ((kernel_accel == 0) || (kernel_accel > accel_cap))) kernel_accel = accel_cap;
  }

  if (user_options->kernel_accel_chgd == true) kernel_accel = user_options->kernel_accel;

  char *device_name = hcstrdup (device_param->device_name);

  const size_t device_name_len = strlen (device_name);

  for (size_t i = 0; i < device_name_len; i++)
  {
    if (device_name[i] == ' ') device_name[i] = '_';
  }

  char *lines_buf = NULL;

  if (kernel_accel == 0)
  {
    hc_asprintf (&lines_buf, "%s * %u 1 A A\n", device_name, user_options->hash_mode);
  }
  else
  {
    hc_asprintf (&lines_buf, "%s * %u 1 %u A\n", device_name, user_options->hash_mode, kernel_accel);
  }

  hcfree (device_name);

  return lines_buf;
}

static bool rarl_is_hex (const char *s, const u32 len)
{
  for (u32 i = 0; i < len; i++)
  {
    if (is_valid_hex_char ((u8) s[i]) == false) return false;
  }

  return true;
}

// $rar$15$*crc*us*ds*method*data$/rar$ and the same under $rar$20$. Lines without the method
// field, which older ArchiveWolf versions wrote, are read as well.

#define RARL_FIELDS 5

static int rarl_hash_decode (const char *signature, const u32 type, u32 *digest, salt_t *salt, rar_legacy_t *esalt, rar_legacy_hook_salt_t *rl, const char *line_buf, const int line_len)
{
  if (line_len < 8 + 6) return (PARSER_SIGNATURE_UNMATCHED);

  if (memcmp (line_buf, signature, 8) != 0) return (PARSER_SIGNATURE_UNMATCHED);

  if (memcmp (&line_buf[line_len - 6], SIGNATURE_RAR_LEGACY_STOP, 6) != 0) return (PARSER_SIGNATURE_UNMATCHED);

  // Split what is between the two signatures on '*'.

  const char *field[RARL_FIELDS];

  u32 flen[RARL_FIELDS];

  u32 cnt = 0;

  const u32 end = (u32) line_len - 6;

  u32 pos = 8;

  if ((pos >= end) || (line_buf[pos] != '*')) return (PARSER_SEPARATOR_UNMATCHED);

  while (pos < end)
  {
    // Step over the separator.

    pos++;

    const u32 start = pos;

    while ((pos < end) && (line_buf[pos] != '*')) pos++;

    if (cnt == RARL_FIELDS) return (PARSER_TOKEN_LENGTH);

    field[cnt] = &line_buf[start];
    flen[cnt]  = pos - start;

    cnt++;
  }

  if (cnt < RARL_FIELDS - 1) return (PARSER_TOKEN_LENGTH);

  const bool has_method = (cnt == RARL_FIELDS);

  const u32 data_at = (has_method == true) ? 4 : 3;

  if ((flen[0] != 8) || (rarl_is_hex (field[0], 8) == false)) return (PARSER_HASH_LENGTH);

  for (u32 i = 1; i < data_at; i++)
  {
    if ((flen[i] < 1) || (flen[i] > 8)) return (PARSER_SALT_VALUE);

    if (rarl_is_hex (field[i], flen[i]) == false) return (PARSER_SALT_ENCODING);
  }

  memset (rl,    0, sizeof (rar_legacy_hook_salt_t));
  memset (esalt, 0, sizeof (rar_legacy_t));

  rl->type        = type;
  rl->crc32       = (u32) hc_strtoull (field[0], NULL, 16);
  rl->unpack_size = (u32) hc_strtoull (field[1], NULL, 16);

  const u32 data_size = (u32) hc_strtoull (field[2], NULL, 16);

  if (has_method == true)
  {
    rl->method = (u32) hc_strtoull (field[3], NULL, 16);

    if ((rl->method < 0x30) || (rl->method > 0x35)) return (PARSER_SALT_VALUE);
  }

  const u32 data_hex_len = flen[data_at];

  if (rarl_is_hex (field[data_at], data_hex_len) == false) return (PARSER_SALT_ENCODING);

  // The line has to carry the whole entry: the CRC32 covers every byte of it.

  if (data_size == 0) return (PARSER_SALT_LENGTH);

  if (data_size > RARL_DATA_MAX) return (PARSER_SALT_LENGTH);

  if (data_hex_len != data_size * 2) return (PARSER_SALT_LENGTH);

  if ((type == 20) && ((data_size % 16) != 0)) return (PARSER_SALT_LENGTH);

  // An empty file has nothing to check a password against.

  if (rl->unpack_size == 0) return (PARSER_SALT_VALUE);

  if ((rl->method == 0x30) && (data_size != rarl_stored_len (type, rl->unpack_size))) return (PARSER_SALT_VALUE);

  rl->data_len = data_size;

  rl->data = (u8 *) hcmalloc (data_size);

  if (rl->data == NULL) return (PARSER_HAVE_ERRNO);

  for (u32 i = 0; i < data_size; i++) rl->data[i] = hex_to_u8 ((const u8 *) &field[data_at][i * 2]);

  rl->in_kernel = ((rl->method == 0x30) && (data_size <= RARL_KERNEL_DATA)) ? 1 : 0;

  esalt->type        = rl->type;
  esalt->method      = rl->method;
  esalt->crc32       = rl->crc32;
  esalt->unpack_size = rl->unpack_size;
  esalt->data_len    = rl->data_len;
  esalt->in_kernel   = rl->in_kernel;

  if (rl->in_kernel == 1) memcpy (esalt->data, rl->data, data_size);

  // Neither cipher has a salt, so the entry itself tells two hashes apart.

  rarl_crc32_init ();

  salt->salt_buf[0] = rl->type;
  salt->salt_buf[1] = rl->crc32;
  salt->salt_buf[2] = rl->unpack_size;
  salt->salt_buf[3] = rl->data_len;
  salt->salt_buf[4] = rarl_crc32 (0xffffffff, rl->data, rl->data_len);
  salt->salt_buf[5] = rl->method;

  salt->salt_len = 24;

  digest[0] = rl->crc32;
  digest[1] = rl->unpack_size;
  digest[2] = rl->data_len;
  digest[3] = salt->salt_buf[4];

  return (PARSER_OK);
}

static int rarl_hash_encode (const char *signature, const rar_legacy_hook_salt_t *rl, char *line_buf, const int line_size)
{
  int line_len = snprintf (line_buf, line_size, "%s*%08x*%x*%x*", signature, rl->crc32, rl->unpack_size, rl->data_len);

  if (rl->method != 0) line_len += snprintf (&line_buf[line_len], line_size - line_len, "%x*", rl->method);

  if ((u64) line_len + ((u64) rl->data_len * 2) + 8 >= (u64) line_size) return 0;

  line_len += hex_encode (rl->data, (int) rl->data_len, (u8 *) &line_buf[line_len]);

  line_len += snprintf (&line_buf[line_len], line_size - line_len, "%s", SIGNATURE_RAR_LEGACY_STOP);

  return line_len;
}
