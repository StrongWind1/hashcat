/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "modules.h"
#include "bitops.h"
#include "convert.h"
#include "shared.h"
#include "parser.h"
#include "memory.h"
#include "emu_inc_cipher_aes.h"
#include "cpu_crc32.h"
#include "ext_zstd.h"

#include <inttypes.h>
#include <stdarg.h>

// 7-Zip: 2^power rounds of SHA-256 over the password give an AES-256 key, and the data is
// encrypted in CBC mode after it has been packed. The archive stores nothing that says whether a
// password is right, so a candidate is tested on what it decrypts.
//
//   $7z$*power*salt*crc32*crc_len*join*N*stream_1*...*stream_N$/7z$
//
//   stream  =  iv*packed*unpacked*chain*data
//
//   power     NumCyclesPower, decimal
//   salt      hex, usually empty
//   crc32     CRC-32 of the first crc_len bytes the folder unpacks to, 8 hex digits, or empty,
//             or the word header
//   crc_len   hex
//   join      the coders that run after the streams have been joined, empty for one stream
//   N         number of packed streams, 1, or 4 for a folder that uses BCJ2
//   iv        initialisation vector of the stream, hex, as many bytes as the archive stores
//   packed    size of the encrypted stream, hex. A stream of BCJ2 can be empty
//   unpacked  size of what it decrypts to, hex: the rest of the last cipher block is padding
//   chain     the coders that run on this stream after decryption, in that order
//   data      the encrypted stream, or the start of it
//
// A chain is a list of coders separated by commas. A coder is id/properties/size, the id and the
// properties in hex as the archive stores them and the size of its output in hex, 0 when the line
// does not know it.
//
// A line with a CRC-32 is tested against it. A line without one is tested on its stream: all of
// it has to unpack to the size the line names and end there, or, when the line holds only the
// start of a stream, that start has to unpack without an error. A line that says header is the
// encrypted header of an archive that stores no CRC-32 for it: what it unpacks to has to be the
// header of a 7z archive, every field of it.
//
// The lines of mode 11600 are read as well and are written back in the form above.

static const u32   ATTACK_EXEC    = ATTACK_EXEC_OUTSIDE_KERNEL;
static const u32   DGST_POS0      = 0;
static const u32   DGST_POS1      = 1;
static const u32   DGST_POS2      = 2;
static const u32   DGST_POS3      = 3;
static const u32   DGST_SIZE      = DGST_SIZE_4_4;
static const u32   HASH_CATEGORY  = HASH_CATEGORY_ARCHIVE;
static const char *HASH_NAME      = "7-Zip";
static const u64   KERN_TYPE      = 46900;
static const bool  LENGTH_SORT    = true;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE
                                  | OPTS_TYPE_SUGGEST_KG;
static const u64   KERN_BITS      = KERN_BIT_HOOK23;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "$7z$*14**8cf8659e*c**1*3336343735313833313830*10*c**d00321533b483f54a523f624a5f63269$/7z$";

#define MODULE_OWN_KERN_BITS
#define MODULE_OWN_LENGTH_SORT

#include "hooks_common.c"

#include "sevenzip_decode.c"

static u64  module_kern_bits   (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return KERN_BITS;   }
static bool module_length_sort (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return LENGTH_SORT; }

static const char *module_usage_notice (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  return "Use ArchiveWolf or tools/7z2hashcat.py to extract the hash from a 7z archive. Lines written for mode 11600 are read as well.";
}

#define SZ_STREAMS_MAX 4

// What a line is tested on: its stream alone, a CRC-32, or being the header of an archive.

#define SZ_CHECK_STREAM 0
#define SZ_CHECK_CRC    1
#define SZ_CHECK_HEADER 2

#define SZ_CHAIN_MAX   8
#define SZ_PROPS_MAX   16

// A line holds at most this much data, which is what fits the buffer hashcat reads a line into.

#define SZ_DATA_MAX 0x7ff000u

// A candidate is unpacked to at most this many bytes when a CRC-32 is to be tested, and to this
// many when only the start of a stream is.

#define SZ_OUT_MAX   (64u * 1024 * 1024)
#define SZ_START_MAX (16u * 1024 * 1024)

// How much of an LZMA2 or Deflate stream has to be there for its start to be a test.

#define SZ_START_MIN (1024u * 1024)

// A branch converter looks this far past the bytes it has been asked for.

#define SZ_LOOKAHEAD 16

typedef struct seven_zip_tmp
{
  u32 h[8];

  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  int len;

} seven_zip_tmp_t;

typedef struct seven_zip_hook
{
  u32 ukey[8];

  u32 hook_success;

} seven_zip_hook_t;

typedef struct sz_coder
{
  u32 kind;
  u32 props_len;
  u8  props[SZ_PROPS_MAX];
  u64 size;

} sz_coder_t;

typedef struct sz_stream
{
  u32 iv_len;
  u8  iv[16];

  u64 packed;
  u64 unpacked;

  u32        chain_cnt;
  sz_coder_t chain[SZ_CHAIN_MAX];

  u32 data_len;
  u8 *data;

} sz_stream_t;

typedef struct seven_zip_hook_salt
{
  u32 power;

  u32 salt_len;
  u8  salt[16];

  u32 has_crc; // one of SZ_CHECK_*
  u32 crc;
  u64 crc_len;

  u32        join_cnt;
  sz_coder_t join[SZ_CHAIN_MAX];

  u32         stream_cnt;
  sz_stream_t streams[SZ_STREAMS_MAX];

  // a line of mode 11600 does not say how large the output of a coder is, nor which of the two
  // Deflate coders packed it

  u32 legacy;

} seven_zip_hook_salt_t;

// The buffers one hook thread keeps between candidates for one device, allocated on first use.

typedef struct sz_buf
{
  u8    *ptr;
  size_t cap;

} sz_buf_t;

typedef struct sz_work
{
  sz_buf_t plain[SZ_STREAMS_MAX];
  sz_buf_t stage[SZ_STREAMS_MAX];
  sz_buf_t joined;
  sz_buf_t spare;

  sz_mem_t mem;

} sz_work_t;

// Hook thread i of every device is handed the same one of these, and the devices run at the same
// time, so each device has a set of buffers of its own.

typedef struct seven_zip_hook_extra
{
  sz_work_t *work[DEVICES_MAX];

} seven_zip_hook_extra_t;

static const char *SIGNATURE_SEVEN_ZIP      = "$7z$";
static const char *SIGNATURE_SEVEN_ZIP_NEW  = "$7z$*";
static const char *SIGNATURE_SEVEN_ZIP_STOP = "$/7z$";

static char *module_jit_build_options (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra, MAYBE_UNUSED const hashes_t *hashes, MAYBE_UNUSED const hc_device_param_t *device_param)
{
  char *jit_build_options = NULL;

  // Extra treatment for Apple systems
  if (device_param->opencl_platform_vendor_id == VENDOR_ID_APPLE)
  {
    return jit_build_options;
  }

  // HIP
  if (device_param->opencl_device_vendor_id == VENDOR_ID_AMD_USE_HIP)
  {
    hc_asprintf (&jit_build_options, "-D _unroll");
  }

  // ROCM
  if ((device_param->opencl_device_vendor_id == VENDOR_ID_AMD) && (device_param->has_vperm == true))
  {
    hc_asprintf (&jit_build_options, "-D _unroll");
  }

  return jit_build_options;
}

static bool module_hook_extra_param_init (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra, MAYBE_UNUSED const folder_config_t *folder_config, MAYBE_UNUSED const backend_ctx_t *backend_ctx, void *hook_extra_param)
{
  memset (hook_extra_param, 0, sizeof (seven_zip_hook_extra_t));

  return true;
}

static bool module_hook_extra_param_term (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra, MAYBE_UNUSED const folder_config_t *folder_config, MAYBE_UNUSED const backend_ctx_t *backend_ctx, void *hook_extra_param)
{
  seven_zip_hook_extra_t *extra = (seven_zip_hook_extra_t *) hook_extra_param;

  for (u32 d = 0; d < DEVICES_MAX; d++)
  {
    sz_work_t *work = extra->work[d];

    if (work == NULL) continue;

    for (u32 i = 0; i < SZ_STREAMS_MAX; i++)
    {
      free (work->plain[i].ptr);
      free (work->stage[i].ptr);
    }

    free (work->joined.ptr);
    free (work->spare.ptr);

    sz_mem_free (&work->mem);

    free (work);
  }

  memset (extra, 0, sizeof (seven_zip_hook_extra_t));

  return true;
}

static u8 *sz_buf_get (sz_buf_t *buf, const size_t size)
{
  if ((buf->ptr != NULL) && (buf->cap >= size)) return buf->ptr;

  free (buf->ptr);

  // a few bytes more, because the decoders of 7-Zip read and write in words

  buf->ptr = (u8 *) malloc (size + 64);
  buf->cap = (buf->ptr == NULL) ? 0 : size;

  return buf->ptr;
}

// AES-256 in CBC mode, one block or many. The cipher takes its words as they lie in memory.

static void sz_cbc_decrypt (const u32 *rdk, const u8 *iv, const u8 *in, u8 *out, const size_t len)
{
  u32 prev[4];

  memcpy (prev, iv, 16);

  for (size_t pos = 0; pos + 16 <= len; pos += 16)
  {
    u32 data[4];
    u32 text[4];

    memcpy (data, in + pos, 16);

    aes256_decrypt (rdk, data, text, (u32 *) td0, (u32 *) td1, (u32 *) td2, (u32 *) td3, (u32 *) td4);

    text[0] ^= prev[0];
    text[1] ^= prev[1];
    text[2] ^= prev[2];
    text[3] ^= prev[3];

    prev[0] = data[0];
    prev[1] = data[1];
    prev[2] = data[2];
    prev[3] = data[3];

    memcpy (out + pos, text, 16);
  }
}

static u32 sz_first_packer (const sz_stream_t *stream)
{
  if (stream->chain_cnt == 0) return SZ_KIND_NONE;

  return (SZ_KIND_IS_PACKER (stream->chain[0].kind)) ? stream->chain[0].kind : SZ_KIND_NONE;
}

static bool sz_has_filter (const seven_zip_hook_salt_t *seven_zip)
{
  for (u32 i = 0; i < seven_zip->join_cnt; i++)
  {
    if (SZ_KIND_IS_FILTER (seven_zip->join[i].kind)) return true;
  }

  for (u32 s = 0; s < seven_zip->stream_cnt; s++)
  {
    for (u32 i = 0; i < seven_zip->streams[s].chain_cnt; i++)
    {
      if (SZ_KIND_IS_FILTER (seven_zip->streams[s].chain[i].kind)) return true;
    }
  }

  return false;
}

// Size of what the folder unpacks to, 0 when the line does not say.

static u64 sz_final_size (const seven_zip_hook_salt_t *seven_zip)
{
  if (seven_zip->join_cnt > 0) return seven_zip->join[seven_zip->join_cnt - 1].size;

  const sz_stream_t *stream = &seven_zip->streams[0];

  if (stream->chain_cnt > 0) return stream->chain[stream->chain_cnt - 1].size;

  return stream->unpacked;
}

// The test that costs one cipher block: the first block has to look like the start of the stream
// the line says it is. What is left of the last block is not looked at. 7-Zip fills it with zeros,
// but nothing reads it back, and other writers fill it with something else.

static bool sz_cheap_tests (const u32 *rdk, const sz_stream_t *stream)
{
  const u32 kind = sz_first_packer (stream);

  if ((kind != SZ_KIND_NONE) && (stream->unpacked >= 16))
  {
    u8 iv[16] = { 0 };

    memcpy (iv, stream->iv, stream->iv_len);

    u8 text[16];

    sz_cbc_decrypt (rdk, iv, stream->data, text, 16);

    if (sz_start_fits (kind, text) == false) return false;
  }

  return true;
}

// Run the coders of one stream over what it decrypted to. A packer writes into a buffer of its
// own, a filter works in place. want is how much of the last coder's output is needed. Returns how
// the last packer stopped, and where the result is.

static int sz_run_chain (sz_work_t *extra, const u32 s, const sz_coder_t *chain, const u32 chain_cnt, u8 *in, size_t in_len, const bool whole, const size_t want, u8 **out, size_t *out_len)
{
  u8    *cur     = in;
  size_t cur_len = in_len;

  int rc = SZ_DONE;

  bool flip = false;

  // a filter that comes first would change what was decrypted, which a second try starts from

  if ((chain_cnt > 0) && (SZ_KIND_IS_FILTER (chain[0].kind)))
  {
    u8 *copy = sz_buf_get (&extra->stage[s], in_len);

    if (copy == NULL) return SZ_BAD;

    memcpy (copy, in, in_len);

    cur  = copy;
    flip = true;
  }

  for (u32 i = 0; i < chain_cnt; i++)
  {
    const sz_coder_t *coder = &chain[i];

    if (SZ_KIND_IS_FILTER (coder->kind))
    {
      if (sz_filter (coder->kind, coder->props, coder->props_len, cur, cur_len) == false) return SZ_BAD;

      continue;
    }

    // a packer that feeds another one has to give all it has

    bool feeds = false;

    for (u32 k = i + 1; k < chain_cnt; k++)
    {
      if (SZ_KIND_IS_PACKER (chain[k].kind)) feeds = true;
    }

    size_t need = want;

    if (feeds == true)
    {
      if ((coder->size == 0) || (coder->size > SZ_OUT_MAX)) return SZ_BAD;

      need = (size_t) coder->size;
    }

    const bool to_end = (whole == true) && (coder->size != 0) && (need == coder->size) && (rc == SZ_DONE);

    sz_buf_t *buf = (flip == false) ? &extra->stage[s] : &extra->spare;

    flip = !flip;

    u8 *dst = sz_buf_get (buf, need);

    if (dst == NULL) return SZ_BAD;

    size_t produced = 0;
    size_t consumed = 0;

    rc = sz_unpack (&extra->mem, coder->kind, coder->props, coder->props_len, cur, cur_len, dst, need, to_end, &produced, &consumed);

    // a stream of 7-Zip's own range coders ends with its last byte

    if ((rc == SZ_DONE) && (to_end == true) && (consumed != cur_len))
    {
      if ((coder->kind == SZ_KIND_LZMA) || (coder->kind == SZ_KIND_LZMA2)) rc = SZ_BAD;
    }

    cur     = dst;
    cur_len = produced;

    if (rc == SZ_BAD) return SZ_BAD;

    if ((feeds == true) && (rc != SZ_DONE)) return SZ_BAD;
  }

  *out     = cur;
  *out_len = cur_len;

  return rc;
}

// A wrong key that got past the first block almost never gets far: the packers here give up
// within a few bytes of a stream that is not theirs. So the start is decrypted and unpacked on
// its own before the whole stream is, which for a long stream is most of the work.

#define SZ_PROBE_IN  4096
#define SZ_PROBE_OUT 65536

static bool sz_probe (sz_work_t *extra, const u32 *rdk, const sz_stream_t *stream, const u32 s, const u32 kind)
{
  if (stream->data_len <= SZ_PROBE_IN * 4) return true;

  u8 *plain = sz_buf_get (&extra->plain[s], stream->data_len);
  u8 *out   = sz_buf_get (&extra->spare, SZ_PROBE_OUT);

  if ((plain == NULL) || (out == NULL)) return false;

  u8 iv[16] = { 0 };

  memcpy (iv, stream->iv, stream->iv_len);

  sz_cbc_decrypt (rdk, iv, stream->data, plain, SZ_PROBE_IN);

  size_t produced = 0;
  size_t consumed = 0;

  const sz_coder_t *coder = &stream->chain[0];

  const int rc = sz_unpack (&extra->mem, kind, coder->props, coder->props_len, plain, SZ_PROBE_IN, out, SZ_PROBE_OUT, false, &produced, &consumed);

  return (rc != SZ_BAD);
}

static bool sz_crc_matches (const seven_zip_hook_salt_t *seven_zip, const u8 *data, const size_t len)
{
  if (len < seven_zip->crc_len) return false;

  return (cpu_crc32_buffer (data, (size_t) seven_zip->crc_len) == seven_zip->crc);
}

// Apply the filters that run after BCJ2 and compare.

static bool sz_finish (const seven_zip_hook_salt_t *seven_zip, const sz_coder_t *tail, const u32 tail_cnt, u8 *data, const size_t len)
{
  for (u32 i = 0; i < tail_cnt; i++)
  {
    if (sz_filter (tail[i].kind, tail[i].props, tail[i].props_len, data, len) == false) return false;
  }

  return sz_crc_matches (seven_zip, data, len);
}

static bool sz_test_candidate (sz_work_t *extra, const seven_zip_hook_salt_t *seven_zip, const u32 *rdk, const bool deflate64)
{
  // nothing is decrypted in full before every stream has passed what costs one block

  for (u32 s = 0; s < seven_zip->stream_cnt; s++)
  {
    if (seven_zip->streams[s].data_len == 0) continue;

    if (sz_cheap_tests (rdk, &seven_zip->streams[s]) == false) return false;
  }

  for (u32 s = 0; s < seven_zip->stream_cnt; s++)
  {
    const sz_stream_t *stream = &seven_zip->streams[s];

    if (stream->data_len == 0) continue;

    u32 kind = sz_first_packer (stream);

    if ((deflate64 == true) && (kind == SZ_KIND_DEFLATE)) kind = SZ_KIND_DEFLATE64;

    // the library for Zstandard and the PPMd model are not worth starting twice

    if ((kind != SZ_KIND_NONE) && (kind != SZ_KIND_ZSTD) && (kind != SZ_KIND_PPMD))
    {
      if (sz_probe (extra, rdk, stream, s, kind) == false) return false;
    }
  }

  for (u32 s = 0; s < seven_zip->stream_cnt; s++)
  {
    const sz_stream_t *stream = &seven_zip->streams[s];

    u8 *plain = sz_buf_get (&extra->plain[s], stream->data_len);

    if (plain == NULL) return false;

    u8 iv[16] = { 0 };

    memcpy (iv, stream->iv, stream->iv_len);

    sz_cbc_decrypt (rdk, iv, stream->data, plain, stream->data_len);
  }

  if (seven_zip->has_crc == SZ_CHECK_HEADER)
  {
    const sz_stream_t *stream = &seven_zip->streams[0];

    u8    *out     = NULL;
    size_t out_len = 0;

    const u64 size = sz_final_size (seven_zip);

    const int rc = sz_run_chain (extra, 0, stream->chain, stream->chain_cnt, extra->plain[0].ptr, (size_t) stream->unpacked, true, (size_t) size, &out, &out_len);

    if ((rc != SZ_DONE) || (out_len != size)) return false;

    return sz_header_valid (out, out_len);
  }

  const u64  final  = sz_final_size (seven_zip);
  const bool filter = sz_has_filter (seven_zip);

  if (seven_zip->stream_cnt == 1)
  {
    const sz_stream_t *stream = &seven_zip->streams[0];

    const bool   whole  = (stream->data_len == stream->packed);
    const size_t in_len = (whole == true) ? (size_t) stream->unpacked : stream->data_len;

    sz_coder_t chain[SZ_CHAIN_MAX];

    memcpy (chain, stream->chain, sizeof (chain));

    if ((deflate64 == true) && (chain[0].kind == SZ_KIND_DEFLATE)) chain[0].kind = SZ_KIND_DEFLATE64;

    u8    *out     = NULL;
    size_t out_len = 0;

    if (seven_zip->has_crc == SZ_CHECK_STREAM)
    {
      // no checksum: the stream itself has to be right

      // all of it is here and it is not too large: it has to unpack to its size and end there

      if ((whole == true) && (final != 0) && (final <= SZ_OUT_MAX))
      {
        const int rc = sz_run_chain (extra, 0, chain, stream->chain_cnt, extra->plain[0].ptr, in_len, true, (size_t) final, &out, &out_len);

        return (rc == SZ_DONE) && (out_len == final);
      }

      // otherwise its start has to unpack without an error, up to where the line or the buffer ends

      size_t want = SZ_START_MAX;

      if ((final != 0) && (final < want)) want = (size_t) final;

      // only the packer is run: a filter has nothing to say here

      const int rc = sz_run_chain (extra, 0, chain, 1, extra->plain[0].ptr, in_len, false, want, &out, &out_len);

      return (rc == SZ_SHORT) || (rc == SZ_DONE);
    }

    // with a filter, first try with the bytes it may look ahead at, then without them: which of
    // the two is right depends on whether the first file is all the folder holds

    size_t want = (size_t) seven_zip->crc_len;

    if (filter == true)
    {
      want += SZ_LOOKAHEAD;

      if ((final != 0) && (want > final)) want = (size_t) final;
    }

    const int rc = sz_run_chain (extra, 0, chain, stream->chain_cnt, extra->plain[0].ptr, in_len, whole, want, &out, &out_len);

    if (rc == SZ_BAD) return false;

    if (sz_crc_matches (seven_zip, out, out_len) == true) return true;

    if ((filter == false) || (out_len <= seven_zip->crc_len)) return false;

    const int rc2 = sz_run_chain (extra, 0, chain, stream->chain_cnt, extra->plain[0].ptr, in_len, whole, (size_t) seven_zip->crc_len, &out, &out_len);

    if (rc2 == SZ_BAD) return false;

    return sz_crc_matches (seven_zip, out, out_len);
  }

  // four streams: each is unpacked in full, then BCJ2 puts them together

  const u8 *bufs[SZ_STREAMS_MAX];
  size_t    lens[SZ_STREAMS_MAX];

  for (u32 s = 0; s < seven_zip->stream_cnt; s++)
  {
    const sz_stream_t *stream = &seven_zip->streams[s];

    u8    *out     = extra->plain[s].ptr;
    size_t out_len = (size_t) stream->unpacked;

    if (stream->chain_cnt > 0)
    {
      const u64 size = stream->chain[stream->chain_cnt - 1].size;

      if (size > SZ_OUT_MAX) return false;

      const int rc = sz_run_chain (extra, s, stream->chain, stream->chain_cnt, extra->plain[s].ptr, (size_t) stream->unpacked, true, (size_t) size, &out, &out_len);

      // a stream that unpacks to nothing ends before it has given anything

      if ((rc != SZ_DONE) && !((rc == SZ_END) && (size == 0))) return false;

      if (out_len != size) return false;
    }

    bufs[s] = out;
    lens[s] = out_len;
  }

  size_t want = (size_t) seven_zip->crc_len;

  if ((seven_zip->join_cnt > 1) && (want < final))
  {
    want += SZ_LOOKAHEAD;

    if (want > final) want = (size_t) final;
  }

  u8 *joined = sz_buf_get (&extra->joined, want);

  if (joined == NULL) return false;

  size_t produced = 0;

  const int rc = sz_bcj2 (bufs, lens, joined, want, (want == seven_zip->join[0].size), &produced);

  if (rc != SZ_DONE) return false;

  return sz_finish (seven_zip, seven_zip->join + 1, seven_zip->join_cnt - 1, joined, produced);
}

static void module_hook23 (hc_device_param_t *device_param, const void *hook_extra_param, const void *hook_salts_buf, const u32 salt_pos, const u64 pw_pos)
{
  seven_zip_hook_t *hook_items = (seven_zip_hook_t *) device_param->hooks_buf;
  seven_zip_hook_t *hook_item  = &hook_items[pw_pos];

  const seven_zip_hook_salt_t *seven_zips = (const seven_zip_hook_salt_t *) hook_salts_buf;
  const seven_zip_hook_salt_t *seven_zip  = &seven_zips[salt_pos];

  // The interface hands this over as const, but it belongs to this module and this hook thread.

  seven_zip_hook_extra_t *shared = (seven_zip_hook_extra_t *) hook_extra_param;

  hook_item->hook_success = 0;

  if (shared->work[device_param->device_id] == NULL) shared->work[device_param->device_id] = (sz_work_t *) calloc (1, sizeof (sz_work_t));

  sz_work_t *extra = shared->work[device_param->device_id];

  if (extra == NULL) return;

  AES_KEY aes_key;

  memset (&aes_key, 0, sizeof (aes_key));

  aes256_set_decrypt_key (aes_key.rdk, hook_item->ukey, (u32 *) te0, (u32 *) te1, (u32 *) te2, (u32 *) te3, (u32 *) td0, (u32 *) td1, (u32 *) td2, (u32 *) td3);

  bool match = sz_test_candidate (extra, seven_zip, aes_key.rdk, false);

  // a line of mode 11600 has one number for both Deflate coders

  if ((match == false) && (seven_zip->legacy == 1) && (seven_zip->streams[0].chain_cnt > 0) && (seven_zip->streams[0].chain[0].kind == SZ_KIND_DEFLATE))
  {
    match = sz_test_candidate (extra, seven_zip, aes_key.rdk, true);
  }

  hook_item->hook_success = (match == true) ? 1 : 0;
}

static u64 module_hook_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 hook_size = (const u64) sizeof (seven_zip_hook_t);

  return hook_size;
}

static u64 module_hook_salt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 hook_salt_size = (const u64) sizeof (seven_zip_hook_salt_t);

  return hook_salt_size;
}

static u64 module_hook_extra_param_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 hook_extra_param_size = (const u64) sizeof (seven_zip_hook_extra_t);

  return hook_extra_param_size;
}

static u64 module_tmp_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 tmp_size = (const u64) sizeof (seven_zip_tmp_t);

  return tmp_size;
}

static u32 module_pw_max (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const bool optimized_kernel = (hashconfig->opti_type & OPTI_TYPE_OPTIMIZED_KERNEL);

  u32 pw_max = PW_MAX;

  if (optimized_kernel == true)
  {
    pw_max = 20;
  }

  return pw_max;
}

static u32 module_kernel_loops_min (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const bool optimized_kernel = (hashconfig->opti_type & OPTI_TYPE_OPTIMIZED_KERNEL);

  u32 kernel_loops_min = KERNEL_LOOPS_MIN;

  if (optimized_kernel == true)
  {
    kernel_loops_min = 4096;
  }

  return kernel_loops_min;
}

static u32 module_kernel_loops_max (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const bool optimized_kernel = (hashconfig->opti_type & OPTI_TYPE_OPTIMIZED_KERNEL);

  u32 kernel_loops_max = KERNEL_LOOPS_MAX;

  if (optimized_kernel == true)
  {
    kernel_loops_max = 4096;
  }

  return kernel_loops_max;
}

static bool sz_is_dec (const u8 *buf, const u32 len)
{
  if (len == 0) return false;

  for (u32 i = 0; i < len; i++)
  {
    if ((buf[i] < '0') || (buf[i] > '9')) return false;
  }

  return true;
}

// The fields are not terminated, so a number is copied out before it is converted.

static bool sz_number (const u8 *buf, const u32 len, const int base, u64 *value)
{
  if ((len < 1) || (len > 16)) return false;

  if ((base == 10) && (sz_is_dec (buf, len) == false)) return false;

  if ((base == 16) && (is_valid_hex_string (buf, len) == false)) return false;

  char tmp[20] = { 0 };

  memcpy (tmp, buf, len);

  *value = hc_strtoull (tmp, NULL, base);

  return true;
}

static bool sz_bytes (const u8 *buf, const u32 len, u8 *out, const u32 out_max, u32 *out_len)
{
  if ((len & 1) || ((len / 2) > out_max)) return false;

  if ((len > 0) && (is_valid_hex_string (buf, len) == false)) return false;

  for (u32 i = 0; i < len / 2; i++) out[i] = hex_to_u8 (&buf[i * 2]);

  *out_len = len / 2;

  return true;
}

// A list of coders: id/properties/size, separated by commas. There is no colon in a line, because
// hashcat counts the colons of a line to tell lists of other tools apart.

static int sz_parse_chain (const u8 *buf, const u32 len, sz_coder_t *chain, u32 *chain_cnt)
{
  *chain_cnt = 0;

  u32 pos = 0;

  while (pos < len)
  {
    u32 end = pos;

    while ((end < len) && (buf[end] != ',')) end++;

    if (*chain_cnt == SZ_CHAIN_MAX) return (PARSER_SEVEN_ZIP_METHOD_UNSUPPORTED);

    u32 slash1 = pos;

    while ((slash1 < end) && (buf[slash1] != '/')) slash1++;

    u32 slash2 = slash1 + 1;

    while ((slash2 < end) && (buf[slash2] != '/')) slash2++;

    if ((slash1 >= end) || (slash2 >= end)) return (PARSER_SEPARATOR_UNMATCHED);

    sz_coder_t *coder = &chain[*chain_cnt];

    memset (coder, 0, sizeof (sz_coder_t));

    u8  id[4];
    u32 id_len = 0;

    if (sz_bytes (buf + pos, slash1 - pos, id, 4, &id_len) == false) return (PARSER_SEVEN_ZIP_METHOD_UNSUPPORTED);

    coder->kind = sz_kind_of (id, id_len);

    if (coder->kind == SZ_KIND_NONE) return (PARSER_SEVEN_ZIP_METHOD_UNSUPPORTED);

    if (sz_bytes (buf + slash1 + 1, slash2 - slash1 - 1, coder->props, SZ_PROPS_MAX, &coder->props_len) == false) return (PARSER_SALT_VALUE);

    if (sz_number (buf + slash2 + 1, end - slash2 - 1, 16, &coder->size) == false) return (PARSER_SALT_VALUE);

    (*chain_cnt)++;

    pos = end + 1;

    if ((end < len) && (pos == len)) return (PARSER_SEPARATOR_UNMATCHED);
  }

  return (PARSER_OK);
}

// What a parser of either form has filled in is checked here, and what the kernel and the hook
// need beyond the fields is worked out.

static int sz_finish_line (const hashconfig_t *hashconfig, u32 *digest, salt_t *salt, seven_zip_hook_salt_t *seven_zip, const char *line_buf, const int line_len)
{
  // only the pure kernel hashes a salt in front of the password

  if ((seven_zip->salt_len != 0) && (hashconfig->opti_type & OPTI_TYPE_OPTIMIZED_KERNEL)) return (PARSER_SALT_VALUE);

  // 7-Zip itself takes no more than 2^24 rounds. 63 stands for a key that is the salt and the
  // password as they are, which 7-Zip reads and never writes, and which is not tested here.

  if (seven_zip->power > 24) return (PARSER_SALT_ITERATION);

  // the optimized kernel hashes 64 rounds at a time

  if ((seven_zip->power < 6) && (hashconfig->opti_type & OPTI_TYPE_OPTIMIZED_KERNEL)) return (PARSER_SALT_ITERATION);

  if ((seven_zip->stream_cnt != 1) && (seven_zip->stream_cnt != SZ_STREAMS_MAX)) return (PARSER_SALT_VALUE);

  if (seven_zip->stream_cnt == 1)
  {
    if (seven_zip->join_cnt != 0) return (PARSER_SALT_VALUE);
  }
  else
  {
    if ((seven_zip->join_cnt == 0) || (seven_zip->join[0].kind != SZ_KIND_BCJ2)) return (PARSER_SEVEN_ZIP_METHOD_UNSUPPORTED);

    if (seven_zip->has_crc != SZ_CHECK_CRC) return (PARSER_HASH_VALUE);
  }

  for (u32 i = 1; i < seven_zip->join_cnt; i++)
  {
    if (!SZ_KIND_IS_FILTER (seven_zip->join[i].kind)) return (PARSER_SEVEN_ZIP_METHOD_UNSUPPORTED);
  }

  u64 data_total = 0;

  for (u32 s = 0; s < seven_zip->stream_cnt; s++)
  {
    const sz_stream_t *stream = &seven_zip->streams[s];

    // BCJ2 leaves a stream empty when the code has no calls or no jumps to take out

    if ((seven_zip->stream_cnt > 1) && (stream->packed == 0) && (stream->unpacked == 0) && (stream->data_len == 0) && (stream->chain_cnt == 0)) continue;

    if ((stream->packed == 0) || (stream->packed & 15)) return (PARSER_SALT_VALUE);

    if ((stream->unpacked > stream->packed) || (stream->packed - stream->unpacked >= 16)) return (PARSER_SALT_VALUE);

    if ((stream->data_len == 0) || (stream->data_len & 15) || (stream->data_len > stream->packed)) return (PARSER_SALT_VALUE);

    // four streams are put together from all they hold

    if ((seven_zip->stream_cnt > 1) && (stream->data_len != stream->packed)) return (PARSER_SALT_VALUE);

    data_total += stream->data_len;

    for (u32 i = 0; i < stream->chain_cnt; i++)
    {
      const sz_coder_t *coder = &stream->chain[i];

      if (coder->kind == SZ_KIND_BCJ2) return (PARSER_SEVEN_ZIP_METHOD_UNSUPPORTED);

      if ((coder->kind == SZ_KIND_ZSTD) && (hc_zstd_available () == false)) return (PARSER_ZSTD_UNAVAILABLE);

      if (coder->kind == SZ_KIND_PPMD)
      {
        if (coder->props_len < 5) return (PARSER_SALT_VALUE);

        const u32 mem = ((u32) coder->props[1]) | ((u32) coder->props[2] << 8) | ((u32) coder->props[3] << 16) | ((u32) coder->props[4] << 24);

        if (mem > SZ_PPMD_MEM_MAX) return (PARSER_SEVEN_ZIP_METHOD_UNSUPPORTED);
      }
    }
  }

  if (data_total > SZ_DATA_MAX) return (PARSER_SALT_LENGTH);

  const sz_stream_t *first = &seven_zip->streams[0];

  const u64 final = sz_final_size (seven_zip);

  if (seven_zip->has_crc == SZ_CHECK_CRC)
  {
    if ((seven_zip->crc_len == 0) || (seven_zip->crc_len + SZ_LOOKAHEAD > SZ_OUT_MAX)) return (PARSER_SALT_VALUE);

    if ((final != 0) && (seven_zip->crc_len > final)) return (PARSER_SALT_VALUE);
  }
  else if (seven_zip->has_crc == SZ_CHECK_HEADER)
  {
    // a header is unpacked in full

    if ((first->data_len != first->packed) || (final == 0) || (final > SZ_OUT_MAX)) return (PARSER_SALT_VALUE);
  }
  else
  {
    // without a checksum the stream has to speak for itself, which stored data cannot

    if (sz_first_packer (first) == SZ_KIND_NONE) return (PARSER_HASH_VALUE);

    // only the start is tested: these two take anything, or do not say how far they came

    const bool to_end = (first->data_len == first->packed) && (final != 0) && (final <= SZ_OUT_MAX);

    if (to_end == false)
    {
      const u32 kind = first->chain[0].kind;

      if ((kind == SZ_KIND_PPMD) || (kind == SZ_KIND_ZSTD)) return (PARSER_HASH_VALUE);

      // LZMA2 and Deflate can store data as it is, in chunks of up to 64 KiB that nothing checks.
      // A megabyte holds enough chunk headers for a wrong key to fail on one of them. Of three
      // million random starts of 4 KiB, LZMA2 took 10,808 and Deflate 14.

      if ((kind == SZ_KIND_LZMA2) || (kind == SZ_KIND_DEFLATE) || (kind == SZ_KIND_DEFLATE64))
      {
        if (first->data_len < SZ_START_MIN) return (PARSER_HASH_VALUE);
      }
    }
  }

  // Every line is a salt of its own: the hook is handed one hook salt for a salt, so two lines
  // that shared one would be tested against the data of the first.

  salt->salt_buf[0] = cpu_crc32_buffer ((const u8 *) line_buf, (size_t) line_len);
  salt->salt_buf[1] = cpu_crc32_buffer (first->data, first->data_len);
  salt->salt_buf[2] = seven_zip->crc;
  salt->salt_buf[3] = (u32) seven_zip->crc_len;
  salt->salt_buf[4] = (u32) first->packed;
  salt->salt_buf[5] = seven_zip->stream_cnt;

  // the salt of the key derivation, for the kernel

  memcpy (&salt->salt_buf[8], seven_zip->salt, 16);

  salt->salt_buf[12] = seven_zip->salt_len;

  salt->salt_len = 52;

  salt->salt_iter = 1u << seven_zip->power;

  digest[0] = salt->salt_buf[0];
  digest[1] = salt->salt_buf[1];
  digest[2] = salt->salt_buf[2];
  digest[3] = salt->salt_buf[3];

  return (PARSER_OK);
}

static int sz_decode_new (const hashconfig_t *hashconfig, u32 *digest, salt_t *salt, seven_zip_hook_salt_t *seven_zip, const char *line_buf, const int line_len)
{
  if (line_len < 5 + 5) return (PARSER_SIGNATURE_UNMATCHED);

  if (memcmp (line_buf + line_len - 5, SIGNATURE_SEVEN_ZIP_STOP, 5) != 0) return (PARSER_SIGNATURE_UNMATCHED);

  #define SZ_FIELDS_MAX (6 + (SZ_STREAMS_MAX * 5))

  const u8 *field[SZ_FIELDS_MAX];

  u32 flen[SZ_FIELDS_MAX];

  u32 cnt = 0;

  const u8 *buf = (const u8 *) line_buf;

  const u32 end = (u32) line_len - 5;

  u32 pos = 4;

  while (pos < end)
  {
    pos++;

    const u32 start = pos;

    while ((pos < end) && (buf[pos] != '*')) pos++;

    if (cnt == SZ_FIELDS_MAX) return (PARSER_TOKEN_LENGTH);

    field[cnt] = buf + start;
    flen[cnt]  = pos - start;

    cnt++;
  }

  if (cnt < 6) return (PARSER_TOKEN_LENGTH);

  u64 value = 0;

  if (sz_number (field[0], flen[0], 10, &value) == false) return (PARSER_SALT_ITERATION);

  if (value > 63) return (PARSER_SALT_ITERATION);

  seven_zip->power = (u32) value;

  if (sz_bytes (field[1], flen[1], seven_zip->salt, 16, &seven_zip->salt_len) == false) return (PARSER_SALT_LENGTH);

  if (flen[2] == 0)
  {
    seven_zip->has_crc = SZ_CHECK_STREAM;
  }
  else if ((flen[2] == 6) && (memcmp (field[2], "header", 6) == 0))
  {
    seven_zip->has_crc = SZ_CHECK_HEADER;
  }
  else
  {
    if ((flen[2] != 8) || (sz_number (field[2], 8, 16, &value) == false)) return (PARSER_HASH_ENCODING);

    seven_zip->has_crc = SZ_CHECK_CRC;
    seven_zip->crc     = (u32) value;
  }

  if (sz_number (field[3], flen[3], 16, &seven_zip->crc_len) == false) return (PARSER_SALT_VALUE);

  const int rc_join = sz_parse_chain (field[4], flen[4], seven_zip->join, &seven_zip->join_cnt);

  if (rc_join != PARSER_OK) return rc_join;

  if (sz_number (field[5], flen[5], 10, &value) == false) return (PARSER_SALT_VALUE);

  if ((value != 1) && (value != SZ_STREAMS_MAX)) return (PARSER_SALT_VALUE);

  seven_zip->stream_cnt = (u32) value;

  if (cnt != 6 + (seven_zip->stream_cnt * 5)) return (PARSER_TOKEN_LENGTH);

  for (u32 s = 0; s < seven_zip->stream_cnt; s++)
  {
    const u32 at = 6 + (s * 5);

    sz_stream_t *stream = &seven_zip->streams[s];

    if (sz_bytes (field[at + 0], flen[at + 0], stream->iv, 16, &stream->iv_len) == false) return (PARSER_SALT_LENGTH);

    if (sz_number (field[at + 1], flen[at + 1], 16, &stream->packed)   == false) return (PARSER_SALT_VALUE);
    if (sz_number (field[at + 2], flen[at + 2], 16, &stream->unpacked) == false) return (PARSER_SALT_VALUE);

    const int rc_chain = sz_parse_chain (field[at + 3], flen[at + 3], stream->chain, &stream->chain_cnt);

    if (rc_chain != PARSER_OK) return rc_chain;

    const u32 hex_len = flen[at + 4];

    if ((hex_len & 1) || ((hex_len / 2) > SZ_DATA_MAX)) return (PARSER_SALT_LENGTH);

    if (hex_len == 0) continue;

    if (is_valid_hex_string (field[at + 4], hex_len) == false) return (PARSER_SALT_ENCODING);

    stream->data_len = hex_len / 2;
    stream->data     = (u8 *) hcmalloc (stream->data_len);

    if (stream->data == NULL) return (PARSER_HAVE_ERRNO);

    for (u32 i = 0; i < stream->data_len; i++) stream->data[i] = hex_to_u8 (&field[at + 4][i * 2]);
  }

  return sz_finish_line (hashconfig, digest, salt, seven_zip, line_buf, line_len);
}

// The line of mode 11600, which 7z2hashcat writes:
//
//   $7z$type$power$salt_len$salt$iv_len$iv$crc32$data_len$unpack_size$data[$crc_len$attributes[$filter_attributes]]
//
// The low four bits of type name the packer and the high four bits a filter that follows it.

static u32 sz_legacy_packer (const u32 coder)
{
  switch (coder)
  {
    case 1: return SZ_KIND_LZMA;
    case 2: return SZ_KIND_LZMA2;
    case 3: return SZ_KIND_PPMD;
    case 6: return SZ_KIND_BZIP2;
    case 7: return SZ_KIND_DEFLATE;
    case 8: return SZ_KIND_ZSTD;
  }

  return SZ_KIND_NONE;
}

static u32 sz_legacy_filter (const u32 filter)
{
  switch (filter)
  {
    case 1: return SZ_KIND_X86;
    case 3: return SZ_KIND_PPC;
    case 4: return SZ_KIND_IA64;
    case 5: return SZ_KIND_ARM;
    case 6: return SZ_KIND_ARMT;
    case 7: return SZ_KIND_SPARC;
    case 9: return SZ_KIND_DELTA;
  }

  return SZ_KIND_NONE;
}

static int sz_decode_legacy (const hashconfig_t *hashconfig, u32 *digest, salt_t *salt, seven_zip_hook_salt_t *seven_zip, const char *line_buf, const int line_len)
{
  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  token.token_cnt  = 11;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_SEVEN_ZIP;

  token.len[0]      = 4;
  token.attr[0]     = TOKEN_ATTR_FIXED_LENGTH
                    | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.sep[1]      = '$';
  token.len_min[1]  = 1;
  token.len_max[1]  = 3;
  token.attr[1]     = TOKEN_ATTR_VERIFY_LENGTH
                    | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[2]      = '$';
  token.len_min[2]  = 1;
  token.len_max[2]  = 2;
  token.attr[2]     = TOKEN_ATTR_VERIFY_LENGTH
                    | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[3]      = '$';
  token.len[3]      = 1;
  token.attr[3]     = TOKEN_ATTR_FIXED_LENGTH
                    | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[4]      = '$';
  token.len_min[4]  = 0;
  token.len_max[4]  = 32;
  token.attr[4]     = TOKEN_ATTR_VERIFY_LENGTH;

  token.sep[5]      = '$';
  token.len_min[5]  = 1;
  token.len_max[5]  = 2;
  token.attr[5]     = TOKEN_ATTR_VERIFY_LENGTH
                    | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[6]      = '$';
  token.len[6]      = 32;
  token.attr[6]     = TOKEN_ATTR_FIXED_LENGTH
                    | TOKEN_ATTR_VERIFY_HEX;

  token.sep[7]      = '$';
  token.len_min[7]  = 1;
  token.len_max[7]  = 10;
  token.attr[7]     = TOKEN_ATTR_VERIFY_LENGTH
                    | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[8]      = '$';
  token.len_min[8]  = 1;
  token.len_max[8]  = 8;
  token.attr[8]     = TOKEN_ATTR_VERIFY_LENGTH
                    | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[9]      = '$';
  token.len_min[9]  = 1;
  token.len_max[9]  = 8;
  token.attr[9]     = TOKEN_ATTR_VERIFY_LENGTH
                    | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[10]     = '$';
  token.len_min[10] = 2;
  token.len_max[10] = SZ_DATA_MAX * 2 + 64;
  token.attr[10]    = TOKEN_ATTR_VERIFY_LENGTH;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  const u8 *line_end = (const u8 *) line_buf + line_len;

  // what follows the data: the length the CRC-32 covers, the attributes of the packer and
  // those of the filter, each behind a separator of its own

  const u8 *tail[3]     = { NULL, NULL, NULL };
  u32       tail_len[3] = { 0, 0, 0 };
  u32       tails       = 0;

  const u8 *data_pos = token.buf[10];
  u32       data_hex = token.len[10];

  const u8 *sep = (const u8 *) hc_strchr_next (data_pos, data_hex, '$');

  if (sep != NULL)
  {
    data_hex = (u32) (sep - data_pos);

    const u8 *at = sep + 1;

    while (tails < 3)
    {
      const u8 *next = (const u8 *) hc_strchr_next (at, (size_t) (line_end - at), '$');

      tail[tails]     = at;
      tail_len[tails] = (next == NULL) ? (u32) (line_end - at) : (u32) (next - at);

      tails++;

      if (next == NULL) break;

      at = next + 1;
    }

    if ((tails == 3) && (hc_strchr_next (tail[2], tail_len[2], '$') != NULL)) return (PARSER_SEPARATOR_UNMATCHED);
  }

  const u32 data_type   = hc_strtoul ((const char *) token.buf[1], NULL, 10);
  const u32 power       = hc_strtoul ((const char *) token.buf[2], NULL, 10);
  const u32 salt_len    = hc_strtoul ((const char *) token.buf[3], NULL, 10);
  const u32 iv_len      = hc_strtoul ((const char *) token.buf[5], NULL, 10);
  const u32 crc         = hc_strtoul ((const char *) token.buf[7], NULL, 10);
  const u32 data_len    = hc_strtoul ((const char *) token.buf[8], NULL, 10);
  const u32 unpack_size = hc_strtoul ((const char *) token.buf[9], NULL, 10);

  // 0x80 marks data that 7z2hashcat cut down to its last blocks, which leaves nothing to test
  // but the padding

  if (data_type == 0x80) return (PARSER_SEVEN_ZIP_TRUNCATED);

  if (data_type > 0xff) return (PARSER_SEVEN_ZIP_METHOD_UNSUPPORTED);

  const u32 coder  = data_type & 0x0f;
  const u32 filter = data_type >> 4;

  if ((coder != 0) && (sz_legacy_packer (coder) == SZ_KIND_NONE)) return (PARSER_SEVEN_ZIP_METHOD_UNSUPPORTED);

  if ((filter != 0) && (sz_legacy_filter (filter) == SZ_KIND_NONE)) return (PARSER_SEVEN_ZIP_METHOD_UNSUPPORTED);

  if (salt_len != 0) return (PARSER_SALT_VALUE);

  if (iv_len > 16) return (PARSER_SALT_VALUE);

  if ((data_len * 2) != data_hex) return (PARSER_SALT_VALUE);

  if ((data_len == 0) || (data_len > SZ_DATA_MAX)) return (PARSER_SALT_VALUE);

  if (is_valid_hex_string (data_pos, data_hex) == false) return (PARSER_SALT_ENCODING);

  seven_zip->legacy     = 1;
  seven_zip->power      = power;
  seven_zip->has_crc    = SZ_CHECK_CRC;
  seven_zip->crc        = crc;
  seven_zip->crc_len    = unpack_size;
  seven_zip->stream_cnt = 1;

  sz_stream_t *stream = &seven_zip->streams[0];

  stream->iv_len = iv_len;

  for (u32 i = 0; i < iv_len; i++) stream->iv[i] = hex_to_u8 (&token.buf[6][i * 2]);

  stream->packed   = data_len;
  stream->unpacked = unpack_size;

  if (data_type != 0)
  {
    // a packer or a filter: the length the CRC-32 covers is not the length of the stream

    if (tails < 2) return (PARSER_SEPARATOR_UNMATCHED);

    if (sz_number (tail[0], tail_len[0], 10, &seven_zip->crc_len) == false) return (PARSER_SALT_VALUE);

    if (coder != 0)
    {
      sz_coder_t *packer = &stream->chain[stream->chain_cnt++];

      packer->kind = sz_legacy_packer (coder);

      if (sz_bytes (tail[1], tail_len[1], packer->props, SZ_PROPS_MAX, &packer->props_len) == false) return (PARSER_SALT_VALUE);

      if ((packer->kind == SZ_KIND_LZMA)  && (packer->props_len != 5)) return (PARSER_SALT_VALUE);
      if ((packer->kind == SZ_KIND_LZMA2) && (packer->props_len != 1)) return (PARSER_SALT_VALUE);
      if ((packer->kind == SZ_KIND_PPMD)  && (packer->props_len != 5)) return (PARSER_SALT_VALUE);
    }

    if (filter != 0)
    {
      sz_coder_t *conv = &stream->chain[stream->chain_cnt++];

      conv->kind = sz_legacy_filter (filter);

      if (tails == 3)
      {
        if (sz_bytes (tail[2], tail_len[2], conv->props, SZ_PROPS_MAX, &conv->props_len) == false) return (PARSER_SALT_VALUE);
      }

      if ((conv->kind == SZ_KIND_DELTA) && (conv->props_len != 1)) return (PARSER_SALT_VALUE);

      if ((conv->kind != SZ_KIND_DELTA) && (conv->props_len != 0) && (conv->props_len != 4)) return (PARSER_SALT_VALUE);
    }
    else if (tails == 3)
    {
      return (PARSER_SALT_VALUE);
    }
  }

  stream->data_len = data_len;
  stream->data     = (u8 *) hcmalloc (data_len);

  if (stream->data == NULL) return (PARSER_HAVE_ERRNO);

  for (u32 i = 0; i < data_len; i++) stream->data[i] = hex_to_u8 (&data_pos[i * 2]);

  return sz_finish_line (hashconfig, digest, salt, seven_zip, line_buf, line_len);
}

static int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  seven_zip_hook_salt_t *seven_zip = (seven_zip_hook_salt_t *) hook_salt_buf;

  memset (seven_zip, 0, sizeof (seven_zip_hook_salt_t));

  if ((line_len >= 5) && (memcmp (line_buf, SIGNATURE_SEVEN_ZIP_NEW, 5) == 0))
  {
    return sz_decode_new (hashconfig, digest, salt, seven_zip, line_buf, line_len);
  }

  return sz_decode_legacy (hashconfig, digest, salt, seven_zip, line_buf, line_len);
}

static int sz_put (char *line_buf, const int line_size, int pos, const char *fmt, ...)
{
  if (pos >= line_size - 1) return line_size - 1;

  va_list ap;

  va_start (ap, fmt);

  const int n = vsnprintf (line_buf + pos, (size_t) (line_size - pos), fmt, ap);

  va_end (ap);

  pos += n;

  // vsnprintf returns the length it would have written, so a line that does not fit is cut here

  return (pos >= line_size) ? line_size - 1 : pos;
}

static int sz_put_hex (char *line_buf, const int line_size, int pos, const u8 *data, const u32 len)
{
  for (u32 i = 0; i < len; i++)
  {
    if (pos + 2 >= line_size) return line_size - 1;

    u8_to_hex (data[i], (u8 *) line_buf + pos);

    pos += 2;
  }

  line_buf[pos] = 0;

  return pos;
}

static int sz_put_chain (char *line_buf, const int line_size, int pos, const sz_coder_t *chain, const u32 chain_cnt)
{
  for (u32 i = 0; i < chain_cnt; i++)
  {
    const sz_coder_id_t *id = sz_id_of (chain[i].kind);

    if (i > 0) pos = sz_put (line_buf, line_size, pos, ",");

    pos = sz_put_hex (line_buf, line_size, pos, id->id, id->id_len);
    pos = sz_put     (line_buf, line_size, pos, "/");
    pos = sz_put_hex (line_buf, line_size, pos, chain[i].props, chain[i].props_len);
    pos = sz_put     (line_buf, line_size, pos, "/%" PRIx64, chain[i].size);
  }

  return pos;
}

static int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const seven_zip_hook_salt_t *seven_zip = (const seven_zip_hook_salt_t *) hook_salt_buf;

  int pos = 0;

  pos = sz_put     (line_buf, line_size, pos, "%s%u*", SIGNATURE_SEVEN_ZIP_NEW, seven_zip->power);
  pos = sz_put_hex (line_buf, line_size, pos, seven_zip->salt, seven_zip->salt_len);
  pos = sz_put     (line_buf, line_size, pos, "*");

  if (seven_zip->has_crc == SZ_CHECK_CRC)    pos = sz_put (line_buf, line_size, pos, "%08x", seven_zip->crc);
  if (seven_zip->has_crc == SZ_CHECK_HEADER) pos = sz_put (line_buf, line_size, pos, "header");

  pos = sz_put       (line_buf, line_size, pos, "*%" PRIx64 "*", seven_zip->crc_len);
  pos = sz_put_chain (line_buf, line_size, pos, seven_zip->join, seven_zip->join_cnt);
  pos = sz_put       (line_buf, line_size, pos, "*%u", seven_zip->stream_cnt);

  for (u32 s = 0; s < seven_zip->stream_cnt; s++)
  {
    const sz_stream_t *stream = &seven_zip->streams[s];

    pos = sz_put       (line_buf, line_size, pos, "*");
    pos = sz_put_hex   (line_buf, line_size, pos, stream->iv, stream->iv_len);
    pos = sz_put       (line_buf, line_size, pos, "*%" PRIx64 "*%" PRIx64 "*", stream->packed, stream->unpacked);
    pos = sz_put_chain (line_buf, line_size, pos, stream->chain, stream->chain_cnt);
    pos = sz_put       (line_buf, line_size, pos, "*");
    pos = sz_put_hex   (line_buf, line_size, pos, stream->data, stream->data_len);
  }

  pos = sz_put (line_buf, line_size, pos, "%s", SIGNATURE_SEVEN_ZIP_STOP);

  return pos;
}

void module_init (module_ctx_t *module_ctx)
{
  module_init_common (module_ctx);

  module_ctx->module_hash_decode              = module_hash_decode;
  module_ctx->module_hash_encode              = module_hash_encode;
  module_ctx->module_hook_extra_param_size    = module_hook_extra_param_size;
  module_ctx->module_hook_extra_param_init    = module_hook_extra_param_init;
  module_ctx->module_hook_extra_param_term    = module_hook_extra_param_term;
  module_ctx->module_hook23                   = module_hook23;
  module_ctx->module_hook_salt_size           = module_hook_salt_size;
  module_ctx->module_hook_size                = module_hook_size;
  module_ctx->module_jit_build_options        = module_jit_build_options;
  module_ctx->module_kernel_loops_max         = module_kernel_loops_max;
  module_ctx->module_kernel_loops_min         = module_kernel_loops_min;
  module_ctx->module_kern_bits                = module_kern_bits;
  module_ctx->module_length_sort              = module_length_sort;
  module_ctx->module_pw_max                   = module_pw_max;
  module_ctx->module_tmp_size                 = module_tmp_size;
  module_ctx->module_usage_notice             = module_usage_notice;
}
