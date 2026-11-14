/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include <inttypes.h>
#include "common.h"
#include "types.h"
#include "modules.h"
#include "bitops.h"
#include "convert.h"
#include "shared.h"
#include "parser.h"
#include "memory.h"
#include "event.h"
#include "emu_inc_cipher_aes.h"
#include "cpu_crc32.h"

// The RAR3 decompressor a compressed entry is verified with.

#include "rar3_unpack.c"

static const u32   ATTACK_EXEC    = ATTACK_EXEC_OUTSIDE_KERNEL;
static const u32   DGST_POS0      = 0;
static const u32   DGST_POS1      = 1;
static const u32   DGST_POS2      = 2;
static const u32   DGST_POS3      = 3;
static const u32   DGST_SIZE      = DGST_SIZE_4_4;
static const u32   HASH_CATEGORY  = HASH_CATEGORY_ARCHIVE;
static const char *HASH_NAME      = "RAR3 (header or file encryption)";
static const u64   KERN_TYPE      = 46700;
static const u64   KERN_BITS      = KERN_BIT_HOOK23;
static const bool  LENGTH_SORT    = true;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE
                                  | OPTS_TYPE_POST_AMP_UTF16LE;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "$rar$30$*0*45109af8ab5f297a*c43d7b00*10*10*0*adbf6c5385d7a40373e8f77d7b89d317$/rar$";

#define MODULE_OWN_KERN_BITS

#include "hooks_common.c"

// The CRC32 and the AES-CBC decryption the hook uses on large entries.

#include "rar_fast.c"

static u64 module_kern_bits (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return KERN_BITS; }

static bool        module_length_sort    (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return LENGTH_SORT;     }

static const char *module_usage_notice (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  return "Use ArchiveWolf to extract $rar$30$ hashes. A type 1 line carries the whole encrypted entry; solid members that depend on earlier files cannot be verified.";
}

typedef struct rar3_tmp
{
  u32 dgst[5];

  u32 w[66]; // 256 byte pass + 8 byte salt

  u32 iv[4];

} rar3_tmp_t;

typedef struct rar3_tmp_optimized
{
  u32 dgst[17][5];

} rar3_tmp_optimized_t;

// Hook buffer: the kernel writes the derived AES key+IV here for type=1
typedef struct rar3_hook
{
  u32 ukey[4];
  u32 iv[4];
  u32 hook_success;

} rar3_hook_t;

// The most encrypted data one hash line may carry. ArchiveWolf emits an entry whole up to this size
// and emits nothing above it, because a cut stream cannot be checked against the file CRC32.

#define RAR30_DATA_MAX (4 * 1024 * 1024)

// Hook salt: what a type=1 hash is verified against. The entry data is on the heap, because one
// hash can carry megabytes and a fixed array would charge every hash for the largest one.

typedef struct rar3_hook_salt
{
  // type is 0 for header encryption and 1 for file encryption. legacy_format is 1 when the line
  // was a $RAR3$ one, so that it is written back as one. The rest describes a type 1 entry: the
  // CRC32 of the unpacked file, the encrypted size (a multiple of 16), the unpacked size, the
  // method (0x30 stored, 0x31 to 0x35 compressed) and the encrypted entry itself, data_len bytes
  // on the heap.

  u32 type;
  u32 legacy_format;
  u32 crc32;
  u32 pack_size;
  u32 unpack_size;
  u32 method;
  u32 data_len;
  u32 reserved;

  u8 *data;

} rar3_hook_salt_t;

// The buffers one hook thread keeps between candidates, allocated on the first candidate that
// needs them, so a run over header-encrypted hashes never pays for them.

typedef struct rar3_hook_extra
{
  u8 *stream;

  rar29_buffers_t buffers;

  // Candidates this hook thread could not test, because the stream uses a filter the decoder does
  // not implement.

  u64 unsupported_cnt;

} rar3_hook_extra_t;

static u64 rar3_unsupported_total = 0;
static int rar3_term_calls        = 0;

// How much of a compressed entry is decrypted before the first unpack attempt. The rest follows
// only if the stream wants more.

#define RAR30_FIRST_CHUNK 4096

static const int   ROUNDS_RAR3      = 262144;
static const char *SIGNATURE_RAR3   = "$RAR3$";
static const char *SIGNATURE_RAR30  = "$rar$30$";
static const char *SIGNATURE_RAR_STOP = "$/rar$";

static bool module_unstable_warning (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra, MAYBE_UNUSED const hc_device_param_t *device_param)
{
  if ((device_param->opencl_platform_vendor_id == VENDOR_ID_APPLE) && (device_param->opencl_device_type & CL_DEVICE_TYPE_GPU))
  {
    if (device_param->opencl_device_vendor_id == VENDOR_ID_INTEL_SDK)
    {
      return true;
    }
  }

  return false;
}

static u64 module_hook_salt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  return sizeof (rar3_hook_salt_t);
}

static u64 module_hook_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  return sizeof (rar3_hook_t);
}

static u64 module_tmp_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const bool optimized_kernel = (hashconfig->opti_type & OPTI_TYPE_OPTIMIZED_KERNEL);

  u64 tmp_size = (u64) sizeof (rar3_tmp_t);

  if (optimized_kernel == true)
  {
    tmp_size = (u64) sizeof (rar3_tmp_optimized_t);
  }

  return tmp_size;
}

static u32 module_kernel_loops_min (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u32 kernel_loops_min = ROUNDS_RAR3 / 16;

  return kernel_loops_min;
}

static u32 module_kernel_loops_max (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u32 kernel_loops_max = ROUNDS_RAR3 / 16;

  return kernel_loops_max;
}

static u32 module_pw_max (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const bool optimized_kernel = (hashconfig->opti_type & OPTI_TYPE_OPTIMIZED_KERNEL);

  u32 pw_max = 128;

  if (optimized_kernel == true)
  {
    pw_max = 20;
  }

  return pw_max;
}

static const char *module_benchmark_mask (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const char *mask = "?l?l?l?l?l";

  return mask;
}

static u64 module_hook_extra_param_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  return (u64) sizeof (rar3_hook_extra_t);
}

static bool module_hook_extra_param_init (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra, MAYBE_UNUSED const folder_config_t *folder_config, MAYBE_UNUSED const backend_ctx_t *backend_ctx, void *hook_extra_param)
{
  memset (hook_extra_param, 0, sizeof (rar3_hook_extra_t));

  return true;
}

static bool module_hook_extra_param_term (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra, MAYBE_UNUSED const folder_config_t *folder_config, MAYBE_UNUSED const backend_ctx_t *backend_ctx, void *hook_extra_param)
{
  rar3_hook_extra_t *extra = (rar3_hook_extra_t *) hook_extra_param;

  hcfree (extra->stream);

  extra->stream = NULL;

  rar29_buffers_free (&extra->buffers);

  rar3_unsupported_total += extra->unsupported_cnt;

  extra->unsupported_cnt = 0;

  rar3_term_calls++;

  if (rar3_term_calls < (int) user_options->hook_threads) return true;

  // These never produced a CRC32 to compare, and saying nothing would look like Exhausted.

  if (rar3_unsupported_total > 0)
  {
    event_log_warning (hashcat_ctx, "hashcat could not decode part of a RAR3 stream in this run.");
    event_log_warning (hashcat_ctx, "Candidates that reached it and could not be tested: %" PRIu64, rar3_unsupported_total);
    event_log_warning (hashcat_ctx, "A correct password among them would not have been reported, so this result is");
    event_log_warning (hashcat_ctx, "incomplete rather than negative.");
    event_log_warning (hashcat_ctx, NULL);
  }

  rar3_unsupported_total = 0;
  rar3_term_calls        = 0;

  return true;
}

// AES-128-CBC over whole blocks. chain carries the previous ciphertext block between calls.

static void rar3_cbc_decrypt (const u8 *key_bytes, const u32 *ks, u32 *chain, const u8 *in, u8 *out, const u32 len)
{
  // The AES instructions where the processor has them, the table AES otherwise.

  if (rarf_cbc_decrypt (key_bytes, 16, (u8 *) chain, in, out, len) == true) return;

  for (u32 off = 0; off + 16 <= len; off += 16)
  {
    u32 ct[4];
    u32 pt[4];

    memcpy (ct, &in[off], 16);

    aes128_decrypt (ks, ct, pt, (u32 *) td0, (u32 *) td1, (u32 *) td2, (u32 *) td3, (u32 *) td4);

    pt[0] ^= chain[0];
    pt[1] ^= chain[1];
    pt[2] ^= chain[2];
    pt[3] ^= chain[3];

    chain[0] = ct[0];
    chain[1] = ct[1];
    chain[2] = ct[2];
    chain[3] = ct[3];

    memcpy (&out[off], pt, 16);
  }
}

// Hook23: CPU-side verification of a type=1 hash. The kernel exported the AES key and IV. A stored
// entry is decrypted and its CRC32 compared. A compressed entry is decrypted, unpacked by the RAR3
// decoder, and the CRC32 of the unpacked data compared. Nothing else counts as a match.

static void module_hook23 (hc_device_param_t *device_param, const void *hook_extra_param, const void *hook_salts_buf, const u32 salt_pos, const u64 pw_pos)
{
  rar3_hook_t *hook_items = (rar3_hook_t *) device_param->hooks_buf;
  rar3_hook_t *hook_item = &hook_items[pw_pos];

  const rar3_hook_salt_t *rar3s = (const rar3_hook_salt_t *) hook_salts_buf;
  const rar3_hook_salt_t *rar3  = &rar3s[salt_pos];

  hook_item->hook_success = 0;

  if (rar3->type != 1) return;

  const u32 data_len = rar3->data_len;

  if (rar3->data == NULL) return;

  if ((data_len < 16) || (data_len > RAR30_DATA_MAX)) return;

  // The interface hands this over as const, but it belongs to this module and this hook thread.

  rar3_hook_extra_t *extra = (rar3_hook_extra_t *) hook_extra_param;

  if (extra->stream == NULL) extra->stream = (u8 *) hcmalloc (RAR30_DATA_MAX + 16);

  if (extra->stream == NULL) return;

  u8 *stream = extra->stream;

  rarf_crc32_init ();

  // The kernel exports the key byte-swapped for its own AES. The host AES wants the SHA-1 words as
  // they are, the same order module 23800 hands over.

  u32 key[4];

  key[0] = byte_swap_32 (hook_item->ukey[0]);
  key[1] = byte_swap_32 (hook_item->ukey[1]);
  key[2] = byte_swap_32 (hook_item->ukey[2]);
  key[3] = byte_swap_32 (hook_item->ukey[3]);

  u8 key_bytes[16];

  memcpy (key_bytes, key, 16);

  u32 ks[44];

  aes128_set_decrypt_key (ks, key, (u32 *) te0, (u32 *) te1, (u32 *) te2, (u32 *) te3, (u32 *) td0, (u32 *) td1, (u32 *) td2, (u32 *) td3);

  u32 chain[4];

  chain[0] = hook_item->iv[0];
  chain[1] = hook_item->iv[1];
  chain[2] = hook_item->iv[2];
  chain[3] = hook_item->iv[3];

  if (rar3->method == 0x30)
  {
    if (rar3->unpack_size > data_len) return;

    rar3_cbc_decrypt (key_bytes, ks, chain, rar3->data, stream, data_len);

    const u32 stored_crc32 = rarf_crc32_large (0xffffffff, stream, rar3->unpack_size) ^ 0xffffffff;

    if (stored_crc32 == rar3->crc32) hook_item->hook_success = 1;

    return;
  }

  // Compressed. The first block decides nearly every candidate before anything else is decrypted.

  rar3_cbc_decrypt (key_bytes, ks, chain, rar3->data, stream, 16);

  if (rar29_first_block_ok (stream) == false) return;

  if (rar29_buffers_ready (&extra->buffers) == false) return;

  // The first pass is given RAR30_FIRST_CHUNK bytes, and only a stream that wanted more gets the rest.

  u32 done = 16;

  for (u32 pass = 0; pass < 2; pass++)
  {
    const u32 want = (pass == 0) ? MIN (data_len, RAR30_FIRST_CHUNK) : data_len;

    if (want > done)
    {
      rar3_cbc_decrypt (key_bytes, ks, chain, &rar3->data[done], &stream[done], want - done);

      done = want;
    }

    u32  crc32       = 0;
    bool ran_off     = false;
    bool unsupported = false;

    const bool ok = rar29_unpack (&extra->buffers, stream, done, rar3->unpack_size, &crc32, &ran_off, &unsupported);

    if (ok == true)
    {
      if (crc32 == rar3->crc32) hook_item->hook_success = 1;

      return;
    }

    if ((ran_off == false) || (done >= data_len))
    {
      if (unsupported == true) extra->unsupported_cnt++;

      return;
    }
  }
}

// Parse new format: $rar$30$*type*salt*crc*ps*us*method*data$/rar$

static int parse_new_rar30 (u32 *digest, salt_t *salt, rar3_hook_salt_t *hook_salt, const char *line_buf, const int line_len)
{
  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  token.token_cnt  = 8;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_RAR30;

  token.sep[0]     = '*';
  token.len[0]     = 8;
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  // type
  token.sep[1]     = '*';
  token.len[1]     = 1;
  token.attr[1]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  // salt (16 hex = 8 bytes)
  token.sep[2]     = '*';
  token.len[2]     = 16;
  token.attr[2]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  // crc (hex)
  token.sep[3]     = '*';
  token.len_min[3] = 1;
  token.len_max[3] = 16;
  token.attr[3]    = TOKEN_ATTR_VERIFY_LENGTH;

  // ps (pack_size hex)
  token.sep[4]     = '*';
  token.len_min[4] = 1;
  token.len_max[4] = 10;
  token.attr[4]    = TOKEN_ATTR_VERIFY_LENGTH;

  // us (unpack_size hex)
  token.sep[5]     = '*';
  token.len_min[5] = 1;
  token.len_max[5] = 10;
  token.attr[5]    = TOKEN_ATTR_VERIFY_LENGTH;

  // method (hex)
  token.sep[6]     = '*';
  token.len_min[6] = 1;
  token.len_max[6] = 4;
  token.attr[6]    = TOKEN_ATTR_VERIFY_LENGTH;

  // data (encrypted bytes as hex) + trailing $/rar$
  token.len_min[7] = 38;
  token.len_max[7] = (RAR30_DATA_MAX * 2) + 16;
  token.attr[7]    = TOKEN_ATTR_VERIFY_LENGTH;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  const u32 hash_type = token.buf[1][0] - '0';

  if (hash_type > 1) return (PARSER_SALT_VALUE);

  // salt (shared by type 0 and type 1)

  const u8 *salt_pos = token.buf[2];

  salt->salt_buf[0] = hex_to_u32 (salt_pos + 0);
  salt->salt_buf[1] = hex_to_u32 (salt_pos + 8);

  // data

  const u8 *data_pos = token.buf[7];
  int data_hex_len = token.len[7];

  // strip trailing $/rar$
  if (data_hex_len >= 6 && memcmp (data_pos + data_hex_len - 6, SIGNATURE_RAR_STOP, 6) == 0)
  {
    data_hex_len -= 6;
  }

  // strip optional trailing *
  if (data_hex_len > 0 && data_pos[data_hex_len - 1] == '*')
  {
    data_hex_len--;
  }

  hook_salt->type = hash_type;

  if (hash_type == 0)
  {
    // Type 0, header encryption: one or two encrypted blocks to check.

    if ((data_hex_len != 32) && (data_hex_len != 64)) return (PARSER_CT_LENGTH);

    for (int i = 0, j = 0; j < data_hex_len; i += 1, j += 8)
    {
      salt->salt_buf[2 + i] = byte_swap_32 (hex_to_u32 (data_pos + j));
    }

    salt->salt_len  = 8 + (data_hex_len / 2);
    salt->salt_iter = ROUNDS_RAR3;

    digest[0] = 0xc43d7b00;
    digest[1] = 0x40070000;
    digest[2] = 0;
    digest[3] = 0;

    if (data_hex_len == 64)
    {
      digest[0] = 0;
      digest[1] = 0;
      digest[2] = 0;
      digest[3] = 0;
    }

    hook_salt->data_len = 0;
  }
  else
  {
    // Type 1: file-level encryption
    const u32 crc32 = (u32) hc_strtoull ((const char *) token.buf[3], NULL, 16);
    const u64 pack_size = hc_strtoull ((const char *) token.buf[4], NULL, 16);
    const u64 unpack_size = hc_strtoull ((const char *) token.buf[5], NULL, 16);
    const u32 method = (u32) hc_strtoull ((const char *) token.buf[6], NULL, 16);

    if (data_hex_len % 2) return (PARSER_SALT_ENCODING);

    if (is_valid_hex_string (data_pos, data_hex_len) == false) return (PARSER_SALT_ENCODING);

    const u32 data_bytes = (u32) data_hex_len / 2;

    if ((method < 0x30) || (method > 0x35)) return (PARSER_SALT_VALUE);

    if (unpack_size > 0xffffffffull) return (PARSER_SALT_VALUE);

    // AES-128-CBC works on whole blocks, and the hash has to carry the whole entry: the CRC32
    // covers every byte of it, so a shorter line could never confirm a password.

    if ((data_bytes < 16) || ((data_bytes % 16) != 0)) return (PARSER_SALT_LENGTH);
    if (data_bytes > RAR30_DATA_MAX) return (PARSER_SALT_LENGTH);
    if (pack_size != data_bytes) return (PARSER_SALT_LENGTH);

    // An empty file has nothing to check a password against.

    if (unpack_size == 0) return (PARSER_SALT_VALUE);

    if ((method == 0x30) && (unpack_size > data_bytes)) return (PARSER_SALT_VALUE);

    hook_salt->crc32 = crc32;
    hook_salt->pack_size = (u32) pack_size;
    hook_salt->unpack_size = (u32) unpack_size;
    hook_salt->method = method;
    hook_salt->data_len = data_bytes;

    hook_salt->data = (u8 *) hcmalloc (data_bytes);

    if (hook_salt->data == NULL) return (PARSER_HAVE_ERRNO);

    for (u32 i = 0; i < data_bytes; i++)
    {
      hook_salt->data[i] = hex_to_u8 (&data_pos[i * 2]);
    }

    // Salt still carries the 8-byte encryption salt for KDF
    salt->salt_len  = 8;
    salt->salt_iter = ROUNDS_RAR3;

    // Files of one archive can share their 8 salt bytes. Each hash is verified against its own
    // entry, so two words past the salt keep such hashes apart instead of merging them into one.

    salt->salt_buf[14] = crc32;
    salt->salt_buf[15] = cpu_crc32_buffer (hook_salt->data, data_bytes);

    // For type=1, the kernel writes a fixed "success" digest that always matches.
    // The actual verification happens in module_hook23.
    digest[0] = 1;
    digest[1] = 0;
    digest[2] = 0;
    digest[3] = 0;
  }

  return (PARSER_OK);
}

static int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  rar3_hook_salt_t *hook_salt = (rar3_hook_salt_t *) hook_salt_buf;

  memset (hook_salt, 0, sizeof (rar3_hook_salt_t));

  // try new ArchiveWolf format first

  if ((line_len > 8) && (strncmp (line_buf, "$rar$30$", 8) == 0))
  {
    return parse_new_rar30 (digest, salt, hook_salt, line_buf, line_len);
  }

  // fall back to old $RAR3$ format (type=0 only)

  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  token.token_cnt  = 4;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_RAR3;

  token.sep[0]     = '*';
  token.len[0]     = 6;
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.sep[1]     = '*';
  token.len[1]     = 1;
  token.attr[1]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[2]     = '*';
  token.len[2]     = 16;
  token.attr[2]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.sep[3]     = '*';
  token.len_min[3] = 32;
  token.len_max[3] = 64;
  token.attr[3]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  const u8 *type_pos    = token.buf[1];
  const u8 *salt_pos    = token.buf[2];
  const u8 *crypted_pos = token.buf[3];

  if (type_pos[0] != '0') return (PARSER_SIGNATURE_UNMATCHED);

  const int crypted_len = token.len[3];

  if ((crypted_len != 32) && (crypted_len != 64)) return (PARSER_CT_LENGTH);

  salt->salt_buf[0] = hex_to_u32 (salt_pos + 0);
  salt->salt_buf[1] = hex_to_u32 (salt_pos + 8);

  for (int i = 0, j = 0; j < crypted_len; i += 1, j += 8)
  {
    salt->salt_buf[2 + i] = byte_swap_32 (hex_to_u32 (crypted_pos + j));
  }

  salt->salt_len  = 8 + (crypted_len / 2);
  salt->salt_iter = ROUNDS_RAR3;

  digest[0] = 0xc43d7b00;
  digest[1] = 0x40070000;
  digest[2] = 0;
  digest[3] = 0;

  if (crypted_len == 64)
  {
    digest[0] = 0;
    digest[1] = 0;
  }

  hook_salt->type = 0;
  hook_salt->legacy_format = 1;
  hook_salt->data_len = 0;

  return (PARSER_OK);
}

static int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const rar3_hook_salt_t *hook_salt = (const rar3_hook_salt_t *) hook_salt_buf;

  if (hook_salt != NULL && hook_salt->type == 1)
  {
    int line_len = snprintf (line_buf, line_size, "%s*1*%08x%08x*%08x*%x*%x*%x*",
        SIGNATURE_RAR30,
        byte_swap_32 (salt->salt_buf[0]),
        byte_swap_32 (salt->salt_buf[1]),
        hook_salt->crc32,
        hook_salt->pack_size,
        hook_salt->unpack_size,
        hook_salt->method);

    if ((u64) line_len + ((u64) hook_salt->data_len * 2) + 8 >= (u64) line_size) return 0;

    line_len += hex_encode (hook_salt->data, (int) hook_salt->data_len, (u8 *) &line_buf[line_len]);

    line_len += snprintf (&line_buf[line_len], line_size - line_len, "%s", SIGNATURE_RAR_STOP);

    return line_len;
  }

  const u32 crypted_words = (salt->salt_len - 8) / 4;

  const bool legacy = ((hook_salt != NULL) && (hook_salt->legacy_format == 1));

  int line_len = 0;

  if (legacy == true)
  {
    line_len = snprintf (line_buf, line_size, "%s*0*%08x%08x*",
        SIGNATURE_RAR3,
        byte_swap_32 (salt->salt_buf[0]),
        byte_swap_32 (salt->salt_buf[1]));
  }
  else
  {
    line_len = snprintf (line_buf, line_size, "%s*0*%08x%08x*c43d7b00*%x*%x*0*",
        SIGNATURE_RAR30,
        byte_swap_32 (salt->salt_buf[0]),
        byte_swap_32 (salt->salt_buf[1]),
        crypted_words * 4,
        crypted_words * 4);
  }

  for (u32 i = 0; i < crypted_words; i++)
  {
    line_len += snprintf (&line_buf[line_len], line_size - line_len, "%08x", salt->salt_buf[2 + i]);
  }

  if (legacy == false)
  {
    line_len += snprintf (&line_buf[line_len], line_size - line_len, "%s", SIGNATURE_RAR_STOP);
  }

  return line_len;
}

void module_init (module_ctx_t *module_ctx)
{
  module_init_common (module_ctx);

  module_ctx->module_benchmark_mask           = module_benchmark_mask;
  module_ctx->module_hash_decode              = module_hash_decode;
  module_ctx->module_hash_encode              = module_hash_encode;
  module_ctx->module_hook23                   = module_hook23;
  module_ctx->module_hook_extra_param_size    = module_hook_extra_param_size;
  module_ctx->module_hook_extra_param_init    = module_hook_extra_param_init;
  module_ctx->module_hook_extra_param_term    = module_hook_extra_param_term;
  module_ctx->module_hook_salt_size           = module_hook_salt_size;
  module_ctx->module_hook_size                = module_hook_size;
  module_ctx->module_kern_bits                = module_kern_bits;
  module_ctx->module_kernel_loops_max         = module_kernel_loops_max;
  module_ctx->module_kernel_loops_min         = module_kernel_loops_min;
  module_ctx->module_length_sort              = module_length_sort;
  module_ctx->module_pw_max                   = module_pw_max;
  module_ctx->module_tmp_size                 = module_tmp_size;
  module_ctx->module_unstable_warning         = module_unstable_warning;
  module_ctx->module_usage_notice             = module_usage_notice;
}
