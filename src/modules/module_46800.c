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

static const u32   ATTACK_EXEC    = ATTACK_EXEC_OUTSIDE_KERNEL;
static const u32   DGST_POS0      = 0;
static const u32   DGST_POS1      = 1;
static const u32   DGST_POS2      = 2;
static const u32   DGST_POS3      = 3;
static const u32   DGST_SIZE      = DGST_SIZE_4_4;
static const u32   HASH_CATEGORY  = HASH_CATEGORY_ARCHIVE;
static const char *HASH_NAME      = "RAR5";
static const u64   KERN_TYPE      = 46800;
static const u64   KERN_BITS      = KERN_BIT_HOOK23;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE
                                  | OPTI_TYPE_SLOW_HASH_SIMD_LOOP;
// Files of one archive share their salt. The salt of a type 0 hash is those 16 bytes and nothing
// else, so such hashes form one salt group and PBKDF2 runs once for all of them. The comp kernel is
// then called once per hash of the group, the way the Kerberos AES modes do it.

static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE
                                  | OPTS_TYPE_DEEP_COMP_KERNEL;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "$rar$50$*0*38466361001011015181344360681307*15*00000000000000000000000000000000*cc7a30583e62676a*0*****$/rar$";

#define MODULE_OWN_KERN_BITS

#include "hooks_common.c"

// The CRC32 and the AES-CBC decryption the hook uses on large entries.

#include "rar_fast.c"

// The RAR5 decompressor and the checksums an entry without a password check value is verified with.

#include "rar5_decode.c"

static u64 module_kern_bits (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return KERN_BITS; }

static const char *module_usage_notice (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  return "You can use https://github.com/hashcat/hashcat/blob/master/tools/rar2hashcat.py or ArchiveWolf to extract $rar$50$ hashes. The $rar5$ lines of mode 13000 are read as well. A type 1 line carries the whole encrypted entry, up to 4 MiB.";
}

typedef struct pbkdf2_sha256_tmp
{
  u32  ipad[8];
  u32  opad[8];

  u32  dgst[32];

  // out[0..7] is the running PBKDF2 output. out[8..15] keeps it as it was after 2^lg2 iterations,
  // which is the AES key, and out[16..23] as it was 16 iterations later, which is the hash key.

  u32  out[32];

} pbkdf2_sha256_tmp_t;

// One per hash. The kernel reads the first 7 words. The rest is what a type 1 line is written back
// from: hashcat hands a hook salt over by the position of its salt, so only an esalt is certain to
// belong to the hash being written.

typedef struct rar5
{
  u32 iv[4];

  // type is 0 for a hash with a password check value, which is in psw_check, and 1 for one that
  // is decrypted and compared with its checksum.

  u32 type;
  u32 psw_check[2];

  // legacy_format is 1 when the line was a $rar5$ one, so that it is written back as one. The
  // rest describes a type 1 entry: the kind of checksum (RAR5_CHECK_*), the method (0 stored, 1 to
  // 5 compressed), the sizes, the checksum (a CRC32 as 4 bytes, most significant first, or the 32
  // byte BLAKE2sp digest) and the address of the encrypted entry, which the hook salt owns.

  u32 legacy_format;
  u32 check_type;
  u32 method;
  u32 data_len;
  u32 reserved;

  u64 pack_size;
  u64 unpack_size;

  u8  check[32];

  u64 data;

} rar5_t;

// What the kernel hands the host for a type 1 hash, as SHA-256 state words.

typedef struct rar5_hook
{
  u32 key[8];
  u32 hash_key[8];

  u32 hook_success;

} rar5_hook_t;

// The most encrypted data one hash line may carry. ArchiveWolf emits an entry whole up to this size
// and emits nothing above it, because a cut stream cannot be checked against the file checksum.

#define RAR50_DATA_MAX (4 * 1024 * 1024)

typedef struct rar5_hook_salt
{
  // The same fields as in rar5_t, and the encrypted entry itself, data_len bytes on the heap.

  u32 type;
  u32 legacy_format;
  u32 check_type;
  u32 method;
  u32 data_len;
  u32 reserved;

  u64 pack_size;
  u64 unpack_size;

  u8  iv[16];
  u8  check[32];

  u8 *data;

} rar5_hook_salt_t;

// The buffers one hook thread keeps between candidates, allocated on first use.

typedef struct rar5_work
{
  u8 *plain;

  rar5_buffers_t buffers;

  u64 unsupported_cnt;

} rar5_work_t;

// Hook thread i of every device is handed the same one of these, and the devices run at the same
// time, so each device has a set of buffers of its own.

typedef struct rar5_hook_extra
{
  rar5_work_t work[DEVICES_MAX];

} rar5_hook_extra_t;

static u64 rar5_unsupported_total = 0;
static int rar5_term_calls        = 0;

static const char *SIGNATURE_RAR5     = "$rar5$";
static const char *SIGNATURE_RAR50    = "$rar$50$";
static const char *SIGNATURE_RAR_STOP = "$/rar$";

static bool module_unstable_warning (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra, MAYBE_UNUSED const hc_device_param_t *device_param)
{
  if ((device_param->opencl_platform_vendor_id == VENDOR_ID_APPLE) && (device_param->opencl_device_type & CL_DEVICE_TYPE_GPU))
  {
    if (device_param->opencl_device_vendor_id == VENDOR_ID_INTEL_SDK)
    {
      // Intel Iris
      return true;
    }
  }

  return false;
}

static char *module_jit_build_options (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra, MAYBE_UNUSED const hashes_t *hashes, MAYBE_UNUSED const hc_device_param_t *device_param)
{
  char *jit_build_options = NULL;

  // Extra treatment for Apple systems
  if (device_param->opencl_platform_vendor_id == VENDOR_ID_APPLE)
  {
    return jit_build_options;
  }

  // NVIDIA GPU
  if (device_param->opencl_device_vendor_id == VENDOR_ID_NV)
  {
    hc_asprintf (&jit_build_options, "-D _unroll");
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

// The kernel declares the same struct with its host-only part as plain words, so the two have to
// agree on the size or every hash after the first reads the wrong esalt.

_Static_assert (sizeof (rar5_t) == 104, "rar5_t is 104 bytes in OpenCL/m46800-pure.cl");

static u32 module_deep_comp_kernel (MAYBE_UNUSED const hashes_t *hashes, MAYBE_UNUSED const u32 salt_pos, MAYBE_UNUSED const u32 digest_pos)
{
  return KERN_RUN_3;
}

static u64 module_esalt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  return (u64) sizeof (rar5_t);
}

static u64 module_tmp_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  return (u64) sizeof (pbkdf2_sha256_tmp_t);
}

static u64 module_hook_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  return (u64) sizeof (rar5_hook_t);
}

static u64 module_hook_salt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  return (u64) sizeof (rar5_hook_salt_t);
}

static u64 module_hook_extra_param_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  return (u64) sizeof (rar5_hook_extra_t);
}

static bool module_hook_extra_param_init (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra, MAYBE_UNUSED const folder_config_t *folder_config, MAYBE_UNUSED const backend_ctx_t *backend_ctx, void *hook_extra_param)
{
  memset (hook_extra_param, 0, sizeof (rar5_hook_extra_t));

  return true;
}

static bool module_hook_extra_param_term (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra, MAYBE_UNUSED const folder_config_t *folder_config, MAYBE_UNUSED const backend_ctx_t *backend_ctx, void *hook_extra_param)
{
  rar5_hook_extra_t *extra = (rar5_hook_extra_t *) hook_extra_param;

  for (u32 d = 0; d < DEVICES_MAX; d++)
  {
    rar5_work_t *work = &extra->work[d];

    hcfree (work->plain);

    work->plain = NULL;

    rar5_buffers_free (&work->buffers);

    rar5_unsupported_total += work->unsupported_cnt;

    work->unsupported_cnt = 0;
  }

  rar5_term_calls++;

  if (rar5_term_calls < (int) user_options->hook_threads) return true;

  // These never produced a checksum to compare, and saying nothing would look like Exhausted.

  if (rar5_unsupported_total > 0)
  {
    event_log_warning (hashcat_ctx, "hashcat could not decode part of a RAR5 stream in this run.");
    event_log_warning (hashcat_ctx, "Candidates that reached it and could not be tested: %" PRIu64, rar5_unsupported_total);
    event_log_warning (hashcat_ctx, "A correct password among them would not have been reported, so this result is");
    event_log_warning (hashcat_ctx, "incomplete rather than negative.");
    event_log_warning (hashcat_ctx, NULL);
  }

  rar5_unsupported_total = 0;
  rar5_term_calls        = 0;

  return true;
}

// AES-256-CBC over whole blocks. chain carries the previous ciphertext block between calls.

static void rar5_cbc_decrypt (const u8 *key_bytes, const u32 *ks, u32 *chain, const u8 *in, u8 *out, const u32 len)
{
  // The AES instructions where the processor has them, the table AES otherwise.

  if (rarf_cbc_decrypt (key_bytes, 32, (u8 *) chain, in, out, len) == true) return;

  for (u32 off = 0; off + 16 <= len; off += 16)
  {
    u32 ct[4];
    u32 pt[4];

    memcpy (ct, &in[off], 16);

    aes256_decrypt (ks, ct, pt, (u32 *) td0, (u32 *) td1, (u32 *) td2, (u32 *) td3, (u32 *) td4);

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

// Hook23: CPU-side verification of a type 1 hash. The kernel exported the AES key and the hash key.
// The entry is decrypted, unpacked if it is compressed, and its checksum compared with the one in
// the hash line. Nothing else counts as a match.

static void module_hook23 (hc_device_param_t *device_param, const void *hook_extra_param, const void *hook_salts_buf, const u32 salt_pos, const u64 pw_pos)
{
  rar5_hook_t *hook_items = (rar5_hook_t *) device_param->hooks_buf;
  rar5_hook_t *hook_item  = &hook_items[pw_pos];

  const rar5_hook_salt_t *rar5s = (const rar5_hook_salt_t *) hook_salts_buf;
  const rar5_hook_salt_t *rar5  = &rar5s[salt_pos];

  hook_item->hook_success = 0;

  if (rar5->type != 1) return;

  const u32 data_len = rar5->data_len;

  if (rar5->data == NULL) return;

  if ((data_len < 16) || (data_len > RAR50_DATA_MAX)) return;

  // The interface hands this over as const, but it belongs to this module and this hook thread.

  rar5_hook_extra_t *shared = (rar5_hook_extra_t *) hook_extra_param;

  rar5_work_t *extra = &shared->work[device_param->device_id];

  if (extra->plain == NULL) extra->plain = (u8 *) hcmalloc (RAR50_DATA_MAX + 16);

  if (extra->plain == NULL) return;

  u8 *plain = extra->plain;

  rar5_crc32_init ();

  // The kernel hands over SHA-256 state words. The key bytes are those words most significant byte
  // first, and the host AES takes its key as words read least significant byte first.

  u32 key[8];
  u8  hash_key[32];

  for (u32 i = 0; i < 8; i++)
  {
    key[i] = byte_swap_32 (hook_item->key[i]);

    hash_key[i * 4 + 0] = (u8) (hook_item->hash_key[i] >> 24);
    hash_key[i * 4 + 1] = (u8) (hook_item->hash_key[i] >> 16);
    hash_key[i * 4 + 2] = (u8) (hook_item->hash_key[i] >>  8);
    hash_key[i * 4 + 3] = (u8) (hook_item->hash_key[i] >>  0);
  }

  u8 key_bytes[32];

  memcpy (key_bytes, key, 32);

  u32 ks[60];

  aes256_set_decrypt_key (ks, key, (u32 *) te0, (u32 *) te1, (u32 *) te2, (u32 *) te3, (u32 *) td0, (u32 *) td1, (u32 *) td2, (u32 *) td3);

  u32 chain[4];

  memcpy (chain, rar5->iv, 16);

  if (rar5->check_type == RAR5_CHECK_HEADER)
  {
    rar5_cbc_decrypt (key_bytes, ks, chain, rar5->data, plain, data_len);

    if (rar5_header_matches (plain, data_len) == true) hook_item->hook_success = 1;

    return;
  }

  rar5_sum_t sum;

  if (rar5->method == 0)
  {
    if (rar5->unpack_size > data_len) return;

    rar5_cbc_decrypt (key_bytes, ks, chain, rar5->data, plain, data_len);

    rar5_sum_init (&sum, rar5->check_type);

    rar5_sum_update (&sum, plain, (size_t) rar5->unpack_size);

    if (rar5_sum_matches (&sum, rar5->check_type, hash_key, rar5->check) == true) hook_item->hook_success = 1;

    return;
  }

  // Compressed. The first block decides 255 of 256 candidates before anything else is decrypted.

  rar5_cbc_decrypt (key_bytes, ks, chain, rar5->data, plain, 16);

  if (rar5_block_header_ok (plain) == false) return;

  rar5_cbc_decrypt (key_bytes, ks, chain, &rar5->data[16], &plain[16], data_len - 16);

  if (rar5_buffers_ready (&extra->buffers, rar5->unpack_size) == false) return;

  // The hash line does not say whether RAR 5.x or RAR 7.x wrote the entry, and the two differ in
  // the size of the distance table. The RAR 5.x layout is tried first.

  bool unsupported_any = false;

  for (u32 layout = 0; layout < 2; layout++)
  {
    bool header_ok   = false;
    bool unsupported = false;

    rar5_sum_init (&sum, rar5->check_type);

    const bool ok = rar5_unpack (&extra->buffers, plain, data_len, rar5->unpack_size, (layout == 1), &sum, &header_ok, &unsupported);

    if (ok == true)
    {
      if (rar5_sum_matches (&sum, rar5->check_type, hash_key, rar5->check) == true)
      {
        hook_item->hook_success = 1;

        return;
      }
    }

    if (unsupported == true) unsupported_any = true;

    if (header_ok == false) break;
  }

  if (unsupported_any == true) extra->unsupported_cnt++;
}

static bool rar5_is_hex (const char *s, const u32 len)
{
  for (u32 i = 0; i < len; i++)
  {
    if (is_valid_hex_char ((u8) s[i]) == false) return false;
  }

  return true;
}

// $rar$50$*type*salt*lg2*iv*pswcheck*checktype*checksum*ps*us*method*data$/rar$
//
// Type 0 fills pswcheck and leaves the 5 fields after checktype empty. Type 1 leaves pswcheck
// empty and fills the rest, except that checktype 4 has no checksum.

#define RAR50_FIELDS 11

static int parse_new_rar50 (u32 *digest, salt_t *salt, rar5_t *rar5, rar5_hook_salt_t *hook_salt, const char *line_buf, const int line_len)
{
  if (line_len < 8 + 6) return (PARSER_SIGNATURE_UNMATCHED);

  if (memcmp (&line_buf[line_len - 6], SIGNATURE_RAR_STOP, 6) != 0) return (PARSER_SIGNATURE_UNMATCHED);

  // Split what is between the two signatures on '*'.

  const char *field[RAR50_FIELDS];

  u32 flen[RAR50_FIELDS];

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

    if (cnt == RAR50_FIELDS)
    {
      // Older ArchiveWolf versions wrote one more empty field on a type 0 line.

      if ((pos != start) || (pos != end)) return (PARSER_TOKEN_LENGTH);

      break;
    }

    field[cnt] = &line_buf[start];
    flen[cnt]  = pos - start;

    cnt++;
  }

  if (cnt != RAR50_FIELDS) return (PARSER_TOKEN_LENGTH);

  // type

  if (flen[0] != 1) return (PARSER_SALT_VALUE);

  const u32 type = (u32) (field[0][0] - '0');

  if (type > 1) return (PARSER_SALT_VALUE);

  // salt, iterations, iv

  if ((flen[1] != 32) || (rar5_is_hex (field[1], 32) == false)) return (PARSER_SALT_LENGTH);
  if ((flen[2] < 1) || (flen[2] > 2)) return (PARSER_SALT_ITERATION);
  if ((flen[3] != 32) || (rar5_is_hex (field[3], 32) == false)) return (PARSER_SALT_LENGTH);

  u32 iterations = 0;

  for (u32 i = 0; i < flen[2]; i++)
  {
    if ((field[2][i] < '0') || (field[2][i] > '9')) return (PARSER_SALT_ITERATION);

    iterations = (iterations * 10) + (u32) (field[2][i] - '0');
  }

  // salt_iter is a u32 and the kernel dispatch loop is bound by it, so nothing above 31 fits.

  if (iterations == 0) return (PARSER_SALT_VALUE);
  if (iterations > 31) return (PARSER_SALT_ITERATION);

  salt->salt_iter    = ((1u << iterations) + 32) - 1;
  salt->salt_sign[0] = (u8) iterations;

  const u8 *salt_pos = (const u8 *) field[1];

  salt->salt_buf[0] = byte_swap_32 (hex_to_u32 (&salt_pos[ 0]));
  salt->salt_buf[1] = byte_swap_32 (hex_to_u32 (&salt_pos[ 8]));
  salt->salt_buf[2] = byte_swap_32 (hex_to_u32 (&salt_pos[16]));
  salt->salt_buf[3] = byte_swap_32 (hex_to_u32 (&salt_pos[24]));

  salt->salt_len = 16;

  const u8 *iv_pos = (const u8 *) field[3];

  rar5->iv[0] = byte_swap_32 (hex_to_u32 (&iv_pos[ 0]));
  rar5->iv[1] = byte_swap_32 (hex_to_u32 (&iv_pos[ 8]));
  rar5->iv[2] = byte_swap_32 (hex_to_u32 (&iv_pos[16]));
  rar5->iv[3] = byte_swap_32 (hex_to_u32 (&iv_pos[24]));

  for (u32 i = 0; i < 16; i++) hook_salt->iv[i] = hex_to_u8 (&iv_pos[i * 2]);

  hook_salt->type = type;

  rar5->type = type;

  // checktype

  if (flen[5] != 1) return (PARSER_SALT_VALUE);

  if ((field[5][0] < '0') || (field[5][0] > '4')) return (PARSER_SALT_VALUE);

  const u32 check_type = (u32) (field[5][0] - '0');

  hook_salt->check_type = check_type;

  rar5->check_type = check_type;

  if (type == 0)
  {
    if ((flen[4] != 16) || (rar5_is_hex (field[4], 16) == false)) return (PARSER_HASH_LENGTH);

    for (u32 i = 6; i < RAR50_FIELDS; i++)
    {
      if (flen[i] != 0) return (PARSER_TOKEN_LENGTH);
    }

    digest[0] = byte_swap_32 (hex_to_u32 ((const u8 *) &field[4][0]));
    digest[1] = byte_swap_32 (hex_to_u32 ((const u8 *) &field[4][8]));
    digest[2] = 0;
    digest[3] = 0;

    rar5->psw_check[0] = digest[0];
    rar5->psw_check[1] = digest[1];

    // The word after the 16 salt bytes tells the kernel which kind of hash this is. Nothing else
    // goes into the salt, so the type 0 hashes of one archive share a salt group.

    salt->salt_buf[4] = 0;

    return (PARSER_OK);
  }

  // type 1

  if (flen[4] != 0) return (PARSER_HASH_LENGTH);

  u32 check_hex = 8;

  if (check_type >= RAR5_CHECK_BLAKE2SP) check_hex = 64;
  if (check_type == RAR5_CHECK_HEADER)   check_hex = 0;

  if ((flen[6] != check_hex) || (rar5_is_hex (field[6], check_hex) == false)) return (PARSER_HASH_LENGTH);

  for (u32 i = 0; i < check_hex / 2; i++) hook_salt->check[i] = hex_to_u8 ((const u8 *) &field[6][i * 2]);

  for (u32 i = 7; i <= 9; i++)
  {
    if ((flen[i] < 1) || (flen[i] > 16)) return (PARSER_SALT_VALUE);

    if (rar5_is_hex (field[i], flen[i]) == false) return (PARSER_SALT_VALUE);
  }

  const u64 pack_size   = hc_strtoull (field[7], NULL, 16);
  const u64 unpack_size = hc_strtoull (field[8], NULL, 16);
  const u32 method      = (u32) hc_strtoull (field[9], NULL, 16);

  if (method > 5) return (PARSER_SALT_VALUE);

  const u32 data_hex_len = flen[10];

  if (((data_hex_len % 2) != 0) || (rar5_is_hex (field[10], data_hex_len) == false)) return (PARSER_SALT_ENCODING);

  const u32 data_bytes = data_hex_len / 2;

  // AES-256-CBC works on whole blocks, and the hash has to carry the whole entry: the checksum
  // covers every byte of it, so a shorter line could never confirm a password.

  if ((data_bytes < 16) || ((data_bytes % 16) != 0)) return (PARSER_SALT_LENGTH);
  if (data_bytes > RAR50_DATA_MAX) return (PARSER_SALT_LENGTH);
  if (pack_size != data_bytes) return (PARSER_SALT_LENGTH);

  if (check_type != RAR5_CHECK_HEADER)
  {
    // An empty file has nothing to check a password against.

    if (unpack_size == 0) return (PARSER_SALT_VALUE);

    if ((method == 0) && (unpack_size > data_bytes)) return (PARSER_SALT_VALUE);
  }

  hook_salt->method      = method;
  hook_salt->pack_size   = pack_size;
  hook_salt->unpack_size = unpack_size;
  hook_salt->data_len    = data_bytes;

  hook_salt->data = (u8 *) hcmalloc (data_bytes);

  if (hook_salt->data == NULL) return (PARSER_HAVE_ERRNO);

  for (u32 i = 0; i < data_bytes; i++) hook_salt->data[i] = hex_to_u8 ((const u8 *) &field[10][i * 2]);

  for (u32 i = 0; i < 32; i++) rar5->check[i] = hook_salt->check[i];

  rar5->method      = method;
  rar5->pack_size   = pack_size;
  rar5->unpack_size = unpack_size;
  rar5->data_len    = data_bytes;
  rar5->data        = (u64) (size_t) hook_salt->data;

  // The word after the 16 salt bytes tells the kernel which kind of hash this is. The next one
  // gives every type 1 hash a salt group of its own: its entry is verified by the host hook, which
  // is handed one hook salt per salt group.

  rar5_crc32_init ();

  salt->salt_buf[4] = 1;
  salt->salt_buf[5] = rar5_crc32 (0xffffffff, hook_salt->data, data_bytes);

  // A type 1 hash has no value of its own to compare, so its digest only has to tell it apart.

  digest[0] = 1;
  digest[1] = salt->salt_buf[5];
  digest[2] = 0;
  digest[3] = 0;

  return (PARSER_OK);
}

static int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  rar5_t *rar5 = (rar5_t *) esalt_buf;

  rar5_hook_salt_t *hook_salt = (rar5_hook_salt_t *) hook_salt_buf;

  memset (hook_salt, 0, sizeof (rar5_hook_salt_t));

  if ((line_len > 8) && (strncmp (line_buf, SIGNATURE_RAR50, 8) == 0))
  {
    return parse_new_rar50 (digest, salt, rar5, hook_salt, line_buf, line_len);
  }

  hook_salt->legacy_format = 1;

  rar5->legacy_format = 1;

  // fall back to old $rar5$ format

  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  token.token_cnt  = 7;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_RAR5;

  token.len[0]     = 6;
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.sep[1]     = '$';
  token.len[1]     = 2;
  token.attr[1]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[2]     = '$';
  token.len[2]     = 32;
  token.attr[2]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.sep[3]     = '$';
  token.len[3]     = 2;
  token.attr[3]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[4]     = '$';
  token.len[4]     = 32;
  token.attr[4]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.sep[5]     = '$';
  token.len[5]     = 1;
  token.attr[5]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[6]     = '$';
  token.len[6]     = 16;
  token.attr[6]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  // iter

  const u8 *iter_pos = token.buf[3];

  const u32 iterations = hc_strtoul ((const char *) iter_pos, NULL, 10);

  if (iterations == 0) return (PARSER_SALT_VALUE);

  // RAR5 log2 iteration count has no hard spec cap, but salt_iter is u32
  // and the kernel dispatch loop is u32-bound, so we cannot support > 31.

  if (iterations > 31) return (PARSER_SALT_ITERATION);

  salt->salt_iter = ((1u << iterations) + 32) - 1;

  salt->salt_sign[0] = iterations;

  // salt

  const u8 *salt_buf = token.buf[2];

  salt->salt_buf[0] = hex_to_u32 (salt_buf +  0);
  salt->salt_buf[1] = hex_to_u32 (salt_buf +  8);
  salt->salt_buf[2] = hex_to_u32 (salt_buf + 16);
  salt->salt_buf[3] = hex_to_u32 (salt_buf + 24);

  salt->salt_buf[0] = byte_swap_32 (salt->salt_buf[0]);
  salt->salt_buf[1] = byte_swap_32 (salt->salt_buf[1]);
  salt->salt_buf[2] = byte_swap_32 (salt->salt_buf[2]);
  salt->salt_buf[3] = byte_swap_32 (salt->salt_buf[3]);

  // iv

  const u8 *iv = token.buf[4];

  rar5->iv[0] = hex_to_u32 (iv +  0);
  rar5->iv[1] = hex_to_u32 (iv +  8);
  rar5->iv[2] = hex_to_u32 (iv + 16);
  rar5->iv[3] = hex_to_u32 (iv + 24);

  rar5->iv[0] = byte_swap_32 (rar5->iv[0]);
  rar5->iv[1] = byte_swap_32 (rar5->iv[1]);
  rar5->iv[2] = byte_swap_32 (rar5->iv[2]);
  rar5->iv[3] = byte_swap_32 (rar5->iv[3]);

  salt->salt_len = 16;

  // hash

  const u8 *pswcheck = token.buf[6];

  digest[0] = hex_to_u32 (pswcheck + 0);
  digest[1] = hex_to_u32 (pswcheck + 8);
  digest[2] = 0;
  digest[3] = 0;

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = 0;
  digest[3] = 0;

  rar5->type = 0;

  rar5->psw_check[0] = digest[0];
  rar5->psw_check[1] = digest[1];

  salt->salt_buf[4] = 0;

  return (PARSER_OK);
}

static int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  // Everything comes from the esalt, which belongs to this hash. The hook salt belongs to the salt
  // group.

  const rar5_t *rar5 = (const rar5_t *) esalt_buf;

  if (rar5->legacy_format == 1)
  {
    return snprintf (line_buf, line_size, "%s16$%08x%08x%08x%08x$%u$%08x%08x%08x%08x$8$%08x%08x",
      SIGNATURE_RAR5,
      salt->salt_buf[0], salt->salt_buf[1], salt->salt_buf[2], salt->salt_buf[3],
      salt->salt_sign[0],
      rar5->iv[0], rar5->iv[1], rar5->iv[2], rar5->iv[3],
      rar5->psw_check[0], rar5->psw_check[1]);
  }

  int line_len = snprintf (line_buf, line_size, "%s*%u*%08x%08x%08x%08x*%u*%08x%08x%08x%08x*",
    SIGNATURE_RAR50,
    rar5->type,
    salt->salt_buf[0], salt->salt_buf[1], salt->salt_buf[2], salt->salt_buf[3],
    salt->salt_sign[0],
    rar5->iv[0], rar5->iv[1], rar5->iv[2], rar5->iv[3]);

  if (rar5->type == 0)
  {
    line_len += snprintf (&line_buf[line_len], line_size - line_len, "%08x%08x*%u*****%s", rar5->psw_check[0], rar5->psw_check[1], rar5->check_type, SIGNATURE_RAR_STOP);

    return line_len;
  }

  line_len += snprintf (&line_buf[line_len], line_size - line_len, "*%u*", rar5->check_type);

  int check_len = 4;

  if (rar5->check_type >= RAR5_CHECK_BLAKE2SP) check_len = 32;
  if (rar5->check_type == RAR5_CHECK_HEADER)   check_len = 0;

  line_len += hex_encode (rar5->check, check_len, (u8 *) &line_buf[line_len]);

  line_len += snprintf (&line_buf[line_len], line_size - line_len, "*%" PRIx64 "*%" PRIx64 "*%x*", rar5->pack_size, rar5->unpack_size, rar5->method);

  const u8 *data = (const u8 *) (size_t) rar5->data;

  if (data == NULL) return 0;

  if ((u64) line_len + ((u64) rar5->data_len * 2) + 8 >= (u64) line_size) return 0;

  line_len += hex_encode (data, (int) rar5->data_len, (u8 *) &line_buf[line_len]);

  line_len += snprintf (&line_buf[line_len], line_size - line_len, "%s", SIGNATURE_RAR_STOP);

  return line_len;
}

void module_init (module_ctx_t *module_ctx)
{
  module_init_common (module_ctx);

  module_ctx->module_deep_comp_kernel         = module_deep_comp_kernel;
  module_ctx->module_esalt_size               = module_esalt_size;
  module_ctx->module_hash_decode              = module_hash_decode;
  module_ctx->module_hash_encode              = module_hash_encode;
  module_ctx->module_hook23                   = module_hook23;
  module_ctx->module_hook_extra_param_size    = module_hook_extra_param_size;
  module_ctx->module_hook_extra_param_init    = module_hook_extra_param_init;
  module_ctx->module_hook_extra_param_term    = module_hook_extra_param_term;
  module_ctx->module_hook_salt_size           = module_hook_salt_size;
  module_ctx->module_hook_size                = module_hook_size;
  module_ctx->module_jit_build_options        = module_jit_build_options;
  module_ctx->module_kern_bits                = module_kern_bits;
  module_ctx->module_tmp_size                 = module_tmp_size;
  module_ctx->module_unstable_warning         = module_unstable_warning;
  module_ctx->module_usage_notice             = module_usage_notice;
}
