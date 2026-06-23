/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 *
 * Shared host core for the WPA-PSK "universal" modes (22002 / 22003) and the
 * 90001-90010 bake-off plugins. Each module_NNNNN.c #includes this header,
 * then defines only KERN_TYPE, OPTS_TYPE (its aux wiring), and (where used)
 * module_deep_comp_kernel + module_init.
 *
 * The 2-digit type code after WPA* is the SOLE dispatch axis: one esalt struct
 * carries every hash type and the loader/kernel branch purely on that number.
 */

#ifndef INC_WPA_PSK_UNIVERSAL_MODULE_H
#define INC_WPA_PSK_UNIVERSAL_MODULE_H

#include "common.h"          // hashcat-wide typedefs and macros
#include "types.h"           // salt_t / hashconfig_t / module_ctx_t etc.
#include "modules.h"         // module API constants (PARSER_*, MODULE_DEFAULT, ...)
#include "bitops.h"          // byte_swap_16/32 endianness helpers
#include "convert.h"         // hex_to_u8 / hex_decode / u32_to_hex string conversions
#include "shared.h"          // tokenizer (hc_token_t, input_tokenizer)
#include "memory.h"          // hcmalloc/hcfree (not directly used here but pulled by siblings)
#include "emu_general.h"     // host-side emulation of device intrinsics
#include "emu_inc_hash_md5.h"// md5_transform for the uniqueness digest below

static const u32   WPA_ATTACK_EXEC   = ATTACK_EXEC_OUTSIDE_KERNEL;            // slow hash: separate _init/_loop/_comp + aux kernels
static const u32   WPA_DGST_POS0     = 0;                                     // 32-bit word index hashcat compares first in the bloom filter
static const u32   WPA_DGST_POS1     = 1;                                     // second word position
static const u32   WPA_DGST_POS2     = 2;                                     // third word position
static const u32   WPA_DGST_POS3     = 3;                                     // fourth word position
static const u32   WPA_DGST_SIZE     = DGST_SIZE_4_4;                         // 16-byte (4x u32) digest stored per hash
static const u32   WPA_HASH_CATEGORY = HASH_CATEGORY_NETWORK_PROTOCOL;        // grouping shown in --help
static const u32   WPA_SALT_TYPE     = SALT_TYPE_EMBEDDED;                    // salt is part of the strict hash line, not a --hex-salt
static const char *WPA_ST_PASS       = "hashcat!";                           // self-test passphrase
// self-test: a WPA2-PSK-PMKID (type 2) line for ESSID "hashcat-essid", PSK "hashcat!".
static const char *WPA_ST_HASH       = "WPA*02*4d4fe7aac3a2cecab195321ceb99a7d0*fc690c158264*f4747f87f9f4*686173686361742d6573736964***01";

static const u32 ROUNDS_WPA_PBKDF2 = 4096;                                   // WPA PMK = PBKDF2-HMAC-SHA1 over 4096 iterations

// The HOOK23 plugins (90003 / 90007) #include the device .cl first to reuse the
// device verifiers on the host; that file already defines these structs under its
// own guard, so skip them here to avoid a redefinition clash.
#ifndef INC_WPA_PSK_UNIVERSAL_CL

// Per-workitem PBKDF2-HMAC-SHA1 scratch carried across the _init/_loop/_comp kernels.
typedef struct wpa_pbkdf2_tmp
{
  u32 ipad[5];   // precomputed HMAC inner-pad SHA1 state (passphrase xor 0x36)
  u32 opad[5];   // precomputed HMAC outer-pad SHA1 state (passphrase xor 0x5c)

  u32 dgst[10];  // running PBKDF2 block digest (two 5-word SHA1 blocks = 40 bytes)
  u32 out[10];   // accumulated PBKDF2 output, first 32 bytes are the PMK

} wpa_pbkdf2_tmp_t;

// Tmps for a future PMK-direct mode (PMK supplied instead of derived); 32-byte PMK only.
typedef struct wpa_pmk_tmp
{
  u32 out[8];    // 32-byte PMK supplied directly, no PBKDF2

} wpa_pmk_tmp_t;

// One esalt per digest; a single struct holds every per-handshake field for all 11 types.
typedef struct wpa_universal
{
  u32  essid_buf[16];   // network name bytes (also copied into the salt for PBKDF2)
  u32  essid_len;       // network name length in bytes

  u32  mac_ap[2];       // 6-byte AP MAC (BSSID) packed into two words
  u32  mac_sta[2];      // 6-byte station MAC packed into two words

  u32  type;            // 1..11 hash type, the sole dispatch axis for loader and kernel

  u32  pmkid[4];        // 16-byte PMKID (PMKR1Name for FT) stored big-endian, for PMKID rows
  u32  pmkid_data[32];  // scratch holding "PMK Name"||AP||STA (or FT "FT-R1N" template)

  u32  keymic[6];       // 16- or 24-byte expected MIC stored big-endian, for EAPOL rows
  u32  anonce[8];       // the external 32-byte <nonce> field from the line
  u32  eapol[256 + 16]; // raw EAPOL-Key frame, MIC field zeroed; 1088 B holds real FT M3 frames (observed up to ~515 B / 1030 hex)
  u32  eapol_len;       // EAPOL frame length in bytes
  u32  pke[32];         // PTK-derivation input (PRF or KDF "Pairwise key expansion" block)

  u32  keyver;          // legacy key-descriptor version (low bits of key_information); used only in the uniqueness digest

  u32  mdid[1];         // 2-byte Mobility Domain ID (FT only)
  u32  r0khid[12]; u32 r0khid_len;   // 1..48-byte R0 Key Holder ID (FT only) and its length
  u32  r1khid[12]; u32 r1khid_len;   // 6-byte R1 Key Holder ID (FT only) and its length
  u32  pke_r0[32];      // FT PMK-R0 / R0Name-Salt KDF input template
  u32  pke_r1[32];      // FT PMK-R1 KDF input template

  int  message_pair_chgd;   u32 message_pair;          // whether --hccapx-message-pair was forced; the message-pair byte
  int  nonce_error_corrections_chgd;  int nonce_error_corrections;  // whether NC count was forced; +/- nonce sweep count
  int  nonce_compare;  int detected_le;  int detected_be;           // nonce min/max ordering result; replay-counter endianness flags

} wpa_universal_t;

#endif // INC_WPA_PSK_UNIVERSAL_CL

// Byte-exact overlay onto the raw EAPOL-Key frame so its header fields can be read in place.
#pragma pack(push,1)
struct wpa_auth_packet
{
  u8  version;              // EAPOL protocol version
  u8  type;                 // EAPOL packet type (3 = EAPOL-Key)
  u16 length;               // body length (big-endian on the wire)
  u8  key_descriptor;       // key descriptor type
  u16 key_information;      // big-endian flags; low 3 bits are the key-descriptor version
  u16 key_length;           // key length field
  u64 replay_counter;       // monotonically increasing replay counter
  u8  wpa_key_nonce[32];    // the nonce carried inside the frame (SNonce or ANonce)
  u8  wpa_key_iv[16];       // key IV
  u8  wpa_key_rsc[8];       // receive sequence counter
  u8  wpa_key_id[8];        // key identifier
  u8  wpa_key_mic[16];      // MIC field (zeroed in the captured frame so we can recompute it)
  u16 wpa_key_data_length;  // length of the trailing key data
} __attribute__((packed));
typedef struct wpa_auth_packet wpa_auth_packet_t;
#pragma pack(pop)

// --- helpers ---

// FT (802.11r fast-roaming) types use the extra mdid/r0khid/r1khid fields and the FT key hierarchy.
static bool wpa_type_is_ft (const u32 type)
{
  return (type == 6) || (type == 7) || (type == 10) || (type == 11);
}

// Assembles the KDF input that derives the first stage of the FT hierarchy.
// Layout: 16-bit LE counter || "FT-R0" label || ESSID-len || ESSID || MDID || R0KH-len || R0KH-ID || STA MAC || key-length-in-bits (16-bit LE).
// counter = 2 reads out the R0Name-Salt block (used to form PMKR0Name for PMKID rows);
// counter = 1 reads out the PMK-R0 block (used to derive PMK-R1 for EAPOL rows).
static void wpa_build_pke_r0 (wpa_universal_t *wpa, const u8 *mac_sta, const u8 counter, const u32 size_bits)
{
  u8 *p = (u8 *) wpa->pke_r0;        // build the template directly in the esalt scratch
  memset (p, 0, 128);                // start from zeros so trailing slack is clean

  p[0] = counter;                    // 16-bit LE block counter, low byte
  p[1] = 0;                          // counter high byte (always 0 here)
  memcpy (p + 2, "FT-R0", 5);        // the FT-R0 key-derivation label
  p[7] = (u8) wpa->essid_len;        // single-byte ESSID length prefix
  memcpy (p + 8, wpa->essid_buf, wpa->essid_len);                 // the ESSID bytes
  memcpy (p + 8 + wpa->essid_len, wpa->mdid, 2);                  // 2-byte Mobility Domain ID
  p[10 + wpa->essid_len] = (u8) wpa->r0khid_len;                  // single-byte R0KH-ID length prefix
  memcpy (p + 11 + wpa->essid_len, wpa->r0khid, wpa->r0khid_len); // the R0KH-ID bytes
  memcpy (p + 11 + wpa->essid_len + wpa->r0khid_len, mac_sta, 6); // station MAC (S0KH-ID)
  p[17 + wpa->essid_len + wpa->r0khid_len] = (u8) (size_bits & 0xff);  // key length in bits, low byte
  p[18 + wpa->essid_len + wpa->r0khid_len] = (u8) (size_bits >> 8);    // key length in bits, high byte
}

// Assembles the KDF input that derives PMK-R1 from PMK-R0 in the FT hierarchy.
// Layout: 16-bit LE counter (1) || "FT-R1" label || R1KH-ID || STA MAC || key-length-in-bits (16-bit LE).
static void wpa_build_pke_r1 (wpa_universal_t *wpa, const u8 *mac_sta, const u32 size_bits)
{
  u8 *p = (u8 *) wpa->pke_r1;        // build the template directly in the esalt scratch
  memset (p, 0, 128);                // start from zeros

  p[0] = 1;                          // block counter low byte (1: only one output block)
  p[1] = 0;                          // counter high byte
  memcpy (p + 2, "FT-R1", 5);        // the FT-R1 key-derivation label
  memcpy (p + 7, wpa->r1khid, wpa->r1khid_len);                   // 6-byte R1KH-ID
  memcpy (p + 7 + wpa->r1khid_len, mac_sta, 6);                   // station MAC (S1KH-ID)
  p[13 + wpa->r1khid_len] = (u8) (size_bits & 0xff);             // key length in bits, low byte
  p[14 + wpa->r1khid_len] = (u8) (size_bits >> 8);              // key length in bits, high byte
}

// --- mandatory module-config getters (shared) ---

// Slow-hash execution model: kernels live outside the single-shot path.
u32 module_attack_exec (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return WPA_ATTACK_EXEC; }
// First digest word position hashcat compares.
u32 module_dgst_pos0 (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return WPA_DGST_POS0; }
// Second digest word position.
u32 module_dgst_pos1 (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return WPA_DGST_POS1; }
// Third digest word position.
u32 module_dgst_pos2 (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return WPA_DGST_POS2; }
// Fourth digest word position.
u32 module_dgst_pos3 (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return WPA_DGST_POS3; }
// 16-byte digest size.
u32 module_dgst_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return WPA_DGST_SIZE; }
// Hash category for --help grouping.
u32 module_hash_category (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return WPA_HASH_CATEGORY; }
// Salt is embedded in the strict hash format.
u32 module_salt_type (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return WPA_SALT_TYPE; }
// Self-test hash line.
const char *module_st_hash (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return WPA_ST_HASH; }
// Self-test passphrase.
const char *module_st_pass (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return WPA_ST_PASS; }
// Minimum WPA passphrase length.
u32 module_pw_min (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return 8; }
// Maximum WPA passphrase length.
u32 module_pw_max (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return 63; }

// Optimizer hints: candidates never contain a zero byte; the slow-hash loop is SIMD-vectorizable.
u32 module_opti_type (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return OPTI_TYPE_ZERO_BYTE | OPTI_TYPE_SLOW_HASH_SIMD_LOOP; }

// Tmps buffer size: the PBKDF2-HMAC-SHA1 working state (one per workitem).
u64 module_tmp_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return (u64) sizeof (wpa_pbkdf2_tmp_t); }
// Esalt buffer size: one universal struct per digest holds all per-handshake data.
u64 module_esalt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return (u64) sizeof (wpa_universal_t); }

// Benchmark mask: 8 mixed characters (the minimum WPA length).
const char *module_benchmark_mask (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return "?a?a?a?a?a?a?a?a"; }

// Disable the legacy hashfile formats; only the WPA* line is accepted.
bool module_hlfmt_disable (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return true; }

// --- loader ---

// Parses one WPA* line into the salt, esalt, and 16-byte digest.
int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;                       // bloom-filter/dedup digest output
  wpa_universal_t *wpa = (wpa_universal_t *) esalt_buf;    // per-handshake esalt to fill

  // Need at least "WPA*NN" before we can read the type that sizes the tokenizer.
  if (line_len < 7) return (PARSER_SALT_LENGTH);
  // The line must start with the "WPA*" signature.
  if ((line_buf[0] != 'W') || (line_buf[1] != 'P') || (line_buf[2] != 'A') || (line_buf[3] != '*')) return (PARSER_SIGNATURE_UNMATCHED);

  // The type is two DECIMAL digits 01..11, not hex: "10"/"11" mean ten/eleven, so
  // parse it as (hi-'0')*10 + (lo-'0') rather than via hex_to_u8.
  const char t_hi = line_buf[4];                          // tens digit
  const char t_lo = line_buf[5];                          // units digit
  if ((t_hi < '0') || (t_hi > '9') || (t_lo < '0') || (t_lo > '9')) return (PARSER_SALT_VALUE);  // both must be digits
  const u8 type = (u8) (((t_hi - '0') * 10) + (t_lo - '0'));    // decimal type code
  if ((type < 1) || (type > 11)) return (PARSER_SALT_VALUE);    // only 1..11 are defined

  const bool is_ft = wpa_type_is_ft (type);               // FT types carry 3 extra fields
  const int  mic_hex = ((type == 9) || (type == 11)) ? 48 : 32;  // SHA-384 MIC is 24 bytes (48 hex), else 16 bytes

  hc_token_t token;                                       // tokenizer config splitting on '*'
  memset (&token, 0, sizeof (hc_token_t));

  token.token_cnt = is_ft ? 12 : 9;                       // FT lines have 12 fields (incl. mdid/r0kh/r1kh), others 9

  token.signatures_cnt    = 1;                            // exactly one leading literal to match
  token.signatures_buf[0] = "WPA";                        // ...and it is "WPA"

  token.sep[0]  = '*'; token.len[0] = 3;       token.attr[0] = TOKEN_ATTR_FIXED_LENGTH | TOKEN_ATTR_VERIFY_SIGNATURE;  // field 0: literal "WPA"
  token.sep[1]  = '*'; token.len[1] = 2;       token.attr[1] = TOKEN_ATTR_FIXED_LENGTH | TOKEN_ATTR_VERIFY_HEX;        // field 1: 2-char type code
  token.sep[2]  = '*'; token.len[2] = mic_hex; token.attr[2] = TOKEN_ATTR_FIXED_LENGTH | TOKEN_ATTR_VERIFY_HEX;        // field 2: <hash> (PMKID or MIC), width per type
  token.sep[3]  = '*'; token.len[3] = 12;      token.attr[3] = TOKEN_ATTR_FIXED_LENGTH | TOKEN_ATTR_VERIFY_HEX;        // field 3: AP MAC (6 bytes = 12 hex)
  token.sep[4]  = '*'; token.len[4] = 12;      token.attr[4] = TOKEN_ATTR_FIXED_LENGTH | TOKEN_ATTR_VERIFY_HEX;        // field 4: STA MAC (6 bytes = 12 hex)

  token.sep[5]  = '*'; token.len_min[5] = 0;  token.len_max[5] = 64;   token.attr[5] = TOKEN_ATTR_VERIFY_LENGTH | TOKEN_ATTR_VERIFY_HEX;  // field 5: ESSID hex (up to 32 bytes)
  token.sep[6]  = '*'; token.len_min[6] = 0;  token.len_max[6] = 64;   token.attr[6] = TOKEN_ATTR_VERIFY_LENGTH | TOKEN_ATTR_VERIFY_HEX;  // field 6: <nonce> hex, empty for PMKID rows
  token.sep[7]  = '*'; token.len_min[7] = 0;  token.len_max[7] = 2048; token.attr[7] = TOKEN_ATTR_VERIFY_LENGTH | TOKEN_ATTR_VERIFY_HEX;  // field 7: <eapol> hex (up to 1024 B); empty for PMKID rows. Real FT M3 frames reach ~515 B, so the legacy 512-hex cap rejected them
  token.sep[8]  = '*'; token.len_min[8] = 0;  token.len_max[8] = 2;    token.attr[8] = TOKEN_ATTR_VERIFY_LENGTH | TOKEN_ATTR_VERIFY_HEX;  // field 8: message-pair byte, empty for PMKID rows

  if (is_ft)
  {
    token.sep[9]  = '*'; token.len_min[9]  = 0;  token.len_max[9]  = 4;   token.attr[9]  = TOKEN_ATTR_VERIFY_LENGTH | TOKEN_ATTR_VERIFY_HEX;  // field 9: MDID (2 bytes = 4 hex)
    token.sep[10] = '*'; token.len_min[10] = 2;  token.len_max[10] = 96;  token.attr[10] = TOKEN_ATTR_VERIFY_LENGTH | TOKEN_ATTR_VERIFY_HEX;  // field 10: R0KH-ID (1..48 bytes)
    token.sep[11] = '*'; token.len_min[11] = 12; token.len_max[11] = 12;  token.attr[11] = TOKEN_ATTR_VERIFY_LENGTH | TOKEN_ATTR_VERIFY_HEX;  // field 11: R1KH-ID (6 bytes = 12 hex)
  }

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);  // run the split + per-field checks
  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);   // bail on any malformed field

  wpa->type = type;                                       // record the dispatch type in the esalt

  // macs
  u8 *mac_ap  = (u8 *) wpa->mac_ap;                        // byte view of the AP MAC slot
  u8 *mac_sta = (u8 *) wpa->mac_sta;                       // byte view of the STA MAC slot

  const u8 *macap_buf = token.buf[3];                      // hex of the AP MAC
  for (int i = 0; i < 6; i++) mac_ap[i] = hex_to_u8 (macap_buf + (i * 2));   // decode 6 bytes

  const u8 *macsta_buf = token.buf[4];                     // hex of the STA MAC
  for (int i = 0; i < 6; i++) mac_sta[i] = hex_to_u8 (macsta_buf + (i * 2)); // decode 6 bytes

  // essid -> salt
  const u8 *essid_buf = token.buf[5];                      // hex of the network name
  const int essid_len = token.len[5];                      // hex length (must be even)
  if (essid_len & 1) return (PARSER_SALT_VALUE);           // odd hex length is invalid

  wpa->essid_len = hex_decode (essid_buf, essid_len, (u8 *) wpa->essid_buf);  // decode ESSID into the esalt

  memcpy (salt->salt_buf, wpa->essid_buf, wpa->essid_len); // the salt holds ONLY the ESSID
  salt->salt_len  = wpa->essid_len;                        // ...so PBKDF2 runs once per unique ESSID
  salt->salt_iter = ROUNDS_WPA_PBKDF2 - 1;                 // 4096-1: the _init kernel produces PBKDF2 block 1, counting as the first iteration

  // FT extras
  if (is_ft)
  {
    const u8 *mdid_pos = token.buf[9];                     // hex of the 2-byte Mobility Domain ID
    u8 *mdid_ptr = (u8 *) wpa->mdid;                       // byte view of the MDID slot
    mdid_ptr[0] = hex_to_u8 (mdid_pos + 0);               // MDID byte 0
    mdid_ptr[1] = hex_to_u8 (mdid_pos + 2);               // MDID byte 1

    wpa->r0khid_len = hex_decode (token.buf[10], token.len[10], (u8 *) wpa->r0khid);  // R0KH-ID bytes + length
    wpa->r1khid_len = hex_decode (token.buf[11], token.len[11], (u8 *) wpa->r1khid);  // R1KH-ID bytes + length
  }

  const bool is_pmkid = ((type % 2) == 0);                 // even types are PMKID attacks, odd types are EAPOL

  if (is_pmkid)
  {
    // The PMKID is the first 16 bytes of the keyed hash; store it as big-endian words so
    // the (big-endian) SHA-family hash output in the kernel compares directly.
    const u8 *pmkid_buf = token.buf[2];                    // hex of the expected PMKID
    wpa->pmkid[0] = byte_swap_32 (hex_to_u32 (pmkid_buf +  0));  // word 0, byte-swapped to BE
    wpa->pmkid[1] = byte_swap_32 (hex_to_u32 (pmkid_buf +  8));  // word 1
    wpa->pmkid[2] = byte_swap_32 (hex_to_u32 (pmkid_buf + 16));  // word 2
    wpa->pmkid[3] = byte_swap_32 (hex_to_u32 (pmkid_buf + 24));  // word 3

    digest[0] = wpa->pmkid[0];                             // PMKID rows store the PMKID itself as the dedup digest
    digest[1] = wpa->pmkid[1];
    digest[2] = wpa->pmkid[2];
    digest[3] = wpa->pmkid[3];

    if (is_ft == 0)
    {
      // Non-FT PMKID input = the literal "PMK Name" then AP MAC then STA MAC. Packed
      // little-endian here; the kernel byte-swaps when it re-reads the stream for the HMAC.
      wpa->pmkid_data[0] = 0x204b4d50; // "PMK " (little-endian)
      wpa->pmkid_data[1] = 0x656d614e; // "Name" (little-endian)
      wpa->pmkid_data[2] = (mac_ap[0]  <<  0) | (mac_ap[1]  <<  8) | (mac_ap[2]  << 16) | (mac_ap[3]  << 24);  // AP MAC bytes 0..3
      wpa->pmkid_data[3] = (mac_ap[4]  <<  0) | (mac_ap[5]  <<  8) | (mac_sta[0] << 16) | (mac_sta[1] << 24);  // AP MAC 4..5 + STA 0..1
      wpa->pmkid_data[4] = (mac_sta[2] <<  0) | (mac_sta[3] <<  8) | (mac_sta[4] << 16) | (mac_sta[5] << 24);  // STA MAC bytes 2..5
    }
    else
    {
      // FT PMKID (types 6 / 10): the emitted value is actually the PMKR1Name from the FT hierarchy.
      const u32 r0_size = (type == 6) ? 0x0180 : 0x0200;   // 384 bits for the SHA-256 family, 512 bits for SHA-384
      wpa_build_pke_r0 (wpa, mac_sta, 2, r0_size);          // counter = 2 yields the R0Name-Salt directly

      // PMKR1Name input = "FT-R1N" then PMKR0Name (16-byte gap the kernel fills) then R1KH-ID then STA MAC.
      u8 *p = (u8 *) wpa->pmkid_data;                       // build the template in pmkid_data
      memset (p, 0, 128);                                   // zero the buffer (incl. the gap)
      memcpy (p, "FT-R1N", 6);                              // the FT-R1Name label
      memcpy (p + 6 + 16, wpa->r1khid, wpa->r1khid_len);    // R1KH-ID after the 16-byte PMKR0Name gap
      memcpy (p + 6 + 16 + wpa->r1khid_len, mac_sta, 6);    // station MAC

      for (int i = 0; i < 32; i++)
      {
        wpa->pke_r0[i]     = byte_swap_32 (wpa->pke_r0[i]);     // swap each word to BE for the big-endian hash
        wpa->pmkid_data[i] = byte_swap_32 (wpa->pmkid_data[i]); // ...same for the PMKR1Name template
      }
    }

    return (PARSER_OK);                                    // PMKID rows are fully parsed
  }

  // ---- EAPOL rows (odd types) ----

  if (token.len[6] != 64) return (PARSER_SALT_LENGTH);                              // nonce must be exactly 32 bytes (64 hex)
  if (token.len[7] < (int) sizeof (wpa_auth_packet_t) * 2) return (PARSER_SALT_LENGTH);  // EAPOL frame must hold at least a full header
  if (token.len[8] != 2) return (PARSER_SALT_LENGTH);                              // message-pair byte is one byte (2 hex)

  // The external <nonce> field; loaded word-wise so the in-memory byte order matches the nonce stream.
  const u8 *anonce_pos = token.buf[6];                    // hex of the 32-byte nonce
  for (int i = 0; i < 8; i++) wpa->anonce[i] = hex_to_u32 (anonce_pos + (i * 8));   // 8 words = 32 bytes

  // The EAPOL-Key frame, raw bytes (its MIC field was already zeroed by the emitter).
  const u8 *eapol_pos = token.buf[7];                     // hex of the frame
  u8 *eapol_ptr = (u8 *) wpa->eapol;                      // byte view of the eapol slot
  wpa->eapol_len = hex_decode (eapol_pos, token.len[7], eapol_ptr);                // decode frame, record length
  memset (eapol_ptr + wpa->eapol_len, 0, (1024 + 64) - wpa->eapol_len);           // zero the slack (whole 1088 B buffer) so the MAC sees clean padding

  wpa_auth_packet_t *auth_packet = (wpa_auth_packet_t *) wpa->eapol;               // overlay the header on the frame
  const u16 key_information = byte_swap_16 (auth_packet->key_information);          // wire field is big-endian
  wpa->keyver = key_information & 3; // legacy key-descriptor version; kept only for the uniqueness digest

  // The message-pair byte, decoded now because the FT-PTK build below needs its APLESS bit.
  const u8 message_pair = hex_to_u8 (token.buf[8]);       // one byte
  wpa->message_pair = message_pair;                       // stash in the esalt

  if (is_ft == 0)
  {
    u8 *pke_ptr = (u8 *) wpa->pke;                         // byte view of the PTK-input scratch
    memset (pke_ptr, 0, 128);                              // start clean

    if ((type == 1) || (type == 3))
    {
      // Legacy WPA1/WPA2 PRF input: the label "Pairwise key expansion" then a 0x00 separator,
      // then the two MACs (smaller first), then the two nonces (smaller first), then a 0x00 counter byte.
      memcpy (pke_ptr, "Pairwise key expansion\x00", 23); // label + single 0x00 separator

      // Sort the MACs so it does not matter which side each came from: smaller MAC first.
      if (memcmp (mac_ap, mac_sta, 6) < 0)
      {
        memcpy (pke_ptr + 23, mac_ap, 6);
        memcpy (pke_ptr + 29, mac_sta, 6);
      }
      else
      {
        memcpy (pke_ptr + 23, mac_sta, 6);
        memcpy (pke_ptr + 29, mac_ap, 6);
      }

      // Likewise sort the two nonces lexicographically; remember the ordering for diagnostics.
      wpa->nonce_compare = memcmp (wpa->anonce, auth_packet->wpa_key_nonce, 32);
      if (wpa->nonce_compare < 0)   // external nonce smaller
      {
        memcpy (pke_ptr + 35, wpa->anonce, 32);
        memcpy (pke_ptr + 67, auth_packet->wpa_key_nonce, 32);
      }
      else                          // frame nonce smaller
      {
        memcpy (pke_ptr + 35, auth_packet->wpa_key_nonce, 32);
        memcpy (pke_ptr + 67, wpa->anonce, 32);
      }
    }
    else
    {
      // SHA-256/384 KDF input: a 16-bit LE counter (1), the label "Pairwise key expansion",
      // the two MACs and two nonces (each smaller first), then the key length in BITS (16-bit LE).
      const u32 ptk_bits = (type == 5) ? 0x0180 : 0x02C0;  // 384 bits (16-byte KCK family) vs 704 bits (24-byte KCK SHA-384 PTK)

      pke_ptr[0] = 1; pke_ptr[1] = 0;                      // 16-bit LE block counter = 1
      memcpy (pke_ptr + 2, "Pairwise key expansion", 22);  // label (no 0x00 separator in the KDF form)

      if (memcmp (mac_ap, mac_sta, 6) < 0)   // smaller MAC first
      {
        memcpy (pke_ptr + 24, mac_ap, 6);
        memcpy (pke_ptr + 30, mac_sta, 6);
      }
      else
      {
        memcpy (pke_ptr + 24, mac_sta, 6);
        memcpy (pke_ptr + 30, mac_ap, 6);
      }

      wpa->nonce_compare = memcmp (wpa->anonce, auth_packet->wpa_key_nonce, 32);  // record nonce ordering
      if (wpa->nonce_compare < 0)   // smaller nonce first
      {
        memcpy (pke_ptr + 36, wpa->anonce, 32);
        memcpy (pke_ptr + 68, auth_packet->wpa_key_nonce, 32);
      }
      else
      {
        memcpy (pke_ptr + 36, auth_packet->wpa_key_nonce, 32);
        memcpy (pke_ptr + 68, wpa->anonce, 32);
      }

      pke_ptr[100] = (u8) (ptk_bits & 0xff);              // key length in bits, low byte (part of the hashed input)
      pke_ptr[101] = (u8) (ptk_bits >> 8);               // key length in bits, high byte
    }

    for (int i = 0; i < 32; i++) wpa->pke[i] = byte_swap_32 (wpa->pke[i]);  // swap each word to BE so the big-endian hash re-reads the original byte stream

    if (type == 5) eapol_ptr[wpa->eapol_len] = 0x80; // AES-128-CMAC pads a partial final block with a leading 0x80
  }
  else
  {
    // FT EAPOL (types 7 / 11): build the whole FT chain template (PMK-R0 -> PMK-R1 -> FT-PTK).
    const u32 r0_size  = (type == 7) ? 0x0180 : 0x0200;   // PMK-R0 length in bits per family (SHA-256 vs SHA-384)
    const u32 r1_size  = (type == 7) ? 0x0100 : 0x0180;   // PMK-R1 length in bits per family
    const u32 ptk_size = (type == 7) ? 0x0180 : 0x02C0;   // FT-PTK length in bits (384 vs 704)

    wpa_build_pke_r0 (wpa, mac_sta, 1, r0_size);   // counter = 1 yields the PMK-R0 block
    wpa_build_pke_r1 (wpa, mac_sta, r1_size);      // PMK-R1 template from PMK-R0

    // FT-PTK input: 16-bit LE counter (1), label "FT-PTK", then SNonce, ANonce (positional, NOT min/max),
    // then BSSID (AP MAC), STA MAC, and key length in bits. Which nonce is SNonce vs ANonce depends on
    // the APLESS bit (bit 4) of the message-pair byte: when set the <nonce> field holds the SNonce and
    // the frame body holds the ANonce, when clear it is the other way around.
    u8 *p = (u8 *) wpa->pke;                               // build in the PTK scratch
    memset (p, 0, 128);                                    // clean buffer
    p[0] = 1; p[1] = 0;                                    // 16-bit LE block counter = 1
    memcpy (p + 2, "FT-PTK", 6);                           // the FT-PTK label

    const u8 *ext_nonce  = (const u8 *) wpa->anonce;                  // the external <nonce> field
    const u8 *body_nonce = (const u8 *) auth_packet->wpa_key_nonce;   // the nonce inside the EAPOL frame
    const u8 *snonce    = (message_pair & 0x10) ? ext_nonce  : body_nonce;  // APLESS: <nonce> is SNonce
    const u8 *anonce_in = (message_pair & 0x10) ? body_nonce : ext_nonce;   // ...frame nonce is ANonce

    memcpy (p + 8,  snonce,    32);                        // SNonce comes first (positional, no sorting)
    memcpy (p + 40, anonce_in, 32);                        // then ANonce
    memcpy (p + 72, mac_ap,  6);                           // BSSID (AP MAC)
    memcpy (p + 78, mac_sta, 6);                           // station MAC
    p[84] = (u8) (ptk_size & 0xff);                        // key length in bits, low byte
    p[85] = (u8) (ptk_size >> 8);                          // key length in bits, high byte

    for (int i = 0; i < 32; i++)
    {
      wpa->pke[i]    = byte_swap_32 (wpa->pke[i]);          // swap the FT-PTK template to BE
      wpa->pke_r0[i] = byte_swap_32 (wpa->pke_r0[i]);       // ...the PMK-R0 template
      wpa->pke_r1[i] = byte_swap_32 (wpa->pke_r1[i]);       // ...the PMK-R1 template
    }

    if (type == 7) eapol_ptr[wpa->eapol_len] = 0x80; // AES-128-CMAC pads a partial final block with a leading 0x80
  }

  // Replay-counter endianness hints from the message-pair byte. Default: try both orders.
  wpa->detected_le = 1;                                   // assume little-endian possible
  wpa->detected_be = 1;                                   // assume big-endian possible
  if (message_pair & (1 << 5))   // bit 5: resolved as little-endian only
  {
    wpa->detected_le = 1;
    wpa->detected_be = 0;
  }
  else if (message_pair & (1 << 6))   // bit 6: resolved as big-endian only
  {
    wpa->detected_le = 0;
    wpa->detected_be = 1;
  }

  // The expected MIC, stored big-endian. SHA-family outputs compare directly; the kernel
  // byte-swaps MD5 / AES-CMAC outputs to BE before comparing.
  const u8 *mic_pos = token.buf[2];                       // hex of the expected MIC
  const int mic_words = (mic_hex == 48) ? 6 : 4;          // 24-byte SHA-384 MIC = 6 words, else 4
  for (int i = 0; i < mic_words; i++) wpa->keymic[i] = byte_swap_32 (hex_to_u32 (mic_pos + (i * 8)));  // decode + swap to BE

  // The 16-byte dedup/bloom digest for EAPOL rows is NOT the MIC: it is an MD5 hashing every
  // field (salt, PKE, EAPOL frame, MACs, nonces, MIC) so distinct handshakes are unique. The
  // real MIC compare happens in the kernel verifier against keymic[].
  u32 hash[4]; hash[0] = 0; hash[1] = 1; hash[2] = 2; hash[3] = 3;  // seed the running MD5 state
  u32 block[16];                                          // one 64-byte MD5 input block
  memset (block, 0, sizeof (block));                      // start zeroed
  u8 *block_ptr = (u8 *) block;                           // byte view for the nonce copies

  for (int i = 0; i < 16; i++) block[i] = salt->salt_buf[i];        // block 1: the ESSID/salt
  md5_transform (block + 0, block + 4, block + 8, block + 12, hash);
  for (int i = 0; i < 16; i++) block[i] = wpa->pke[i + 0];          // block 2: PKE first half
  md5_transform (block + 0, block + 4, block + 8, block + 12, hash);
  for (int i = 0; i < 16; i++) block[i] = wpa->pke[i + 16];         // block 3: PKE second half
  md5_transform (block + 0, block + 4, block + 8, block + 12, hash);
  for (int i = 0; i < 16; i++) block[i] = wpa->eapol[i + 0];        // block 4: EAPOL words 0..15
  md5_transform (block + 0, block + 4, block + 8, block + 12, hash);
  for (int i = 0; i < 16; i++) block[i] = wpa->eapol[i + 16];       // block 5: EAPOL words 16..31
  md5_transform (block + 0, block + 4, block + 8, block + 12, hash);
  for (int i = 0; i < 16; i++) block[i] = wpa->eapol[i + 32];       // block 6: EAPOL words 32..47
  md5_transform (block + 0, block + 4, block + 8, block + 12, hash);
  for (int i = 0; i < 16; i++) block[i] = wpa->eapol[i + 48];       // block 7: EAPOL words 48..63
  md5_transform (block + 0, block + 4, block + 8, block + 12, hash);
  for (int i = 0; i <  2; i++) block[0 + i] = wpa->mac_ap[i];       // block 8: AP MAC...
  for (int i = 0; i <  2; i++) block[2 + i] = wpa->mac_ap[i];       // ...AP MAC again (matches m22000 layout)
  for (int i = 0; i < 12; i++) block[4 + i] = 0;                    // ...rest zeroed
  md5_transform (block + 0, block + 4, block + 8, block + 12, hash);
  memcpy (block_ptr +  0, wpa->anonce, 32);                        // block 9: external nonce...
  memcpy (block_ptr + 32, auth_packet->wpa_key_nonce, 32);         // ...then the frame nonce
  md5_transform (block + 0, block + 4, block + 8, block + 12, hash);
  block[0] = wpa->keymic[0];                              // block 10: the expected MIC (first 16 bytes)
  block[1] = wpa->keymic[1];
  block[2] = wpa->keymic[2];
  block[3] = wpa->keymic[3];
  md5_transform (block + 0, block + 4, block + 8, block + 12, hash);

  digest[0] = hash[0];                                    // store the uniqueness hash as the digest
  digest[1] = hash[1];
  digest[2] = hash[2];
  digest[3] = hash[3];

  return (PARSER_OK);                                     // EAPOL row fully parsed
}

// --- encoder (round-trips the WPA*XX* line for the potfile / status display) ---

// Rebuilds the WPA* line from the esalt for the potfile / status display.
int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const wpa_universal_t *wpa = (const wpa_universal_t *) esalt_buf;   // the parsed esalt

  char essid_buf[128];                                   // ESSID re-encoded as hex
  const int essid_len = hex_encode ((const u8 *) wpa->essid_buf, wpa->essid_len, (u8 *) essid_buf);  // bytes -> hex
  essid_buf[essid_len] = 0;                              // NUL-terminate for %s

  const u8 *mac_ap  = (const u8 *) wpa->mac_ap;          // byte view of AP MAC
  const u8 *mac_sta = (const u8 *) wpa->mac_sta;         // byte view of STA MAC

  const bool is_pmkid = ((wpa->type % 2) == 0);          // even types emit a PMKID, odd a MIC

  char hashhex[128];                                     // the <hash> field as hex
  int hl = 0;                                            // current length written
  if (is_pmkid)
  {
    // Re-swap the big-endian-stored PMKID words back to the original byte order for display.
    u32_to_hex (byte_swap_32 (wpa->pmkid[0]), (u8 *) hashhex + hl); hl += 8;
    u32_to_hex (byte_swap_32 (wpa->pmkid[1]), (u8 *) hashhex + hl); hl += 8;
    u32_to_hex (byte_swap_32 (wpa->pmkid[2]), (u8 *) hashhex + hl); hl += 8;
    u32_to_hex (byte_swap_32 (wpa->pmkid[3]), (u8 *) hashhex + hl); hl += 8;
  }
  else
  {
    const int mic_words = ((wpa->type == 9) || (wpa->type == 11)) ? 6 : 4;  // 24-byte SHA-384 MIC vs 16-byte
    for (int i = 0; i < mic_words; i++) { u32_to_hex (byte_swap_32 (wpa->keymic[i]), (u8 *) hashhex + hl); hl += 8; }  // re-swap each MIC word to display order
  }
  hashhex[hl] = 0;                                       // NUL-terminate

  // Print the type as 2-digit DECIMAL (%02d) so 10/11 stay decimal, then hash, both MACs, and ESSID hex.
  int line_len = snprintf (line_buf, line_size, "WPA*%02d*%s*%02x%02x%02x%02x%02x%02x*%02x%02x%02x%02x%02x%02x*%s",
    wpa->type, hashhex,
    mac_ap[0], mac_ap[1], mac_ap[2], mac_ap[3], mac_ap[4], mac_ap[5],
    mac_sta[0], mac_sta[1], mac_sta[2], mac_sta[3], mac_sta[4], mac_sta[5],
    essid_buf);

  return line_len;                                       // bytes written into line_buf
}

// --- decode-postprocess: nonce-error-correction count from the message-pair byte ---

// Applies message-pair / nonce-correction overrides after decode, setting the NC sweep count.
int module_hash_decode_postprocess (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  wpa_universal_t *wpa = (wpa_universal_t *) esalt_buf;   // the esalt to adjust

  wpa->message_pair_chgd            = user_options->hccapx_message_pair_chgd;       // did the user force a message pair?
  wpa->nonce_error_corrections_chgd = user_options->nonce_error_corrections_chgd;   // did the user force an NC count?

  if (wpa->message_pair_chgd == true)
  {
    // If forced, this row's low 7 bits of the message-pair byte must match the requested pair.
    if (user_options->hccapx_message_pair != (wpa->message_pair & 0x7f)) return (PARSER_HCCAPX_MESSAGE_PAIR);
  }

  if (wpa->nonce_error_corrections_chgd == true)
  {
    wpa->nonce_error_corrections = user_options->nonce_error_corrections;  // honour the user-supplied count
  }
  else
  {
    wpa->nonce_error_corrections = NONCE_ERROR_CORRECTIONS;   // default +/- nonce sweep width

    if (wpa->message_pair & (1 << 4))
    {
      wpa->nonce_error_corrections = 0; // bit 4 (AP-less / M3-anchored): no replay-counter window to walk
    }
    else if ((wpa->message_pair & (1 << 7)) == 0)
    {
      wpa->nonce_error_corrections = 0; // bit 7 clear: nonce was exact, no correction needed
    }
  }

  return (PARSER_OK);
}

// Self-test: re-parse the canned WPA_ST_HASH line and report whether it decodes cleanly.
int module_hash_init_selftest (MAYBE_UNUSED const hashconfig_t *hashconfig, hash_t *hash)
{
  const int parser_status = module_hash_decode (hashconfig, hash->digest, hash->salt, hash->esalt, hash->hook_salt, hash->hash_info, hashconfig->st_hash, strlen (hashconfig->st_hash));  // run the decoder on the self-test line

  return parser_status;                                  // PARSER_OK on success
}

// --- shared module_ctx wiring (each module_NNNNN.c adds OPTS_TYPE + deep_comp) ---

// Registers every shared function pointer / flag on the module_ctx. MODULE_DEFAULT means
// "feature not used" so hashcat falls back to its built-in behaviour for that hook.
#define WPA_MODULE_CTX_COMMON(module_ctx)                                                  \
  do {                                                                                     \
    (module_ctx)->module_context_size            = MODULE_CONTEXT_SIZE_CURRENT;            /* size of this struct, ABI guard */ \
    (module_ctx)->module_interface_version       = MODULE_INTERFACE_VERSION_CURRENT;       /* module API version */ \
    (module_ctx)->module_attack_exec             = module_attack_exec;                     /* slow-hash outside-kernel model */ \
    (module_ctx)->module_benchmark_esalt         = MODULE_DEFAULT;                          /* no custom benchmark esalt */ \
    (module_ctx)->module_benchmark_hook_salt     = MODULE_DEFAULT;                          /* no custom benchmark hook salt */ \
    (module_ctx)->module_benchmark_mask          = module_benchmark_mask;                  /* 8-char benchmark mask */ \
    (module_ctx)->module_benchmark_charset       = MODULE_DEFAULT;                          /* default benchmark charset */ \
    (module_ctx)->module_benchmark_salt          = MODULE_DEFAULT;                          /* default benchmark salt */ \
    (module_ctx)->module_bridge_name             = MODULE_DEFAULT;                          /* no host bridge */ \
    (module_ctx)->module_bridge_type             = MODULE_DEFAULT;                          /* no host bridge */ \
    (module_ctx)->module_build_plain_postprocess = MODULE_DEFAULT;                          /* no plaintext postprocessing */ \
    (module_ctx)->module_deep_comp_kernel        = MODULE_DEFAULT;                          /* per-module file sets the per-digest aux dispatch */ \
    (module_ctx)->module_deprecated_notice       = MODULE_DEFAULT;                          /* not deprecated */ \
    (module_ctx)->module_dgst_pos0               = module_dgst_pos0;                        /* compare-word positions */ \
    (module_ctx)->module_dgst_pos1               = module_dgst_pos1;                        \
    (module_ctx)->module_dgst_pos2               = module_dgst_pos2;                        \
    (module_ctx)->module_dgst_pos3               = module_dgst_pos3;                        \
    (module_ctx)->module_dgst_size               = module_dgst_size;                        /* 16-byte digest */ \
    (module_ctx)->module_dictstat_disable        = MODULE_DEFAULT;                          /* keep dictionary stats */ \
    (module_ctx)->module_esalt_size              = module_esalt_size;                       /* per-digest esalt size */ \
    (module_ctx)->module_extra_buffer_size       = MODULE_DEFAULT;                          /* no extra device buffer */ \
    (module_ctx)->module_extra_tmp_size          = MODULE_DEFAULT;                          /* no extra tmp size */ \
    (module_ctx)->module_extra_tuningdb_block    = MODULE_DEFAULT;                          /* no extra tuning entries */ \
    (module_ctx)->module_forced_outfile_format   = MODULE_DEFAULT;                          /* default outfile format */ \
    (module_ctx)->module_hash_binary_count       = MODULE_DEFAULT;                          /* no binary hash input */ \
    (module_ctx)->module_hash_binary_parse       = MODULE_DEFAULT;                          \
    (module_ctx)->module_hash_binary_save        = MODULE_DEFAULT;                          \
    (module_ctx)->module_hash_decode_postprocess = module_hash_decode_postprocess;         /* NC / message-pair overrides */ \
    (module_ctx)->module_hash_decode_potfile     = MODULE_DEFAULT;                          /* potfile uses the normal decoder */ \
    (module_ctx)->module_hash_decode_zero_hash   = MODULE_DEFAULT;                          /* no zero-hash special case */ \
    (module_ctx)->module_hash_decode             = module_hash_decode;                      /* line -> salt+esalt+digest */ \
    (module_ctx)->module_hash_encode_status      = MODULE_DEFAULT;                          /* status line uses the normal encoder */ \
    (module_ctx)->module_hash_encode_potfile     = MODULE_DEFAULT;                          /* potfile uses the normal encoder */ \
    (module_ctx)->module_hash_encode             = module_hash_encode;                      /* esalt -> WPA* line */ \
    (module_ctx)->module_hash_init_selftest      = module_hash_init_selftest;               /* self-test decode */ \
    (module_ctx)->module_hash_mode               = MODULE_DEFAULT;                          /* single hash mode */ \
    (module_ctx)->module_hash_category           = module_hash_category;                    /* network-protocol category */ \
    (module_ctx)->module_hash_name               = module_hash_name;                        /* per-module display name */ \
    (module_ctx)->module_hashes_count_min        = MODULE_DEFAULT;                          /* no min hash count */ \
    (module_ctx)->module_hashes_count_max        = MODULE_DEFAULT;                          /* no max hash count */ \
    (module_ctx)->module_hlfmt_disable           = module_hlfmt_disable;                    /* reject legacy hashfile formats */ \
    (module_ctx)->module_hook_extra_param_size   = MODULE_DEFAULT;                          /* no hook extra params */ \
    (module_ctx)->module_hook_extra_param_init   = MODULE_DEFAULT;                          \
    (module_ctx)->module_hook_extra_param_term   = MODULE_DEFAULT;                          \
    (module_ctx)->module_hook12                  = MODULE_DEFAULT;                          /* no _init/_loop hook */ \
    (module_ctx)->module_hook23                  = MODULE_DEFAULT;                          /* HOOK23 plugins override this */ \
    (module_ctx)->module_hook_salt_size          = MODULE_DEFAULT;                          /* HOOK23 plugins override this */ \
    (module_ctx)->module_hook_size               = MODULE_DEFAULT;                          /* HOOK23 plugins override this */ \
    (module_ctx)->module_jit_build_options       = MODULE_DEFAULT;                          /* no extra JIT options */ \
    (module_ctx)->module_jit_cache_disable       = MODULE_DEFAULT;                          /* allow JIT cache */ \
    (module_ctx)->module_kernel_accel_max        = MODULE_DEFAULT;                          /* autotune accel */ \
    (module_ctx)->module_kernel_accel_min        = MODULE_DEFAULT;                          \
    (module_ctx)->module_kernel_loops_max        = MODULE_DEFAULT;                          /* autotune loops */ \
    (module_ctx)->module_kernel_loops_min        = MODULE_DEFAULT;                          \
    (module_ctx)->module_kernel_threads_max      = MODULE_DEFAULT;                          /* autotune threads */ \
    (module_ctx)->module_kernel_threads_min      = MODULE_DEFAULT;                          \
    (module_ctx)->module_kern_type               = module_kern_type;                        /* per-module mode number */ \
    (module_ctx)->module_kern_type_dynamic       = MODULE_DEFAULT;                          /* fixed mode, not dynamic */ \
    (module_ctx)->module_opti_type               = module_opti_type;                        /* optimizer hints */ \
    (module_ctx)->module_opts_type               = module_opts_type;                        /* per-module OPTS_TYPE / aux wiring */ \
    (module_ctx)->module_outfile_check_disable   = MODULE_DEFAULT;                          /* allow outfile checking */ \
    (module_ctx)->module_outfile_check_nocomp    = MODULE_DEFAULT;                          \
    (module_ctx)->module_potfile_custom_check    = MODULE_DEFAULT;                          /* standard potfile matching */ \
    (module_ctx)->module_potfile_disable         = MODULE_DEFAULT;                          /* keep potfile */ \
    (module_ctx)->module_potfile_keep_all_hashes = MODULE_DEFAULT;                          \
    (module_ctx)->module_pwdump_column           = MODULE_DEFAULT;                          /* no pwdump column */ \
    (module_ctx)->module_pw_max                  = module_pw_max;                           /* max passphrase length 63 */ \
    (module_ctx)->module_pw_min                  = module_pw_min;                           /* min passphrase length 8 */ \
    (module_ctx)->module_salt_max                = MODULE_DEFAULT;                          /* no extra salt-length cap */ \
    (module_ctx)->module_salt_min                = MODULE_DEFAULT;                          \
    (module_ctx)->module_salt_type               = module_salt_type;                        /* embedded salt */ \
    (module_ctx)->module_separator               = MODULE_DEFAULT;                          /* default field separator */ \
    (module_ctx)->module_st_hash                 = module_st_hash;                          /* self-test hash */ \
    (module_ctx)->module_st_pass                 = module_st_pass;                          /* self-test passphrase */ \
    (module_ctx)->module_tmp_size                = module_tmp_size;                         /* PBKDF2 tmps size */ \
    (module_ctx)->module_unstable_warning        = MODULE_DEFAULT;                          /* no instability warning */ \
    (module_ctx)->module_warmup_disable          = MODULE_DEFAULT;                          /* allow warmup */ \
  } while (0)

#endif // INC_WPA_PSK_UNIVERSAL_MODULE_H
