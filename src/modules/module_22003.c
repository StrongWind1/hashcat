/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 *
 * WPA-PMK Universal mode (22003): verifies a raw 32-byte PMK (given as 64 hex
 * characters) against all eleven WPA-PSK AKM/handshake types, skipping the
 * PBKDF2 derivation that mode 22002 performs. Same hash format, same kernel
 * verification code, same aux-kernel dispatch.
 */

#include "common.h"
#include "types.h"
#include "modules.h"
#include "bitops.h"
#include "convert.h"
#include "shared.h"
#include "parser.h"
#include "emu_general.h"
#include "emu_inc_hash_md5.h"

static const u32   WPA_ATTACK_EXEC   = ATTACK_EXEC_OUTSIDE_KERNEL;
static const u32   WPA_DGST_POS0     = 0;
static const u32   WPA_DGST_POS1     = 1;
static const u32   WPA_DGST_POS2     = 2;
static const u32   WPA_DGST_POS3     = 3;
static const u32   WPA_DGST_SIZE     = DGST_SIZE_4_4;
static const u32   WPA_HASH_CATEGORY = HASH_CATEGORY_NETWORK_PROTOCOL;
static const u32   WPA_SALT_TYPE     = SALT_TYPE_EMBEDDED;
static const char *WPA_ST_PASS       = "88f43854ae7b1624fc2ab7724859e795130f4843c7535729e819cf92f39535dc";
static const char *WPA_ST_HASH       = "WPA*02*4d4fe7aac3a2cecab195321ceb99a7d0*fc690c158264*f4747f87f9f4*686173686361742d6573736964***01";

static const u32 ROUNDS_WPA_PMK = 0;

#ifndef INC_WPA_PSK_UNIVERSAL_CL

typedef struct wpa_pmk_tmp
{
  u32 out[8];

} wpa_pmk_tmp_t;

typedef struct wpa_universal
{
  u32  essid_buf[16];
  u32  essid_len;

  u32  mac_ap[2];
  u32  mac_sta[2];

  u32  type;

  u32  pmkid[4];
  u32  pmkid_data[32];

  u32  keymic[6];
  u32  anonce[8];
  u32  eapol[256 + 16];
  u32  eapol_len;
  u32  pke[32];

  u32  keyver;

  u32  mdid[1];
  u32  r0khid[12]; u32 r0khid_len;
  u32  r1khid[12]; u32 r1khid_len;
  u32  pke_r0[32];
  u32  pke_r1[32];

  int  message_pair_chgd;   u32 message_pair;
  int  nonce_error_corrections_chgd;  int nonce_error_corrections;
  int  nonce_compare;  int detected_le;  int detected_be;

} wpa_universal_t;

#endif

#pragma pack(push,1)
struct wpa_auth_packet
{
  u8  version;
  u8  type;
  u16 length;
  u8  key_descriptor;
  u16 key_information;
  u16 key_length;
  u64 replay_counter;
  u8  wpa_key_nonce[32];
  u8  wpa_key_iv[16];
  u8  wpa_key_rsc[8];
  u8  wpa_key_id[8];
  u8  wpa_key_mic[16];
  u16 wpa_key_data_length;
} __attribute__((packed));
typedef struct wpa_auth_packet wpa_auth_packet_t;
#pragma pack(pop)

static bool wpa_type_is_ft (const u32 type)
{
  return (type == 6) || (type == 7) || (type == 10) || (type == 11);
}

static void wpa_build_pke_r0 (wpa_universal_t *wpa, const u8 *mac_sta, const u8 counter, const u32 size_bits)
{
  u8 *p = (u8 *) wpa->pke_r0;
  memset (p, 0, 128);

  p[0] = counter;
  p[1] = 0;
  memcpy (p + 2, "FT-R0", 5);
  p[7] = (u8) wpa->essid_len;
  memcpy (p + 8, wpa->essid_buf, wpa->essid_len);
  memcpy (p + 8 + wpa->essid_len, wpa->mdid, 2);
  p[10 + wpa->essid_len] = (u8) wpa->r0khid_len;
  memcpy (p + 11 + wpa->essid_len, wpa->r0khid, wpa->r0khid_len);
  memcpy (p + 11 + wpa->essid_len + wpa->r0khid_len, mac_sta, 6);
  p[17 + wpa->essid_len + wpa->r0khid_len] = (u8) (size_bits & 0xff);
  p[18 + wpa->essid_len + wpa->r0khid_len] = (u8) (size_bits >> 8);
}

static void wpa_build_pke_r1 (wpa_universal_t *wpa, const u8 *mac_sta, const u32 size_bits)
{
  u8 *p = (u8 *) wpa->pke_r1;
  memset (p, 0, 128);

  p[0] = 1;
  p[1] = 0;
  memcpy (p + 2, "FT-R1", 5);
  memcpy (p + 7, wpa->r1khid, wpa->r1khid_len);
  memcpy (p + 7 + wpa->r1khid_len, mac_sta, 6);
  p[13 + wpa->r1khid_len] = (u8) (size_bits & 0xff);
  p[14 + wpa->r1khid_len] = (u8) (size_bits >> 8);
}

u32 module_attack_exec (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return WPA_ATTACK_EXEC; }
u32 module_dgst_pos0 (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return WPA_DGST_POS0; }
u32 module_dgst_pos1 (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return WPA_DGST_POS1; }
u32 module_dgst_pos2 (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return WPA_DGST_POS2; }
u32 module_dgst_pos3 (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return WPA_DGST_POS3; }
u32 module_dgst_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return WPA_DGST_SIZE; }
u32 module_hash_category (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return WPA_HASH_CATEGORY; }
u32 module_salt_type (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return WPA_SALT_TYPE; }
const char *module_st_hash (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return WPA_ST_HASH; }
const char *module_st_pass (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return WPA_ST_PASS; }
u32 module_pw_min (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return 64; }
u32 module_pw_max (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return 64; }

u32 module_opti_type (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return OPTI_TYPE_ZERO_BYTE; }

u64 module_tmp_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return (u64) sizeof (wpa_pmk_tmp_t); }
u64 module_esalt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return (u64) sizeof (wpa_universal_t); }

bool module_hlfmt_disable (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return true; }

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;
  wpa_universal_t *wpa = (wpa_universal_t *) esalt_buf;
  if (line_len < 7) return (PARSER_SALT_LENGTH);
  if ((line_buf[0] != 'W') || (line_buf[1] != 'P') || (line_buf[2] != 'A') || (line_buf[3] != '*')) return (PARSER_SIGNATURE_UNMATCHED);

  const char t_hi = line_buf[4];
  const char t_lo = line_buf[5];
  if ((t_hi < '0') || (t_hi > '9') || (t_lo < '0') || (t_lo > '9')) return (PARSER_SALT_VALUE);
  const u8 type = (u8) (((t_hi - '0') * 10) + (t_lo - '0'));
  if ((type < 1) || (type > 11)) return (PARSER_SALT_VALUE);
  const bool is_ft = wpa_type_is_ft (type);
  const int  mic_hex = ((type == 9) || (type == 11)) ? 48 : 32;

  hc_token_t token;
  memset (&token, 0, sizeof (hc_token_t));

  token.token_cnt = is_ft ? 12 : 9;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = "WPA";

  token.sep[0]  = '*'; token.len[0] = 3;       token.attr[0] = TOKEN_ATTR_FIXED_LENGTH | TOKEN_ATTR_VERIFY_SIGNATURE;
  token.sep[1]  = '*'; token.len[1] = 2;       token.attr[1] = TOKEN_ATTR_FIXED_LENGTH | TOKEN_ATTR_VERIFY_HEX;
  token.sep[2]  = '*'; token.len[2] = mic_hex; token.attr[2] = TOKEN_ATTR_FIXED_LENGTH | TOKEN_ATTR_VERIFY_HEX;
  token.sep[3]  = '*'; token.len[3] = 12;      token.attr[3] = TOKEN_ATTR_FIXED_LENGTH | TOKEN_ATTR_VERIFY_HEX;
  token.sep[4]  = '*'; token.len[4] = 12;      token.attr[4] = TOKEN_ATTR_FIXED_LENGTH | TOKEN_ATTR_VERIFY_HEX;

  token.sep[5]  = '*'; token.len_min[5] = 0;  token.len_max[5] = 64;   token.attr[5] = TOKEN_ATTR_VERIFY_LENGTH | TOKEN_ATTR_VERIFY_HEX;
  token.sep[6]  = '*'; token.len_min[6] = 0;  token.len_max[6] = 64;   token.attr[6] = TOKEN_ATTR_VERIFY_LENGTH | TOKEN_ATTR_VERIFY_HEX;
  token.sep[7]  = '*'; token.len_min[7] = 0;  token.len_max[7] = 2048; token.attr[7] = TOKEN_ATTR_VERIFY_LENGTH | TOKEN_ATTR_VERIFY_HEX;
  token.sep[8]  = '*'; token.len_min[8] = 0;  token.len_max[8] = 2;    token.attr[8] = TOKEN_ATTR_VERIFY_LENGTH | TOKEN_ATTR_VERIFY_HEX;

  if (is_ft)
  {
    token.sep[9]  = '*'; token.len_min[9]  = 0;  token.len_max[9]  = 4;   token.attr[9]  = TOKEN_ATTR_VERIFY_LENGTH | TOKEN_ATTR_VERIFY_HEX;
    token.sep[10] = '*'; token.len_min[10] = 2;  token.len_max[10] = 96;  token.attr[10] = TOKEN_ATTR_VERIFY_LENGTH | TOKEN_ATTR_VERIFY_HEX;
    token.sep[11] = '*'; token.len_min[11] = 12; token.len_max[11] = 12;  token.attr[11] = TOKEN_ATTR_VERIFY_LENGTH | TOKEN_ATTR_VERIFY_HEX;
  }

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);
  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  wpa->type = type;

  u8 *mac_ap  = (u8 *) wpa->mac_ap;
  u8 *mac_sta = (u8 *) wpa->mac_sta;

  const u8 *macap_buf = token.buf[3];
  for (int i = 0; i < 6; i++) mac_ap[i] = hex_to_u8 (macap_buf + (i * 2));

  const u8 *macsta_buf = token.buf[4];
  for (int i = 0; i < 6; i++) mac_sta[i] = hex_to_u8 (macsta_buf + (i * 2));

  const u8 *essid_buf = token.buf[5];
  const int essid_len = token.len[5];
  if (essid_len & 1) return (PARSER_SALT_VALUE);

  wpa->essid_len = hex_decode (essid_buf, essid_len, (u8 *) wpa->essid_buf);

  memcpy (salt->salt_buf, wpa->essid_buf, wpa->essid_len);
  salt->salt_len  = wpa->essid_len;
  salt->salt_iter = ROUNDS_WPA_PMK;

  if (is_ft)
  {
    const u8 *mdid_pos = token.buf[9];
    u8 *mdid_ptr = (u8 *) wpa->mdid;
    mdid_ptr[0] = hex_to_u8 (mdid_pos + 0);
    mdid_ptr[1] = hex_to_u8 (mdid_pos + 2);

    wpa->r0khid_len = hex_decode (token.buf[10], token.len[10], (u8 *) wpa->r0khid);
    wpa->r1khid_len = hex_decode (token.buf[11], token.len[11], (u8 *) wpa->r1khid);
  }

  const bool is_pmkid = ((type % 2) == 0);

  if (is_pmkid)
  {
    const u8 *pmkid_buf = token.buf[2];
    wpa->pmkid[0] = byte_swap_32 (hex_to_u32 (pmkid_buf +  0));
    wpa->pmkid[1] = byte_swap_32 (hex_to_u32 (pmkid_buf +  8));
    wpa->pmkid[2] = byte_swap_32 (hex_to_u32 (pmkid_buf + 16));
    wpa->pmkid[3] = byte_swap_32 (hex_to_u32 (pmkid_buf + 24));

    digest[0] = wpa->pmkid[0];
    digest[1] = wpa->pmkid[1];
    digest[2] = wpa->pmkid[2];
    digest[3] = wpa->pmkid[3];

    if (is_ft == 0)
    {
      wpa->pmkid_data[0] = 0x204b4d50;
      wpa->pmkid_data[1] = 0x656d614e;
      wpa->pmkid_data[2] = (mac_ap[0]  <<  0) | (mac_ap[1]  <<  8) | (mac_ap[2]  << 16) | (mac_ap[3]  << 24);
      wpa->pmkid_data[3] = (mac_ap[4]  <<  0) | (mac_ap[5]  <<  8) | (mac_sta[0] << 16) | (mac_sta[1] << 24);
      wpa->pmkid_data[4] = (mac_sta[2] <<  0) | (mac_sta[3] <<  8) | (mac_sta[4] << 16) | (mac_sta[5] << 24);
    }
    else
    {
      const u32 r0_size = (type == 6) ? 0x0180 : 0x0200;
      wpa_build_pke_r0 (wpa, mac_sta, 2, r0_size);

      u8 *p = (u8 *) wpa->pmkid_data;
      memset (p, 0, 128);
      memcpy (p, "FT-R1N", 6);
      memcpy (p + 6 + 16, wpa->r1khid, wpa->r1khid_len);
      memcpy (p + 6 + 16 + wpa->r1khid_len, mac_sta, 6);

      for (int i = 0; i < 32; i++)
      {
        wpa->pke_r0[i]     = byte_swap_32 (wpa->pke_r0[i]);
        wpa->pmkid_data[i] = byte_swap_32 (wpa->pmkid_data[i]);
      }
    }

    if (token.len[8] >= 2) wpa->message_pair = hex_to_u8 (token.buf[8]);

    return (PARSER_OK);
  }

  // ---- EAPOL rows (odd types) ----

  if (token.len[6] != 64) return (PARSER_SALT_LENGTH);
  if (token.len[7] < (int) sizeof (wpa_auth_packet_t) * 2) return (PARSER_SALT_LENGTH);
  if (token.len[8] != 2) return (PARSER_SALT_LENGTH);

  const u8 *anonce_pos = token.buf[6];
  for (int i = 0; i < 8; i++) wpa->anonce[i] = hex_to_u32 (anonce_pos + (i * 8));

  const u8 *eapol_pos = token.buf[7];
  u8 *eapol_ptr = (u8 *) wpa->eapol;
  wpa->eapol_len = hex_decode (eapol_pos, token.len[7], eapol_ptr);
  memset (eapol_ptr + wpa->eapol_len, 0, (1024 + 64) - wpa->eapol_len);

  wpa_auth_packet_t *auth_packet = (wpa_auth_packet_t *) wpa->eapol;
  const u16 key_information = byte_swap_16 (auth_packet->key_information);
  wpa->keyver = key_information & 3;

  const u8 message_pair = hex_to_u8 (token.buf[8]);
  wpa->message_pair = message_pair;

  if (is_ft == 0)
  {
    u8 *pke_ptr = (u8 *) wpa->pke;
    memset (pke_ptr, 0, 128);

    if ((type == 1) || (type == 3))
    {
      memcpy (pke_ptr, "Pairwise key expansion\x00", 23);

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

      wpa->nonce_compare = memcmp (wpa->anonce, auth_packet->wpa_key_nonce, 32);
      if (wpa->nonce_compare < 0)
      {
        memcpy (pke_ptr + 35, wpa->anonce, 32);
        memcpy (pke_ptr + 67, auth_packet->wpa_key_nonce, 32);
      }
      else
      {
        memcpy (pke_ptr + 35, auth_packet->wpa_key_nonce, 32);
        memcpy (pke_ptr + 67, wpa->anonce, 32);
      }
    }
    else
    {
      const u32 ptk_bits = (type == 5) ? 0x0180 : 0x02C0;

      pke_ptr[0] = 1; pke_ptr[1] = 0;
      memcpy (pke_ptr + 2, "Pairwise key expansion", 22);

      if (memcmp (mac_ap, mac_sta, 6) < 0)
      {
        memcpy (pke_ptr + 24, mac_ap, 6);
        memcpy (pke_ptr + 30, mac_sta, 6);
      }
      else
      {
        memcpy (pke_ptr + 24, mac_sta, 6);
        memcpy (pke_ptr + 30, mac_ap, 6);
      }

      wpa->nonce_compare = memcmp (wpa->anonce, auth_packet->wpa_key_nonce, 32);
      if (wpa->nonce_compare < 0)
      {
        memcpy (pke_ptr + 36, wpa->anonce, 32);
        memcpy (pke_ptr + 68, auth_packet->wpa_key_nonce, 32);
      }
      else
      {
        memcpy (pke_ptr + 36, auth_packet->wpa_key_nonce, 32);
        memcpy (pke_ptr + 68, wpa->anonce, 32);
      }

      pke_ptr[100] = (u8) (ptk_bits & 0xff);
      pke_ptr[101] = (u8) (ptk_bits >> 8);
    }

    for (int i = 0; i < 32; i++) wpa->pke[i] = byte_swap_32 (wpa->pke[i]);

    if (type == 5) eapol_ptr[wpa->eapol_len] = 0x80;
  }
  else
  {
    const u32 r0_size  = (type == 7) ? 0x0180 : 0x0200;
    const u32 r1_size  = (type == 7) ? 0x0100 : 0x0180;
    const u32 ptk_size = (type == 7) ? 0x0180 : 0x02C0;

    wpa_build_pke_r0 (wpa, mac_sta, 1, r0_size);
    wpa_build_pke_r1 (wpa, mac_sta, r1_size);

    u8 *p = (u8 *) wpa->pke;
    memset (p, 0, 128);
    p[0] = 1; p[1] = 0;
    memcpy (p + 2, "FT-PTK", 6);

    const u8 *ext_nonce  = (const u8 *) wpa->anonce;
    const u8 *body_nonce = (const u8 *) auth_packet->wpa_key_nonce;
    const u8 *snonce    = (message_pair & 0x10) ? ext_nonce  : body_nonce;
    const u8 *anonce_in = (message_pair & 0x10) ? body_nonce : ext_nonce;

    memcpy (p + 8,  snonce,    32);
    memcpy (p + 40, anonce_in, 32);
    memcpy (p + 72, mac_ap,  6);
    memcpy (p + 78, mac_sta, 6);
    p[84] = (u8) (ptk_size & 0xff);
    p[85] = (u8) (ptk_size >> 8);

    for (int i = 0; i < 32; i++)
    {
      wpa->pke[i]    = byte_swap_32 (wpa->pke[i]);
      wpa->pke_r0[i] = byte_swap_32 (wpa->pke_r0[i]);
      wpa->pke_r1[i] = byte_swap_32 (wpa->pke_r1[i]);
    }

    if (type == 7) eapol_ptr[wpa->eapol_len] = 0x80;
  }

  wpa->detected_le = 1;
  wpa->detected_be = 1;
  if (message_pair & (1 << 5))
  {
    wpa->detected_le = 1;
    wpa->detected_be = 0;
  }
  else if (message_pair & (1 << 6))
  {
    wpa->detected_le = 0;
    wpa->detected_be = 1;
  }

  const u8 *mic_pos = token.buf[2];
  const int mic_words = (mic_hex == 48) ? 6 : 4;
  for (int i = 0; i < mic_words; i++) wpa->keymic[i] = byte_swap_32 (hex_to_u32 (mic_pos + (i * 8)));

  u32 hash[4]; hash[0] = 0; hash[1] = 1; hash[2] = 2; hash[3] = 3;
  u32 block[16];
  memset (block, 0, sizeof (block));
  u8 *block_ptr = (u8 *) block;

  for (int i = 0; i < 16; i++) block[i] = salt->salt_buf[i];
  md5_transform (block + 0, block + 4, block + 8, block + 12, hash);
  for (int i = 0; i < 16; i++) block[i] = wpa->pke[i + 0];
  md5_transform (block + 0, block + 4, block + 8, block + 12, hash);
  for (int i = 0; i < 16; i++) block[i] = wpa->pke[i + 16];
  md5_transform (block + 0, block + 4, block + 8, block + 12, hash);
  for (int i = 0; i < 16; i++) block[i] = wpa->eapol[i + 0];
  md5_transform (block + 0, block + 4, block + 8, block + 12, hash);
  for (int i = 0; i < 16; i++) block[i] = wpa->eapol[i + 16];
  md5_transform (block + 0, block + 4, block + 8, block + 12, hash);
  for (int i = 0; i < 16; i++) block[i] = wpa->eapol[i + 32];
  md5_transform (block + 0, block + 4, block + 8, block + 12, hash);
  for (int i = 0; i < 16; i++) block[i] = wpa->eapol[i + 48];
  md5_transform (block + 0, block + 4, block + 8, block + 12, hash);
  for (int i = 0; i <  2; i++) block[0 + i] = wpa->mac_ap[i];
  for (int i = 0; i <  2; i++) block[2 + i] = wpa->mac_sta[i];
  for (int i = 0; i < 12; i++) block[4 + i] = 0;
  md5_transform (block + 0, block + 4, block + 8, block + 12, hash);
  memcpy (block_ptr +  0, wpa->anonce, 32);
  memcpy (block_ptr + 32, auth_packet->wpa_key_nonce, 32);
  md5_transform (block + 0, block + 4, block + 8, block + 12, hash);
  block[0] = wpa->keymic[0];
  block[1] = wpa->keymic[1];
  block[2] = wpa->keymic[2];
  block[3] = wpa->keymic[3];
  md5_transform (block + 0, block + 4, block + 8, block + 12, hash);

  digest[0] = hash[0];
  digest[1] = hash[1];
  digest[2] = hash[2];
  digest[3] = hash[3];

  return (PARSER_OK);
}

int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const wpa_universal_t *wpa = (const wpa_universal_t *) esalt_buf;

  const u8 *mac_ap  = (const u8 *) wpa->mac_ap;
  const u8 *mac_sta = (const u8 *) wpa->mac_sta;

  char essid_hex[128 + 1];
  const int essid_hex_len = hex_encode ((const u8 *) wpa->essid_buf, wpa->essid_len, (u8 *) essid_hex);
  essid_hex[essid_hex_len] = 0;

  const bool is_pmkid = ((wpa->type % 2) == 0);

  int line_len = 0;

  if (is_pmkid)
  {
    u8 pmkid_hex[32 + 1];
    for (int i = 0; i < 4; i++) u32_to_hex (byte_swap_32 (wpa->pmkid[i]), pmkid_hex + (i * 8));
    pmkid_hex[32] = 0;

    line_len = snprintf (line_buf, line_size,
      "WPA*%02u*%s"
      "*%02x%02x%02x%02x%02x%02x"
      "*%02x%02x%02x%02x%02x%02x"
      "*%s***%02x",
      wpa->type, pmkid_hex,
      mac_ap[0],  mac_ap[1],  mac_ap[2],  mac_ap[3],  mac_ap[4],  mac_ap[5],
      mac_sta[0], mac_sta[1], mac_sta[2], mac_sta[3], mac_sta[4], mac_sta[5],
      essid_hex,
      wpa->message_pair);
  }
  else
  {
    const int mic_words = ((wpa->type == 9) || (wpa->type == 11)) ? 6 : 4;

    u8 mic_hex[48 + 1];
    for (int i = 0; i < mic_words; i++) u32_to_hex (byte_swap_32 (wpa->keymic[i]), mic_hex + (i * 8));
    mic_hex[mic_words * 8] = 0;

    u8 anonce_hex[64 + 1];
    for (int i = 0; i < 8; i++) u32_to_hex (wpa->anonce[i], anonce_hex + (i * 8));
    anonce_hex[64] = 0;

    char eapol_hex[2048 + 1];
    const int eapol_hex_len = hex_encode ((const u8 *) wpa->eapol, wpa->eapol_len, (u8 *) eapol_hex);
    eapol_hex[eapol_hex_len] = 0;

    line_len = snprintf (line_buf, line_size,
      "WPA*%02u*%s"
      "*%02x%02x%02x%02x%02x%02x"
      "*%02x%02x%02x%02x%02x%02x"
      "*%s*%s*%s*%02x",
      wpa->type, (const char *) mic_hex,
      mac_ap[0],  mac_ap[1],  mac_ap[2],  mac_ap[3],  mac_ap[4],  mac_ap[5],
      mac_sta[0], mac_sta[1], mac_sta[2], mac_sta[3], mac_sta[4], mac_sta[5],
      essid_hex, (const char *) anonce_hex, eapol_hex,
      wpa->message_pair);
  }

  if (wpa_type_is_ft (wpa->type))
  {
    const u8 *mdid = (const u8 *) wpa->mdid;

    char r0kh_hex[96 + 1];
    const int r0kh_hex_len = hex_encode ((const u8 *) wpa->r0khid, wpa->r0khid_len, (u8 *) r0kh_hex);
    r0kh_hex[r0kh_hex_len] = 0;

    char r1kh_hex[12 + 1];
    const int r1kh_hex_len = hex_encode ((const u8 *) wpa->r1khid, wpa->r1khid_len, (u8 *) r1kh_hex);
    r1kh_hex[r1kh_hex_len] = 0;

    line_len += snprintf (line_buf + line_len, line_size - line_len,
      "*%02x%02x*%s*%s",
      mdid[0], mdid[1], r0kh_hex, r1kh_hex);
  }

  return line_len;
}

int module_hash_decode_postprocess (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  wpa_universal_t *wpa = (wpa_universal_t *) esalt_buf;

  wpa->message_pair_chgd            = user_options->hccapx_message_pair_chgd;
  wpa->nonce_error_corrections_chgd = user_options->nonce_error_corrections_chgd;

  if (wpa->message_pair_chgd == true)
  {
    if (user_options->hccapx_message_pair != (wpa->message_pair & 0x7f)) return (PARSER_HCCAPX_MESSAGE_PAIR);
  }

  if (wpa->nonce_error_corrections_chgd == true)
  {
    wpa->nonce_error_corrections = user_options->nonce_error_corrections;
  }
  else
  {
    wpa->nonce_error_corrections = NONCE_ERROR_CORRECTIONS;

    if (wpa->message_pair & (1 << 4))
    {
      wpa->nonce_error_corrections = 0;
    }
    else if ((wpa->message_pair & (1 << 7)) == 0)
    {
      wpa->nonce_error_corrections = 0;
    }
  }

  return (PARSER_OK);
}

u32 module_hash_hints (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const salt_t *salt, const void *esalt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, hlfmt_word_t *out_words, const u32 out_max, char *scratch, const u32 scratch_size)
{
  if (esalt_buf == NULL) return 0;

  const wpa_universal_t *wpa = (const wpa_universal_t *) esalt_buf;

  u32 cnt = 0;
  u32 at  = 0;

  const u8 *essid = (const u8 *) wpa->essid_buf;

  bool printable = (wpa->essid_len > 0);

  for (u32 i = 0; i < wpa->essid_len; i++)
  {
    if ((essid[i] >= 0x20) && (essid[i] != 0x7f)) continue;

    printable = false;

    break;
  }

  if ((printable == true) && (cnt < out_max) && ((at + wpa->essid_len) < scratch_size))
  {
    memcpy (scratch + at, essid, wpa->essid_len);

    out_words[cnt].buf = scratch + at;
    out_words[cnt].len = wpa->essid_len;

    cnt++;
    at += wpa->essid_len;
  }

  const u8 *macs[2] = { (const u8 *) wpa->mac_ap, (const u8 *) wpa->mac_sta };

  for (u32 m = 0; m < 2; m++)
  {
    if (cnt == out_max) break;

    if ((at + 12) >= scratch_size) break;

    for (u32 i = 0; i < 6; i++)
    {
      static const char hex[] = "0123456789abcdef";

      scratch[at + (i * 2) + 0] = hex[macs[m][i] >> 4];
      scratch[at + (i * 2) + 1] = hex[macs[m][i] & 15];
    }

    out_words[cnt].buf = scratch + at;
    out_words[cnt].len = 12;

    cnt++;
    at += 12;
  }

  return cnt;
}

int module_hash_init_selftest (MAYBE_UNUSED const hashconfig_t *hashconfig, hash_t *hash)
{
  const int parser_status = module_hash_decode (hashconfig, hash->digest, hash->salt, hash->esalt, hash->hook_salt, hash->hash_info, hashconfig->st_hash, strlen (hashconfig->st_hash));

  return parser_status;
}

static const char *HASH_NAME = "WPA-PMK-PMKID-EAPOL (WPA-PMK Universal)";
static const u64   KERN_TYPE = 22003;
static const u64   OPTS_TYPE = OPTS_TYPE_STOCK_MODULE
                             | OPTS_TYPE_PT_GENERATE_LE
                             | OPTS_TYPE_PT_ALWAYS_ASCII
                             | OPTS_TYPE_AUX1
                             | OPTS_TYPE_AUX2
                             | OPTS_TYPE_AUX3
                             | OPTS_TYPE_AUX4
                             | OPTS_TYPE_AUX5
                             | OPTS_TYPE_DEEP_COMP_KERNEL
                             | OPTS_TYPE_COPY_TMPS
                             | OPTS_TYPE_POTFILE_NOPASS
                             | OPTS_TYPE_AUTODETECT_DISABLE;

const char *module_hash_name (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return HASH_NAME; }
u64         module_kern_type (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return KERN_TYPE; }
u64         module_opts_type (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return OPTS_TYPE; }

u32 module_deep_comp_kernel (MAYBE_UNUSED const hashes_t *hashes, MAYBE_UNUSED const u32 salt_pos, MAYBE_UNUSED const u32 digest_pos)
{
  const u32 digests_offset = hashes->salts_buf[salt_pos].digests_offset;
  const wpa_universal_t *wpa = &((const wpa_universal_t *) hashes->esalts_buf)[digests_offset + digest_pos];

  switch (wpa->type)
  {
    case  1: return KERN_RUN_AUX1;
    case  2: return KERN_RUN_AUX4;
    case  3: return KERN_RUN_AUX2;
    case  4: return KERN_RUN_AUX4;
    case  5: return KERN_RUN_AUX3;
    case  6: return KERN_RUN_AUX4;
    case  7: return KERN_RUN_AUX3;
    case  8: return KERN_RUN_AUX4;
    case  9: return KERN_RUN_AUX5;
    case 10: return KERN_RUN_AUX4;
    case 11: return KERN_RUN_AUX5;
  }

  return 0;
}

char *module_jit_build_options (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra, MAYBE_UNUSED const hashes_t *hashes, MAYBE_UNUSED const hc_device_param_t *device_param)
{
  char *jit_build_options = NULL;

  u32 types_seen = (1u << 2);

  for (u32 salt_idx = 0; salt_idx < hashes->salts_cnt; salt_idx++)
  {
    const u32 digests_offset = hashes->salts_buf[salt_idx].digests_offset;
    const u32 digests_cnt    = hashes->salts_buf[salt_idx].digests_cnt;

    for (u32 digest_idx = 0; digest_idx < digests_cnt; digest_idx++)
    {
      const wpa_universal_t *wpa = &((const wpa_universal_t *) hashes->esalts_buf)[digests_offset + digest_idx];

      if (wpa->type >= 1 && wpa->type <= 11) types_seen |= (1u << wpa->type);
    }
  }

  char buf[512];
  int pos = 0;

  for (int t = 1; t <= 11; t++)
  {
    if (types_seen & (1u << t))
      pos += snprintf (buf + pos, sizeof(buf) - pos, "-DENABLE_TYPE_%d ", t);
  }

  if (pos > 0) hc_asprintf (&jit_build_options, "%s", buf);

  return jit_build_options;
}

void module_init (module_ctx_t *module_ctx)
{
  module_ctx->module_context_size             = MODULE_CONTEXT_SIZE_CURRENT;
  module_ctx->module_interface_version        = MODULE_INTERFACE_VERSION_CURRENT;

  module_ctx->module_advice_notice            = MODULE_DEFAULT;
  module_ctx->module_attack_exec              = module_attack_exec;
  module_ctx->module_benchmark_esalt          = MODULE_DEFAULT;
  module_ctx->module_benchmark_hook_salt      = MODULE_DEFAULT;
  module_ctx->module_benchmark_mask           = MODULE_DEFAULT;
  module_ctx->module_benchmark_charset        = MODULE_DEFAULT;
  module_ctx->module_benchmark_salt           = MODULE_DEFAULT;
  module_ctx->module_bridge_name              = MODULE_DEFAULT;
  module_ctx->module_bridge_type              = MODULE_DEFAULT;
  module_ctx->module_build_plain_postprocess  = MODULE_DEFAULT;
  module_ctx->module_deep_comp_kernel         = module_deep_comp_kernel;
  module_ctx->module_deprecated_notice        = MODULE_DEFAULT;
  module_ctx->module_dgst_pos0                = module_dgst_pos0;
  module_ctx->module_dgst_pos1                = module_dgst_pos1;
  module_ctx->module_dgst_pos2                = module_dgst_pos2;
  module_ctx->module_dgst_pos3                = module_dgst_pos3;
  module_ctx->module_dgst_size                = module_dgst_size;
  module_ctx->module_esalt_size               = module_esalt_size;
  module_ctx->module_extra_buffer_size        = MODULE_DEFAULT;
  module_ctx->module_extra_tmp_size           = MODULE_DEFAULT;
  module_ctx->module_extra_tuningdb_block     = MODULE_DEFAULT;
  module_ctx->module_forced_outfile_format    = MODULE_DEFAULT;
  module_ctx->module_hash_binary_count        = MODULE_DEFAULT;
  module_ctx->module_hash_binary_parse        = MODULE_DEFAULT;
  module_ctx->module_hash_binary_save         = MODULE_DEFAULT;
  module_ctx->module_hash_decode_postprocess  = module_hash_decode_postprocess;
  module_ctx->module_hash_decode_potfile      = MODULE_DEFAULT;
  module_ctx->module_hash_decode_zero_hash    = MODULE_DEFAULT;
  module_ctx->module_hash_decode              = module_hash_decode;
  module_ctx->module_hash_encode_status       = MODULE_DEFAULT;
  module_ctx->module_hash_encode_potfile      = MODULE_DEFAULT;
  module_ctx->module_hash_encode              = module_hash_encode;
  module_ctx->module_hash_hints               = module_hash_hints;
  module_ctx->module_hash_init_selftest       = module_hash_init_selftest;
  module_ctx->module_hash_mode                = MODULE_DEFAULT;
  module_ctx->module_hash_category            = module_hash_category;
  module_ctx->module_hash_name                = module_hash_name;
  module_ctx->module_hashes_count_min         = MODULE_DEFAULT;
  module_ctx->module_hashes_count_max         = MODULE_DEFAULT;
  module_ctx->module_hlfmt_disable            = module_hlfmt_disable;
  module_ctx->module_hook_extra_param_size    = MODULE_DEFAULT;
  module_ctx->module_hook_extra_param_init    = MODULE_DEFAULT;
  module_ctx->module_hook_extra_param_term    = MODULE_DEFAULT;
  module_ctx->module_hook12                   = MODULE_DEFAULT;
  module_ctx->module_hook23                   = MODULE_DEFAULT;
  module_ctx->module_hook_salt_size           = MODULE_DEFAULT;
  module_ctx->module_hook_size                = MODULE_DEFAULT;
  module_ctx->module_jit_build_options        = module_jit_build_options;
  module_ctx->module_jit_cache_disable        = MODULE_DEFAULT;
  module_ctx->module_kernel_accel_max         = MODULE_DEFAULT;
  module_ctx->module_kernel_accel_min         = MODULE_DEFAULT;
  module_ctx->module_kernel_loops_max         = MODULE_DEFAULT;
  module_ctx->module_kernel_loops_min         = MODULE_DEFAULT;
  module_ctx->module_kernel_threads_max       = MODULE_DEFAULT;
  module_ctx->module_kernel_threads_min       = MODULE_DEFAULT;
  module_ctx->module_kern_type                = module_kern_type;
  module_ctx->module_kern_type_dynamic        = MODULE_DEFAULT;
  module_ctx->module_opti_type                = module_opti_type;
  module_ctx->module_opts_type                = module_opts_type;
  module_ctx->module_outfile_check_disable    = MODULE_DEFAULT;
  module_ctx->module_outfile_check_nocomp     = MODULE_DEFAULT;
  module_ctx->module_potfile_custom_check     = MODULE_DEFAULT;
  module_ctx->module_potfile_disable          = MODULE_DEFAULT;
  module_ctx->module_potfile_keep_all_hashes  = MODULE_DEFAULT;
  module_ctx->module_pwdump_column            = MODULE_DEFAULT;
  module_ctx->module_pw_max                   = module_pw_max;
  module_ctx->module_pw_min                   = module_pw_min;
  module_ctx->module_salt_max                 = MODULE_DEFAULT;
  module_ctx->module_salt_min                 = MODULE_DEFAULT;
  module_ctx->module_salt_type                = module_salt_type;
  module_ctx->module_separator                = MODULE_DEFAULT;
  module_ctx->module_st_hash                  = module_st_hash;
  module_ctx->module_st_pass                  = module_st_pass;
  module_ctx->module_tmp_size                 = module_tmp_size;
  module_ctx->module_unstable_warning         = MODULE_DEFAULT;
  module_ctx->module_usage_notice             = MODULE_DEFAULT;
  module_ctx->module_warmup_disable           = MODULE_DEFAULT;
}
