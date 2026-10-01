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

#define DGST_ELEM 4

#include "emu_general.h"
#include "emu_inc_cipher_aes.h"
#include "emu_inc_hash_md5.h"
#include "m22000-pure.cl"

static const u32   ATTACK_EXEC    = ATTACK_EXEC_OUTSIDE_KERNEL;
static const u32   DGST_POS0      = 0;
static const u32   DGST_POS1      = 1;
static const u32   DGST_POS2      = 2;
static const u32   DGST_POS3      = 3;
static const u32   DGST_SIZE      = DGST_SIZE_4_4;
static const u32   HASH_CATEGORY  = HASH_CATEGORY_NETWORK_PROTOCOL;
static const char *HASH_NAME      = "WPA-PBKDF2-PMKID+EAPOL";
static const u64   KERN_TYPE      = 22000;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE
                                  | OPTI_TYPE_SLOW_HASH_SIMD_LOOP;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE
                                  | OPTS_TYPE_AUX1
                                  | OPTS_TYPE_AUX2
                                  | OPTS_TYPE_AUX3
                                  | OPTS_TYPE_AUX4
                                  | OPTS_TYPE_DEEP_COMP_KERNEL
                                  | OPTS_TYPE_HASH_COPY
                                  | OPTS_TYPE_COPY_TMPS;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "hashcat!";
static const char *ST_HASH        = "WPA*01*4d4fe7aac3a2cecab195321ceb99a7d0*fc690c158264*f4747f87f9f4*686173686361742d6573736964***";

u32         module_attack_exec    (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return ATTACK_EXEC;     }
u32         module_dgst_pos0      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return DGST_POS0;       }
u32         module_dgst_pos1      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return DGST_POS1;       }
u32         module_dgst_pos2      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return DGST_POS2;       }
u32         module_dgst_pos3      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return DGST_POS3;       }
u32         module_dgst_size      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return DGST_SIZE;       }
u32         module_hash_category  (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return HASH_CATEGORY;   }
const char *module_hash_name      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return HASH_NAME;       }
u64         module_kern_type      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return KERN_TYPE;       }
u32         module_opti_type      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return OPTI_TYPE;       }
u64         module_opts_type      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return OPTS_TYPE;       }
u32         module_salt_type      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return SALT_TYPE;       }
const char *module_st_hash        (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return ST_HASH;         }
const char *module_st_pass        (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return ST_PASS;         }

static const u32 ROUNDS_WPA_PBKDF2 = 4096;

#pragma pack(push,1)

struct auth_packet
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

#pragma pack(pop)

typedef struct auth_packet auth_packet_t;

static bool wpa_type_is_ft (const u32 type)
{
  return (type == 5) || (type == 6);
}

static void wpa_build_pke_r0 (wpa_t *wpa, const u8 *mac_sta, const u8 counter, const u32 size_bits)
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

static void wpa_build_pke_r1 (wpa_t *wpa, const u8 *mac_sta, const u32 size_bits)
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

const char *module_benchmark_mask (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const char *mask = "?a?a?a?a?a?a?a?a";

  return mask;
}

u64 module_tmp_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 tmp_size = (const u64) sizeof (wpa_pbkdf2_tmp_t);

  return tmp_size;
}

u64 module_esalt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 esalt_size = (const u64) sizeof (wpa_t);

  return esalt_size;
}

int module_hash_init_selftest (MAYBE_UNUSED const hashconfig_t *hashconfig, hash_t *hash)
{
  const int parser_status = module_hash_decode (hashconfig, hash->digest, hash->salt, hash->esalt, hash->hook_salt, hash->hash_info, hashconfig->st_hash, strlen (hashconfig->st_hash));

  wpa_t *wpa = (wpa_t *) hash->esalt;

  wpa->detected_le = 1;
  wpa->detected_be = 0;

  wpa->nonce_error_corrections = 3;

  return parser_status;
}

bool module_hlfmt_disable (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const bool hlfmt_disable = true;

  return hlfmt_disable;
}

u32 module_pw_min (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u32 pw_min = 8;

  return pw_min;
}

u32 module_pw_max (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u32 pw_max = 63;

  return pw_max;
}

u32 module_hash_hints (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const salt_t *salt, const void *esalt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, hlfmt_word_t *out_words, const u32 out_max, char *scratch, const u32 scratch_size)
{
  if (esalt_buf == NULL) return 0;

  const wpa_t *wpa = (const wpa_t *) esalt_buf;

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

int module_hash_decode_potfile (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len, MAYBE_UNUSED void *tmps)
{
  wpa_t *wpa = (wpa_t *) esalt_buf;

  wpa_pbkdf2_tmp_t *wpa_pbkdf2_tmp = (wpa_pbkdf2_tmp_t *) tmps;

  if (line_len < 64) return (PARSER_HASH_LENGTH);

  wpa_pbkdf2_tmp->out[0] = hex_to_u32 ((const u8 *) line_buf +  0);
  wpa_pbkdf2_tmp->out[1] = hex_to_u32 ((const u8 *) line_buf +  8);
  wpa_pbkdf2_tmp->out[2] = hex_to_u32 ((const u8 *) line_buf + 16);
  wpa_pbkdf2_tmp->out[3] = hex_to_u32 ((const u8 *) line_buf + 24);
  wpa_pbkdf2_tmp->out[4] = hex_to_u32 ((const u8 *) line_buf + 32);
  wpa_pbkdf2_tmp->out[5] = hex_to_u32 ((const u8 *) line_buf + 40);
  wpa_pbkdf2_tmp->out[6] = hex_to_u32 ((const u8 *) line_buf + 48);
  wpa_pbkdf2_tmp->out[7] = hex_to_u32 ((const u8 *) line_buf + 56);

  const char *sep_pos = strrchr (line_buf, '*');

  if (sep_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  if ((line_buf + 64) != sep_pos) return (PARSER_HASH_LENGTH);

  const char *essid_pos = sep_pos + 1;

  const int essid_len = strlen (essid_pos);

  if (essid_len & 1) return (PARSER_SALT_VALUE);

  if (essid_len > 64) return (PARSER_SALT_VALUE);

  wpa->essid_len = hex_decode ((const u8 *) essid_pos, essid_len, (u8 *) wpa->essid_buf);

  return PARSER_OK;
}

int module_hash_encode_potfile (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size, MAYBE_UNUSED const void *tmps)
{
  const wpa_t *wpa = (const wpa_t *) esalt_buf;

  const wpa_pbkdf2_tmp_t *wpa_pbkdf2_tmp = (const wpa_pbkdf2_tmp_t *) tmps;

  char tmp_buf[128];

  const int tmp_len = hex_encode ((const u8 *) wpa->essid_buf, wpa->essid_len, (u8 *) tmp_buf);

  tmp_buf[tmp_len] = 0;

  const int line_len = snprintf (line_buf, line_size, "%08x%08x%08x%08x%08x%08x%08x%08x*%s",
    wpa_pbkdf2_tmp->out[0],
    wpa_pbkdf2_tmp->out[1],
    wpa_pbkdf2_tmp->out[2],
    wpa_pbkdf2_tmp->out[3],
    wpa_pbkdf2_tmp->out[4],
    wpa_pbkdf2_tmp->out[5],
    wpa_pbkdf2_tmp->out[6],
    wpa_pbkdf2_tmp->out[7],
    tmp_buf);

  return line_len;
}

int module_hash_binary_save (MAYBE_UNUSED const hashes_t *hashes, MAYBE_UNUSED const u32 salt_pos, MAYBE_UNUSED const u32 digest_pos, char **buf)
{
  const salt_t *salts_buf   = hashes->salts_buf;
  const void   *esalts_buf  = hashes->esalts_buf;

  const salt_t *salt = &salts_buf[salt_pos];

  const u32 digest_cur = salt->digests_offset + digest_pos;

  const wpa_t *wpas = (const wpa_t *) esalts_buf;
  const wpa_t *wpa  = &wpas[digest_cur];

  const u8 *mac_ap  = (const u8 *) wpa->mac_ap;
  const u8 *mac_sta = (const u8 *) wpa->mac_sta;

  char essid_hex[128 + 1];

  const int essid_hex_len = hex_encode ((const u8 *) wpa->essid_buf, wpa->essid_len, (u8 *) essid_hex);

  essid_hex[essid_hex_len] = 0;

  // PMKID types: 01, 03, 05

  if ((wpa->type == 1) || (wpa->type == 3) || (wpa->type == 5))
  {
    u8 pmkid_hex[32 + 1];

    for (int i = 0; i < 4; i++)
    {
      u32_to_hex (byte_swap_32 (wpa->pmkid[i]), pmkid_hex + (i * 8));
    }

    pmkid_hex[32] = 0;

    int len = 0;

    if (wpa_type_is_ft (wpa->type) == true)
    {
      const u8 *mdid = (const u8 *) wpa->mdid;

      char r0kh_hex[96 + 1];

      const int r0kh_hex_len = hex_encode ((const u8 *) wpa->r0khid, wpa->r0khid_len, (u8 *) r0kh_hex);

      r0kh_hex[r0kh_hex_len] = 0;

      char r1kh_hex[12 + 1];

      const int r1kh_hex_len = hex_encode ((const u8 *) wpa->r1khid, wpa->r1khid_len, (u8 *) r1kh_hex);

      r1kh_hex[r1kh_hex_len] = 0;

      len = hc_asprintf (buf, "WPA*%02x*%s*%02x%02x%02x%02x%02x%02x*%02x%02x%02x%02x%02x%02x*%s****%02x%02x*%s*%s" EOL,
        wpa->type, (const char *) pmkid_hex,
        mac_ap[0],  mac_ap[1],  mac_ap[2],  mac_ap[3],  mac_ap[4],  mac_ap[5],
        mac_sta[0], mac_sta[1], mac_sta[2], mac_sta[3], mac_sta[4], mac_sta[5],
        essid_hex,
        mdid[0], mdid[1], r0kh_hex, r1kh_hex);
    }
    else
    {
      len = hc_asprintf (buf, "WPA*%02x*%s*%02x%02x%02x%02x%02x%02x*%02x%02x%02x%02x%02x%02x*%s***" EOL,
        wpa->type, (const char *) pmkid_hex,
        mac_ap[0],  mac_ap[1],  mac_ap[2],  mac_ap[3],  mac_ap[4],  mac_ap[5],
        mac_sta[0], mac_sta[1], mac_sta[2], mac_sta[3], mac_sta[4], mac_sta[5],
        essid_hex);
    }

    return len;
  }

  // EAPOL types: 02, 04, 06

  if ((wpa->type == 2) || (wpa->type == 4) || (wpa->type == 6))
  {
    u32 eapol_swapped[256 + 16 + 2];

    for (u32 i = 0; i < (wpa->eapol_len / 4) + 1; i++)
    {
      eapol_swapped[i] = wpa->eapol[i];

      if (wpa->type == 2 && wpa->keyver == 2)
      {
        eapol_swapped[i] = byte_swap_32 (eapol_swapped[i]);
      }
    }

    char eapol_hex[2048 + 1];

    const int eapol_hex_len = hex_encode ((const u8 *) eapol_swapped, wpa->eapol_len, (u8 *) eapol_hex);

    eapol_hex[eapol_hex_len] = 0;

    int len = 0;

    if (wpa_type_is_ft (wpa->type) == true)
    {
      const u8 *mdid = (const u8 *) wpa->mdid;

      char r0kh_hex[96 + 1];

      const int r0kh_hex_len = hex_encode ((const u8 *) wpa->r0khid, wpa->r0khid_len, (u8 *) r0kh_hex);

      r0kh_hex[r0kh_hex_len] = 0;

      char r1kh_hex[12 + 1];

      const int r1kh_hex_len = hex_encode ((const u8 *) wpa->r1khid, wpa->r1khid_len, (u8 *) r1kh_hex);

      r1kh_hex[r1kh_hex_len] = 0;

      len = hc_asprintf (buf, "WPA*%02x*%08x%08x%08x%08x*%02x%02x%02x%02x%02x%02x*%02x%02x%02x%02x%02x%02x*%s*%08x%08x%08x%08x%08x%08x%08x%08x*%s*%02x*%02x%02x*%s*%s" EOL,
        wpa->type,
        wpa->keymic[0], wpa->keymic[1], wpa->keymic[2], wpa->keymic[3],
        mac_ap[0],  mac_ap[1],  mac_ap[2],  mac_ap[3],  mac_ap[4],  mac_ap[5],
        mac_sta[0], mac_sta[1], mac_sta[2], mac_sta[3], mac_sta[4], mac_sta[5],
        essid_hex,
        byte_swap_32 (wpa->anonce[0]), byte_swap_32 (wpa->anonce[1]),
        byte_swap_32 (wpa->anonce[2]), byte_swap_32 (wpa->anonce[3]),
        byte_swap_32 (wpa->anonce[4]), byte_swap_32 (wpa->anonce[5]),
        byte_swap_32 (wpa->anonce[6]), byte_swap_32 (wpa->anonce[7]),
        eapol_hex,
        wpa->message_pair,
        mdid[0], mdid[1], r0kh_hex, r1kh_hex);
    }
    else
    {
      len = hc_asprintf (buf, "WPA*%02x*%08x%08x%08x%08x*%02x%02x%02x%02x%02x%02x*%02x%02x%02x%02x%02x%02x*%s*%08x%08x%08x%08x%08x%08x%08x%08x*%s*%02x" EOL,
        wpa->type,
        wpa->keymic[0], wpa->keymic[1], wpa->keymic[2], wpa->keymic[3],
        mac_ap[0],  mac_ap[1],  mac_ap[2],  mac_ap[3],  mac_ap[4],  mac_ap[5],
        mac_sta[0], mac_sta[1], mac_sta[2], mac_sta[3], mac_sta[4], mac_sta[5],
        essid_hex,
        byte_swap_32 (wpa->anonce[0]), byte_swap_32 (wpa->anonce[1]),
        byte_swap_32 (wpa->anonce[2]), byte_swap_32 (wpa->anonce[3]),
        byte_swap_32 (wpa->anonce[4]), byte_swap_32 (wpa->anonce[5]),
        byte_swap_32 (wpa->anonce[6]), byte_swap_32 (wpa->anonce[7]),
        eapol_hex,
        wpa->message_pair);
    }

    return len;
  }

  return 0;
}

u32 module_deep_comp_kernel (MAYBE_UNUSED const hashes_t *hashes, MAYBE_UNUSED const u32 salt_pos, MAYBE_UNUSED const u32 digest_pos)
{
  const u32 digests_offset = hashes->salts_buf[salt_pos].digests_offset;

  const wpa_t *wpas = (const wpa_t *) hashes->esalts_buf;
  const wpa_t *wpa  = &wpas[digests_offset + digest_pos];

  switch (wpa->type)
  {
    case 1: return KERN_RUN_AUX4;
    case 2:
      if (wpa->keyver == 1) return KERN_RUN_AUX1;
      if (wpa->keyver == 2) return KERN_RUN_AUX2;
      if (wpa->keyver == 3) return KERN_RUN_AUX3;
      break;
    case 3: return KERN_RUN_AUX4;
    case 4: return KERN_RUN_AUX3;
    case 5: return KERN_RUN_AUX4;
    case 6: return KERN_RUN_AUX3;
  }

  return 0;
}

bool module_potfile_custom_check (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const hash_t *db, MAYBE_UNUSED const hash_t *entry_hash, MAYBE_UNUSED const void *entry_tmps)
{
  const wpa_t *wpa_entry = (const wpa_t *) entry_hash->esalt;
  const wpa_t *wpa_db    = (const wpa_t *) db->esalt;

  if (wpa_db->essid_len != wpa_entry->essid_len) return false;

  if (strcmp ((const char *) wpa_db->essid_buf, (const char *) wpa_entry->essid_buf)) return false;

  const wpa_pbkdf2_tmp_t *wpa_pbkdf2_tmp = (const wpa_pbkdf2_tmp_t *) entry_tmps;

  wpa_pbkdf2_tmp_t tmps;

  tmps.out[0] = byte_swap_32 (wpa_pbkdf2_tmp->out[0]);
  tmps.out[1] = byte_swap_32 (wpa_pbkdf2_tmp->out[1]);
  tmps.out[2] = byte_swap_32 (wpa_pbkdf2_tmp->out[2]);
  tmps.out[3] = byte_swap_32 (wpa_pbkdf2_tmp->out[3]);
  tmps.out[4] = byte_swap_32 (wpa_pbkdf2_tmp->out[4]);
  tmps.out[5] = byte_swap_32 (wpa_pbkdf2_tmp->out[5]);
  tmps.out[6] = byte_swap_32 (wpa_pbkdf2_tmp->out[6]);
  tmps.out[7] = byte_swap_32 (wpa_pbkdf2_tmp->out[7]);

  plain_t plains_buf;

  u32 hashes_shown = 0;

  u32 d_return_buf = 0;

  void (*m22000_aux) (KERN_ATTR_TMPS_ESALT (wpa_pbkdf2_tmp_t, wpa_t));

  if (wpa_db->type == 1)
  {
    m22000_aux = m22000_aux4;
  }
  else if (wpa_db->type == 2)
  {
    if (wpa_db->keyver == 1)
    {
      m22000_aux = m22000_aux1;
    }
    else if (wpa_db->keyver == 2)
    {
      m22000_aux = m22000_aux2;
    }
    else if (wpa_db->keyver == 3)
    {
      m22000_aux = m22000_aux3;
    }
    else
    {
      return false;
    }
  }
  else if (wpa_db->type == 3)
  {
    m22000_aux = m22000_aux4;
  }
  else if (wpa_db->type == 4)
  {
    m22000_aux = m22000_aux3;
  }
  else if (wpa_db->type == 5)
  {
    m22000_aux = m22000_aux4;
  }
  else if (wpa_db->type == 6)
  {
    m22000_aux = m22000_aux3;
  }
  else
  {
    return false;
  }

  kernel_param_t kernel_param;

  kernel_param.bitmap_mask         = 0;
  kernel_param.salt_pos_host       = 0;
  kernel_param.loop_pos            = 0;
  kernel_param.loop_cnt            = 0;
  kernel_param.il_cnt              = 0;
  kernel_param.digests_cnt         = 1;
  kernel_param.digests_offset_host = 0;
  kernel_param.combs_mode          = 0;
  kernel_param.salt_repeat         = 0;
  kernel_param.pws_pos             = 0;
  kernel_param.gid_max             = 1;

  m22000_aux
  (
    NULL,               // pws
    NULL,               // rules_buf
    NULL,               // combs_buf
    NULL,               // bfs_buf
    &tmps,              // tmps
    NULL,               // hooks
    NULL,               // bitmaps_buf_s1_a
    NULL,               // bitmaps_buf_s1_b
    NULL,               // bitmaps_buf_s1_c
    NULL,               // bitmaps_buf_s1_d
    NULL,               // bitmaps_buf_s2_a
    NULL,               // bitmaps_buf_s2_b
    NULL,               // bitmaps_buf_s2_c
    NULL,               // bitmaps_buf_s2_d
    &plains_buf,        // plains_buf
    db->digest,         // digests_buf
    &hashes_shown,      // hashes_shown
    db->salt,           // salt_bufs
    db->esalt,          // esalt_bufs
    &d_return_buf,      // d_return_buf
    NULL,               // d_extra0_buf
    NULL,               // d_extra1_buf
    NULL,               // d_extra2_buf
    NULL,               // d_extra3_buf
    &kernel_param       // kernel_param
  );

  const bool r = (d_return_buf == 0) ? false : true;

  return r;
}

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  wpa_t *wpa = (wpa_t *) esalt_buf;

  const char *input_buf = line_buf;
  int   input_len = line_len;

  // determine type from the WPA*TT* prefix

  const bool is_ft = (input_len >= 7)
                  && (input_buf[0] == 'W') && (input_buf[1] == 'P') && (input_buf[2] == 'A') && (input_buf[3] == '*')
                  && (((input_buf[4] == '0') && (input_buf[5] == '5')) || ((input_buf[4] == '0') && (input_buf[5] == '6')));

  // main tokenizer

  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  token.token_cnt  = is_ft ? 12 : 9;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = "WPA";

  token.sep[0]     = '*';
  token.len[0]     = 3;
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.sep[1]     = '*';
  token.len[1]     = 2;
  token.attr[1]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.sep[2]     = '*';
  token.len[2]     = 32;
  token.attr[2]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.sep[3]     = '*';
  token.len[3]     = 12;
  token.attr[3]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.sep[4]     = '*';
  token.len[4]     = 12;
  token.attr[4]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.sep[5]     = '*';
  token.len_min[5] = 0;
  token.len_max[5] = 64;
  token.attr[5]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.sep[6]     = '*';
  token.len_min[6] = 0;
  token.len_max[6] = 64;
  token.attr[6]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.sep[7]     = '*';
  token.len_min[7] = 0;
  token.len_max[7] = 2048;
  token.attr[7]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.sep[8]     = '*';
  token.len_min[8] = 0;
  token.len_max[8] = 2;
  token.attr[8]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  if (is_ft == true)
  {
    token.sep[9]      = '*';
    token.len_min[9]  = 0;
    token.len_max[9]  = 4;
    token.attr[9]     = TOKEN_ATTR_VERIFY_LENGTH
                      | TOKEN_ATTR_VERIFY_HEX;

    token.sep[10]     = '*';
    token.len_min[10] = 2;
    token.len_max[10] = 96;
    token.attr[10]    = TOKEN_ATTR_VERIFY_LENGTH
                      | TOKEN_ATTR_VERIFY_HEX;

    token.sep[11]     = '*';
    token.len_min[11] = 12;
    token.len_max[11] = 12;
    token.attr[11]    = TOKEN_ATTR_VERIFY_LENGTH
                      | TOKEN_ATTR_VERIFY_HEX;
  }

  const int rc_tokenizer = input_tokenizer ((const u8 *) input_buf, input_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  // type

  const u8 *type_buf = token.buf[1];

  const u8 type = hex_to_u8 (type_buf);

  if ((type < 1) || (type > 6)) return (PARSER_SALT_VALUE);

  wpa->type = type;

  // mac_ap

  u8 *mac_ap  = (u8 *) wpa->mac_ap;
  u8 *mac_sta = (u8 *) wpa->mac_sta;

  const u8 *macap_buf = token.buf[3];

  mac_ap[0] = hex_to_u8 (macap_buf +  0);
  mac_ap[1] = hex_to_u8 (macap_buf +  2);
  mac_ap[2] = hex_to_u8 (macap_buf +  4);
  mac_ap[3] = hex_to_u8 (macap_buf +  6);
  mac_ap[4] = hex_to_u8 (macap_buf +  8);
  mac_ap[5] = hex_to_u8 (macap_buf + 10);

  // mac_sta

  const u8 *macsta_buf = token.buf[4];

  mac_sta[0] = hex_to_u8 (macsta_buf +  0);
  mac_sta[1] = hex_to_u8 (macsta_buf +  2);
  mac_sta[2] = hex_to_u8 (macsta_buf +  4);
  mac_sta[3] = hex_to_u8 (macsta_buf +  6);
  mac_sta[4] = hex_to_u8 (macsta_buf +  8);
  mac_sta[5] = hex_to_u8 (macsta_buf + 10);

  // essid

  const u8 *essid_buf = token.buf[5];
  const int essid_len = token.len[5];

  if (essid_len & 1) return (PARSER_SALT_VALUE);

  wpa->essid_len = hex_decode (essid_buf, essid_len, (u8 *) wpa->essid_buf);

  // salt

  memcpy (salt->salt_buf, wpa->essid_buf, wpa->essid_len);

  salt->salt_len = wpa->essid_len;

  salt->salt_iter = ROUNDS_WPA_PBKDF2 - 1;

  // FT extras (types 05/06)

  if (is_ft == true)
  {
    const u8 *mdid_pos = token.buf[9];
    u8 *mdid_ptr = (u8 *) wpa->mdid;

    mdid_ptr[0] = hex_to_u8 (mdid_pos + 0);
    mdid_ptr[1] = hex_to_u8 (mdid_pos + 2);

    wpa->r0khid_len = hex_decode (token.buf[10], token.len[10], (u8 *) wpa->r0khid);
    wpa->r1khid_len = hex_decode (token.buf[11], token.len[11], (u8 *) wpa->r1khid);
  }

  // PMKID types: 01, 03, 05

  if ((type == 1) || (type == 3) || (type == 5))
  {
    const u8 *pmkid_buf = token.buf[2];

    wpa->pmkid[0] = hex_to_u32 (pmkid_buf +  0);
    wpa->pmkid[1] = hex_to_u32 (pmkid_buf +  8);
    wpa->pmkid[2] = hex_to_u32 (pmkid_buf + 16);
    wpa->pmkid[3] = hex_to_u32 (pmkid_buf + 24);

    if (type == 5)
    {
      // FT PMKID: the emitted value is PMKR1Name from the FT hierarchy
      wpa_build_pke_r0 (wpa, mac_sta, 2, 0x0180);

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
    else
    {
      // Non-FT PMKID input: "PMK Name" || AP_MAC || STA_MAC
      wpa->pmkid_data[0] = 0x204b4d50; // "PMK "
      wpa->pmkid_data[1] = 0x656d614e; // "Name"
      wpa->pmkid_data[2] = ((u32) mac_ap[0]  <<  0)
                         | ((u32) mac_ap[1]  <<  8)
                         | ((u32) mac_ap[2]  << 16)
                         | ((u32) mac_ap[3]  << 24);
      wpa->pmkid_data[3] = ((u32) mac_ap[4]  <<  0)
                         | ((u32) mac_ap[5]  <<  8)
                         | ((u32) mac_sta[0] << 16)
                         | ((u32) mac_sta[1] << 24);
      wpa->pmkid_data[4] = ((u32) mac_sta[2] <<  0)
                         | ((u32) mac_sta[3] <<  8)
                         | ((u32) mac_sta[4] << 16)
                         | ((u32) mac_sta[5] << 24);
    }

    // hash

    digest[0] = wpa->pmkid[0];
    digest[1] = wpa->pmkid[1];
    digest[2] = wpa->pmkid[2];
    digest[3] = wpa->pmkid[3];

    digest[0] = byte_swap_32 (digest[0]);
    digest[1] = byte_swap_32 (digest[1]);
    digest[2] = byte_swap_32 (digest[2]);
    digest[3] = byte_swap_32 (digest[3]);

    return (PARSER_OK);
  }

  // EAPOL types: 02, 04, 06

  if (token.len[6] != 64) return (PARSER_SALT_LENGTH);

  if (token.len[7] < (int) sizeof (auth_packet_t) * 2) return (PARSER_SALT_LENGTH);

  if (token.len[8] != 2) return (PARSER_SALT_LENGTH);

  // anonce

  const u8 *anonce_pos = token.buf[6];

  wpa->anonce[0] = hex_to_u32 (anonce_pos +  0);
  wpa->anonce[1] = hex_to_u32 (anonce_pos +  8);
  wpa->anonce[2] = hex_to_u32 (anonce_pos + 16);
  wpa->anonce[3] = hex_to_u32 (anonce_pos + 24);
  wpa->anonce[4] = hex_to_u32 (anonce_pos + 32);
  wpa->anonce[5] = hex_to_u32 (anonce_pos + 40);
  wpa->anonce[6] = hex_to_u32 (anonce_pos + 48);
  wpa->anonce[7] = hex_to_u32 (anonce_pos + 56);

  // eapol

  const u8 *eapol_pos = token.buf[7];

  u8 *eapol_ptr = (u8 *) wpa->eapol;

  wpa->eapol_len = hex_decode (eapol_pos, token.len[7], eapol_ptr);

  memset (eapol_ptr + wpa->eapol_len, 0, (1024 + 64) - wpa->eapol_len);

  auth_packet_t *auth_packet = (auth_packet_t *) wpa->eapol;

  // keyver

  const u16 key_information = byte_swap_16 (auth_packet->key_information);

  wpa->keyver = key_information & 3;

  // message_pair

  const u8 *message_pair_pos = token.buf[8];

  const u8 message_pair = hex_to_u8 (message_pair_pos);

  wpa->message_pair = message_pair;

  // pke

  if (type == 2)
  {
    // type 02: legacy EAPOL, keyver-driven PKE layout
    if ((wpa->keyver != 1) && (wpa->keyver != 2) && (wpa->keyver != 3)) return (PARSER_SALT_VALUE);

    u8 *pke_ptr = (u8 *) wpa->pke;

    memset (pke_ptr, 0, 128);

    if ((wpa->keyver == 1) || (wpa->keyver == 2))
    {
      memcpy (pke_ptr, "Pairwise key expansion\x00", 23);

      if (memcmp (mac_ap, mac_sta, 6) < 0)
      {
        memcpy (pke_ptr + 23, mac_ap,  6);
        memcpy (pke_ptr + 29, mac_sta, 6);
      }
      else
      {
        memcpy (pke_ptr + 23, mac_sta, 6);
        memcpy (pke_ptr + 29, mac_ap,  6);
      }

      wpa->nonce_compare = memcmp (wpa->anonce, auth_packet->wpa_key_nonce, 32);

      if (wpa->nonce_compare < 0)
      {
        memcpy (pke_ptr + 35, wpa->anonce,  32);
        memcpy (pke_ptr + 67, auth_packet->wpa_key_nonce, 32);
      }
      else
      {
        memcpy (pke_ptr + 35, auth_packet->wpa_key_nonce, 32);
        memcpy (pke_ptr + 67, wpa->anonce,  32);
      }
    }
    else if (wpa->keyver == 3)
    {
      pke_ptr[0] = 1;
      pke_ptr[1] = 0;

      memcpy (pke_ptr + 2, "Pairwise key expansion", 22);

      if (memcmp (mac_ap, mac_sta, 6) < 0)
      {
        memcpy (pke_ptr + 24, mac_ap,  6);
        memcpy (pke_ptr + 30, mac_sta, 6);
      }
      else
      {
        memcpy (pke_ptr + 24, mac_sta, 6);
        memcpy (pke_ptr + 30, mac_ap,  6);
      }

      wpa->nonce_compare = memcmp (wpa->anonce, auth_packet->wpa_key_nonce, 32);

      if (wpa->nonce_compare < 0)
      {
        memcpy (pke_ptr + 36, wpa->anonce,  32);
        memcpy (pke_ptr + 68, auth_packet->wpa_key_nonce, 32);
      }
      else
      {
        memcpy (pke_ptr + 36, auth_packet->wpa_key_nonce, 32);
        memcpy (pke_ptr + 68, wpa->anonce,  32);
      }

      pke_ptr[100] = 0x80;
      pke_ptr[101] = 1;
    }

    for (int i = 0; i < 32; i++)
    {
      wpa->pke[i] = byte_swap_32 (wpa->pke[i]);
    }

    if (wpa->keyver == 2)
    {
      for (int i = 0; i < 64; i++)
      {
        wpa->eapol[i] = byte_swap_32 (wpa->eapol[i]);
      }
    }

    if (wpa->keyver == 3)
    {
      eapol_ptr[wpa->eapol_len] = 0x80;
    }
  }
  else if (type == 4)
  {
    // type 04: PSK-SHA256-EAPOL, KDF-SHA256 layout
    u8 *pke_ptr = (u8 *) wpa->pke;

    memset (pke_ptr, 0, 128);

    pke_ptr[0] = 1;
    pke_ptr[1] = 0;

    memcpy (pke_ptr + 2, "Pairwise key expansion", 22);

    if (memcmp (mac_ap, mac_sta, 6) < 0)
    {
      memcpy (pke_ptr + 24, mac_ap,  6);
      memcpy (pke_ptr + 30, mac_sta, 6);
    }
    else
    {
      memcpy (pke_ptr + 24, mac_sta, 6);
      memcpy (pke_ptr + 30, mac_ap,  6);
    }

    wpa->nonce_compare = memcmp (wpa->anonce, auth_packet->wpa_key_nonce, 32);

    if (wpa->nonce_compare < 0)
    {
      memcpy (pke_ptr + 36, wpa->anonce,  32);
      memcpy (pke_ptr + 68, auth_packet->wpa_key_nonce, 32);
    }
    else
    {
      memcpy (pke_ptr + 36, auth_packet->wpa_key_nonce, 32);
      memcpy (pke_ptr + 68, wpa->anonce,  32);
    }

    pke_ptr[100] = 0x80;
    pke_ptr[101] = 1;

    for (int i = 0; i < 32; i++)
    {
      wpa->pke[i] = byte_swap_32 (wpa->pke[i]);
    }

    eapol_ptr[wpa->eapol_len] = 0x80;
  }
  else if (type == 6)
  {
    // type 06: FT-PSK-EAPOL, SHA-256 FT chain
    wpa_build_pke_r0 (wpa, mac_sta, 1, 0x0180);
    wpa_build_pke_r1 (wpa, mac_sta, 0x0100);

    u8 *p = (u8 *) wpa->pke;
    memset (p, 0, 128);

    p[0] = 1;
    p[1] = 0;
    memcpy (p + 2, "FT-PTK", 6);

    const u8 *ext_nonce  = (const u8 *) wpa->anonce;
    const u8 *body_nonce = (const u8 *) auth_packet->wpa_key_nonce;
    const u8 *snonce     = (message_pair & 0x10) ? ext_nonce  : body_nonce;
    const u8 *anonce_in  = (message_pair & 0x10) ? body_nonce : ext_nonce;

    memcpy (p + 8,  snonce,    32);
    memcpy (p + 40, anonce_in, 32);
    memcpy (p + 72, mac_ap,  6);
    memcpy (p + 78, mac_sta, 6);
    p[84] = 0x80;
    p[85] = 0x01;

    for (int i = 0; i < 32; i++)
    {
      wpa->pke[i]    = byte_swap_32 (wpa->pke[i]);
      wpa->pke_r0[i] = byte_swap_32 (wpa->pke_r0[i]);
      wpa->pke_r1[i] = byte_swap_32 (wpa->pke_r1[i]);
    }

    eapol_ptr[wpa->eapol_len] = 0x80;
  }

  // replay-counter endianness hints

  wpa->detected_le = 1;
  wpa->detected_be = 1;

  if (wpa->message_pair & (1 << 5))
  {
    wpa->detected_le = 1;
    wpa->detected_be = 0;
  }
  else if (wpa->message_pair & (1 << 6))
  {
    wpa->detected_le = 0;
    wpa->detected_be = 1;
  }

  // mic

  const u8 *mic_pos = token.buf[2];

  wpa->keymic[0] = hex_to_u32 (mic_pos +  0);
  wpa->keymic[1] = hex_to_u32 (mic_pos +  8);
  wpa->keymic[2] = hex_to_u32 (mic_pos + 16);
  wpa->keymic[3] = hex_to_u32 (mic_pos + 24);

  wpa->keymic[0] = byte_swap_32 (wpa->keymic[0]);
  wpa->keymic[1] = byte_swap_32 (wpa->keymic[1]);
  wpa->keymic[2] = byte_swap_32 (wpa->keymic[2]);
  wpa->keymic[3] = byte_swap_32 (wpa->keymic[3]);

  // uniqueness digest

  u32 hash[4];

  hash[0] = 0;
  hash[1] = 1;
  hash[2] = 2;
  hash[3] = 3;

  u32 block[16];

  memset (block, 0, sizeof (block));

  u8 *block_ptr = (u8 *) block;

  for (int i = 0; i < 16; i++) block[i] = salt->salt_buf[i];

  md5_transform (block + 0, block + 4, block + 8, block + 12, hash);

  for (int i = 0; i < 16; i++) block[i] = wpa->pke[i +  0];

  md5_transform (block + 0, block + 4, block + 8, block + 12, hash);

  for (int i = 0; i < 16; i++) block[i] = wpa->pke[i + 16];

  md5_transform (block + 0, block + 4, block + 8, block + 12, hash);

  for (int i = 0; i < 16; i++) block[i] = wpa->eapol[i +  0];

  md5_transform (block + 0, block + 4, block + 8, block + 12, hash);

  for (int i = 0; i < 16; i++) block[i] = wpa->eapol[i + 16];

  md5_transform (block + 0, block + 4, block + 8, block + 12, hash);

  for (int i = 0; i < 16; i++) block[i] = wpa->eapol[i + 32];

  md5_transform (block + 0, block + 4, block + 8, block + 12, hash);

  for (int i = 0; i < 16; i++) block[i] = wpa->eapol[i + 48];

  md5_transform (block + 0, block + 4, block + 8, block + 12, hash);

  for (int i = 0; i <  2; i++) block[0 + i] = wpa->mac_ap[i];
  for (int i = 0; i <  2; i++) block[2 + i] = wpa->mac_ap[i];
  for (int i = 0; i < 12; i++) block[4 + i] = 0;

  md5_transform (block + 0, block + 4, block + 8, block + 12, hash);

  memcpy (block_ptr +  0, wpa->anonce,  32);
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
  return snprintf (line_buf, line_size, "%s", hash_info->orighash);
}

int module_hash_decode_postprocess (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  wpa_t *wpa = (wpa_t *) esalt_buf;

  wpa->message_pair_chgd = user_options->hccapx_message_pair_chgd;

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
    else
    {
      if (wpa->message_pair & (1 << 7))
      {
        // replaycount not checked, nc needed
      }
      else
      {
        wpa->nonce_error_corrections = 0;
      }
    }
  }

  return (PARSER_OK);
}

char *module_jit_build_options (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra, MAYBE_UNUSED const hashes_t *hashes, MAYBE_UNUSED const hc_device_param_t *device_param)
{
  char *jit_build_options = NULL;

  u32 types_seen = (1u << 1);

  for (u32 salt_idx = 0; salt_idx < hashes->salts_cnt; salt_idx++)
  {
    const u32 digests_offset = hashes->salts_buf[salt_idx].digests_offset;
    const u32 digests_cnt    = hashes->salts_buf[salt_idx].digests_cnt;

    for (u32 digest_idx = 0; digest_idx < digests_cnt; digest_idx++)
    {
      const wpa_t *wpa = &((const wpa_t *) hashes->esalts_buf)[digests_offset + digest_idx];

      if ((wpa->type >= 1) && (wpa->type <= 6))
      {
        types_seen |= (1u << wpa->type);
      }
    }
  }

  char buf[256];
  int pos = 0;

  for (int t = 1; t <= 6; t++)
  {
    if (types_seen & (1u << t))
    {
      pos += snprintf (buf + pos, sizeof (buf) - pos, "-DENABLE_TYPE_%02d ", t);
    }
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
  module_ctx->module_benchmark_mask           = module_benchmark_mask;
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
  module_ctx->module_hash_binary_save         = module_hash_binary_save;
  module_ctx->module_hash_decode_postprocess  = module_hash_decode_postprocess;
  module_ctx->module_hash_decode_potfile      = module_hash_decode_potfile;
  module_ctx->module_hash_decode_zero_hash    = MODULE_DEFAULT;
  module_ctx->module_hash_decode              = module_hash_decode;
  module_ctx->module_hash_encode_status       = MODULE_DEFAULT;
  module_ctx->module_hash_encode_potfile      = module_hash_encode_potfile;
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
  module_ctx->module_potfile_custom_check     = module_potfile_custom_check;
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
