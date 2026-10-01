/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#define NEW_SIMD_CODE

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_simd.cl)
#include M2S(INCLUDE_PATH/inc_hash_md5.cl)
#include M2S(INCLUDE_PATH/inc_hash_sha1.cl)
#include M2S(INCLUDE_PATH/inc_hash_sha256.cl)
#include M2S(INCLUDE_PATH/inc_cipher_aes.cl)
#else
#include "inc_vendor.h"
#include "inc_types.h"
#include "inc_platform.h"
#include "inc_common.h"
#include "inc_simd.h"
#include "inc_hash_md5.h"
#include "inc_hash_sha1.h"
#include "inc_hash_sha256.h"
#include "inc_cipher_aes.h"
#endif

#ifdef IS_NATIVE
#undef DECLSPEC
#define DECLSPEC static MAYBE_UNUSED
#define ENABLE_TYPE_01
#define ENABLE_TYPE_02
#define ENABLE_TYPE_03
#define ENABLE_TYPE_04
#define ENABLE_TYPE_05
#define ENABLE_TYPE_06
#endif

#define COMPARE_S M2S(INCLUDE_PATH/inc_comp_single.cl)
#define COMPARE_M M2S(INCLUDE_PATH/inc_comp_multi.cl)

typedef struct wpa_pbkdf2_tmp
{
  u32 ipad[5];
  u32 opad[5];

  u32 dgst[10];
  u32 out[10];

} wpa_pbkdf2_tmp_t;

typedef struct wpa
{
  u32  essid_buf[16];
  u32  essid_len;

  u32  mac_ap[2];
  u32  mac_sta[2];

  u32  type;            // 1-6

  u32  pmkid[4];
  u32  pmkid_data[32];

  u32  keymic[4];
  u32  anonce[8];

  u32  keyver;

  u32  eapol[256 + 16];
  u32  eapol_len;

  u32  pke[32];

  u32  mdid[1];
  u32  r0khid[12]; u32 r0khid_len;
  u32  r1khid[12]; u32 r1khid_len;
  u32  pke_r0[32];
  u32  pke_r1[32];

  int  message_pair_chgd;
  u32  message_pair;

  int  nonce_error_corrections_chgd;
  int  nonce_error_corrections;

  int  nonce_compare;
  int  detected_le;
  int  detected_be;

} wpa_t;

// --- AES-CMAC subkey derivation ---

DECLSPEC void make_kn (PRIVATE_AS u32 *k)
{
  u32 kl[4];
  u32 kr[4];

  kl[0] = (k[0] << 1) & 0xfefefefe;
  kl[1] = (k[1] << 1) & 0xfefefefe;
  kl[2] = (k[2] << 1) & 0xfefefefe;
  kl[3] = (k[3] << 1) & 0xfefefefe;

  kr[0] = (k[0] >> 7) & 0x01010101;
  kr[1] = (k[1] >> 7) & 0x01010101;
  kr[2] = (k[2] >> 7) & 0x01010101;
  kr[3] = (k[3] >> 7) & 0x01010101;

  const u32 c = kr[0] & 1;

  kr[0] = kr[0] >> 8 | kr[1] << 24;
  kr[1] = kr[1] >> 8 | kr[2] << 24;
  kr[2] = kr[2] >> 8 | kr[3] << 24;
  kr[3] = kr[3] >> 8;

  k[0] = kl[0] | kr[0];
  k[1] = kl[1] | kr[1];
  k[2] = kl[2] | kr[2];
  k[3] = kl[3] | kr[3];

  k[3] ^= c * 0x87000000;
}

// --- PBKDF2 loop helper ---

DECLSPEC void hmac_sha1_run_V (PRIVATE_AS u32x *w0, PRIVATE_AS u32x *w1, PRIVATE_AS u32x *w2, PRIVATE_AS u32x *w3, PRIVATE_AS const u32x *ipad, PRIVATE_AS const u32x *opad, PRIVATE_AS u32x *digest)
{
  digest[0] = ipad[0];
  digest[1] = ipad[1];
  digest[2] = ipad[2];
  digest[3] = ipad[3];
  digest[4] = ipad[4];

  sha1_transform_vector (w0, w1, w2, w3, digest);

  w0[0] = digest[0];
  w0[1] = digest[1];
  w0[2] = digest[2];
  w0[3] = digest[3];
  w1[0] = digest[4];
  w1[1] = 0x80000000;
  w1[2] = 0;
  w1[3] = 0;
  w2[0] = 0;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;
  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = (64 + 20) * 8;

  digest[0] = opad[0];
  digest[1] = opad[1];
  digest[2] = opad[2];
  digest[3] = opad[3];
  digest[4] = opad[4];

  sha1_transform_vector (w0, w1, w2, w3, digest);
}

// --- Post-PMK verifiers. Each returns 1 on match, 0 otherwise. ---

// type 01 PMKID: HMAC-SHA1(PMK, "PMK Name" || AP || STA)
DECLSPEC int wpa_check_pmkid_sha1 (PRIVATE_AS const u32 *pmk, GLOBAL_AS const wpa_t *wpa)
{
  sha1_hmac_ctx_t ctx;
  sha1_hmac_init (&ctx, pmk, 32);
  sha1_hmac_update_global_swap (&ctx, wpa->pmkid_data, 20);
  sha1_hmac_final (&ctx);

  return (hc_swap32_S (ctx.opad.h[0]) == wpa->pmkid[0])
      && (hc_swap32_S (ctx.opad.h[1]) == wpa->pmkid[1])
      && (hc_swap32_S (ctx.opad.h[2]) == wpa->pmkid[2])
      && (hc_swap32_S (ctx.opad.h[3]) == wpa->pmkid[3]);
}

// type 03 PSK-SHA256-PMKID: HMAC-SHA256(PMK, "PMK Name" || AP || STA)
DECLSPEC int wpa_check_pmkid_sha256 (PRIVATE_AS const u32 *pmk, GLOBAL_AS const wpa_t *wpa)
{
  sha256_hmac_ctx_t ctx;
  sha256_hmac_init (&ctx, pmk, 32);
  sha256_hmac_update_global_swap (&ctx, wpa->pmkid_data, 20);
  sha256_hmac_final (&ctx);

  return (hc_swap32_S (ctx.opad.h[0]) == wpa->pmkid[0])
      && (hc_swap32_S (ctx.opad.h[1]) == wpa->pmkid[1])
      && (hc_swap32_S (ctx.opad.h[2]) == wpa->pmkid[2])
      && (hc_swap32_S (ctx.opad.h[3]) == wpa->pmkid[3]);
}

// type 05 FT-PSK-PMKID: SHA-256 FT chain -> PMKR1Name
DECLSPEC int wpa_check_ft_pmkid_sha256 (PRIVATE_AS const u32 *pmk, GLOBAL_AS const wpa_t *wpa)
{
  u32 pke[32];

  for (int i = 0; i < 32; i++) pke[i] = wpa->pke_r0[i];

  sha256_hmac_ctx_t ctx1;

  sha256_hmac_init (&ctx1, pmk, 32);
  sha256_hmac_update (&ctx1, pke, 19 + wpa->essid_len + wpa->r0khid_len);
  sha256_hmac_final (&ctx1);

  pke[ 0] = 0x46542d52;
  pke[ 1] = 0x304e0000 | (ctx1.opad.h[0] >> 16);
  pke[ 2] = (ctx1.opad.h[0] << 16) | (ctx1.opad.h[1] >> 16);
  pke[ 3] = (ctx1.opad.h[1] << 16) | (ctx1.opad.h[2] >> 16);
  pke[ 4] = (ctx1.opad.h[2] << 16) | (ctx1.opad.h[3] >> 16);
  pke[ 5] = (ctx1.opad.h[3] << 16);

  for (int i = 6; i < 32; i++) pke[i] = 0;

  sha256_ctx_t ctx2;

  sha256_init (&ctx2);
  sha256_update (&ctx2, pke, 22);
  sha256_final (&ctx2);

  pke[ 0] = wpa->pmkid_data[ 0];
  pke[ 1] = wpa->pmkid_data[ 1] | (ctx2.h[0] >> 16);
  pke[ 2] = wpa->pmkid_data[ 2] | (ctx2.h[0] << 16) | (ctx2.h[1] >> 16);
  pke[ 3] = wpa->pmkid_data[ 3] | (ctx2.h[1] << 16) | (ctx2.h[2] >> 16);
  pke[ 4] = wpa->pmkid_data[ 4] | (ctx2.h[2] << 16) | (ctx2.h[3] >> 16);
  pke[ 5] = wpa->pmkid_data[ 5] | (ctx2.h[3] << 16);

  for (int i = 6; i < 32; i++) pke[i] = wpa->pmkid_data[i];

  sha256_init (&ctx2);
  sha256_update (&ctx2, pke, 28 + wpa->r1khid_len);
  sha256_final (&ctx2);

  return (hc_swap32_S (ctx2.h[0]) == wpa->pmkid[0])
      && (hc_swap32_S (ctx2.h[1]) == wpa->pmkid[1])
      && (hc_swap32_S (ctx2.h[2]) == wpa->pmkid[2])
      && (hc_swap32_S (ctx2.h[3]) == wpa->pmkid[3]);
}

// type 02 keyver 1: PRF-SHA1 PTK -> HMAC-MD5 MIC
DECLSPEC int wpa_check_eapol_md5 (PRIVATE_AS const u32 *pmk, GLOBAL_AS const wpa_t *wpa)
{
  u32 pke[32];

  for (int i = 0; i < 32; i++) pke[i] = wpa->pke[i];

  u32 z[4] = { 0, 0, 0, 0 };

  u32 to, m0, m1;

  if (wpa->nonce_compare < 0)
  {
    m0 = pke[15] & ~0x000000ff; m1 = pke[16] & ~0xffffff00;
    to = pke[15] << 24 | pke[16] >> 8;
  }
  else
  {
    m0 = pke[23] & ~0x000000ff; m1 = pke[24] & ~0xffffff00;
    to = pke[23] << 24 | pke[24] >> 8;
  }

  u32 bo_loops = wpa->detected_le + wpa->detected_be;

  bo_loops = (bo_loops == 0) ? 2 : bo_loops;

  const u32 nec = wpa->nonce_error_corrections;

  for (u32 nc = 0; nc <= nec; nc++)
  {
    for (u32 bo = 0; bo < bo_loops; bo++)
    {
      u32 t = to;

      if (bo_loops == 1)
      {
        if (wpa->detected_le == 1)
        {
          t -= nec / 2;
          t += nc;
        }
        else if (wpa->detected_be == 1)
        {
          t = hc_swap32_S (t);
          t -= nec / 2;
          t += nc;
          t = hc_swap32_S (t);
        }
      }
      else
      {
        if (bo == 0)
        {
          t -= nec / 2;
          t += nc;
        }
        else if (bo == 1)
        {
          t = hc_swap32_S (t);
          t -= nec / 2;
          t += nc;
          t = hc_swap32_S (t);
        }
      }

      if (wpa->nonce_compare < 0)
      {
        pke[15] = m0 | (t >> 24);
        pke[16] = m1 | (t <<  8);
      }
      else
      {
        pke[23] = m0 | (t >> 24);
        pke[24] = m1 | (t <<  8);
      }

      sha1_hmac_ctx_t ctx1;

      sha1_hmac_init_64 (&ctx1, pmk, pmk + 4, z, z);
      sha1_hmac_update (&ctx1, pke, 100);
      sha1_hmac_final (&ctx1);

      ctx1.opad.h[0] = hc_swap32_S (ctx1.opad.h[0]);
      ctx1.opad.h[1] = hc_swap32_S (ctx1.opad.h[1]);
      ctx1.opad.h[2] = hc_swap32_S (ctx1.opad.h[2]);
      ctx1.opad.h[3] = hc_swap32_S (ctx1.opad.h[3]);

      md5_hmac_ctx_t ctx2;

      md5_hmac_init_64 (&ctx2, ctx1.opad.h, z, z, z);
      md5_hmac_update_global (&ctx2, wpa->eapol, wpa->eapol_len);
      md5_hmac_final (&ctx2);

      if ((hc_swap32_S (ctx2.opad.h[0]) == wpa->keymic[0])
       && (hc_swap32_S (ctx2.opad.h[1]) == wpa->keymic[1])
       && (hc_swap32_S (ctx2.opad.h[2]) == wpa->keymic[2])
       && (hc_swap32_S (ctx2.opad.h[3]) == wpa->keymic[3])) return 1;
    }
  }

  return 0;
}

// type 02 keyver 2: PRF-SHA1 PTK -> HMAC-SHA1 MIC
DECLSPEC int wpa_check_eapol_sha1 (PRIVATE_AS const u32 *pmk, GLOBAL_AS const wpa_t *wpa)
{
  u32 pke[32];

  for (int i = 0; i < 32; i++) pke[i] = wpa->pke[i];

  u32 z[4] = { 0, 0, 0, 0 };

  u32 to, m0, m1;

  if (wpa->nonce_compare < 0)
  {
    m0 = pke[15] & ~0x000000ff; m1 = pke[16] & ~0xffffff00;
    to = pke[15] << 24 | pke[16] >> 8;
  }
  else
  {
    m0 = pke[23] & ~0x000000ff; m1 = pke[24] & ~0xffffff00;
    to = pke[23] << 24 | pke[24] >> 8;
  }

  u32 bo_loops = wpa->detected_le + wpa->detected_be;

  bo_loops = (bo_loops == 0) ? 2 : bo_loops;

  const u32 nec = wpa->nonce_error_corrections;

  for (u32 nc = 0; nc <= nec; nc++)
  {
    for (u32 bo = 0; bo < bo_loops; bo++)
    {
      u32 t = to;

      if (bo_loops == 1)
      {
        if (wpa->detected_le == 1)
        {
          t -= nec / 2;
          t += nc;
        }
        else if (wpa->detected_be == 1)
        {
          t = hc_swap32_S (t);
          t -= nec / 2;
          t += nc;
          t = hc_swap32_S (t);
        }
      }
      else
      {
        if (bo == 0)
        {
          t -= nec / 2;
          t += nc;
        }
        else if (bo == 1)
        {
          t = hc_swap32_S (t);
          t -= nec / 2;
          t += nc;
          t = hc_swap32_S (t);
        }
      }

      if (wpa->nonce_compare < 0)
      {
        pke[15] = m0 | (t >> 24);
        pke[16] = m1 | (t <<  8);
      }
      else
      {
        pke[23] = m0 | (t >> 24);
        pke[24] = m1 | (t <<  8);
      }

      sha1_hmac_ctx_t ctx1;

      sha1_hmac_init_64 (&ctx1, pmk, pmk + 4, z, z);
      sha1_hmac_update (&ctx1, pke, 100);
      sha1_hmac_final (&ctx1);

      sha1_hmac_ctx_t ctx2;

      sha1_hmac_init_64 (&ctx2, ctx1.opad.h, z, z, z);
      sha1_hmac_update_global (&ctx2, wpa->eapol, wpa->eapol_len);
      sha1_hmac_final (&ctx2);

      if ((ctx2.opad.h[0] == wpa->keymic[0])
       && (ctx2.opad.h[1] == wpa->keymic[1])
       && (ctx2.opad.h[2] == wpa->keymic[2])
       && (ctx2.opad.h[3] == wpa->keymic[3])) return 1;
    }
  }

  return 0;
}

// type 02 keyver 3 / type 04: KDF-SHA256 PTK -> AES-128-CMAC MIC
DECLSPEC int wpa_check_eapol_cmac256 (PRIVATE_AS const u32 *pmk, GLOBAL_AS const wpa_t *wpa, SHM_TYPE u32 *s_te0, SHM_TYPE u32 *s_te1, SHM_TYPE u32 *s_te2, SHM_TYPE u32 *s_te3, SHM_TYPE u32 *s_te4)
{
  u32 pke[32];

  for (int i = 0; i < 32; i++) pke[i] = wpa->pke[i];

  u32 z[4] = { 0, 0, 0, 0 };

  u32 to, m0, m1;

  if (wpa->nonce_compare < 0)
  {
    m0 = pke[15] & ~0x000000ff; m1 = pke[16] & ~0xffffff00;
    to = pke[15] << 24 | pke[16] >> 8;
  }
  else
  {
    m0 = pke[23] & ~0x000000ff; m1 = pke[24] & ~0xffffff00;
    to = pke[23] << 24 | pke[24] >> 8;
  }

  u32 bo_loops = wpa->detected_le + wpa->detected_be;

  bo_loops = (bo_loops == 0) ? 2 : bo_loops;

  const u32 nec = wpa->nonce_error_corrections;

  for (u32 nc = 0; nc <= nec; nc++)
  {
    for (u32 bo = 0; bo < bo_loops; bo++)
    {
      u32 t = to;

      if (bo_loops == 1)
      {
        if (wpa->detected_le == 1)
        {
          t -= nec / 2;
          t += nc;
        }
        else if (wpa->detected_be == 1)
        {
          t = hc_swap32_S (t);
          t -= nec / 2;
          t += nc;
          t = hc_swap32_S (t);
        }
      }
      else
      {
        if (bo == 0)
        {
          t -= nec / 2;
          t += nc;
        }
        else if (bo == 1)
        {
          t = hc_swap32_S (t);
          t -= nec / 2;
          t += nc;
          t = hc_swap32_S (t);
        }
      }

      if (wpa->nonce_compare < 0)
      {
        pke[15] = m0 | (t >> 24);
        pke[16] = m1 | (t <<  8);
      }
      else
      {
        pke[23] = m0 | (t >> 24);
        pke[24] = m1 | (t <<  8);
      }

      sha256_hmac_ctx_t ctx1;

      sha256_hmac_init_64 (&ctx1, pmk, pmk + 4, z, z);
      sha256_hmac_update (&ctx1, pke, 102);
      sha256_hmac_final (&ctx1);

      ctx1.opad.h[0] = hc_swap32_S (ctx1.opad.h[0]);
      ctx1.opad.h[1] = hc_swap32_S (ctx1.opad.h[1]);
      ctx1.opad.h[2] = hc_swap32_S (ctx1.opad.h[2]);
      ctx1.opad.h[3] = hc_swap32_S (ctx1.opad.h[3]);

      u32 ks[44];

      aes128_set_encrypt_key (ks, ctx1.opad.h, s_te0, s_te1, s_te2, s_te3);

      u32 m[4]  = { 0, 0, 0, 0 };
      u32 iv[4] = { 0, 0, 0, 0 };

      int eapol_left;
      int eapol_idx;

      for (eapol_left = wpa->eapol_len, eapol_idx = 0; eapol_left > 16; eapol_left -= 16, eapol_idx += 4)
      {
        m[0] = wpa->eapol[eapol_idx + 0] ^ iv[0];
        m[1] = wpa->eapol[eapol_idx + 1] ^ iv[1];
        m[2] = wpa->eapol[eapol_idx + 2] ^ iv[2];
        m[3] = wpa->eapol[eapol_idx + 3] ^ iv[3];

        aes128_encrypt (ks, m, iv, s_te0, s_te1, s_te2, s_te3, s_te4);
      }

      m[0] = wpa->eapol[eapol_idx + 0];
      m[1] = wpa->eapol[eapol_idx + 1];
      m[2] = wpa->eapol[eapol_idx + 2];
      m[3] = wpa->eapol[eapol_idx + 3];

      u32 k[4] = { 0, 0, 0, 0 };

      aes128_encrypt (ks, k, k, s_te0, s_te1, s_te2, s_te3, s_te4);

      make_kn (k);

      if (eapol_left < 16)
      {
        make_kn (k);
      }

      m[0] ^= k[0]; m[1] ^= k[1]; m[2] ^= k[2]; m[3] ^= k[3];
      m[0] ^= iv[0]; m[1] ^= iv[1]; m[2] ^= iv[2]; m[3] ^= iv[3];

      u32 keymic[4] = { 0, 0, 0, 0 };

      aes128_encrypt (ks, m, keymic, s_te0, s_te1, s_te2, s_te3, s_te4);

      keymic[0] = hc_swap32_S (keymic[0]);
      keymic[1] = hc_swap32_S (keymic[1]);
      keymic[2] = hc_swap32_S (keymic[2]);
      keymic[3] = hc_swap32_S (keymic[3]);

      if ((keymic[0] == wpa->keymic[0])
       && (keymic[1] == wpa->keymic[1])
       && (keymic[2] == wpa->keymic[2])
       && (keymic[3] == wpa->keymic[3])) return 1;
    }
  }

  return 0;
}

// type 06 FT-PSK-EAPOL: SHA-256 FT chain (PMK -> R0 -> R1 -> FT-PTK) -> AES-128-CMAC MIC
DECLSPEC int wpa_check_ft_eapol_cmac256 (PRIVATE_AS const u32 *pmk, GLOBAL_AS const wpa_t *wpa, SHM_TYPE u32 *s_te0, SHM_TYPE u32 *s_te1, SHM_TYPE u32 *s_te2, SHM_TYPE u32 *s_te3, SHM_TYPE u32 *s_te4)
{
  u32 z[4] = { 0, 0, 0, 0 };
  u32 pke[32];

  for (int i = 0; i < 32; i++) pke[i] = wpa->pke_r0[i];

  sha256_hmac_ctx_t ctx1;

  sha256_hmac_init (&ctx1, pmk, 32);
  sha256_hmac_update (&ctx1, pke, 19 + wpa->essid_len + wpa->r0khid_len);
  sha256_hmac_final (&ctx1);

  u32 out0[4]; u32 out1[4];

  out0[0] = ctx1.opad.h[0]; out0[1] = ctx1.opad.h[1]; out0[2] = ctx1.opad.h[2]; out0[3] = ctx1.opad.h[3];
  out1[0] = ctx1.opad.h[4]; out1[1] = ctx1.opad.h[5]; out1[2] = ctx1.opad.h[6]; out1[3] = ctx1.opad.h[7];

  for (int i = 0; i < 32; i++) pke[i] = wpa->pke_r1[i];

  sha256_hmac_init_64 (&ctx1, out0, out1, z, z);
  sha256_hmac_update (&ctx1, pke, 15 + wpa->r1khid_len);
  sha256_hmac_final (&ctx1);

  out0[0] = ctx1.opad.h[0]; out0[1] = ctx1.opad.h[1]; out0[2] = ctx1.opad.h[2]; out0[3] = ctx1.opad.h[3];
  out1[0] = ctx1.opad.h[4]; out1[1] = ctx1.opad.h[5]; out1[2] = ctx1.opad.h[6]; out1[3] = ctx1.opad.h[7];

  for (int i = 0; i < 32; i++) pke[i] = wpa->pke[i];

  u32 to = pke[17];

  u32 bo_loops = wpa->detected_le + wpa->detected_be;

  bo_loops = (bo_loops == 0) ? 2 : bo_loops;

  const u32 nec = wpa->nonce_error_corrections;

  for (u32 nc = 0; nc <= nec; nc++)
  {
    for (u32 bo = 0; bo < bo_loops; bo++)
    {
      u32 t = to;

      if (bo_loops == 1)
      {
        if (wpa->detected_le == 1)
        {
          t -= nec / 2;
          t += nc;
        }
        else if (wpa->detected_be == 1)
        {
          t = hc_swap32_S (t);
          t -= nec / 2;
          t += nc;
          t = hc_swap32_S (t);
        }
      }
      else
      {
        if (bo == 0)
        {
          t -= nec / 2;
          t += nc;
        }
        else if (bo == 1)
        {
          t = hc_swap32_S (t);
          t -= nec / 2;
          t += nc;
          t = hc_swap32_S (t);
        }
      }

      pke[17] = t;

      sha256_hmac_init_64 (&ctx1, out0, out1, z, z);
      sha256_hmac_update (&ctx1, pke, 86);
      sha256_hmac_final (&ctx1);

      ctx1.opad.h[0] = hc_swap32_S (ctx1.opad.h[0]);
      ctx1.opad.h[1] = hc_swap32_S (ctx1.opad.h[1]);
      ctx1.opad.h[2] = hc_swap32_S (ctx1.opad.h[2]);
      ctx1.opad.h[3] = hc_swap32_S (ctx1.opad.h[3]);

      u32 ks[44];

      aes128_set_encrypt_key (ks, ctx1.opad.h, s_te0, s_te1, s_te2, s_te3);

      u32 m[4]  = { 0, 0, 0, 0 };
      u32 iv[4] = { 0, 0, 0, 0 };

      int eapol_left;
      int eapol_idx;

      for (eapol_left = wpa->eapol_len, eapol_idx = 0; eapol_left > 16; eapol_left -= 16, eapol_idx += 4)
      {
        m[0] = wpa->eapol[eapol_idx + 0] ^ iv[0];
        m[1] = wpa->eapol[eapol_idx + 1] ^ iv[1];
        m[2] = wpa->eapol[eapol_idx + 2] ^ iv[2];
        m[3] = wpa->eapol[eapol_idx + 3] ^ iv[3];

        aes128_encrypt (ks, m, iv, s_te0, s_te1, s_te2, s_te3, s_te4);
      }

      m[0] = wpa->eapol[eapol_idx + 0];
      m[1] = wpa->eapol[eapol_idx + 1];
      m[2] = wpa->eapol[eapol_idx + 2];
      m[3] = wpa->eapol[eapol_idx + 3];

      u32 k[4] = { 0, 0, 0, 0 };

      aes128_encrypt (ks, k, k, s_te0, s_te1, s_te2, s_te3, s_te4);

      make_kn (k);

      if (eapol_left < 16)
      {
        make_kn (k);
      }

      m[0] ^= k[0]; m[1] ^= k[1]; m[2] ^= k[2]; m[3] ^= k[3];
      m[0] ^= iv[0]; m[1] ^= iv[1]; m[2] ^= iv[2]; m[3] ^= iv[3];

      u32 keymic[4] = { 0, 0, 0, 0 };

      aes128_encrypt (ks, m, keymic, s_te0, s_te1, s_te2, s_te3, s_te4);

      keymic[0] = hc_swap32_S (keymic[0]);
      keymic[1] = hc_swap32_S (keymic[1]);
      keymic[2] = hc_swap32_S (keymic[2]);
      keymic[3] = hc_swap32_S (keymic[3]);

      if ((keymic[0] == wpa->keymic[0])
       && (keymic[1] == wpa->keymic[1])
       && (keymic[2] == wpa->keymic[2])
       && (keymic[3] == wpa->keymic[3])) return 1;
    }
  }

  return 0;
}

// --- Aux kernel macros ---

#define WPA_AUX_PROLOGUE                                         \
  const u64 gid = get_global_id (0);                             \
  if (gid >= GID_CNT) return;                                    \
  const u32 digest_pos = LOOP_POS;                               \
  const u32 digest_cur = DIGESTS_OFFSET_HOST + digest_pos;       \
  GLOBAL_AS const wpa_t *wpa = &esalt_bufs[digest_cur];          \
  u32 pmk[32];                                                   \
  for (int wi = 0; wi < 32; wi++) pmk[wi] = 0;                   \
  pmk[0] = tmps[gid].out[0]; pmk[1] = tmps[gid].out[1];          \
  pmk[2] = tmps[gid].out[2]; pmk[3] = tmps[gid].out[3];          \
  pmk[4] = tmps[gid].out[4]; pmk[5] = tmps[gid].out[5];          \
  pmk[6] = tmps[gid].out[6]; pmk[7] = tmps[gid].out[7];

#define WPA_MARK_IF(matched)                                                                            \
  if (matched)                                                                                          \
  {                                                                                                     \
    if (hc_atomic_inc (&hashes_shown[digest_cur]) == 0)                                                 \
    {                                                                                                   \
      mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, digest_pos, digest_cur, gid, 0, 0, 0); \
    }                                                                                                   \
  }

#ifdef REAL_SHM
#define WPA_AES_SHARED                                           \
  const u64 lid = get_local_id (0);                              \
  const u64 lsz = get_local_size (0);                            \
  LOCAL_VK u32 s_te0[256];                                       \
  LOCAL_VK u32 s_te1[256];                                       \
  LOCAL_VK u32 s_te2[256];                                       \
  LOCAL_VK u32 s_te3[256];                                       \
  LOCAL_VK u32 s_te4[256];                                       \
  for (u32 i = lid; i < 256; i += lsz)                           \
  {                                                              \
    s_te0[i] = te0[i];                                           \
    s_te1[i] = te1[i];                                           \
    s_te2[i] = te2[i];                                           \
    s_te3[i] = te3[i];                                           \
    s_te4[i] = te4[i];                                           \
  }                                                              \
  SYNC_THREADS ();
#else
#define WPA_AES_SHARED                                           \
  CONSTANT_AS u32a *s_te0 = te0;                                 \
  CONSTANT_AS u32a *s_te1 = te1;                                 \
  CONSTANT_AS u32a *s_te2 = te2;                                 \
  CONSTANT_AS u32a *s_te3 = te3;                                 \
  CONSTANT_AS u32a *s_te4 = te4;
#endif

// --- PBKDF2-HMAC-SHA1 init/loop/comp ---

KERNEL_FQ KERNEL_FA void m22000_init (KERN_ATTR_TMPS_ESALT (wpa_pbkdf2_tmp_t, wpa_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  sha1_hmac_ctx_t sha1_hmac_ctx0;

  sha1_hmac_init_global_swap (&sha1_hmac_ctx0, pws[gid].i, pws[gid].pw_len);

  tmps[gid].ipad[0] = sha1_hmac_ctx0.ipad.h[0];
  tmps[gid].ipad[1] = sha1_hmac_ctx0.ipad.h[1];
  tmps[gid].ipad[2] = sha1_hmac_ctx0.ipad.h[2];
  tmps[gid].ipad[3] = sha1_hmac_ctx0.ipad.h[3];
  tmps[gid].ipad[4] = sha1_hmac_ctx0.ipad.h[4];

  tmps[gid].opad[0] = sha1_hmac_ctx0.opad.h[0];
  tmps[gid].opad[1] = sha1_hmac_ctx0.opad.h[1];
  tmps[gid].opad[2] = sha1_hmac_ctx0.opad.h[2];
  tmps[gid].opad[3] = sha1_hmac_ctx0.opad.h[3];
  tmps[gid].opad[4] = sha1_hmac_ctx0.opad.h[4];

  sha1_hmac_update_global_swap (&sha1_hmac_ctx0, esalt_bufs[DIGESTS_OFFSET_HOST].essid_buf, esalt_bufs[DIGESTS_OFFSET_HOST].essid_len);

  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  sha1_hmac_ctx_t sha1_hmac_ctx1 = sha1_hmac_ctx0;

  w0[0] = 1;
  w0[1] = 0;
  w0[2] = 0;
  w0[3] = 0;
  w1[0] = 0;
  w1[1] = 0;
  w1[2] = 0;
  w1[3] = 0;
  w2[0] = 0;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;
  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = 0;

  sha1_hmac_update_64 (&sha1_hmac_ctx1, w0, w1, w2, w3, 4);

  sha1_hmac_final (&sha1_hmac_ctx1);

  tmps[gid].dgst[0] = sha1_hmac_ctx1.opad.h[0];
  tmps[gid].dgst[1] = sha1_hmac_ctx1.opad.h[1];
  tmps[gid].dgst[2] = sha1_hmac_ctx1.opad.h[2];
  tmps[gid].dgst[3] = sha1_hmac_ctx1.opad.h[3];
  tmps[gid].dgst[4] = sha1_hmac_ctx1.opad.h[4];

  tmps[gid].out[0] = sha1_hmac_ctx1.opad.h[0];
  tmps[gid].out[1] = sha1_hmac_ctx1.opad.h[1];
  tmps[gid].out[2] = sha1_hmac_ctx1.opad.h[2];
  tmps[gid].out[3] = sha1_hmac_ctx1.opad.h[3];
  tmps[gid].out[4] = sha1_hmac_ctx1.opad.h[4];

  sha1_hmac_ctx_t sha1_hmac_ctx2 = sha1_hmac_ctx0;

  w0[0] = 2;
  w0[1] = 0;
  w0[2] = 0;
  w0[3] = 0;
  w1[0] = 0;
  w1[1] = 0;
  w1[2] = 0;
  w1[3] = 0;
  w2[0] = 0;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;
  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = 0;

  sha1_hmac_update_64 (&sha1_hmac_ctx2, w0, w1, w2, w3, 4);

  sha1_hmac_final (&sha1_hmac_ctx2);

  tmps[gid].dgst[5] = sha1_hmac_ctx2.opad.h[0];
  tmps[gid].dgst[6] = sha1_hmac_ctx2.opad.h[1];
  tmps[gid].dgst[7] = sha1_hmac_ctx2.opad.h[2];
  tmps[gid].dgst[8] = sha1_hmac_ctx2.opad.h[3];
  tmps[gid].dgst[9] = sha1_hmac_ctx2.opad.h[4];

  tmps[gid].out[5] = sha1_hmac_ctx2.opad.h[0];
  tmps[gid].out[6] = sha1_hmac_ctx2.opad.h[1];
  tmps[gid].out[7] = sha1_hmac_ctx2.opad.h[2];
  tmps[gid].out[8] = sha1_hmac_ctx2.opad.h[3];
  tmps[gid].out[9] = sha1_hmac_ctx2.opad.h[4];
}

KERNEL_FQ KERNEL_FA void m22000_loop (KERN_ATTR_TMPS_ESALT (wpa_pbkdf2_tmp_t, wpa_t))
{
  const u64 gid = get_global_id (0);

  if ((gid * VECT_SIZE) >= GID_CNT) return;

  u32x ipad[5];
  u32x opad[5];

  ipad[0] = packv (tmps, ipad, gid, 0);
  ipad[1] = packv (tmps, ipad, gid, 1);
  ipad[2] = packv (tmps, ipad, gid, 2);
  ipad[3] = packv (tmps, ipad, gid, 3);
  ipad[4] = packv (tmps, ipad, gid, 4);

  opad[0] = packv (tmps, opad, gid, 0);
  opad[1] = packv (tmps, opad, gid, 1);
  opad[2] = packv (tmps, opad, gid, 2);
  opad[3] = packv (tmps, opad, gid, 3);
  opad[4] = packv (tmps, opad, gid, 4);

  u32x dgst[5];
  u32x out[5];

  dgst[0] = packv (tmps, dgst, gid, 0);
  dgst[1] = packv (tmps, dgst, gid, 1);
  dgst[2] = packv (tmps, dgst, gid, 2);
  dgst[3] = packv (tmps, dgst, gid, 3);
  dgst[4] = packv (tmps, dgst, gid, 4);

  out[0] = packv (tmps, out, gid, 0);
  out[1] = packv (tmps, out, gid, 1);
  out[2] = packv (tmps, out, gid, 2);
  out[3] = packv (tmps, out, gid, 3);
  out[4] = packv (tmps, out, gid, 4);

  for (u32 j = 0; j < LOOP_CNT; j++)
  {
    u32x w0[4];
    u32x w1[4];
    u32x w2[4];
    u32x w3[4];

    w0[0] = dgst[0];
    w0[1] = dgst[1];
    w0[2] = dgst[2];
    w0[3] = dgst[3];
    w1[0] = dgst[4];
    w1[1] = 0x80000000;
    w1[2] = 0;
    w1[3] = 0;
    w2[0] = 0;
    w2[1] = 0;
    w2[2] = 0;
    w2[3] = 0;
    w3[0] = 0;
    w3[1] = 0;
    w3[2] = 0;
    w3[3] = (64 + 20) * 8;

    hmac_sha1_run_V (w0, w1, w2, w3, ipad, opad, dgst);

    out[0] ^= dgst[0];
    out[1] ^= dgst[1];
    out[2] ^= dgst[2];
    out[3] ^= dgst[3];
    out[4] ^= dgst[4];
  }

  unpackv (tmps, dgst, gid, 0, dgst[0]);
  unpackv (tmps, dgst, gid, 1, dgst[1]);
  unpackv (tmps, dgst, gid, 2, dgst[2]);
  unpackv (tmps, dgst, gid, 3, dgst[3]);
  unpackv (tmps, dgst, gid, 4, dgst[4]);

  unpackv (tmps, out, gid, 0, out[0]);
  unpackv (tmps, out, gid, 1, out[1]);
  unpackv (tmps, out, gid, 2, out[2]);
  unpackv (tmps, out, gid, 3, out[3]);
  unpackv (tmps, out, gid, 4, out[4]);

  dgst[0] = packv (tmps, dgst, gid, 5);
  dgst[1] = packv (tmps, dgst, gid, 6);
  dgst[2] = packv (tmps, dgst, gid, 7);
  dgst[3] = packv (tmps, dgst, gid, 8);
  dgst[4] = packv (tmps, dgst, gid, 9);

  out[0] = packv (tmps, out, gid, 5);
  out[1] = packv (tmps, out, gid, 6);
  out[2] = packv (tmps, out, gid, 7);
  out[3] = packv (tmps, out, gid, 8);
  out[4] = packv (tmps, out, gid, 9);

  for (u32 j = 0; j < LOOP_CNT; j++)
  {
    u32x w0[4];
    u32x w1[4];
    u32x w2[4];
    u32x w3[4];

    w0[0] = dgst[0];
    w0[1] = dgst[1];
    w0[2] = dgst[2];
    w0[3] = dgst[3];
    w1[0] = dgst[4];
    w1[1] = 0x80000000;
    w1[2] = 0;
    w1[3] = 0;
    w2[0] = 0;
    w2[1] = 0;
    w2[2] = 0;
    w2[3] = 0;
    w3[0] = 0;
    w3[1] = 0;
    w3[2] = 0;
    w3[3] = (64 + 20) * 8;

    hmac_sha1_run_V (w0, w1, w2, w3, ipad, opad, dgst);

    out[0] ^= dgst[0];
    out[1] ^= dgst[1];
    out[2] ^= dgst[2];
    out[3] ^= dgst[3];
    out[4] ^= dgst[4];
  }

  unpackv (tmps, dgst, gid, 5, dgst[0]);
  unpackv (tmps, dgst, gid, 6, dgst[1]);
  unpackv (tmps, dgst, gid, 7, dgst[2]);
  unpackv (tmps, dgst, gid, 8, dgst[3]);
  unpackv (tmps, dgst, gid, 9, dgst[4]);

  unpackv (tmps, out, gid, 5, out[0]);
  unpackv (tmps, out, gid, 6, out[1]);
  unpackv (tmps, out, gid, 7, out[2]);
  unpackv (tmps, out, gid, 8, out[3]);
  unpackv (tmps, out, gid, 9, out[4]);
}

KERNEL_FQ KERNEL_FA void m22000_comp (KERN_ATTR_TMPS_ESALT (wpa_pbkdf2_tmp_t, wpa_t))
{
  // not in use here, special case...
}

// --- Aux kernels ---

// aux1: type 02 keyver 1 (WPA1-PSK-EAPOL, HMAC-MD5 MIC)
KERNEL_FQ KERNEL_FA void m22000_aux1 (KERN_ATTR_TMPS_ESALT (wpa_pbkdf2_tmp_t, wpa_t))
{
  WPA_AUX_PROLOGUE

  int matched = 0;

  if ((wpa->type == 2) && (wpa->keyver == 1))
  {
    matched = wpa_check_eapol_md5 (pmk, wpa);
  }

  WPA_MARK_IF (matched)
}

// aux2: type 02 keyver 2 (WPA2-PSK-EAPOL, HMAC-SHA1 MIC)
KERNEL_FQ KERNEL_FA void m22000_aux2 (KERN_ATTR_TMPS_ESALT (wpa_pbkdf2_tmp_t, wpa_t))
{
  WPA_AUX_PROLOGUE

  int matched = 0;

  if ((wpa->type == 2) && (wpa->keyver == 2))
  {
    matched = wpa_check_eapol_sha1 (pmk, wpa);
  }

  WPA_MARK_IF (matched)
}

// aux3: type 02 keyver 3 / type 04 / type 06 (AES-128-CMAC MIC family)
KERNEL_FQ KERNEL_FA void m22000_aux3 (KERN_ATTR_TMPS_ESALT (wpa_pbkdf2_tmp_t, wpa_t))
{
  WPA_AES_SHARED
  WPA_AUX_PROLOGUE

  int matched = 0;

  switch (wpa->type)
  {
    #ifdef ENABLE_TYPE_02
    case 2:
      if (wpa->keyver == 3) matched = wpa_check_eapol_cmac256 (pmk, wpa, s_te0, s_te1, s_te2, s_te3, s_te4);
      break;
    #endif
    #ifdef ENABLE_TYPE_04
    case 4: matched = wpa_check_eapol_cmac256    (pmk, wpa, s_te0, s_te1, s_te2, s_te3, s_te4); break;
    #endif
    #ifdef ENABLE_TYPE_06
    case 6: matched = wpa_check_ft_eapol_cmac256 (pmk, wpa, s_te0, s_te1, s_te2, s_te3, s_te4); break;
    #endif
  }

  WPA_MARK_IF (matched)
}

// aux4: type 01 / type 03 / type 05 (all PMKID types)
KERNEL_FQ KERNEL_FA void m22000_aux4 (KERN_ATTR_TMPS_ESALT (wpa_pbkdf2_tmp_t, wpa_t))
{
  WPA_AUX_PROLOGUE

  int matched = 0;

  switch (wpa->type)
  {
    #ifdef ENABLE_TYPE_01
    case 1: matched = wpa_check_pmkid_sha1      (pmk, wpa); break;
    #endif
    #ifdef ENABLE_TYPE_03
    case 3: matched = wpa_check_pmkid_sha256    (pmk, wpa); break;
    #endif
    #ifdef ENABLE_TYPE_05
    case 5: matched = wpa_check_ft_pmkid_sha256 (pmk, wpa); break;
    #endif
  }

  WPA_MARK_IF (matched)
}
