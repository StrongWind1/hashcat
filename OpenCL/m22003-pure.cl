/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_hash_md5.cl)
#include M2S(INCLUDE_PATH/inc_hash_sha1.cl)
#include M2S(INCLUDE_PATH/inc_hash_sha256.cl)
#include M2S(INCLUDE_PATH/inc_hash_sha384.cl)
#include M2S(INCLUDE_PATH/inc_cipher_aes.cl)

#ifndef INC_WPA_PSK_UNIVERSAL_CL
#define INC_WPA_PSK_UNIVERSAL_CL

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

DECLSPEC u8 hex_convert (const u8 c)
{
  return (c & 15) + (c >> 6) * 9;
}

DECLSPEC u8 hex_to_u8 (PRIVATE_AS const u8 *hex)
{
  u8 v = 0;

  v |= ((u8) hex_convert (hex[1]) << 0);
  v |= ((u8) hex_convert (hex[0]) << 4);

  return (v);
}

DECLSPEC int wpa_check_pmkid_sha1 (PRIVATE_AS const u32 *pmk, GLOBAL_AS const wpa_universal_t *wpa)
{
  sha1_hmac_ctx_t ctx;
  sha1_hmac_init (&ctx, pmk, 32);
  sha1_hmac_update_global_swap (&ctx, wpa->pmkid_data, 20);
  sha1_hmac_final (&ctx);

  return (ctx.opad.h[0] == wpa->pmkid[0])
      && (ctx.opad.h[1] == wpa->pmkid[1])
      && (ctx.opad.h[2] == wpa->pmkid[2])
      && (ctx.opad.h[3] == wpa->pmkid[3]);
}

DECLSPEC int wpa_check_pmkid_sha256 (PRIVATE_AS const u32 *pmk, GLOBAL_AS const wpa_universal_t *wpa)
{
  sha256_hmac_ctx_t ctx;
  sha256_hmac_init (&ctx, pmk, 32);
  sha256_hmac_update_global_swap (&ctx, wpa->pmkid_data, 20);
  sha256_hmac_final (&ctx);

  return (ctx.opad.h[0] == wpa->pmkid[0])
      && (ctx.opad.h[1] == wpa->pmkid[1])
      && (ctx.opad.h[2] == wpa->pmkid[2])
      && (ctx.opad.h[3] == wpa->pmkid[3]);
}

DECLSPEC int wpa_check_pmkid_sha384 (PRIVATE_AS const u32 *pmk, GLOBAL_AS const wpa_universal_t *wpa)
{
  sha384_hmac_ctx_t ctx;
  sha384_hmac_init (&ctx, pmk, 32);
  sha384_hmac_update_global_swap (&ctx, wpa->pmkid_data, 20);
  sha384_hmac_final (&ctx);

  const u32 r0 = h32_from_64_S (ctx.opad.h[0]);
  const u32 r1 = l32_from_64_S (ctx.opad.h[0]);
  const u32 r2 = h32_from_64_S (ctx.opad.h[1]);
  const u32 r3 = l32_from_64_S (ctx.opad.h[1]);

  return (r0 == wpa->pmkid[0])
      && (r1 == wpa->pmkid[1])
      && (r2 == wpa->pmkid[2])
      && (r3 == wpa->pmkid[3]);
}

DECLSPEC int wpa_check_eapol_md5 (PRIVATE_AS const u32 *pmk, GLOBAL_AS const wpa_universal_t *wpa)
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
      if (((bo_loops == 1) && (wpa->detected_le == 1)) || ((bo_loops != 1) && (bo == 0)))
      {
        t -= nec / 2; t += nc;
      }
      else
      {
        t = hc_swap32_S (t); t -= nec / 2; t += nc; t = hc_swap32_S (t);
      }

      if (wpa->nonce_compare < 0)
      {
        pke[15] = m0 | (t >> 24);
        pke[16] = m1 | (t << 8);
      }
      else
      {
        pke[23] = m0 | (t >> 24);
        pke[24] = m1 | (t << 8);
      }

      sha1_hmac_ctx_t ctx1;
      sha1_hmac_init (&ctx1, pmk, 32);
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

DECLSPEC int wpa_check_eapol_sha1 (PRIVATE_AS const u32 *pmk, GLOBAL_AS const wpa_universal_t *wpa)
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
      if (((bo_loops == 1) && (wpa->detected_le == 1)) || ((bo_loops != 1) && (bo == 0)))
      {
        t -= nec / 2; t += nc;
      }
      else
      {
        t = hc_swap32_S (t); t -= nec / 2; t += nc; t = hc_swap32_S (t);
      }

      if (wpa->nonce_compare < 0)
      {
        pke[15] = m0 | (t >> 24);
        pke[16] = m1 | (t << 8);
      }
      else
      {
        pke[23] = m0 | (t >> 24);
        pke[24] = m1 | (t << 8);
      }

      sha1_hmac_ctx_t ctx1;
      sha1_hmac_init (&ctx1, pmk, 32);
      sha1_hmac_update (&ctx1, pke, 100);
      sha1_hmac_final (&ctx1);

      sha1_hmac_ctx_t ctx2;
      sha1_hmac_init_64 (&ctx2, ctx1.opad.h, z, z, z);
      sha1_hmac_update_global_swap (&ctx2, wpa->eapol, wpa->eapol_len);
      sha1_hmac_final (&ctx2);

      if ((ctx2.opad.h[0] == wpa->keymic[0])
       && (ctx2.opad.h[1] == wpa->keymic[1])
       && (ctx2.opad.h[2] == wpa->keymic[2])
       && (ctx2.opad.h[3] == wpa->keymic[3])) return 1;
    }
  }
  return 0;
}

DECLSPEC int wpa_check_eapol_cmac256 (PRIVATE_AS const u32 *pmk, GLOBAL_AS const wpa_universal_t *wpa, SHM_TYPE u32 *s_te0, SHM_TYPE u32 *s_te1, SHM_TYPE u32 *s_te2, SHM_TYPE u32 *s_te3, SHM_TYPE u32 *s_te4)
{
  u32 pke[32];
  for (int i = 0; i < 32; i++) pke[i] = wpa->pke[i];

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
      if (((bo_loops == 1) && (wpa->detected_le == 1)) || ((bo_loops != 1) && (bo == 0)))
      {
        t -= nec / 2; t += nc;
      }
      else
      {
        t = hc_swap32_S (t); t -= nec / 2; t += nc; t = hc_swap32_S (t);
      }

      if (wpa->nonce_compare < 0)
      {
        pke[15] = m0 | (t >> 24);
        pke[16] = m1 | (t << 8);
      }
      else
      {
        pke[23] = m0 | (t >> 24);
        pke[24] = m1 | (t << 8);
      }

      sha256_hmac_ctx_t ctx1;
      sha256_hmac_init (&ctx1, pmk, 32);
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
      if (eapol_left < 16) make_kn (k);

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

DECLSPEC int wpa_check_eapol_sha384 (PRIVATE_AS const u32 *pmk, GLOBAL_AS const wpa_universal_t *wpa)
{
  u32 pke[32];
  for (int i = 0; i < 32; i++) pke[i] = wpa->pke[i];

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
      if (((bo_loops == 1) && (wpa->detected_le == 1)) || ((bo_loops != 1) && (bo == 0)))
      {
        t -= nec / 2; t += nc;
      }
      else
      {
        t = hc_swap32_S (t); t -= nec / 2; t += nc; t = hc_swap32_S (t);
      }

      if (wpa->nonce_compare < 0)
      {
        pke[15] = m0 | (t >> 24);
        pke[16] = m1 | (t << 8);
      }
      else
      {
        pke[23] = m0 | (t >> 24);
        pke[24] = m1 | (t << 8);
      }

      sha384_hmac_ctx_t ctx1;
      sha384_hmac_init (&ctx1, pmk, 32);
      sha384_hmac_update (&ctx1, pke, 102);
      sha384_hmac_final (&ctx1);

      u32 kck[32];
      for (int i = 0; i < 32; i++) kck[i] = 0;
      kck[0] = h32_from_64_S (ctx1.opad.h[0]);
      kck[1] = l32_from_64_S (ctx1.opad.h[0]);
      kck[2] = h32_from_64_S (ctx1.opad.h[1]);
      kck[3] = l32_from_64_S (ctx1.opad.h[1]);
      kck[4] = h32_from_64_S (ctx1.opad.h[2]);
      kck[5] = l32_from_64_S (ctx1.opad.h[2]);

      sha384_hmac_ctx_t ctx2;
      sha384_hmac_init (&ctx2, kck, 24);
      sha384_hmac_update_global_swap (&ctx2, wpa->eapol, wpa->eapol_len);
      sha384_hmac_final (&ctx2);

      if ((h32_from_64_S (ctx2.opad.h[0]) == wpa->keymic[0])
       && (l32_from_64_S (ctx2.opad.h[0]) == wpa->keymic[1])
       && (h32_from_64_S (ctx2.opad.h[1]) == wpa->keymic[2])
       && (l32_from_64_S (ctx2.opad.h[1]) == wpa->keymic[3])
       && (h32_from_64_S (ctx2.opad.h[2]) == wpa->keymic[4])
       && (l32_from_64_S (ctx2.opad.h[2]) == wpa->keymic[5])) return 1;
    }
  }
  return 0;
}

DECLSPEC int wpa_check_ft_pmkid_sha256 (PRIVATE_AS const u32 *pmk, GLOBAL_AS const wpa_universal_t *wpa)
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

  return (ctx2.h[0] == wpa->pmkid[0])
      && (ctx2.h[1] == wpa->pmkid[1])
      && (ctx2.h[2] == wpa->pmkid[2])
      && (ctx2.h[3] == wpa->pmkid[3]);
}

DECLSPEC int wpa_check_ft_eapol_cmac256 (PRIVATE_AS const u32 *pmk, GLOBAL_AS const wpa_universal_t *wpa, SHM_TYPE u32 *s_te0, SHM_TYPE u32 *s_te1, SHM_TYPE u32 *s_te2, SHM_TYPE u32 *s_te3, SHM_TYPE u32 *s_te4)
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
      if (((bo_loops == 1) && (wpa->detected_le == 1)) || ((bo_loops != 1) && (bo == 0)))
      {
        t -= nec / 2; t += nc;
      }
      else
      {
        t = hc_swap32_S (t); t -= nec / 2; t += nc; t = hc_swap32_S (t);
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
      if (eapol_left < 16) make_kn (k);

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

DECLSPEC void sha384_dgst_to_w6 (PRIVATE_AS const u64 *h, PRIVATE_AS u32 *w)
{
  w[0] = h32_from_64_S (h[0]); w[1] = l32_from_64_S (h[0]);
  w[2] = h32_from_64_S (h[1]); w[3] = l32_from_64_S (h[1]);
  w[4] = h32_from_64_S (h[2]); w[5] = l32_from_64_S (h[2]);
}

DECLSPEC void sha384_dgst_to_w12 (PRIVATE_AS const u64 *h, PRIVATE_AS u32 *w)
{
  w[ 0] = h32_from_64_S (h[0]); w[ 1] = l32_from_64_S (h[0]);
  w[ 2] = h32_from_64_S (h[1]); w[ 3] = l32_from_64_S (h[1]);
  w[ 4] = h32_from_64_S (h[2]); w[ 5] = l32_from_64_S (h[2]);
  w[ 6] = h32_from_64_S (h[3]); w[ 7] = l32_from_64_S (h[3]);
  w[ 8] = h32_from_64_S (h[4]); w[ 9] = l32_from_64_S (h[4]);
  w[10] = h32_from_64_S (h[5]); w[11] = l32_from_64_S (h[5]);
}

DECLSPEC int wpa_check_ft_pmkid_sha384 (PRIVATE_AS const u32 *pmk, GLOBAL_AS const wpa_universal_t *wpa)
{
  u32 pke[32];
  for (int i = 0; i < 32; i++) pke[i] = wpa->pke_r0[i];
  sha384_hmac_ctx_t ctx1;
  sha384_hmac_init (&ctx1, pmk, 32);
  sha384_hmac_update (&ctx1, pke, 19 + wpa->essid_len + wpa->r0khid_len);
  sha384_hmac_final (&ctx1);

  u32 salt[4];
  salt[0] = h32_from_64_S (ctx1.opad.h[0]);
  salt[1] = l32_from_64_S (ctx1.opad.h[0]);
  salt[2] = h32_from_64_S (ctx1.opad.h[1]);
  salt[3] = l32_from_64_S (ctx1.opad.h[1]);
  pke[ 0] = 0x46542d52;
  pke[ 1] = 0x304e0000 | (salt[0] >> 16);
  pke[ 2] = (salt[0] << 16) | (salt[1] >> 16);
  pke[ 3] = (salt[1] << 16) | (salt[2] >> 16);
  pke[ 4] = (salt[2] << 16) | (salt[3] >> 16);
  pke[ 5] = (salt[3] << 16);
  for (int i = 6; i < 32; i++) pke[i] = 0;

  sha384_ctx_t ctx2;
  sha384_init (&ctx2);
  sha384_update (&ctx2, pke, 22);
  sha384_final (&ctx2);

  u32 name[4];
  name[0] = h32_from_64_S (ctx2.h[0]);
  name[1] = l32_from_64_S (ctx2.h[0]);
  name[2] = h32_from_64_S (ctx2.h[1]);
  name[3] = l32_from_64_S (ctx2.h[1]);
  pke[ 0] = wpa->pmkid_data[ 0];
  pke[ 1] = wpa->pmkid_data[ 1] | (name[0] >> 16);
  pke[ 2] = wpa->pmkid_data[ 2] | (name[0] << 16) | (name[1] >> 16);
  pke[ 3] = wpa->pmkid_data[ 3] | (name[1] << 16) | (name[2] >> 16);
  pke[ 4] = wpa->pmkid_data[ 4] | (name[2] << 16) | (name[3] >> 16);
  pke[ 5] = wpa->pmkid_data[ 5] | (name[3] << 16);
  for (int i = 6; i < 32; i++) pke[i] = wpa->pmkid_data[i];

  sha384_init (&ctx2);
  sha384_update (&ctx2, pke, 28 + wpa->r1khid_len);
  sha384_final (&ctx2);

  return (h32_from_64_S (ctx2.h[0]) == wpa->pmkid[0])
      && (l32_from_64_S (ctx2.h[0]) == wpa->pmkid[1])
      && (h32_from_64_S (ctx2.h[1]) == wpa->pmkid[2])
      && (l32_from_64_S (ctx2.h[1]) == wpa->pmkid[3]);
}

DECLSPEC int wpa_check_ft_eapol_sha384 (PRIVATE_AS const u32 *pmk, GLOBAL_AS const wpa_universal_t *wpa)
{
  u32 pke[32];
  for (int i = 0; i < 32; i++) pke[i] = wpa->pke_r0[i];
  sha384_hmac_ctx_t ctx1;
  sha384_hmac_init (&ctx1, pmk, 32);
  sha384_hmac_update (&ctx1, pke, 19 + wpa->essid_len + wpa->r0khid_len);
  sha384_hmac_final (&ctx1);

  u32 r0[32];
  for (int i = 0; i < 32; i++) r0[i] = 0;
  sha384_dgst_to_w12 (ctx1.opad.h, r0);
  for (int i = 0; i < 32; i++) pke[i] = wpa->pke_r1[i];
  sha384_hmac_init (&ctx1, r0, 48);
  sha384_hmac_update (&ctx1, pke, 15 + wpa->r1khid_len);
  sha384_hmac_final (&ctx1);

  u32 r1[32];
  for (int i = 0; i < 32; i++) r1[i] = 0;
  sha384_dgst_to_w12 (ctx1.opad.h, r1);
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
      if (((bo_loops == 1) && (wpa->detected_le == 1)) || ((bo_loops != 1) && (bo == 0)))
      {
        t -= nec / 2; t += nc;
      }
      else
      {
        t = hc_swap32_S (t); t -= nec / 2; t += nc; t = hc_swap32_S (t);
      }

      pke[17] = t;

      sha384_hmac_init (&ctx1, r1, 48);
      sha384_hmac_update (&ctx1, pke, 86);
      sha384_hmac_final (&ctx1);

      u32 kck[32];
      for (int i = 0; i < 32; i++) kck[i] = 0;
      sha384_dgst_to_w6 (ctx1.opad.h, kck);

      sha384_hmac_ctx_t ctx2;
      sha384_hmac_init (&ctx2, kck, 24);
      sha384_hmac_update_global_swap (&ctx2, wpa->eapol, wpa->eapol_len);
      sha384_hmac_final (&ctx2);

      if ((h32_from_64_S (ctx2.opad.h[0]) == wpa->keymic[0])
       && (l32_from_64_S (ctx2.opad.h[0]) == wpa->keymic[1])
       && (h32_from_64_S (ctx2.opad.h[1]) == wpa->keymic[2])
       && (l32_from_64_S (ctx2.opad.h[1]) == wpa->keymic[3])
       && (h32_from_64_S (ctx2.opad.h[2]) == wpa->keymic[4])
       && (l32_from_64_S (ctx2.opad.h[2]) == wpa->keymic[5])) return 1;
    }
  }
  return 0;
}

#define WPA_AUX_PROLOGUE                                       \
  const u64 gid = get_global_id (0);                           \
  if (gid >= GID_CNT) return;                                  \
  const u32 digest_pos = LOOP_POS;                             \
  const u32 digest_cur = DIGESTS_OFFSET_HOST + digest_pos;     \
  GLOBAL_AS const wpa_universal_t *wpa = &esalt_bufs[digest_cur]; \
  u32 pmk[32];                                                 \
  for (int wi = 0; wi < 32; wi++) pmk[wi] = 0;                 \
  pmk[0] = tmps[gid].out[0]; pmk[1] = tmps[gid].out[1];        \
  pmk[2] = tmps[gid].out[2]; pmk[3] = tmps[gid].out[3];        \
  pmk[4] = tmps[gid].out[4]; pmk[5] = tmps[gid].out[5];        \
  pmk[6] = tmps[gid].out[6]; pmk[7] = tmps[gid].out[7];

#define WPA_MARK_IF(matched)                                                                          \
  if (matched)                                                                                        \
  {                                                                                                   \
    if (hc_atomic_inc (&hashes_shown[digest_cur]) == 0)                                               \
    {                                                                                                 \
      mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, digest_pos, digest_cur, gid, 0, 0, 0); \
    }                                                                                                 \
  }

#ifdef REAL_SHM
#define WPA_AES_SHARED                                         \
  const u64 lid = get_local_id (0);                            \
  const u64 lsz = get_local_size (0);                          \
  LOCAL_VK u32 s_te0[256];                                     \
  LOCAL_VK u32 s_te1[256];                                     \
  LOCAL_VK u32 s_te2[256];                                     \
  LOCAL_VK u32 s_te3[256];                                     \
  LOCAL_VK u32 s_te4[256];                                     \
  for (u32 i = lid; i < 256; i += lsz)                         \
  {                                                            \
    s_te0[i] = te0[i];                                         \
    s_te1[i] = te1[i];                                         \
    s_te2[i] = te2[i];                                         \
    s_te3[i] = te3[i];                                         \
    s_te4[i] = te4[i];                                         \
  }                                                            \
  SYNC_THREADS ();
#else
#define WPA_AES_SHARED                                         \
  CONSTANT_AS u32a *s_te0 = te0;                               \
  CONSTANT_AS u32a *s_te1 = te1;                               \
  CONSTANT_AS u32a *s_te2 = te2;                               \
  CONSTANT_AS u32a *s_te3 = te3;                               \
  CONSTANT_AS u32a *s_te4 = te4;
#endif

#define WPA_DISPATCH_ONE(matched)                                                                  \
  switch (wpa->type)                                                                               \
  {                                                                                                \
    case  1: matched = wpa_check_eapol_md5       (pmk, wpa); break;                                 \
    case  2: matched = wpa_check_pmkid_sha1      (pmk, wpa); break;                                 \
    case  3: matched = wpa_check_eapol_sha1      (pmk, wpa); break;                                 \
    case  4: matched = wpa_check_pmkid_sha256    (pmk, wpa); break;                                 \
    case  5: matched = wpa_check_eapol_cmac256   (pmk, wpa, s_te0, s_te1, s_te2, s_te3, s_te4); break; \
    case  6: matched = wpa_check_ft_pmkid_sha256 (pmk, wpa); break;                                 \
    case  7: matched = wpa_check_ft_eapol_cmac256(pmk, wpa, s_te0, s_te1, s_te2, s_te3, s_te4); break; \
    case  8: matched = wpa_check_pmkid_sha384    (pmk, wpa); break;                                 \
    case  9: matched = wpa_check_eapol_sha384    (pmk, wpa); break;                                 \
    case 10: matched = wpa_check_ft_pmkid_sha384 (pmk, wpa); break;                                 \
    case 11: matched = wpa_check_ft_eapol_sha384 (pmk, wpa); break;                                 \
  }

#endif // INC_WPA_PSK_UNIVERSAL_CL

#else
#include "inc_vendor.h"
#include "inc_types.h"
#include "inc_platform.h"
#include "inc_common.h"
#include "inc_hash_md5.h"
#include "inc_hash_sha1.h"
#include "inc_hash_sha256.h"
#include "inc_hash_sha384.h"
#include "inc_cipher_aes.h"
// (inc_wpa_psk_universal.cl inlined above)
#endif

KERNEL_FQ KERNEL_FA void m22003_init (KERN_ATTR_TMPS_ESALT (wpa_pmk_tmp_t, wpa_universal_t))
{
  const u64 gid = get_global_id (0);
  if (gid >= GID_CNT) return;

  u32 in[16];

  in[ 0] = pws[gid].i[ 0];
  in[ 1] = pws[gid].i[ 1];
  in[ 2] = pws[gid].i[ 2];
  in[ 3] = pws[gid].i[ 3];
  in[ 4] = pws[gid].i[ 4];
  in[ 5] = pws[gid].i[ 5];
  in[ 6] = pws[gid].i[ 6];
  in[ 7] = pws[gid].i[ 7];
  in[ 8] = pws[gid].i[ 8];
  in[ 9] = pws[gid].i[ 9];
  in[10] = pws[gid].i[10];
  in[11] = pws[gid].i[11];
  in[12] = pws[gid].i[12];
  in[13] = pws[gid].i[13];
  in[14] = pws[gid].i[14];
  in[15] = pws[gid].i[15];

  u32 out[8];

  PRIVATE_AS u8 *in_ptr  = (PRIVATE_AS u8 *) in;
  PRIVATE_AS u8 *out_ptr = (PRIVATE_AS u8 *) out;

  for (int i = 0, j = 0; i < 32; i += 1, j += 2)
  {
    out_ptr[i] = hex_to_u8 (in_ptr + j);
  }

  tmps[gid].out[0] = hc_swap32_S (out[0]);
  tmps[gid].out[1] = hc_swap32_S (out[1]);
  tmps[gid].out[2] = hc_swap32_S (out[2]);
  tmps[gid].out[3] = hc_swap32_S (out[3]);
  tmps[gid].out[4] = hc_swap32_S (out[4]);
  tmps[gid].out[5] = hc_swap32_S (out[5]);
  tmps[gid].out[6] = hc_swap32_S (out[6]);
  tmps[gid].out[7] = hc_swap32_S (out[7]);
}

KERNEL_FQ KERNEL_FA void m22003_loop (KERN_ATTR_TMPS_ESALT (wpa_pmk_tmp_t, wpa_universal_t))
{
  const u64 gid = get_global_id (0);
  if (gid >= GID_CNT) return;
}

KERNEL_FQ KERNEL_FA void m22003_comp (KERN_ATTR_TMPS_ESALT (wpa_pmk_tmp_t, wpa_universal_t))
{
}

KERNEL_FQ KERNEL_FA void m22003_aux1 (KERN_ATTR_TMPS_ESALT (wpa_pmk_tmp_t, wpa_universal_t))
{
  WPA_AUX_PROLOGUE

  int matched = 0;

  switch (wpa->type)
  {
    #ifdef ENABLE_TYPE_1
    case 1: matched = wpa_check_eapol_md5 (pmk, wpa); break;
    #endif
  }

  WPA_MARK_IF (matched)
}

KERNEL_FQ KERNEL_FA void m22003_aux2 (KERN_ATTR_TMPS_ESALT (wpa_pmk_tmp_t, wpa_universal_t))
{
  WPA_AUX_PROLOGUE

  int matched = 0;

  switch (wpa->type)
  {
    #ifdef ENABLE_TYPE_3
    case 3: matched = wpa_check_eapol_sha1 (pmk, wpa); break;
    #endif
  }

  WPA_MARK_IF (matched)
}

KERNEL_FQ KERNEL_FA void m22003_aux3 (KERN_ATTR_TMPS_ESALT (wpa_pmk_tmp_t, wpa_universal_t))
{
  WPA_AES_SHARED
  WPA_AUX_PROLOGUE

  int matched = 0;

  switch (wpa->type)
  {
    #ifdef ENABLE_TYPE_5
    case 5: matched = wpa_check_eapol_cmac256    (pmk, wpa, s_te0, s_te1, s_te2, s_te3, s_te4); break;
    #endif
    #ifdef ENABLE_TYPE_7
    case 7: matched = wpa_check_ft_eapol_cmac256 (pmk, wpa, s_te0, s_te1, s_te2, s_te3, s_te4); break;
    #endif
  }

  WPA_MARK_IF (matched)
}

KERNEL_FQ KERNEL_FA void m22003_aux4 (KERN_ATTR_TMPS_ESALT (wpa_pmk_tmp_t, wpa_universal_t))
{
  WPA_AUX_PROLOGUE

  int matched = 0;

  switch (wpa->type)
  {
    #ifdef ENABLE_TYPE_2
    case  2: matched = wpa_check_pmkid_sha1      (pmk, wpa); break;
    #endif
    #ifdef ENABLE_TYPE_4
    case  4: matched = wpa_check_pmkid_sha256    (pmk, wpa); break;
    #endif
    #ifdef ENABLE_TYPE_6
    case  6: matched = wpa_check_ft_pmkid_sha256 (pmk, wpa); break;
    #endif
    #ifdef ENABLE_TYPE_8
    case  8: matched = wpa_check_pmkid_sha384    (pmk, wpa); break;
    #endif
    #ifdef ENABLE_TYPE_10
    case 10: matched = wpa_check_ft_pmkid_sha384 (pmk, wpa); break;
    #endif
  }

  WPA_MARK_IF (matched)
}

KERNEL_FQ KERNEL_FA void m22003_aux5 (KERN_ATTR_TMPS_ESALT (wpa_pmk_tmp_t, wpa_universal_t))
{
  WPA_AUX_PROLOGUE

  int matched = 0;

  switch (wpa->type)
  {
    #ifdef ENABLE_TYPE_9
    case  9: matched = wpa_check_eapol_sha384    (pmk, wpa); break;
    #endif
    #ifdef ENABLE_TYPE_11
    case 11: matched = wpa_check_ft_eapol_sha384 (pmk, wpa); break;
    #endif
  }

  WPA_MARK_IF (matched)
}
