/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 *
 * Shared device core for the WPA-PSK "universal" modes (22002 passphrase /
 * 22003 PMK-direct) and the 90001-90010 architecture bake-off plugins.
 *
 * One esalt (wpa_universal_t), one PBKDF2 (init/loop), and eleven post-PMK
 * verifier functions covering every per-AKM WPA-PSK hash wpawolf emits
 * (WPA*01*..*11*). The 2-digit type code is the SOLE dispatch axis; each
 * bake-off kernel only differs in how these verifiers are wired into aux
 * kernels.
 *
 * All crypto here follows the IEEE 802.11 key hierarchy; constants are
 * explained inline rather than recalled from memory.
 */

#ifndef INC_WPA_PSK_UNIVERSAL_CL
#define INC_WPA_PSK_UNIVERSAL_CL

// NOTE: the includer must pull in the crypto-library headers (inc_common,
// inc_simd, inc_hash_md5/sha1/sha256/sha384, inc_cipher_aes) BEFORE us. The
// per-mode kernels do this directly; the host CPU-validation modules
// (90003 / 90007) include the .h forms (the device .cl forms lack include
// guards, so we must not pull them in ourselves).

// --- esalt / tmps structs (kept byte-identical with the host module header) ---

// PBKDF2 scratch carried across _init/_loop/_comp: the HMAC-SHA1 ipad/opad over
// the passphrase (reused every iteration) plus the running digest and the
// XOR-accumulated output for both 20-byte PBKDF2 blocks (40 bytes total).
typedef struct wpa_pbkdf2_tmp
{
  u32 ipad[5];          // HMAC-SHA1 inner-key state for the passphrase (5 BE words)
  u32 opad[5];          // HMAC-SHA1 outer-key state for the passphrase (5 BE words)

  u32 dgst[10];         // running HMAC digest, two 20-byte streams back to back
  u32 out[10];          // accumulated PBKDF2 output, two 20-byte streams (PMK = first 32 B)

} wpa_pbkdf2_tmp_t;

// PMK-direct scratch (mode 22003): the 32-byte PMK is supplied as the candidate,
// so no PBKDF2 runs and out[] holds the PMK verbatim.
typedef struct wpa_pmk_tmp
{
  u32 out[8];           // the 32-byte PMK, ready for the verifiers

} wpa_pmk_tmp_t;

// The single esalt covering all 11 types: handshake data the verifiers consume.
// Even types (PMKID) use pmkid/pmkid_data; odd types (EAPOL) use keymic/anonce/
// eapol/pke; FT types additionally use the mdid/r0khid/r1khid/pke_r0/pke_r1 set.
typedef struct wpa_universal
{
  u32  essid_buf[16];   // ESSID bytes, zero-padded -- also serves as the salt_t salt
  u32  essid_len;       // ESSID length in bytes (PBKDF2 salt length)

  u32  mac_ap[2];       // 6-byte AP MAC (the BSSID / authenticator address)
  u32  mac_sta[2];      // 6-byte station MAC (the supplicant address)

  u32  type;            // 1..11 -- the sole dispatch axis (never sniff the key version)

  // PMKID rows (even types 2,4,6,8,10)
  u32  pmkid[4];        // 16-byte target PMKID (every family truncates the HMAC to 128 bits)
  u32  pmkid_data[32];  // non-FT: "PMK Name" || AP MAC || STA MAC ; FT: "FT-R1N" template with a 16-byte gap for the Name

  // EAPOL rows (odd types 1,3,5,7,9,11)
  u32  keymic[6];       // 16-byte (types 1,3,5,7) or 24-byte (types 9,11) target MIC
  u32  anonce[8];       // 32-byte external nonce (ANonce or SNonce depending on the message pair)
  u32  eapol[256 + 16]; // the EAPOL-Key frame with its MIC field zeroed (what the MIC is computed over); 1088 B because real FT M3 frames reach ~515 B, far past the legacy 256 B cap
  u32  eapol_len;       // EAPOL frame length in bytes
  u32  pke[32];         // non-FT PTK input (PRF/KDF block) OR FT-PTK input template, prebuilt byte-swapped to BE

  u32  keyver;          // kept only to make the EAPOL digest unique; verifiers never branch on it

  // FT extras (types 6,7,10,11)
  u32  mdid[1];                 // 2-byte Mobility Domain ID
  u32  r0khid[12]; u32 r0khid_len;   // 1..48-byte R0 key holder ID
  u32  r1khid[12]; u32 r1khid_len;   // 6-byte R1 key holder ID (a MAC)
  u32  pke_r0[32];      // FT-R0 KDF input template (host-built, byte-swapped to BE)
  u32  pke_r1[32];      // FT-R1 KDF input template (host-built, byte-swapped to BE)

  // message-pair / nonce correction (EAPOL) -- identical semantics to m22000 wpa_t
  int  message_pair_chgd;   u32 message_pair;       // which of the four handshake messages was captured
  int  nonce_error_corrections_chgd;  int nonce_error_corrections;  // half-window of nonce guesses to sweep
  int  nonce_compare;  int detected_le;  int detected_be;  // nonce-half selector and which replay-counter byte orders to try

} wpa_universal_t;

// Per-workitem hook buffer for the CPU-validation plugins (90003 / 90007).
// The hook23 kernel (which has esalt access) copies the PMK plus a snapshot of
// each of the salt's digests here; module_hook23 then runs the verifiers on the
// host and records a per-digest match bitmask the comp kernel reads. The
// hashcat hook API does not expose esalts to host hook code, so staging them
// through this buffer is how the CPU side sees them.
#define WPA_HOOK_MAXD 8   // corpus max is 4 distinct digests / ESSID; 8 gives headroom

typedef struct wpa_hook
{
  u32 pmk[8];                     // the 32-byte PMK the host verifiers consume
  u32 ndig;                       // number of digests staged in dig[]
  u32 ok;                         // match bitmask: bit dp set => digest dp validated on the host
  wpa_universal_t dig[WPA_HOOK_MAXD];  // per-digest esalt snapshots the host re-runs

} wpa_hook_t;

// --- shared helpers (lifted from m22000 / m37100) ---

// AES-CMAC subkey derivation: logically left-shift the 128-bit block by one bit,
// and if the bit shifted off the top was set, XOR the Rb constant 0x87 into the
// low byte. Done over four big-endian u32 words.
DECLSPEC void make_kn (PRIVATE_AS u32 *k)
{
  u32 kl[4];            // left part: each word shifted left one bit
  u32 kr[4];            // right part: the bit carried in from the next word

  kl[0] = (k[0] << 1) & 0xfefefefe;   // shift left, mask off the bit that would cross a byte boundary
  kl[1] = (k[1] << 1) & 0xfefefefe;
  kl[2] = (k[2] << 1) & 0xfefefefe;
  kl[3] = (k[3] << 1) & 0xfefefefe;

  kr[0] = (k[0] >> 7) & 0x01010101;   // isolate each byte's top bit, which feeds the next-lower byte
  kr[1] = (k[1] >> 7) & 0x01010101;
  kr[2] = (k[2] >> 7) & 0x01010101;
  kr[3] = (k[3] >> 7) & 0x01010101;

  const u32 c = kr[0] & 1;            // the overall MSB that shifted out of the 128-bit block

  kr[0] = kr[0] >> 8 | kr[1] << 24;   // realign carry bits so each lands in the next-higher byte position
  kr[1] = kr[1] >> 8 | kr[2] << 24;
  kr[2] = kr[2] >> 8 | kr[3] << 24;
  kr[3] = kr[3] >> 8;

  k[0] = kl[0] | kr[0];               // recombine shifted body with the cross-byte carries
  k[1] = kl[1] | kr[1];
  k[2] = kl[2] | kr[2];
  k[3] = kl[3] | kr[3];

  k[3] ^= c * 0x87000000;             // if the top bit shifted out, XOR Rb (0x87) into the low byte
}

// One vectorised HMAC-SHA1 inner block, the PBKDF2 _loop primitive: transform
// the message with the ipad state, then load the 20-byte result plus 0x80
// padding and the (64+20)*8 bit-length and transform again with the opad state.
DECLSPEC void hmac_sha1_run_V (PRIVATE_AS u32x *w0, PRIVATE_AS u32x *w1, PRIVATE_AS u32x *w2, PRIVATE_AS u32x *w3, PRIVATE_AS const u32x *ipad, PRIVATE_AS const u32x *opad, PRIVATE_AS u32x *digest)
{
  digest[0] = ipad[0];   // seed the inner hash with the precomputed ipad state
  digest[1] = ipad[1];
  digest[2] = ipad[2];
  digest[3] = ipad[3];
  digest[4] = ipad[4];

  sha1_transform_vector (w0, w1, w2, w3, digest);   // inner block: H(ipad || message)

  w0[0] = digest[0];     // place the 20-byte inner digest as the outer message
  w0[1] = digest[1];
  w0[2] = digest[2];
  w0[3] = digest[3];
  w1[0] = digest[4];
  w1[1] = 0x80000000;    // SHA-1 padding: a single 1 bit after the message
  w1[2] = 0;
  w1[3] = 0;
  w2[0] = 0;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;
  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = (64 + 20) * 8; // length field: one 64-byte block of key + 20-byte inner digest, in bits

  digest[0] = opad[0];   // seed the outer hash with the precomputed opad state
  digest[1] = opad[1];
  digest[2] = opad[2];
  digest[3] = opad[3];
  digest[4] = opad[4];

  sha1_transform_vector (w0, w1, w2, w3, digest);   // outer block: H(opad || inner) = HMAC result
}

// --- PBKDF2-HMAC-SHA1(passphrase, ESSID, 4096 iters, 32-byte PMK) for all 11 types ---

// _init body: build the HMAC ipad/opad over the passphrase, then seed the two
// PBKDF2 streams. PBKDF2 needs two 20-byte blocks to reach 40 bytes (the PMK is
// the first 32); block index 1 and 2 are HMACed over the ESSID, and that first
// transform counts as iteration 1 of the 4096.
DECLSPEC void wpa_pbkdf2_init (GLOBAL_AS pw_t *pws, GLOBAL_AS wpa_pbkdf2_tmp_t *tmps, GLOBAL_AS const wpa_universal_t *esalt_bufs, const u64 gid, const u64 digests_offset)
{
  sha1_hmac_ctx_t sha1_hmac_ctx0;     // HMAC keyed on the passphrase, reused by both streams

  sha1_hmac_init_global_swap (&sha1_hmac_ctx0, pws[gid].i, pws[gid].pw_len);   // key = passphrase; _swap to BE for SHA-1

  tmps[gid].ipad[0] = sha1_hmac_ctx0.ipad.h[0];   // stash the passphrase ipad state for _loop to reuse
  tmps[gid].ipad[1] = sha1_hmac_ctx0.ipad.h[1];
  tmps[gid].ipad[2] = sha1_hmac_ctx0.ipad.h[2];
  tmps[gid].ipad[3] = sha1_hmac_ctx0.ipad.h[3];
  tmps[gid].ipad[4] = sha1_hmac_ctx0.ipad.h[4];

  tmps[gid].opad[0] = sha1_hmac_ctx0.opad.h[0];   // stash the passphrase opad state for _loop to reuse
  tmps[gid].opad[1] = sha1_hmac_ctx0.opad.h[1];
  tmps[gid].opad[2] = sha1_hmac_ctx0.opad.h[2];
  tmps[gid].opad[3] = sha1_hmac_ctx0.opad.h[3];
  tmps[gid].opad[4] = sha1_hmac_ctx0.opad.h[4];

  sha1_hmac_update_global_swap (&sha1_hmac_ctx0, esalt_bufs[digests_offset].essid_buf, esalt_bufs[digests_offset].essid_len);  // feed the ESSID salt

  u32 w0[4];            // scratch message words for the appended block index
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  // stream 1: HMAC(passphrase, ESSID || big-endian 32-bit block index 1)
  sha1_hmac_ctx_t sha1_hmac_ctx1 = sha1_hmac_ctx0;   // fork the ESSID-primed context

  w0[0] = 1; w0[1] = 0; w0[2] = 0; w0[3] = 0;   // block index 1 as a big-endian 32-bit value
  w1[0] = 0; w1[1] = 0; w1[2] = 0; w1[3] = 0;
  w2[0] = 0; w2[1] = 0; w2[2] = 0; w2[3] = 0;
  w3[0] = 0; w3[1] = 0; w3[2] = 0; w3[3] = 0;

  sha1_hmac_update_64 (&sha1_hmac_ctx1, w0, w1, w2, w3, 4);   // append the 4-byte index
  sha1_hmac_final (&sha1_hmac_ctx1);                          // first PBKDF2 transform = iteration 1

  tmps[gid].dgst[0] = sha1_hmac_ctx1.opad.h[0];   // running digest of stream 1 starts at U_1
  tmps[gid].dgst[1] = sha1_hmac_ctx1.opad.h[1];
  tmps[gid].dgst[2] = sha1_hmac_ctx1.opad.h[2];
  tmps[gid].dgst[3] = sha1_hmac_ctx1.opad.h[3];
  tmps[gid].dgst[4] = sha1_hmac_ctx1.opad.h[4];

  tmps[gid].out[0] = sha1_hmac_ctx1.opad.h[0];    // accumulated output of stream 1 also starts at U_1
  tmps[gid].out[1] = sha1_hmac_ctx1.opad.h[1];
  tmps[gid].out[2] = sha1_hmac_ctx1.opad.h[2];
  tmps[gid].out[3] = sha1_hmac_ctx1.opad.h[3];
  tmps[gid].out[4] = sha1_hmac_ctx1.opad.h[4];

  // stream 2: HMAC(passphrase, ESSID || big-endian 32-bit block index 2)
  sha1_hmac_ctx_t sha1_hmac_ctx2 = sha1_hmac_ctx0;   // fork the same ESSID-primed context

  w0[0] = 2; w0[1] = 0; w0[2] = 0; w0[3] = 0;   // block index 2 as a big-endian 32-bit value
  w1[0] = 0; w1[1] = 0; w1[2] = 0; w1[3] = 0;
  w2[0] = 0; w2[1] = 0; w2[2] = 0; w2[3] = 0;
  w3[0] = 0; w3[1] = 0; w3[2] = 0; w3[3] = 0;

  sha1_hmac_update_64 (&sha1_hmac_ctx2, w0, w1, w2, w3, 4);   // append the 4-byte index
  sha1_hmac_final (&sha1_hmac_ctx2);                          // first transform of stream 2

  tmps[gid].dgst[5] = sha1_hmac_ctx2.opad.h[0];   // running digest of stream 2 (second 20-byte block)
  tmps[gid].dgst[6] = sha1_hmac_ctx2.opad.h[1];
  tmps[gid].dgst[7] = sha1_hmac_ctx2.opad.h[2];
  tmps[gid].dgst[8] = sha1_hmac_ctx2.opad.h[3];
  tmps[gid].dgst[9] = sha1_hmac_ctx2.opad.h[4];

  tmps[gid].out[5] = sha1_hmac_ctx2.opad.h[0];    // accumulated output of stream 2 starts at its U_1
  tmps[gid].out[6] = sha1_hmac_ctx2.opad.h[1];
  tmps[gid].out[7] = sha1_hmac_ctx2.opad.h[2];
  tmps[gid].out[8] = sha1_hmac_ctx2.opad.h[3];
  tmps[gid].out[9] = sha1_hmac_ctx2.opad.h[4];
}

// _loop body: the slow 4096-1 remaining iterations (init did iteration 1) of
// XOR-accumulate over both PBKDF2 streams, vectorised across SIMD lanes.
DECLSPEC void wpa_pbkdf2_loop (GLOBAL_AS wpa_pbkdf2_tmp_t *tmps, const u64 gid, const u32 loop_cnt)
{
  u32x ipad[5];         // passphrase ipad state gathered across SIMD lanes
  u32x opad[5];         // passphrase opad state gathered across SIMD lanes

  ipad[0] = packv (tmps, ipad, gid, 0);   // gather one ipad word from each lane's tmps
  ipad[1] = packv (tmps, ipad, gid, 1);
  ipad[2] = packv (tmps, ipad, gid, 2);
  ipad[3] = packv (tmps, ipad, gid, 3);
  ipad[4] = packv (tmps, ipad, gid, 4);

  opad[0] = packv (tmps, opad, gid, 0);   // gather one opad word from each lane's tmps
  opad[1] = packv (tmps, opad, gid, 1);
  opad[2] = packv (tmps, opad, gid, 2);
  opad[3] = packv (tmps, opad, gid, 3);
  opad[4] = packv (tmps, opad, gid, 4);

  u32x dgst[5];         // running digest for the stream being processed
  u32x out[5];          // accumulated output for the stream being processed

  dgst[0] = packv (tmps, dgst, gid, 0);   // stream 1 running digest, lanes gathered
  dgst[1] = packv (tmps, dgst, gid, 1);
  dgst[2] = packv (tmps, dgst, gid, 2);
  dgst[3] = packv (tmps, dgst, gid, 3);
  dgst[4] = packv (tmps, dgst, gid, 4);

  out[0] = packv (tmps, out, gid, 0);     // stream 1 accumulator, lanes gathered
  out[1] = packv (tmps, out, gid, 1);
  out[2] = packv (tmps, out, gid, 2);
  out[3] = packv (tmps, out, gid, 3);
  out[4] = packv (tmps, out, gid, 4);

  for (u32 j = 0; j < loop_cnt; j++)      // perform this call's slice of the 4095 iterations
  {
    u32x w0[4];         // message words = the previous iteration's digest, padded
    u32x w1[4];
    u32x w2[4];
    u32x w3[4];

    w0[0] = dgst[0];    // feed the running digest back in as the next HMAC message
    w0[1] = dgst[1];
    w0[2] = dgst[2];
    w0[3] = dgst[3];
    w1[0] = dgst[4];
    w1[1] = 0x80000000; // SHA-1 padding bit
    w1[2] = 0;
    w1[3] = 0;
    w2[0] = 0;
    w2[1] = 0;
    w2[2] = 0;
    w2[3] = 0;
    w3[0] = 0;
    w3[1] = 0;
    w3[2] = 0;
    w3[3] = (64 + 20) * 8;   // length of key block + 20-byte digest in bits

    hmac_sha1_run_V (w0, w1, w2, w3, ipad, opad, dgst);   // U_{n+1} = HMAC(passphrase, U_n)

    out[0] ^= dgst[0];  // XOR each U into the PBKDF2 accumulator
    out[1] ^= dgst[1];
    out[2] ^= dgst[2];
    out[3] ^= dgst[3];
    out[4] ^= dgst[4];
  }

  unpackv (tmps, dgst, gid, 0, dgst[0]);  // scatter stream 1 running digest back to per-lane tmps
  unpackv (tmps, dgst, gid, 1, dgst[1]);
  unpackv (tmps, dgst, gid, 2, dgst[2]);
  unpackv (tmps, dgst, gid, 3, dgst[3]);
  unpackv (tmps, dgst, gid, 4, dgst[4]);

  unpackv (tmps, out, gid, 0, out[0]);    // scatter stream 1 accumulator back to per-lane tmps
  unpackv (tmps, out, gid, 1, out[1]);
  unpackv (tmps, out, gid, 2, out[2]);
  unpackv (tmps, out, gid, 3, out[3]);
  unpackv (tmps, out, gid, 4, out[4]);

  dgst[0] = packv (tmps, dgst, gid, 5);   // gather stream 2 running digest (second 20-byte block)
  dgst[1] = packv (tmps, dgst, gid, 6);
  dgst[2] = packv (tmps, dgst, gid, 7);
  dgst[3] = packv (tmps, dgst, gid, 8);
  dgst[4] = packv (tmps, dgst, gid, 9);

  out[0] = packv (tmps, out, gid, 5);     // gather stream 2 accumulator
  out[1] = packv (tmps, out, gid, 6);
  out[2] = packv (tmps, out, gid, 7);
  out[3] = packv (tmps, out, gid, 8);
  out[4] = packv (tmps, out, gid, 9);

  for (u32 j = 0; j < loop_cnt; j++)      // same slice of iterations for stream 2
  {
    u32x w0[4];
    u32x w1[4];
    u32x w2[4];
    u32x w3[4];

    w0[0] = dgst[0];    // feed stream 2's running digest back in
    w0[1] = dgst[1];
    w0[2] = dgst[2];
    w0[3] = dgst[3];
    w1[0] = dgst[4];
    w1[1] = 0x80000000; // SHA-1 padding bit
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

    hmac_sha1_run_V (w0, w1, w2, w3, ipad, opad, dgst);   // U_{n+1} for stream 2

    out[0] ^= dgst[0];  // XOR into stream 2 accumulator
    out[1] ^= dgst[1];
    out[2] ^= dgst[2];
    out[3] ^= dgst[3];
    out[4] ^= dgst[4];
  }

  unpackv (tmps, dgst, gid, 5, dgst[0]);  // scatter stream 2 running digest back
  unpackv (tmps, dgst, gid, 6, dgst[1]);
  unpackv (tmps, dgst, gid, 7, dgst[2]);
  unpackv (tmps, dgst, gid, 8, dgst[3]);
  unpackv (tmps, dgst, gid, 9, dgst[4]);

  unpackv (tmps, out, gid, 5, out[0]);    // scatter stream 2 accumulator back
  unpackv (tmps, out, gid, 6, out[1]);
  unpackv (tmps, out, gid, 7, out[2]);
  unpackv (tmps, out, gid, 8, out[3]);
  unpackv (tmps, out, gid, 9, out[4]);
}

// === Eleven post-PMK verifiers. PMK = pmk[0..8] (big-endian words, 32 B). ======
// Each returns 1 on MIC/PMKID match, 0 otherwise. The caller (an aux kernel)
// owns the mark_hash.

// ---- PMKID verifiers: first 16 bytes of HMAC-Hash(PMK, "PMK Name"||AP||STA) ----

// type 2: PMKID = first 16 bytes of HMAC-SHA1(PMK, "PMK Name" || AP MAC || STA MAC).
DECLSPEC int wpa_check_pmkid_sha1 (PRIVATE_AS const u32 *pmk, GLOBAL_AS const wpa_universal_t *wpa)
{
  sha1_hmac_ctx_t ctx;
  sha1_hmac_init (&ctx, pmk, 32);                                 // key = the 32-byte PMK
  sha1_hmac_update_global_swap (&ctx, wpa->pmkid_data, 20);       // message = "PMK Name"||AP||STA (20 B), swapped to BE
  sha1_hmac_final (&ctx);

  return (ctx.opad.h[0] == wpa->pmkid[0])      // compare the first 16 bytes (4 BE words) against the target
      && (ctx.opad.h[1] == wpa->pmkid[1])
      && (ctx.opad.h[2] == wpa->pmkid[2])
      && (ctx.opad.h[3] == wpa->pmkid[3]);
}

// type 4: identical to type 2 with SHA-256 in place of SHA-1.
DECLSPEC int wpa_check_pmkid_sha256 (PRIVATE_AS const u32 *pmk, GLOBAL_AS const wpa_universal_t *wpa)
{
  sha256_hmac_ctx_t ctx;
  sha256_hmac_init (&ctx, pmk, 32);                               // key = the PMK
  sha256_hmac_update_global_swap (&ctx, wpa->pmkid_data, 20);     // message = "PMK Name"||AP||STA
  sha256_hmac_final (&ctx);

  return (ctx.opad.h[0] == wpa->pmkid[0])      // compare the first 16 bytes of the SHA-256 HMAC
      && (ctx.opad.h[1] == wpa->pmkid[1])
      && (ctx.opad.h[2] == wpa->pmkid[2])
      && (ctx.opad.h[3] == wpa->pmkid[3]);
}

// type 8: same PMKID over SHA-384. SHA-384 emits 64-bit words, so the first 16
// bytes are the high/low 32-bit halves of h[0] and h[1].
DECLSPEC int wpa_check_pmkid_sha384 (PRIVATE_AS const u32 *pmk, GLOBAL_AS const wpa_universal_t *wpa)
{
  sha384_hmac_ctx_t ctx;
  sha384_hmac_init (&ctx, pmk, 32);                               // key = the PMK
  sha384_hmac_update_global_swap (&ctx, wpa->pmkid_data, 20);     // message = "PMK Name"||AP||STA
  sha384_hmac_final (&ctx);

  const u32 r0 = h32_from_64_S (ctx.opad.h[0]);   // first 4 bytes = high half of digest word 0
  const u32 r1 = l32_from_64_S (ctx.opad.h[0]);   // next 4 bytes = low half of digest word 0
  const u32 r2 = h32_from_64_S (ctx.opad.h[1]);   // bytes 8..11 = high half of digest word 1
  const u32 r3 = l32_from_64_S (ctx.opad.h[1]);   // bytes 12..15 = low half of digest word 1

  return (r0 == wpa->pmkid[0])                 // compare the first 16 bytes against the target
      && (r1 == wpa->pmkid[1])
      && (r2 == wpa->pmkid[2])
      && (r3 == wpa->pmkid[3]);
}

// ---- non-FT EAPOL verifiers: derive the PTK, take the KCK, MAC the zeroed
//      EAPOL frame, and sweep nonce / replay-counter-endianness corrections ----

// type 1: PRF-HMAC-SHA1 PTK -> 16-byte KCK; MIC = HMAC-MD5(KCK, eapol), 16 bytes.
DECLSPEC int wpa_check_eapol_md5 (PRIVATE_AS const u32 *pmk, GLOBAL_AS const wpa_universal_t *wpa)
{
  u32 pke[32];
  for (int i = 0; i < 32; i++) pke[i] = wpa->pke[i];   // local copy of the PRF input so we can patch the nonce

  u32 z[4] = { 0, 0, 0, 0 };   // zero block used to zero-pad the MD5 HMAC key

  u32 to, m0, m1;              // to = the captured nonce word; m0/m1 = surrounding bytes to preserve
  if (wpa->nonce_compare < 0)
  {
    m0 = pke[15] & ~0x000000ff; m1 = pke[16] & ~0xffffff00;   // patch nonce in the lower half of the PRF block
    to = pke[15] << 24 | pke[16] >> 8;
  }
  else
  {
    m0 = pke[23] & ~0x000000ff; m1 = pke[24] & ~0xffffff00;   // patch nonce in the upper half of the PRF block
    to = pke[23] << 24 | pke[24] >> 8;
  }

  u32 bo_loops = wpa->detected_le + wpa->detected_be;   // how many replay-counter byte orders to try
  bo_loops = (bo_loops == 0) ? 2 : bo_loops;            // unknown endianness => try both

  const u32 nec = wpa->nonce_error_corrections;         // half-window of nonce values to sweep

  for (u32 nc = 0; nc <= nec; nc++)        // sweep nonce corrections (a clean capture matches at the center)
  {
    for (u32 bo = 0; bo < bo_loops; bo++)  // try each candidate byte order
    {
      u32 t = to;
      if (((bo_loops == 1) && (wpa->detected_le == 1)) || ((bo_loops != 1) && (bo == 0)))
      {
        t -= nec / 2; t += nc;             // little-endian path: offset the nonce around the captured value
      }
      else
      {
        t = hc_swap32_S (t); t -= nec / 2; t += nc; t = hc_swap32_S (t);   // big-endian path: swap, offset, swap back
      }

      if (wpa->nonce_compare < 0)   // write the patched nonce back (lower half)
      {
        pke[15] = m0 | (t >> 24);
        pke[16] = m1 | (t << 8);
      }
      else                          // (upper half)
      {
        pke[23] = m0 | (t >> 24);
        pke[24] = m1 | (t << 8);
      }

      sha1_hmac_ctx_t ctx1;
      sha1_hmac_init (&ctx1, pmk, 32);     // PRF keyed on the PMK
      sha1_hmac_update (&ctx1, pke, 100);  // message = "Pairwise key expansion" || sorted MACs || sorted nonces
      sha1_hmac_final (&ctx1);

      // The MD5 HMAC key is little-endian (MD5 is not byte-swapped), but the
      // KCK came out of SHA-1 as big-endian words, so swap each to LE bytes.
      ctx1.opad.h[0] = hc_swap32_S (ctx1.opad.h[0]);
      ctx1.opad.h[1] = hc_swap32_S (ctx1.opad.h[1]);
      ctx1.opad.h[2] = hc_swap32_S (ctx1.opad.h[2]);
      ctx1.opad.h[3] = hc_swap32_S (ctx1.opad.h[3]);

      md5_hmac_ctx_t ctx2;
      md5_hmac_init_64 (&ctx2, ctx1.opad.h, z, z, z);                 // key = KCK, zero-padded to the HMAC block
      md5_hmac_update_global (&ctx2, wpa->eapol, wpa->eapol_len);     // MAC the zeroed EAPOL frame (MD5 reads LE, no swap)
      md5_hmac_final (&ctx2);

      // MD5 output is little-endian; swap each word to BE to compare with the
      // big-endian-stored target MIC.
      if ((hc_swap32_S (ctx2.opad.h[0]) == wpa->keymic[0])
       && (hc_swap32_S (ctx2.opad.h[1]) == wpa->keymic[1])
       && (hc_swap32_S (ctx2.opad.h[2]) == wpa->keymic[2])
       && (hc_swap32_S (ctx2.opad.h[3]) == wpa->keymic[3])) return 1;  // 16-byte MIC matched
    }
  }
  return 0;
}

// type 3: PRF-HMAC-SHA1 PTK -> 16-byte KCK; MIC = HMAC-SHA1(KCK, eapol) truncated to 128 bits.
DECLSPEC int wpa_check_eapol_sha1 (PRIVATE_AS const u32 *pmk, GLOBAL_AS const wpa_universal_t *wpa)
{
  u32 pke[32];
  for (int i = 0; i < 32; i++) pke[i] = wpa->pke[i];   // local copy to patch the nonce

  u32 z[4] = { 0, 0, 0, 0 };   // zero block to pad the inner HMAC key

  u32 to, m0, m1;
  if (wpa->nonce_compare < 0)
  {
    m0 = pke[15] & ~0x000000ff; m1 = pke[16] & ~0xffffff00;   // nonce in lower half of PRF block
    to = pke[15] << 24 | pke[16] >> 8;
  }
  else
  {
    m0 = pke[23] & ~0x000000ff; m1 = pke[24] & ~0xffffff00;   // nonce in upper half
    to = pke[23] << 24 | pke[24] >> 8;
  }

  u32 bo_loops = wpa->detected_le + wpa->detected_be;   // candidate byte orders
  bo_loops = (bo_loops == 0) ? 2 : bo_loops;

  const u32 nec = wpa->nonce_error_corrections;

  for (u32 nc = 0; nc <= nec; nc++)        // nonce-correction sweep
  {
    for (u32 bo = 0; bo < bo_loops; bo++)
    {
      u32 t = to;
      if (((bo_loops == 1) && (wpa->detected_le == 1)) || ((bo_loops != 1) && (bo == 0)))
      {
        t -= nec / 2; t += nc;             // LE offset
      }
      else
      {
        t = hc_swap32_S (t); t -= nec / 2; t += nc; t = hc_swap32_S (t);   // BE offset
      }

      if (wpa->nonce_compare < 0)   // patch nonce back
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
      sha1_hmac_init (&ctx1, pmk, 32);     // PRF keyed on the PMK
      sha1_hmac_update (&ctx1, pke, 100);  // PRF input block
      sha1_hmac_final (&ctx1);

      sha1_hmac_ctx_t ctx2;
      sha1_hmac_init_64 (&ctx2, ctx1.opad.h, z, z, z);                    // MIC key = KCK (BE words), zero-padded
      sha1_hmac_update_global_swap (&ctx2, wpa->eapol, wpa->eapol_len);   // MAC the zeroed EAPOL frame
      sha1_hmac_final (&ctx2);

      // SHA-1 output is already big-endian; compare the first 16 bytes directly.
      if ((ctx2.opad.h[0] == wpa->keymic[0])
       && (ctx2.opad.h[1] == wpa->keymic[1])
       && (ctx2.opad.h[2] == wpa->keymic[2])
       && (ctx2.opad.h[3] == wpa->keymic[3])) return 1;
    }
  }
  return 0;
}

// type 5: KDF-HMAC-SHA256 PTK (key-length field 0x0180 = 384 bits) -> 16-byte KCK;
// MIC = AES-128-CMAC(KCK, eapol), 16 bytes.
DECLSPEC int wpa_check_eapol_cmac256 (PRIVATE_AS const u32 *pmk, GLOBAL_AS const wpa_universal_t *wpa, SHM_TYPE u32 *s_te0, SHM_TYPE u32 *s_te1, SHM_TYPE u32 *s_te2, SHM_TYPE u32 *s_te3, SHM_TYPE u32 *s_te4)
{
  u32 pke[32];
  for (int i = 0; i < 32; i++) pke[i] = wpa->pke[i];   // local copy of the KDF input to patch the nonce

  u32 to, m0, m1;
  if (wpa->nonce_compare < 0)
  {
    m0 = pke[15] & ~0x000000ff; m1 = pke[16] & ~0xffffff00;   // nonce in lower half
    to = pke[15] << 24 | pke[16] >> 8;
  }
  else
  {
    m0 = pke[23] & ~0x000000ff; m1 = pke[24] & ~0xffffff00;   // nonce in upper half
    to = pke[23] << 24 | pke[24] >> 8;
  }

  u32 bo_loops = wpa->detected_le + wpa->detected_be;
  bo_loops = (bo_loops == 0) ? 2 : bo_loops;

  const u32 nec = wpa->nonce_error_corrections;

  for (u32 nc = 0; nc <= nec; nc++)        // nonce-correction sweep
  {
    for (u32 bo = 0; bo < bo_loops; bo++)
    {
      u32 t = to;
      if (((bo_loops == 1) && (wpa->detected_le == 1)) || ((bo_loops != 1) && (bo == 0)))
      {
        t -= nec / 2; t += nc;             // LE offset
      }
      else
      {
        t = hc_swap32_S (t); t -= nec / 2; t += nc; t = hc_swap32_S (t);   // BE offset
      }

      if (wpa->nonce_compare < 0)   // patch nonce back
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
      sha256_hmac_init (&ctx1, pmk, 32);   // KDF keyed on the PMK
      sha256_hmac_update (&ctx1, pke, 102);   // one KDF block: counter || label || context || key-length-in-bits
      sha256_hmac_final (&ctx1);

      // The AES key is consumed little-endian; the KCK came from SHA-256 as
      // big-endian words, so swap each to LE bytes.
      ctx1.opad.h[0] = hc_swap32_S (ctx1.opad.h[0]);
      ctx1.opad.h[1] = hc_swap32_S (ctx1.opad.h[1]);
      ctx1.opad.h[2] = hc_swap32_S (ctx1.opad.h[2]);
      ctx1.opad.h[3] = hc_swap32_S (ctx1.opad.h[3]);

      u32 ks[44];
      aes128_set_encrypt_key (ks, ctx1.opad.h, s_te0, s_te1, s_te2, s_te3);   // expand the KCK into AES round keys

      u32 m[4]  = { 0, 0, 0, 0 };   // current CBC-MAC block
      u32 iv[4] = { 0, 0, 0, 0 };   // running CMAC chaining value (starts at zero)

      int eapol_left;               // bytes of EAPOL remaining
      int eapol_idx;                // word index into the EAPOL frame
      for (eapol_left = wpa->eapol_len, eapol_idx = 0; eapol_left > 16; eapol_left -= 16, eapol_idx += 4)
      {
        m[0] = wpa->eapol[eapol_idx + 0] ^ iv[0];   // XOR each full block with the chaining value
        m[1] = wpa->eapol[eapol_idx + 1] ^ iv[1];
        m[2] = wpa->eapol[eapol_idx + 2] ^ iv[2];
        m[3] = wpa->eapol[eapol_idx + 3] ^ iv[3];
        aes128_encrypt (ks, m, iv, s_te0, s_te1, s_te2, s_te3, s_te4);   // encrypt to get the next chaining value
      }

      m[0] = wpa->eapol[eapol_idx + 0];   // load the final (possibly partial) block
      m[1] = wpa->eapol[eapol_idx + 1];
      m[2] = wpa->eapol[eapol_idx + 2];
      m[3] = wpa->eapol[eapol_idx + 3];

      u32 k[4] = { 0, 0, 0, 0 };
      aes128_encrypt (ks, k, k, s_te0, s_te1, s_te2, s_te3, s_te4);   // L = AES(KCK, 0) -- base for subkey derivation
      make_kn (k);                         // K1 = subkey for a complete final block
      if (eapol_left < 16) make_kn (k);    // K2 = subkey when the final block needed padding

      m[0] ^= k[0]; m[1] ^= k[1]; m[2] ^= k[2]; m[3] ^= k[3];   // XOR in the chosen subkey
      m[0] ^= iv[0]; m[1] ^= iv[1]; m[2] ^= iv[2]; m[3] ^= iv[3];   // XOR with the chaining value

      u32 keymic[4] = { 0, 0, 0, 0 };
      aes128_encrypt (ks, m, keymic, s_te0, s_te1, s_te2, s_te3, s_te4);   // final AES gives the 16-byte CMAC

      keymic[0] = hc_swap32_S (keymic[0]);   // AES output is LE; swap to BE to compare with the stored target
      keymic[1] = hc_swap32_S (keymic[1]);
      keymic[2] = hc_swap32_S (keymic[2]);
      keymic[3] = hc_swap32_S (keymic[3]);

      if ((keymic[0] == wpa->keymic[0])
       && (keymic[1] == wpa->keymic[1])
       && (keymic[2] == wpa->keymic[2])
       && (keymic[3] == wpa->keymic[3])) return 1;   // 16-byte CMAC matched
    }
  }
  return 0;
}

// type 9: KDF-HMAC-SHA384 PTK (key-length field 0x02C0 = 704 bits: 24-byte KCK +
// 32-byte KEK + 32-byte TK) -> 24-byte KCK; MIC = HMAC-SHA384(KCK, eapol) truncated
// to 192 bits (24 bytes). The KCK lies wholly in KDF block 1, so one HMAC-SHA384
// over the counter=1 input yields it.
DECLSPEC int wpa_check_eapol_sha384 (PRIVATE_AS const u32 *pmk, GLOBAL_AS const wpa_universal_t *wpa)
{
  u32 pke[32];
  for (int i = 0; i < 32; i++) pke[i] = wpa->pke[i];   // local copy of the KDF input to patch the nonce

  u32 to, m0, m1;
  if (wpa->nonce_compare < 0)
  {
    m0 = pke[15] & ~0x000000ff; m1 = pke[16] & ~0xffffff00;   // nonce in lower half
    to = pke[15] << 24 | pke[16] >> 8;
  }
  else
  {
    m0 = pke[23] & ~0x000000ff; m1 = pke[24] & ~0xffffff00;   // nonce in upper half
    to = pke[23] << 24 | pke[24] >> 8;
  }

  u32 bo_loops = wpa->detected_le + wpa->detected_be;
  bo_loops = (bo_loops == 0) ? 2 : bo_loops;

  const u32 nec = wpa->nonce_error_corrections;

  for (u32 nc = 0; nc <= nec; nc++)        // nonce-correction sweep
  {
    for (u32 bo = 0; bo < bo_loops; bo++)
    {
      u32 t = to;
      if (((bo_loops == 1) && (wpa->detected_le == 1)) || ((bo_loops != 1) && (bo == 0)))
      {
        t -= nec / 2; t += nc;             // LE offset
      }
      else
      {
        t = hc_swap32_S (t); t -= nec / 2; t += nc; t = hc_swap32_S (t);   // BE offset
      }

      if (wpa->nonce_compare < 0)   // patch nonce back
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
      sha384_hmac_init (&ctx1, pmk, 32);   // KDF keyed on the PMK
      sha384_hmac_update (&ctx1, pke, 102);   // one KDF block: counter || label || context || 704-bit length
      sha384_hmac_final (&ctx1);

      // KCK = first 24 bytes of the PTK = first 3 SHA-384 (64-bit) words split
      // into 6 big-endian u32. The HMAC key buffer is zero-padded to the full
      // 128-byte SHA-384 block because hmac_init reads the whole block.
      u32 kck[32];
      for (int i = 0; i < 32; i++) kck[i] = 0;   // zero-pad
      kck[0] = h32_from_64_S (ctx1.opad.h[0]);   // KCK bytes 0..3
      kck[1] = l32_from_64_S (ctx1.opad.h[0]);   // KCK bytes 4..7
      kck[2] = h32_from_64_S (ctx1.opad.h[1]);   // KCK bytes 8..11
      kck[3] = l32_from_64_S (ctx1.opad.h[1]);   // KCK bytes 12..15
      kck[4] = h32_from_64_S (ctx1.opad.h[2]);   // KCK bytes 16..19
      kck[5] = l32_from_64_S (ctx1.opad.h[2]);   // KCK bytes 20..23

      sha384_hmac_ctx_t ctx2;
      sha384_hmac_init (&ctx2, kck, 24);         // MIC key = the 24-byte KCK
      sha384_hmac_update_global_swap (&ctx2, wpa->eapol, wpa->eapol_len);   // MAC the zeroed EAPOL frame
      sha384_hmac_final (&ctx2);

      // MIC = first 24 bytes of the SHA-384 HMAC; compare 6 BE words (SHA output
      // is already big-endian, so no swap).
      if ((h32_from_64_S (ctx2.opad.h[0]) == wpa->keymic[0])
       && (l32_from_64_S (ctx2.opad.h[0]) == wpa->keymic[1])
       && (h32_from_64_S (ctx2.opad.h[1]) == wpa->keymic[2])
       && (l32_from_64_S (ctx2.opad.h[1]) == wpa->keymic[3])
       && (h32_from_64_S (ctx2.opad.h[2]) == wpa->keymic[4])
       && (l32_from_64_S (ctx2.opad.h[2]) == wpa->keymic[5])) return 1;   // 24-byte MIC matched
    }
  }
  return 0;
}

// ---- FT (802.11r fast-roaming) verifiers: PMK -> PMK-R0 -> PMK-R1 hierarchy ----

// type 6: SHA-256 FT chain producing the PMKR1Name (used as the FT "PMKID").
// pke_r0 was host-built with KDF counter=2 so a single HMAC yields the second
// KDF block whose first 16 bytes are the R0Name salt.
DECLSPEC int wpa_check_ft_pmkid_sha256 (PRIVATE_AS const u32 *pmk, GLOBAL_AS const wpa_universal_t *wpa)
{
  u32 pke[32];
  for (int i = 0; i < 32; i++) pke[i] = wpa->pke_r0[i];   // FT-R0 KDF input template

  // step 1: R0Name salt = first 16 bytes of HMAC-SHA256(PMK, FT-R0 input) (KDF block counter=2).
  sha256_hmac_ctx_t ctx1;
  sha256_hmac_init (&ctx1, pmk, 32);                          // key = the PMK
  sha256_hmac_update (&ctx1, pke, 19 + wpa->essid_len + wpa->r0khid_len);   // template length = fixed prefix + ESSID + R0KH-ID
  sha256_hmac_final (&ctx1);

  // step 2: PMKR0Name = first 16 bytes of SHA-256("FT-R0N" || salt). The shifts
  // pack the 6-byte label and the 16-byte salt across u32 word boundaries.
  pke[ 0] = 0x46542d52;                            // "FT-R"
  pke[ 1] = 0x304e0000 | (ctx1.opad.h[0] >> 16);   // "0N" then the first 2 salt bytes
  pke[ 2] = (ctx1.opad.h[0] << 16) | (ctx1.opad.h[1] >> 16);   // remaining salt straddling word boundaries
  pke[ 3] = (ctx1.opad.h[1] << 16) | (ctx1.opad.h[2] >> 16);
  pke[ 4] = (ctx1.opad.h[2] << 16) | (ctx1.opad.h[3] >> 16);
  pke[ 5] = (ctx1.opad.h[3] << 16);
  for (int i = 6; i < 32; i++) pke[i] = 0;         // zero the rest before hashing

  sha256_ctx_t ctx2;
  sha256_init (&ctx2);
  sha256_update (&ctx2, pke, 22);                  // hash 6-byte "FT-R0N" + 16-byte salt
  sha256_final (&ctx2);

  // step 3: PMKR1Name = first 16 bytes of SHA-256("FT-R1N" || PMKR0Name || R1KH-ID || STA).
  // pmkid_data carries the template with a 16-byte gap for the Name; OR it in.
  pke[ 0] = wpa->pmkid_data[ 0];
  pke[ 1] = wpa->pmkid_data[ 1] | (ctx2.h[0] >> 16);   // splice PMKR0Name into the Name gap
  pke[ 2] = wpa->pmkid_data[ 2] | (ctx2.h[0] << 16) | (ctx2.h[1] >> 16);
  pke[ 3] = wpa->pmkid_data[ 3] | (ctx2.h[1] << 16) | (ctx2.h[2] >> 16);
  pke[ 4] = wpa->pmkid_data[ 4] | (ctx2.h[2] << 16) | (ctx2.h[3] >> 16);
  pke[ 5] = wpa->pmkid_data[ 5] | (ctx2.h[3] << 16);
  for (int i = 6; i < 32; i++) pke[i] = wpa->pmkid_data[i];   // rest of the template (R1KH-ID, STA)

  sha256_init (&ctx2);
  sha256_update (&ctx2, pke, 28 + wpa->r1khid_len);   // 6 "FT-R1N" + 16 Name + 6 STA + R1KH-ID length
  sha256_final (&ctx2);

  return (ctx2.h[0] == wpa->pmkid[0])      // PMKR1Name first 16 bytes = the FT PMKID
      && (ctx2.h[1] == wpa->pmkid[1])
      && (ctx2.h[2] == wpa->pmkid[2])
      && (ctx2.h[3] == wpa->pmkid[3]);
}

// type 7: SHA-256 FT chain -> FT-PTK -> 16-byte KCK; MIC = AES-128-CMAC, 16 bytes.
// The FT-PTK input is ordered SNonce||ANonce positionally (not min/max); the
// loader already placed them, here we only nonce-correct pke[17].
DECLSPEC int wpa_check_ft_eapol_cmac256 (PRIVATE_AS const u32 *pmk, GLOBAL_AS const wpa_universal_t *wpa, SHM_TYPE u32 *s_te0, SHM_TYPE u32 *s_te1, SHM_TYPE u32 *s_te2, SHM_TYPE u32 *s_te3, SHM_TYPE u32 *s_te4)
{
  u32 z[4] = { 0, 0, 0, 0 };   // zero block to pad the PMK-R0 key buffer
  u32 pke[32];

  // step 1: PMK-R0 = HMAC-SHA256(PMK, FT-R0 input) (KDF block counter=1).
  for (int i = 0; i < 32; i++) pke[i] = wpa->pke_r0[i];
  sha256_hmac_ctx_t ctx1;
  sha256_hmac_init (&ctx1, pmk, 32);                          // key = the PMK
  sha256_hmac_update (&ctx1, pke, 19 + wpa->essid_len + wpa->r0khid_len);  // FT-R0 KDF input bytes: fixed 19 (counter, "FT-R0", the ssid/r0kh length prefixes, MDID, STA, size) + ESSID + R0KH-ID
  sha256_hmac_final (&ctx1);

  // step 2: PMK-R1 = HMAC-SHA256(PMK-R0, FT-R1 input). PMK-R0 is 32 bytes; split
  // into two 4-word halves to feed as the next HMAC key (zero-padded).
  u32 out0[4]; u32 out1[4];
  out0[0] = ctx1.opad.h[0]; out0[1] = ctx1.opad.h[1]; out0[2] = ctx1.opad.h[2]; out0[3] = ctx1.opad.h[3];
  out1[0] = ctx1.opad.h[4]; out1[1] = ctx1.opad.h[5]; out1[2] = ctx1.opad.h[6]; out1[3] = ctx1.opad.h[7];

  for (int i = 0; i < 32; i++) pke[i] = wpa->pke_r1[i];       // FT-R1 KDF input template
  sha256_hmac_init_64 (&ctx1, out0, out1, z, z);              // key = PMK-R0, zero-padded to the block
  sha256_hmac_update (&ctx1, pke, 15 + wpa->r1khid_len);  // FT-R1 KDF input bytes: fixed 15 (counter, "FT-R1", STA, size) + R1KH-ID
  sha256_hmac_final (&ctx1);

  out0[0] = ctx1.opad.h[0]; out0[1] = ctx1.opad.h[1]; out0[2] = ctx1.opad.h[2]; out0[3] = ctx1.opad.h[3];   // PMK-R1 low half
  out1[0] = ctx1.opad.h[4]; out1[1] = ctx1.opad.h[5]; out1[2] = ctx1.opad.h[6]; out1[3] = ctx1.opad.h[7];   // PMK-R1 high half

  // step 3: FT-PTK = HMAC-SHA256(PMK-R1, FT-PTK input); KCK = first 16 bytes.
  for (int i = 0; i < 32; i++) pke[i] = wpa->pke[i];

  u32 to = pke[17];            // the FT nonce word subject to error correction

  u32 bo_loops = wpa->detected_le + wpa->detected_be;
  bo_loops = (bo_loops == 0) ? 2 : bo_loops;

  const u32 nec = wpa->nonce_error_corrections;

  for (u32 nc = 0; nc <= nec; nc++)        // nonce-correction sweep
  {
    for (u32 bo = 0; bo < bo_loops; bo++)
    {
      u32 t = to;
      if (((bo_loops == 1) && (wpa->detected_le == 1)) || ((bo_loops != 1) && (bo == 0)))
      {
        t -= nec / 2; t += nc;             // LE offset
      }
      else
      {
        t = hc_swap32_S (t); t -= nec / 2; t += nc; t = hc_swap32_S (t);   // BE offset
      }

      pke[17] = t;                         // write the corrected nonce word back

      sha256_hmac_init_64 (&ctx1, out0, out1, z, z);   // key = PMK-R1, zero-padded
      sha256_hmac_update (&ctx1, pke, 86);             // FT-PTK KDF input
      sha256_hmac_final (&ctx1);

      ctx1.opad.h[0] = hc_swap32_S (ctx1.opad.h[0]);   // KCK -> AES key: swap BE words to LE bytes
      ctx1.opad.h[1] = hc_swap32_S (ctx1.opad.h[1]);
      ctx1.opad.h[2] = hc_swap32_S (ctx1.opad.h[2]);
      ctx1.opad.h[3] = hc_swap32_S (ctx1.opad.h[3]);

      u32 ks[44];
      aes128_set_encrypt_key (ks, ctx1.opad.h, s_te0, s_te1, s_te2, s_te3);   // expand KCK into round keys

      u32 m[4]  = { 0, 0, 0, 0 };   // CBC-MAC block
      u32 iv[4] = { 0, 0, 0, 0 };   // CMAC chaining value

      int eapol_left;
      int eapol_idx;
      for (eapol_left = wpa->eapol_len, eapol_idx = 0; eapol_left > 16; eapol_left -= 16, eapol_idx += 4)
      {
        m[0] = wpa->eapol[eapol_idx + 0] ^ iv[0];   // XOR full block with chaining value
        m[1] = wpa->eapol[eapol_idx + 1] ^ iv[1];
        m[2] = wpa->eapol[eapol_idx + 2] ^ iv[2];
        m[3] = wpa->eapol[eapol_idx + 3] ^ iv[3];
        aes128_encrypt (ks, m, iv, s_te0, s_te1, s_te2, s_te3, s_te4);   // chain
      }

      m[0] = wpa->eapol[eapol_idx + 0];   // final block
      m[1] = wpa->eapol[eapol_idx + 1];
      m[2] = wpa->eapol[eapol_idx + 2];
      m[3] = wpa->eapol[eapol_idx + 3];

      u32 k[4] = { 0, 0, 0, 0 };
      aes128_encrypt (ks, k, k, s_te0, s_te1, s_te2, s_te3, s_te4);   // L = AES(KCK, 0)
      make_kn (k);                         // K1
      if (eapol_left < 16) make_kn (k);    // K2 if the final block is padded

      m[0] ^= k[0]; m[1] ^= k[1]; m[2] ^= k[2]; m[3] ^= k[3];   // XOR in the subkey
      m[0] ^= iv[0]; m[1] ^= iv[1]; m[2] ^= iv[2]; m[3] ^= iv[3];   // XOR with chaining value

      u32 keymic[4] = { 0, 0, 0, 0 };
      aes128_encrypt (ks, m, keymic, s_te0, s_te1, s_te2, s_te3, s_te4);   // final CMAC block

      keymic[0] = hc_swap32_S (keymic[0]);   // AES output is LE; swap to BE to compare
      keymic[1] = hc_swap32_S (keymic[1]);
      keymic[2] = hc_swap32_S (keymic[2]);
      keymic[3] = hc_swap32_S (keymic[3]);

      if ((keymic[0] == wpa->keymic[0])
       && (keymic[1] == wpa->keymic[1])
       && (keymic[2] == wpa->keymic[2])
       && (keymic[3] == wpa->keymic[3])) return 1;   // 16-byte CMAC matched
    }
  }
  return 0;
}

// Pack the first 24 bytes (3 SHA-384 64-bit words) of a digest into 6 big-endian
// u32 words, for use as a 24-byte KCK HMAC key or a 24-byte MIC comparison.
DECLSPEC void sha384_dgst_to_w6 (PRIVATE_AS const u64 *h, PRIVATE_AS u32 *w)
{
  w[0] = h32_from_64_S (h[0]); w[1] = l32_from_64_S (h[0]);   // word 0 high/low halves
  w[2] = h32_from_64_S (h[1]); w[3] = l32_from_64_S (h[1]);   // word 1 high/low halves
  w[4] = h32_from_64_S (h[2]); w[5] = l32_from_64_S (h[2]);   // word 2 high/low halves
}

// Pack the full 48 bytes (6 SHA-384 64-bit words) of a digest into 12 big-endian
// u32 words (PMK-R0 / PMK-R1 reused as the next HMAC key in the FT chain).
DECLSPEC void sha384_dgst_to_w12 (PRIVATE_AS const u64 *h, PRIVATE_AS u32 *w)
{
  w[ 0] = h32_from_64_S (h[0]); w[ 1] = l32_from_64_S (h[0]);   // word 0
  w[ 2] = h32_from_64_S (h[1]); w[ 3] = l32_from_64_S (h[1]);   // word 1
  w[ 4] = h32_from_64_S (h[2]); w[ 5] = l32_from_64_S (h[2]);   // word 2
  w[ 6] = h32_from_64_S (h[3]); w[ 7] = l32_from_64_S (h[3]);   // word 3
  w[ 8] = h32_from_64_S (h[4]); w[ 9] = l32_from_64_S (h[4]);   // word 4
  w[10] = h32_from_64_S (h[5]); w[11] = l32_from_64_S (h[5]);   // word 5
}

// type 10: SHA-384 FT chain producing the PMKR1Name PMKID. Same shape as type 6,
// but SHA-384 throughout including the FT-R0N / FT-R1N Name hashes.
DECLSPEC int wpa_check_ft_pmkid_sha384 (PRIVATE_AS const u32 *pmk, GLOBAL_AS const wpa_universal_t *wpa)
{
  u32 pke[32];
  for (int i = 0; i < 32; i++) pke[i] = wpa->pke_r0[i];   // FT-R0 KDF input template

  // step 1: R0Name salt = first 16 bytes of HMAC-SHA384(PMK, FT-R0 input) (KDF block counter=2).
  sha384_hmac_ctx_t ctx1;
  sha384_hmac_init (&ctx1, pmk, 32);                          // key = the PMK
  sha384_hmac_update (&ctx1, pke, 19 + wpa->essid_len + wpa->r0khid_len);  // FT-R0 KDF input bytes: fixed 19 (counter, "FT-R0", the ssid/r0kh length prefixes, MDID, STA, size) + ESSID + R0KH-ID
  sha384_hmac_final (&ctx1);

  u32 salt[4];               // the 16-byte salt = first two SHA-384 words, split into 4 BE u32
  salt[0] = h32_from_64_S (ctx1.opad.h[0]);
  salt[1] = l32_from_64_S (ctx1.opad.h[0]);
  salt[2] = h32_from_64_S (ctx1.opad.h[1]);
  salt[3] = l32_from_64_S (ctx1.opad.h[1]);

  // step 2: PMKR0Name = first 16 bytes of SHA-384("FT-R0N" || salt). The shifts
  // pack the 6-byte label and 16-byte salt across word boundaries.
  pke[ 0] = 0x46542d52;                     // "FT-R"
  pke[ 1] = 0x304e0000 | (salt[0] >> 16);   // "0N" then the first 2 salt bytes
  pke[ 2] = (salt[0] << 16) | (salt[1] >> 16);
  pke[ 3] = (salt[1] << 16) | (salt[2] >> 16);
  pke[ 4] = (salt[2] << 16) | (salt[3] >> 16);
  pke[ 5] = (salt[3] << 16);
  for (int i = 6; i < 32; i++) pke[i] = 0;  // zero the rest before hashing

  sha384_ctx_t ctx2;
  sha384_init (&ctx2);
  sha384_update (&ctx2, pke, 22);           // hash 6 "FT-R0N" + 16 salt
  sha384_final (&ctx2);

  u32 name[4];               // PMKR0Name first 16 bytes = first two SHA-384 words split into 4 BE u32
  name[0] = h32_from_64_S (ctx2.h[0]);
  name[1] = l32_from_64_S (ctx2.h[0]);
  name[2] = h32_from_64_S (ctx2.h[1]);
  name[3] = l32_from_64_S (ctx2.h[1]);

  // step 3: PMKR1Name = first 16 bytes of SHA-384("FT-R1N" || PMKR0Name || R1KH-ID || STA).
  pke[ 0] = wpa->pmkid_data[ 0];
  pke[ 1] = wpa->pmkid_data[ 1] | (name[0] >> 16);   // splice PMKR0Name into the Name gap
  pke[ 2] = wpa->pmkid_data[ 2] | (name[0] << 16) | (name[1] >> 16);
  pke[ 3] = wpa->pmkid_data[ 3] | (name[1] << 16) | (name[2] >> 16);
  pke[ 4] = wpa->pmkid_data[ 4] | (name[2] << 16) | (name[3] >> 16);
  pke[ 5] = wpa->pmkid_data[ 5] | (name[3] << 16);
  for (int i = 6; i < 32; i++) pke[i] = wpa->pmkid_data[i];   // rest of template (R1KH-ID, STA)

  sha384_init (&ctx2);
  sha384_update (&ctx2, pke, 28 + wpa->r1khid_len);   // 6 "FT-R1N" + 16 Name + 6 STA + R1KH-ID
  sha384_final (&ctx2);

  return (h32_from_64_S (ctx2.h[0]) == wpa->pmkid[0])   // PMKR1Name first 16 bytes = the FT PMKID
      && (l32_from_64_S (ctx2.h[0]) == wpa->pmkid[1])
      && (h32_from_64_S (ctx2.h[1]) == wpa->pmkid[2])
      && (l32_from_64_S (ctx2.h[1]) == wpa->pmkid[3]);
}

// type 11: SHA-384 FT chain -> FT-PTK -> 24-byte KCK; MIC = HMAC-SHA384 truncated
// to 192 bits (24 bytes).
DECLSPEC int wpa_check_ft_eapol_sha384 (PRIVATE_AS const u32 *pmk, GLOBAL_AS const wpa_universal_t *wpa)
{
  u32 pke[32];

  // step 1: PMK-R0 = first 48 bytes of HMAC-SHA384(PMK, FT-R0 input) (KDF block counter=1).
  for (int i = 0; i < 32; i++) pke[i] = wpa->pke_r0[i];
  sha384_hmac_ctx_t ctx1;
  sha384_hmac_init (&ctx1, pmk, 32);                          // key = the PMK
  sha384_hmac_update (&ctx1, pke, 19 + wpa->essid_len + wpa->r0khid_len);  // FT-R0 KDF input bytes: fixed 19 (counter, "FT-R0", the ssid/r0kh length prefixes, MDID, STA, size) + ESSID + R0KH-ID
  sha384_hmac_final (&ctx1);

  // PMK-R0 / PMK-R1 are 48 bytes used as the next HMAC key; zero-pad the buffer
  // to the full 128-byte SHA-384 block since hmac_init reads it all.
  u32 r0[32];
  for (int i = 0; i < 32; i++) r0[i] = 0;   // zero-pad
  sha384_dgst_to_w12 (ctx1.opad.h, r0);     // PMK-R0 as 12 BE words

  // step 2: PMK-R1 = first 48 bytes of HMAC-SHA384(PMK-R0, FT-R1 input).
  for (int i = 0; i < 32; i++) pke[i] = wpa->pke_r1[i];   // FT-R1 KDF input template
  sha384_hmac_init (&ctx1, r0, 48);                       // key = the 48-byte PMK-R0
  sha384_hmac_update (&ctx1, pke, 15 + wpa->r1khid_len);  // FT-R1 KDF input bytes: fixed 15 (counter, "FT-R1", STA, size) + R1KH-ID
  sha384_hmac_final (&ctx1);

  u32 r1[32];
  for (int i = 0; i < 32; i++) r1[i] = 0;   // zero-pad
  sha384_dgst_to_w12 (ctx1.opad.h, r1);     // PMK-R1 as 12 BE words

  // step 3: FT-PTK = HMAC-SHA384(PMK-R1, FT-PTK input); KCK = first 24 bytes;
  // nonce-correct pke[17].
  for (int i = 0; i < 32; i++) pke[i] = wpa->pke[i];

  u32 to = pke[17];            // the FT nonce word subject to error correction

  u32 bo_loops = wpa->detected_le + wpa->detected_be;
  bo_loops = (bo_loops == 0) ? 2 : bo_loops;

  const u32 nec = wpa->nonce_error_corrections;

  for (u32 nc = 0; nc <= nec; nc++)        // nonce-correction sweep
  {
    for (u32 bo = 0; bo < bo_loops; bo++)
    {
      u32 t = to;
      if (((bo_loops == 1) && (wpa->detected_le == 1)) || ((bo_loops != 1) && (bo == 0)))
      {
        t -= nec / 2; t += nc;             // LE offset
      }
      else
      {
        t = hc_swap32_S (t); t -= nec / 2; t += nc; t = hc_swap32_S (t);   // BE offset
      }

      pke[17] = t;                         // write the corrected nonce word back

      sha384_hmac_init (&ctx1, r1, 48);    // key = the 48-byte PMK-R1
      sha384_hmac_update (&ctx1, pke, 86); // FT-PTK KDF input
      sha384_hmac_final (&ctx1);

      u32 kck[32];
      for (int i = 0; i < 32; i++) kck[i] = 0;   // zero-pad the 24-byte KCK to the HMAC block
      sha384_dgst_to_w6 (ctx1.opad.h, kck);      // KCK = first 24 bytes of the FT-PTK

      sha384_hmac_ctx_t ctx2;
      sha384_hmac_init (&ctx2, kck, 24);         // MIC key = the 24-byte KCK
      sha384_hmac_update_global_swap (&ctx2, wpa->eapol, wpa->eapol_len);   // MAC the zeroed EAPOL frame
      sha384_hmac_final (&ctx2);

      // MIC = first 24 bytes of the SHA-384 HMAC; compare 6 BE words directly.
      if ((h32_from_64_S (ctx2.opad.h[0]) == wpa->keymic[0])
       && (l32_from_64_S (ctx2.opad.h[0]) == wpa->keymic[1])
       && (h32_from_64_S (ctx2.opad.h[1]) == wpa->keymic[2])
       && (l32_from_64_S (ctx2.opad.h[1]) == wpa->keymic[3])
       && (h32_from_64_S (ctx2.opad.h[2]) == wpa->keymic[4])
       && (l32_from_64_S (ctx2.opad.h[2]) == wpa->keymic[5])) return 1;   // 24-byte MIC matched
    }
  }
  return 0;
}

// --- aux-kernel wiring macros (shared by every bake-off kernel) ---

// Load the per-digest cursor and the PMK (zero-padded to a full SHA-384 HMAC
// block of 32 u32 so every verifier's hmac_init can read the whole block) into
// private registers.
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

// Report a cracked digest exactly once via the atomic guard.
#define WPA_MARK_IF(matched)                                                                          \
  if (matched)                                                                                        \
  {                                                                                                   \
    if (hc_atomic_inc (&hashes_shown[digest_cur]) == 0)                                               \
    {                                                                                                 \
      mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, digest_pos, digest_cur, gid, 0, 0, 0); \
    }                                                                                                 \
  }

// Bind the AES T-tables for the CMAC verifiers (types 5, 7) in the address space
// they expect (SHM_TYPE): under REAL_SHM (GPUs) that is LOCAL_AS, so copy the
// constant tables into a local array; otherwise alias them in constant memory.
// Passing constant tables to a local parameter was the mismatch that broke every
// CMAC kernel build on GPU. Runs before any early return so SYNC_THREADS is uniform.
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

// Switch the 2-digit type to its verifier and set `matched`. s_te* must be in
// scope (via WPA_AES_SHARED) for the CMAC types 5 and 7.
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
