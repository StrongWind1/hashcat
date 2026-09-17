/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 *
 * Bake-off plugin 90027 (hook23-sha384-zerotouch): hybrid verifier combining
 * GPU aux kernels for the 32-bit-MAC family (types 1..7) with a CPU hook for
 * the SHA-384 family (types 8..11). Aux layout mirrors 90014's zero-touch
 * packing (aux1-3 = stock 22000, aux4 = PMKIDs, aux5 = type 7). The
 * deep_comp dispatcher routes types 1-7 to the appropriate aux kernel and
 * types 8-11 to the _comp kernel, which reads the host-set hook bitmask.
 *
 *   aux1: type 1       (EAPOL MD5)
 *   aux2: type 3       (EAPOL SHA-1)
 *   aux3: type 5       (EAPOL AES-CMAC-256)
 *   aux4: types 2,4,6  (PMKIDs: SHA-1, SHA-256, FT-256)
 *   aux5: type 7       (FT EAPOL AES-CMAC-256)
 *   _comp via hook: types 8,9,10,11 (SHA-384 family, validated by host CPU)
 */

// hashcat core headers: option/type constants, module ctx API, helpers.
#include "common.h"
#include "types.h"
#include "modules.h"
#include "bitops.h"
#include "convert.h"
#include "shared.h"
#include "memory.h"
#include "emu_general.h"
// CPU emulation of the AES and MD5 crypto primitives the host verifiers call.
#include "emu_inc_cipher_aes.h"
#include "emu_inc_hash_md5.h"

// Crypto-library declarations the host verifiers need; the actual code is linked
// from the emu_* objects, so the .cl included below does not pull these itself.
#include "inc_vendor.h"
#include "inc_types.h"
#include "inc_platform.h"
#include "inc_common.h"
#include "inc_simd.h"
#include "inc_hash_md5.h"
#include "inc_hash_sha1.h"
#include "inc_hash_sha256.h"
#include "inc_hash_sha384.h"
#include "inc_cipher_aes.h"

// The shared universal WPA logic: esalt struct, per-type verifiers, and tokenizer.
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

// The shared host-side decode/encode/init code reused across the bake-off plugins.
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


#include "common.h"          // hashcat-wide typedefs and macros
#include "types.h"           // salt_t / hashconfig_t / module_ctx_t etc.
#include "modules.h"         // module API constants (PARSER_*, MODULE_DEFAULT, ...)
#include "bitops.h"          // byte_swap_16/32 endianness helpers
#include "convert.h"         // hex_to_u8 / hex_decode / u32_to_hex string conversions
#include "shared.h"          // hc_token_t and shared helpers
#include "parser.h"          // input_tokenizer
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
    (module_ctx)->module_advice_notice            = MODULE_DEFAULT;                          /* no advice notice */ \
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
    (module_ctx)->module_hash_hints              = MODULE_DEFAULT;                          /* no association-attack hint words */ \
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
    (module_ctx)->module_usage_notice            = MODULE_DEFAULT;                          /* no usage notice */ \
    (module_ctx)->module_warmup_disable          = MODULE_DEFAULT;                          /* allow warmup */ \
  } while (0)



// Human-readable name shown in --help / status.
static const char *HASH_NAME = "WPA-PBKDF2-Universal (90027 / hook23-sha384-zerotouch)";
// Kernel/mode number; selects the OpenCL kernel file for this plugin.
static const u64   KERN_TYPE = 90027;
// Behavior flags: five aux kernels, deep_comp dispatch, hook23 for SHA-384, copy tmps for comp access.
static const u64   OPTS_TYPE = OPTS_TYPE_STOCK_MODULE
                             | OPTS_TYPE_PT_GENERATE_LE
                             | OPTS_TYPE_AUX1
                             | OPTS_TYPE_AUX2
                             | OPTS_TYPE_AUX3
                             | OPTS_TYPE_AUX4
                             | OPTS_TYPE_AUX5
                             | OPTS_TYPE_DEEP_COMP_KERNEL
                             | OPTS_TYPE_HOOK23
                             | OPTS_TYPE_COPY_TMPS;

// Trivial getters hashcat calls to read this mode's name / kernel number / flags.
const char *module_hash_name (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return HASH_NAME; }
u64         module_kern_type (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return KERN_TYPE; }
u64         module_opts_type (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return OPTS_TYPE; }

// Size of the per-password hook staging record hashcat allocates between kernels.
u64 module_hook_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  return (u64) sizeof (wpa_hook_t);
}

// Per-digest deep_comp dispatch: types 1-7 to the matching GPU aux kernel,
// types 8-11 to _comp which reads the hook bitmask set by module_hook23.
u32 module_deep_comp_kernel (MAYBE_UNUSED const hashes_t *hashes, MAYBE_UNUSED const u32 salt_pos, MAYBE_UNUSED const u32 digest_pos)
{
  const u32 digests_offset = hashes->salts_buf[salt_pos].digests_offset;
  const wpa_universal_t *wpa = &((const wpa_universal_t *) hashes->esalts_buf)[digests_offset + digest_pos];

  switch (wpa->type)
  {
    case  1: return KERN_RUN_AUX1;   // EAPOL MD5
    case  2: return KERN_RUN_AUX4;   // PMKID SHA-1
    case  3: return KERN_RUN_AUX2;   // EAPOL SHA-1
    case  4: return KERN_RUN_AUX4;   // PMKID SHA-256
    case  5: return KERN_RUN_AUX3;   // EAPOL AES-CMAC-256
    case  6: return KERN_RUN_AUX4;   // FT PMKID SHA-256
    case  7: return KERN_RUN_AUX5;   // FT EAPOL AES-CMAC-256
    case  8: return KERN_RUN_3;      // PMKID SHA-384 -> hook readback via _comp
    case  9: return KERN_RUN_3;      // EAPOL SHA-384 -> hook readback via _comp
    case 10: return KERN_RUN_3;      // FT PMKID SHA-384 -> hook readback via _comp
    case 11: return KERN_RUN_3;      // FT EAPOL SHA-384 -> hook readback via _comp
  }

  return 0;
}

// CPU hook running between _loop and _comp: validate only the SHA-384 family {8..11}; 1..7 are GPU-verified.
void module_hook23 (hc_device_param_t *device_param, MAYBE_UNUSED const void *hook_extra_param, MAYBE_UNUSED const void *hook_salts_buf, MAYBE_UNUSED const u32 salt_pos, const u64 pw_pos)
{
  wpa_hook_t *hooks = (wpa_hook_t *) device_param->hooks_buf;
  wpa_hook_t *h     = &hooks[pw_pos];

  u32 pmk[32];
  for (int i = 0; i < 32; i++) pmk[i] = 0;
  for (int i = 0; i <  8; i++) pmk[i] = h->pmk[i];

  for (u32 dp = 0; (dp < h->ndig) && (dp < WPA_HOOK_MAXD); dp++)
  {
    const wpa_universal_t *wpa = &h->dig[dp];

    int ok = 0;
    switch (wpa->type)
    {
      case  8: ok = wpa_check_pmkid_sha384     (pmk, wpa); break;
      case  9: ok = wpa_check_eapol_sha384     (pmk, wpa); break;
      case 10: ok = wpa_check_ft_pmkid_sha384  (pmk, wpa); break;
      case 11: ok = wpa_check_ft_eapol_sha384  (pmk, wpa); break;
      default: continue;
    }

    if (ok) h->ok |= (1u << dp);
  }
}

// Register this mode's function pointers with hashcat.
void module_init (module_ctx_t *module_ctx)
{
  WPA_MODULE_CTX_COMMON (module_ctx);

  module_ctx->module_deep_comp_kernel = module_deep_comp_kernel;
  module_ctx->module_hook23           = module_hook23;
  module_ctx->module_hook_size        = module_hook_size;
}
