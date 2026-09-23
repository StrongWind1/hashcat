/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef INC_CIPHER_RC2_H
#define INC_CIPHER_RC2_H

/**
 * RC2 block cipher (RFC 2268).
 *
 * Block size: 64 bits (8 bytes = 2 u32 words).
 * Key: 1-128 bytes, with configurable effective key bits.
 * Expanded key: 64 u16 subkeys stored as u32[64] (zero-extended).
 *
 * Data convention: big-endian u32, matching hashcat's SHA-1 pipeline.
 * The functions swap to little-endian internally for RC2's u16 word
 * operations, same pattern as AES128_encrypt / AES128_decrypt.
 */

DECLSPEC void rc2_key_setup (PRIVATE_AS u32 *xk, PRIVATE_AS const u32 *key, const int key_bytes, const int effective_bits);
DECLSPEC void rc2_encrypt  (PRIVATE_AS const u32 *xk, PRIVATE_AS const u32 *in, PRIVATE_AS u32 *out);
DECLSPEC void rc2_decrypt  (PRIVATE_AS const u32 *xk, PRIVATE_AS const u32 *in, PRIVATE_AS u32 *out);

#endif // INC_CIPHER_RC2_H
