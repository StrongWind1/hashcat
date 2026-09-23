# Unified Office Hash Modules — Design and Implementation Plan

This document describes six new hashcat modules that replace all twelve existing Office and ODF modes with a unified, self-describing hash line format. The new modules cover every encryption scheme the toolkit can extract, including several that have no hashcat mode today.

## Motivation

The existing Office modules (9400-9820, 18400, 18600, 25300) each hardcode a single parameter tuple. A file encrypted with SHA-256 Agile, or a 56-bit RC4 key, or a SHA-1 sheet-protection hash, or an ODF 1.3 AES-GCM member silently fails at parse time because the parser rejects any parameter it was not built for. The twelve modules also scatter related schemes across unrelated mode numbers, making discovery difficult.

The new modules accept a self-describing hash line whose tokens name the hash algorithm, cipher, chaining mode, and iteration count explicitly. The parser routes to the correct kernel without year-number proxies, version digits, or hardcoded parameter checks. Every parameter combination the spec allows is accepted; the ones the old modes handled are backward-compatible through legacy-format parsers in the same module.

## Why This Is Needed — For Maintainers

Microsoft Office document encryption is not one scheme — it is a matrix of parameters that evolved across 25 years of Office releases. The `\EncryptionInfo` stream in any encrypted OOXML file ([MS-OFFCRYPTO] Section 2.1.4) carries an XML descriptor that names the hash algorithm, cipher algorithm, cipher chaining mode, key size, and iteration count as free variables. The spec explicitly reserves SHA-1, SHA-256, SHA-384, SHA-512, MD5, MD4, and MD2 as hash algorithms and AES-128, AES-192, and AES-256 as ciphers. Third-party producers (LibreOffice, Google Docs, Apache POI, Open XML SDK) exercise these parameters freely.

The current hashcat modules were written when Office shipped exactly three tuples (2007: SHA-1/AES-128/ECB/50000; 2010: SHA-1/AES-128/CBC/100000; 2013: SHA-512/AES-256/CBC/100000) and hardcoded those values into the parser. Every module rejects at parse time — silently, returning `PARSER_SALT_VALUE` — any hash whose parameters differ from the single hardcoded tuple, even when the underlying KDF and cipher are functionally identical. A penetration tester who extracts a hash from a LibreOffice document with `spinCount=200000` or a legacy file with a 56-bit RC4 key gets a parse failure and no diagnostic.

The problem compounds for the protection verifiers: hashcat mode 25300 handles exactly one of the seven spec-reserved hash algorithms (SHA-512) at exactly one iteration count (100000). Sheet-protection hashes using SHA-1 (the Excel 2010 default when saving as `.xls`) or SHA-256 (common in `.xlsx` files from third-party tools) are silently dropped. Word `documentProtection` hashes, which use a different KDF variant (`crypt*` with a legacy pre-stage), have no hashcat mode at all.

The unified modules solve this by parsing the parameters from the hash line rather than hardcoding them. One module replaces three to six old ones, accepts every parameter combination the spec allows, and routes to the correct kernel via `module_kern_type_dynamic`. No hash that is valid per the spec is rejected at parse time.

### Specific hardcoded constraints in existing parsers

Every entry below is a line in `module_hash_decode` that returns a parser error for a spec-valid hash:

**module_09400.c** (Office 2007):
```c
if (version           != 2007)            return (PARSER_SALT_VALUE);
if (verifierHashSize  != 20)              return (PARSER_SALT_VALUE);
if (saltSize          != 16)              return (PARSER_SALT_VALUE);
if ((keySize != 128) && (keySize != 256)) return (PARSER_SALT_VALUE);
```
Rejects AES-192 (`AlgID 0x0000660F`, [MS-OFFCRYPTO] Section 2.3.4.5). Pins `verifierHashSize=20` (SHA-1 only). Rejects non-16-byte salts.

**module_09500.c** (Office 2010):
```c
if (version   != 2010)    return (PARSER_SALT_VALUE);
if (spinCount != 100000)  return (PARSER_SALT_VALUE);
if (keySize   != 128)     return (PARSER_SALT_VALUE);
if (saltSize  != 16)      return (PARSER_SALT_VALUE);
```
Rejects any `spinCount` other than 100000. [MS-OFFCRYPTO] Section 2.3.4.10 declares `spinCount` as a free attribute in the XML descriptor. LibreOffice uses 100000, but Google Docs has used 50000 and enterprise-hardened deployments use 200000+. Also rejects SHA-1/AES-256, an unusual but spec-valid combination.

**module_09600.c** (Office 2013):
```c
if (version   != 2013)    return (PARSER_SALT_VALUE);
if (spinCount != 100000)  return (PARSER_SALT_VALUE);
if (keySize   != 256)     return (PARSER_SALT_VALUE);
if (saltSize  != 16)      return (PARSER_SALT_VALUE);
```
Same `spinCount` pin. Also rejects SHA-512/AES-128, which is valid per the agile XML descriptor.

**module_09700.c** (RC4+MD5):
```c
// Tokenizer-level: only $oldoffice$0 and $oldoffice$1 signatures accepted
token.signatures_buf[0] = SIGNATURE_OLDOFFICE0;  // "$oldoffice$0"
token.signatures_buf[1] = SIGNATURE_OLDOFFICE1;  // "$oldoffice$1"
```
Rejects `$oldoffice$2` (56-bit RC4+MD5) at the signature-matching stage before `module_hash_decode` even runs. [MS-OFFCRYPTO] Section 2.3.6 allows key sizes up to 128 bits in 8-bit steps.

**module_09800.c** (RC4+SHA-1):
```c
token.signatures_buf[0] = SIGNATURE_OLDOFFICE3;  // "$oldoffice$3"
token.signatures_buf[1] = SIGNATURE_OLDOFFICE4;  // "$oldoffice$4"
```
The `$oldoffice$` format encodes key size as a binary digit: 3 = 40-bit, 4 = anything else. A 56-bit file emits `$oldoffice$4` (same as 128-bit). The kernel assumes 128-bit truncation (`Hfinal[:16]`), but a 56-bit key should truncate to 7 bytes (`Hfinal[:7]`). The key derivation produces wrong keys for every size except 40 and 128.

**module_25300.c** (SheetProtection):
```c
if (spinCount != 100000) return (PARSER_SALT_VALUE);
// ...
if (tmp_len != 16) return (PARSER_SALT_LENGTH);   // salt must decode to 16 bytes
if (tmp_len != 64) return (PARSER_HASH_LENGTH);    // hash must decode to 64 bytes
```
Pins SHA-512 (64-byte digest). SHA-1 (20 bytes), SHA-256 (32 bytes), SHA-384 (48 bytes), and MD5 (16 bytes) are all reserved values in [MS-OFFCRYPTO] Section 2.4.2.4 but silently rejected. SHA-1 is the default when Excel saves sheet protection in `.xls` compatibility mode. Pins `spinCount=100000`; real documents use 10000-500000.

**module_18400.c / module_18600.c** (ODF):
```c
// 18400:
if (cipher_type != 1) return (PARSER_SALT_VALUE);  // AES-CBC only
if (checksum_type != 1) return (PARSER_SALT_VALUE); // SHA-256 only
if (key_size != 32) return (PARSER_SALT_VALUE);
if (iv_len != 16) return (PARSER_SALT_VALUE);
if (salt_len != 16) return (PARSER_SALT_VALUE);

// 18600:
if (cipher_type != 0) return (PARSER_SALT_VALUE);  // Blowfish only
if (checksum_type != 0) return (PARSER_SALT_VALUE); // SHA-1 only
if (key_size != 16) return (PARSER_SALT_VALUE);
if (iv_len != 8) return (PARSER_SALT_VALUE);
```
Every field is pinned to exactly one value. ODF 1.3 AES-256-GCM (cipher_type=2) is rejected by both. Mixed-profile manifests (legal per the OASIS schema) are rejected.

## Existing Modules Replaced

| Old mode | Name | Replaced by | Notes |
|----------|------|-------------|-------|
| 9400 | MS Office 2007 (Standard, SHA-1/AES-ECB) | 37000 | Fixed 50000 iterations, AES-128 or AES-256 |
| 9500 | MS Office 2010 (Agile, SHA-1/AES-128-CBC) | 37000 | Hardcoded SHA-1, AES-128, spinCount 100000 |
| 9600 | MS Office 2013 (Agile, SHA-512/AES-256-CBC) | 37000 | Hardcoded SHA-512, AES-256, spinCount 100000 |
| 9700 | MS Office ≤2003 $0/$1, MD5 + RC4 | 37100 | 40-bit key only |
| 9710 | MS Office ≤2003 $0/$1, MD5 + RC4, collider #1 | 37101 | Key-seed brute force |
| 9720 | MS Office ≤2003 $0/$1, MD5 + RC4, collider #2 | 37102 | Password-from-seed recovery |
| 9800 | MS Office ≤2003 $3/$4, SHA1 + RC4 | 37100 | Digit 3 = 40-bit, digit 4 = 128-bit only |
| 9810 | MS Office ≤2003 $3, SHA1 + RC4, collider #1 | 37101 | Key-seed brute force |
| 9820 | MS Office ≤2003 $3, SHA1 + RC4, collider #2 | 37102 | Password-from-seed recovery |
| 18400 | ODF 1.2 (SHA-256/AES-256-CBC) | 37300 | Fixed PBKDF2-HMAC-SHA1 |
| 18600 | ODF 1.1 (SHA-1/Blowfish-CFB) | 37300 | Fixed PBKDF2-HMAC-SHA1 |
| 25300 | MS Office 2016 SheetProtection | 37200 | SHA-512 / spinCount 100000 only |

## Coverage Gaps Closed

These parameter combinations are extracted by the `office-password-toolkit` but have no hashcat mode today. Every one is accepted by the new modules.

| Gap | Scheme | New module |
|-----|--------|------------|
| Non-default Agile: SHA-256/AES-128, SHA-256/AES-256, SHA-384/AES-256 | ECMA-376 Agile | 37000 |
| Non-default spinCount (not 100000) | ECMA-376 Agile | 37000 |
| AES-192 Standard Encryption | ECMA-376 Standard | 37000 |
| 56-bit RC4 ($oldoffice$2 rejected by 9700) | RC4 CryptoAPI | 37100 |
| All intermediate key sizes 48-120 bit (8-bit aligned) | RC4 CryptoAPI | 37100 |
| Protection verifiers: SHA-1, SHA-256, SHA-384, MD5 | ISO write-protection | 37200 |
| Word documentProtection (crypt KDF) | crypt* legacy KDF | 37200 |
| Non-default protection spinCount (not 100000) | ISO write-protection | 37200 |
| ODF 1.3 AES-256-GCM with PBKDF2 | ODF Wholesome Encryption | 37300 |
| MSISAM MD5/SHA-1 + RC4 page encryption | Microsoft Money | 37500 |

## Framework Mechanisms

The design uses two hashcat framework features that compose without conflict.

### `module_kern_type_dynamic`

Selects the OpenCL kernel file at session startup. Called once by `backend.c:14277` with the first hash's esalt. Returns a kern_type integer; the framework loads `OpenCL/mXXXXX-pure.cl` (or `-optimized.cl`) based on that value. All hashes in one session must share the same kernel type.

**Signature:** `u64 module_kern_type_dynamic(hashconfig, digest_buf, salt, esalt_buf, hook_salt_buf, hash_info)`

**Precedent:** LUKS (module 14600) dispatches to 15 kernel types from one module. SQLCipher (24600) dispatches to 3. CryptoAPI (14500) dispatches to 15.

**Usage in this design:** Each module stores `hash_type` (and optionally `cipher_type` or `kdf_type`) in the esalt during parsing. `module_kern_type_dynamic` reads those fields and returns the matching kern_type constant.

### `module_deep_comp_kernel`

Selects the comparison kernel per-digest at runtime, after the init/loop kernels have run. Called by `backend.c:2686` for each digest in the current salt. Returns `KERN_RUN_3` (the `_comp` kernel), `KERN_RUN_AUX1` through `KERN_RUN_AUX5`, or 0 on error.

**Signature:** `u32 module_deep_comp_kernel(hashes, salt_pos, digest_pos)`

**Requires:** `OPTS_TYPE_DEEP_COMP_KERNEL` flag, plus `OPTS_TYPE_AUXn` for each aux kernel used.

**Precedent:** WPA (module 22000) uses this to dispatch PMKID vs EAPOL verification across 4 aux kernels after a shared PBKDF2-SHA1 loop.

**Usage in this design:** Module 37000 uses `deep_comp_kernel` within the SHA-1 kernel (37011) to route Standard 2007 hashes to the `_comp` kernel (AES-ECB verify) and Agile 2010 hashes to `_aux1` (AES-128-CBC verify). The two modes share the identical SHA-1 init + loop but differ in the final verification cipher.

### Composability

`kern_type_dynamic` picks the `.cl` file. `deep_comp_kernel` picks a function within that file. They are orthogonal: one operates at session init, the other at per-digest compare time. No existing module uses both simultaneously, but the framework imposes no constraint against it. Module 37000 is the first to compose them.

### Constraints

- **`module_attack_exec`** is session-global. A module cannot serve both `ATTACK_EXEC_INSIDE_KERNEL` (non-iterated RC4 modes) and `ATTACK_EXEC_OUTSIDE_KERNEL` (iterated ECMA-376 modes). This forces RC4 legacy into a separate module (37100) from ECMA-376 (37000).
- **`module_pw_min` / `module_pw_max`** are session-global. Collider #1 modes pin `pw_min = pw_max = 5` (raw 5-byte key), while password-crack modes use `pw_max = 15`. This forces collider modes into separate modules (37101, 37102) from the base password-crack module (37100).

## Hash Line Formats

### `$office-open$` — Document-Open Encryption

Used by modules 37000 (ECMA-376), 37100 (RC4 password), 37101 (RC4 collider #1), and 37102 (RC4 collider #2).

```
$office-open$*<hashfunc>*<cipher>*<mode>*<iters>*<salt_hex>*<encverifier_hex>*<encverifierhash_hex>
```

| Token | Values | Purpose |
|-------|--------|---------|
| `hashfunc` | `sha1`, `sha256`, `sha384`, `sha512`, `md5` | KDF hash algorithm |
| `cipher` | `aes128`, `aes192`, `aes256`, `rc4-40`, `rc4-48`, ..., `rc4-128` | Cipher and key size |
| `mode` | `ecb`, `cbc`, `stream` | Cipher chaining mode |
| `iters` | Decimal integer; `0` for non-iterated RC4 | Spin count / iteration count |
| `salt_hex` | Lowercase hex | KDF salt (16 bytes typical) |
| `encverifier_hex` | Lowercase hex | Encrypted verifier (16 bytes) |
| `encverifierhash_hex` | Lowercase hex | Encrypted verifier hash (20 or 32 bytes) |

For collider #2 (module 37102), an 8th token is appended:

```
$office-open$*<hashfunc>*<cipher>*<mode>*<iters>*<salt>*<ev>*<evh>*<rc4key_hex>
```

The `(hashfunc, cipher, mode, iters)` tuple identifies the scheme unambiguously without year proxies or version digits.

**Concrete instances:**

| hashfunc | cipher | mode | iters | Scheme | Old mode |
|----------|--------|------|-------|--------|----------|
| `sha1` | `aes128` | `ecb` | `50000` | Standard 2007 (AES-128) | 9400 |
| `sha1` | `aes256` | `ecb` | `50000` | Standard 2007 (AES-256) | 9400 |
| `sha1` | `aes128` | `cbc` | variable | Agile 2010 | 9500 |
| `sha512` | `aes256` | `cbc` | variable | Agile 2013+ | 9600 |
| `sha256` | `aes128` | `cbc` | variable | Non-default Agile | **NEW** |
| `sha256` | `aes256` | `cbc` | variable | Non-default Agile | **NEW** |
| `sha384` | `aes256` | `cbc` | variable | Non-default Agile | **NEW** |
| `sha1` | `aes192` | `ecb` | `50000` | Standard AES-192 | **NEW** |
| `md5` | `rc4-40` | `stream` | `0` | RC4+MD5 (97/2000) | 9700 |
| `sha1` | `rc4-128` | `stream` | `0` | RC4+SHA-1 128-bit (XP/2003) | 9800 |
| `sha1` | `rc4-40` | `stream` | `0` | RC4+SHA-1 40-bit (XP/2003) | 9800 |
| `sha1` | `rc4-56` | `stream` | `0` | RC4+SHA-1 56-bit | **NEW** |

**Backward compatibility:** Modules 37000, 37100, 37101, 37102 also accept the old formats:

- `$office$*2007*<hashSize>*<keyBits>*<saltSize>*<salt>*<ev>*<evh>` → 37000, hash_type=SHA-1, cipher=AES-ECB
- `$office$*2010*<spin>*<keyBits>*<saltSize>*<salt>*<ev>*<evh>` → 37000, hash_type=SHA-1, cipher=AES-CBC-128
- `$office$*2013*<spin>*<keyBits>*<saltSize>*<salt>*<ev>*<evh>` → 37000, hash_type=SHA-512, cipher=AES-CBC-256
- `$oldoffice$0*<salt>*<ev>*<evh>` → 37100/37101, hash_type=MD5
- `$oldoffice$1*<salt>*<ev>*<evh>` → 37100/37101, hash_type=MD5
- `$oldoffice$3*<salt>*<ev>*<evh>` → 37100/37101, hash_type=SHA-1, key_bits=40
- `$oldoffice$4*<salt>*<ev>*<evh>` → 37100/37101, hash_type=SHA-1, key_bits=128
- `$oldoffice$N*<salt>*<ev>*<evh>*<rc4key>` → 37102 (6-token variant)

### `$office-protect$` — Protection/Permission Verifier

Used by module 37200.

```
$office-protect$*<hashfunc>*<kdf>*<iters>*<salt_hex>*<hash_hex>
```

| Token | Values | Purpose |
|-------|--------|---------|
| `hashfunc` | `sha1`, `sha256`, `sha384`, `sha512`, `md5` | Digest algorithm |
| `kdf` | `iso`, `crypt` | KDF variant (counter-appended; `crypt` adds a legacy pre-stage) |
| `iters` | Decimal integer | Spin count |
| `salt_hex` | Lowercase hex | Salt bytes |
| `hash_hex` | Lowercase hex | Expected digest |

The ISO KDF ([MS-OFFCRYPTO] Section 2.4.2.4) computes `H0 = H(salt || UTF16LE(pw))`, then spins `Hn = H(Hn-1 || LE32(i))` for `iters` rounds with the counter **appended** (the mirror image of the document-open KDF, which **prepends** the counter). No block key finalization; the final digest is compared directly.

The `crypt` KDF ([MS-OE376] Section 2.1.410) adds a legacy pre-stage before the same spin loop: the password is reduced through `CreatePasswordVerifier_Method2` (a 32-bit legacy hash), rendered as uppercase hex LE-bytes, then UTF-16LE-encoded, and that transformed value is hashed with the salt prepended.

**Backward compatibility:** Also accepts `$office$2016$0$<spin>$<saltb64>$<hashb64>` (mode 25300 format), mapping to `sha512*iso*100000`.

### `$odf$` — OpenDocument Encryption (Unified)

Used by module 37300.

```
$odf$*<startkey>*<kdf>*<cipher>*<iters>*<mem>*<lanes>*<salt_hex>*<iv_hex>*<checksum_hex>*<ciphertext_hex>
```

| Token | Values | Purpose |
|-------|--------|---------|
| `startkey` | `sha1`, `sha256` | Start-key pre-hash (before PBKDF2) |
| `kdf` | `pbkdf2` | Key derivation function (Argon2id removed from scope) |
| `cipher` | `blowfish`, `aes256`, `aes256gcm` | Symmetric cipher |
| `iters` | Decimal integer | PBKDF2 iteration count |
| `mem` | `0` | Reserved (was Argon2id memory cost; `0` for PBKDF2) |
| `lanes` | `0` | Reserved (was Argon2id parallelism; `0` for PBKDF2) |
| `salt_hex` | Lowercase hex | PBKDF2 salt |
| `iv_hex` | Lowercase hex | Cipher IV (8 bytes Blowfish, 16 bytes AES) |
| `checksum_hex` | Lowercase hex | SHA/1K checksum or GCM auth tag |
| `ciphertext_hex` | Lowercase hex | First ≤1024 encrypted bytes |

ODF deviation: the password is hashed as raw UTF-8 bytes, not UTF-16LE. The PBKDF2 PRF is always HMAC-SHA1, even in the SHA-256 profile (SHA-256 is only the start-key pre-hash and the checksum).

**Backward compatibility:** Also accepts the hashcat/odf2john numeric format:
- `$odf$*0*0*<iters>*<keysize>*<checksum>*<ivlen>*<iv>*<saltlen>*<salt>*0*<ct>` → `sha1*pbkdf2*blowfish` (18600)
- `$odf$*1*1*<iters>*<keysize>*<checksum>*<ivlen>*<iv>*<saltlen>*<salt>*0*<ct>` → `sha256*pbkdf2*aes256` (18400)

### `$office-vba$` — VBA Project Password

Used by module 37400.

```
$office-vba$*sha1*<hash_hex>*<salt_hex>
```

The VBA project password verifier is `SHA1(MBCS(password) || Key)` where `Key` is a 4-byte salt ([MS-OVBA] Section 2.4.4.4). This is exactly `sha1($pass.$salt)` — hashcat mode 110. Module 37400 provides its own parser for the `$office-vba$` line format but delegates to mode 110's kernel (`module_kern_type()` returns `110`). No new OpenCL file is needed.

The MBCS encoding (Windows-1252 by default) applies to the password bytes. For ASCII-range passwords the encoding is identity; for non-ASCII passwords the wordlist must contain cp1252-encoded bytes.

### `$office-msisam$` — MSISAM Page Encryption

Used by module 37500.

```
$office-msisam$<algo>$<salt_hex>$<crypt_check_hex>$<adjustment>
```

| Token | Values | Purpose |
|-------|--------|---------|
| `algo` | `md5`, `sha1` | Hash algorithm |
| `salt_hex` | Lowercase hex | Full salt |
| `crypt_check_hex` | Lowercase hex | Encrypted check bytes (RC4-decrypted and compared) |
| `adjustment` | Decimal integer | Salt adjustment value |

MSISAM (Microsoft Money 2002+) uses uppercased UTF-16LE password → MD5 or SHA-1 → RC4 → decrypt check bytes → compare. Non-iterated, inside-kernel.

## Module Specifications

### Module 37000 — `office-open` (ECMA-376 Document-Open)

**Hash name:** MS Office Document-Open (ECMA-376)

**Replaces:** 9400, 9500, 9600

**Execution:** `ATTACK_EXEC_OUTSIDE_KERNEL` — iterated KDF with counter **prepended**

**OPTS_TYPE:** `STOCK_MODULE | PT_GENERATE_LE | DEEP_COMP_KERNEL | AUX1`

**SALT_TYPE:** `SALT_TYPE_EMBEDDED`

**Hash category:** `HASH_CATEGORY_DOCUMENTS`

**esalt struct:**

```c
typedef struct {
  u32 hash_type;                 // 0=SHA-1, 1=SHA-256, 2=SHA-384, 3=SHA-512
  u32 cipher_type;               // 0=AES-ECB (standard), 1=AES-CBC (agile)
  u32 key_bits;                  // 128, 192, 256
  u32 encryptedVerifier[4];      // 16 bytes
  u32 encryptedVerifierHash[8];  // 20 bytes (standard) or 32 bytes (agile)
} office_open_t;
```

**tmp struct:**

```c
typedef struct {
  u64 out[8]; // SHA-512 state; SHA-1 uses out[0..4] as u32 pairs
} office_open_tmp_t;
```

**`kern_type_dynamic` dispatch:**

```c
enum {
  KERN_TYPE_OFFICE_OPEN_SHA1   = 37011,
  KERN_TYPE_OFFICE_OPEN_SHA256 = 37021,
  KERN_TYPE_OFFICE_OPEN_SHA384 = 37031,
  KERN_TYPE_OFFICE_OPEN_SHA512 = 37041,
};
```

**`deep_comp_kernel` dispatch** (only in 37011, SHA-1 kernel):

- `cipher_type == 0` (Standard/ECB) → `KERN_RUN_3` (`m37011_comp`)
- `cipher_type == 1` (Agile/CBC) → `KERN_RUN_AUX1` (`m37011_aux1`)

SHA-256/384/512 kernels always use Agile/CBC, so they return `KERN_RUN_3` unconditionally.

**Kernel files and lineage:**

| File | Init | Loop | Comp | Lineage |
|------|------|------|------|---------|
| m37011-pure.cl | SHA-1(salt \|\| pw) | SHA-1(LE32(i) \|\| H) | `_comp`: ipad/opad → AES-ECB; `_aux1`: block-key → AES-CBC-128 | init+loop from m09400; `_comp` from m09400; `_aux1` from m09500 |
| m37021-pure.cl | SHA-256(salt \|\| pw) | SHA-256(LE32(i) \|\| H) | block-key → AES-CBC | New; m09500 pattern with SHA-256 |
| m37031-pure.cl | SHA-384(salt \|\| pw) | SHA-384(LE32(i) \|\| H) | block-key → AES-CBC | New; m09500 pattern with SHA-384 |
| m37041-pure.cl | SHA-512(salt \|\| pw) | SHA-512(LE32(i) \|\| H) | block-key → AES-CBC-256 | From m09600 |

**JIT build options:**
- SHA-384/512 kernels: `-D _unroll` on NVIDIA/HIP/ROCM (from m09600)
- SHA-384/512: `OPTI_TYPE_USES_BITS_64`

**Self-test vectors:** Reuse from 9400 (standard), 9500 (agile SHA-1), 9600 (agile SHA-512). New vectors for SHA-256/384 variants.

---

### Module 37100 — `office-open-rc4` (Legacy RC4 Document-Open, Password Crack)

**Hash name:** MS Office Document-Open (Legacy RC4)

**Replaces:** 9700, 9800

**Execution:** `ATTACK_EXEC_INSIDE_KERNEL` — non-iterated, fast

**OPTS_TYPE (dynamic per hash_type):**
- MD5: `STOCK_MODULE | PT_GENERATE_LE | PT_ADD80 | PT_UTF16LE`
- SHA-1: `STOCK_MODULE | PT_GENERATE_BE | PT_ADD80 | PT_UTF16LE`

**esalt struct:**

```c
typedef struct {
  u32 hash_type;              // 0=MD5, 1=SHA-1
  u32 key_bits;               // 40, 48, 56, ..., 128
  u32 version;                // oldoffice digit for backward-compat encode
  u32 encryptedVerifier[4];   // 16 bytes
  u32 encryptedVerifierHash[5]; // 16 bytes (MD5) or 20 bytes (SHA-1)
  u32 secondBlockData[8];     // 40-bit CryptoAPI MITM field
  u32 secondBlockLen;
  u32 rc4key[2];              // recovered key (for potfile)
} office_rc4_t;
```

**`kern_type_dynamic` dispatch:**

```c
enum {
  KERN_TYPE_OFFICE_RC4_MD5  = 37150,
  KERN_TYPE_OFFICE_RC4_SHA1 = 37110,
};
```

**Kernel files and lineage:**

| File | Description | Lineage |
|------|-------------|---------|
| m37150-optimized.cl | MD5 KDF + gen336 + RC4 decrypt + MD5 verify | From m09700 |
| m37110-optimized.cl | SHA-1 KDF + RC4 decrypt + SHA-1 verify; `key_bits` drives truncation | From m09800 |

**Key improvement over 9800:** `key_bits` is parsed from the hash line and passed to the kernel via esalt. The kernel truncates `Hfinal` to `key_bits/8` bytes. A 56-bit file gets the correct 7-byte truncation instead of the old binary 5-or-16 split.

**JIT:** `-D FIXED_LOCAL_SIZE=32` (GPU) / `=1` (CPU) for RC4 shared memory (from m09700/m09800)

**pw_max:** 15 (from m09700/m09800)

---

### Module 37101 — `office-open-rc4-collider1` (RC4 Key-Seed Brute Force)

**Hash name:** MS Office Document-Open (Legacy RC4), collider #1

**Replaces:** 9710, 9810

**Execution:** `ATTACK_EXEC_INSIDE_KERNEL`

**OPTS_TYPE:** `STOCK_MODULE | PT_GENERATE_LE | PT_ALWAYS_HEXIFY | AUTODETECT_DISABLE`

The candidate is a raw 5-byte RC4 key, not a password. The kernel skips the KDF entirely: RC4(candidate, encryptedVerifier) → hash → compare against encryptedVerifierHash.

**pw_min = pw_max = 5** (fixed 40-bit key)

**esalt struct:** Same `office_rc4_t` as 37100.

**`kern_type_dynamic` dispatch:**

```c
enum {
  KERN_TYPE_OFFICE_RC4_MD5_COLL1  = 37151,
  KERN_TYPE_OFFICE_RC4_SHA1_COLL1 = 37111,
};
```

**Kernel files and lineage:**

| File | Description | Lineage |
|------|-------------|---------|
| m37151-optimized.cl | RC4(key5) → MD5 verify (no KDF) | From m09710 |
| m37111-optimized.cl | RC4(key5) → SHA-1 verify (no KDF) | From m09810 |

**Hash line format:** Accepts both `$office-open$*...` (7-token) and `$oldoffice$N*...` (5-token). The hash content is identical to the password-crack format; the user selects the key-brute attack by running `-m 37101` instead of `-m 37100`.

---

### Module 37102 — `office-open-rc4-collider2` (Password-from-Seed Recovery)

**Hash name:** MS Office Document-Open (Legacy RC4), collider #2

**Replaces:** 9720, 9820

**Execution:** `ATTACK_EXEC_INSIDE_KERNEL`

**OPTS_TYPE:**
- MD5: `STOCK_MODULE | PT_GENERATE_LE | PT_ADD80 | PT_UTF16LE | SUGGEST_KG | AUTODETECT_DISABLE`
- SHA-1: `STOCK_MODULE | PT_GENERATE_BE | PT_ADD80 | PT_UTF16LE | SUGGEST_KG | AUTODETECT_DISABLE`

The candidate is a password. The kernel derives the key from the password and compares it against the known `rc4key` stored in the esalt (recovered by collider #1). Does not decrypt or verify the verifier.

**esalt struct:** Same `office_rc4_t` as 37100. The `rc4key[2]` field carries the known key seed.

**`kern_type_dynamic` dispatch:**

```c
enum {
  KERN_TYPE_OFFICE_RC4_MD5_COLL2  = 37152,
  KERN_TYPE_OFFICE_RC4_SHA1_COLL2 = 37112,
};
```

**Kernel files and lineage:**

| File | Description | Lineage |
|------|-------------|---------|
| m37152-optimized.cl | MD5(pw) → truncate → compare rc4key | From m09720 |
| m37112-optimized.cl | SHA-1(salt \|\| pw) → truncate → compare rc4key | From m09820 |

**Hash line format:** Accepts `$office-open$*...*<rc4key_hex>` (8-token) and `$oldoffice$N*...*<rc4key_hex>` (6-token).

---

### Module 37200 — `office-protect` (Protection/Permission Verifier)

**Hash name:** MS Office Protection Verifier

**Replaces:** 25300

**Execution:** `ATTACK_EXEC_OUTSIDE_KERNEL` — iterated KDF with counter **appended**

**OPTS_TYPE:** `STOCK_MODULE | PT_GENERATE_LE`

**esalt struct:**

```c
typedef struct {
  u32 hash_type;   // 0=SHA-1, 1=SHA-256, 2=SHA-384, 3=SHA-512, 4=MD5
  u32 kdf_type;    // 0=iso, 1=crypt
} office_protect_t;
```

Minimal esalt. The digest IS the hash — no cipher verification. Salt goes in `salt_buf`, iteration count in `salt_iter`, expected hash in `digest_buf`.

**`kern_type_dynamic` dispatch:**

```c
enum {
  KERN_TYPE_PROTECT_SHA1_ISO     = 37211,
  KERN_TYPE_PROTECT_SHA1_CRYPT   = 37212,
  KERN_TYPE_PROTECT_SHA256_ISO   = 37221,
  KERN_TYPE_PROTECT_SHA384_ISO   = 37231,
  KERN_TYPE_PROTECT_SHA512_ISO   = 37241,
  KERN_TYPE_PROTECT_SHA512_CRYPT = 37242,
  KERN_TYPE_PROTECT_MD5_ISO      = 37251,
};
```

**Kernel files and lineage:**

| File | Init | Loop | Comp | Lineage |
|------|------|------|------|---------|
| m37211-pure.cl | SHA-1(salt \|\| pw) | SHA-1(H \|\| LE32(i)) | Direct compare | New; m25300 pattern with SHA-1 |
| m37212-pure.cl | SHA-1(salt \|\| method2(pw)) | SHA-1(H \|\| LE32(i)) | Direct compare | New; pre-stage in init |
| m37221-pure.cl | SHA-256(salt \|\| pw) | SHA-256(H \|\| LE32(i)) | Direct compare | New; m25300 pattern with SHA-256 |
| m37231-pure.cl | SHA-384(salt \|\| pw) | SHA-384(H \|\| LE32(i)) | Direct compare | New; m25300 pattern with SHA-384 |
| m37241-pure.cl | SHA-512(salt \|\| pw) | SHA-512(H \|\| LE32(i)) | Direct compare | From m25300 (hardcoded check removed) |
| m37242-pure.cl | SHA-512(salt \|\| method2(pw)) | SHA-512(H \|\| LE32(i)) | Direct compare | New; pre-stage in init |
| m37251-pure.cl | MD5(salt \|\| pw) | MD5(H \|\| LE32(i)) | Direct compare | New; m25300 pattern with MD5 |

The `crypt` KDF kernels (37212, 37242) implement the `CreatePasswordVerifier_Method2` pre-stage in the init kernel: password → 32-bit legacy hash → uppercase hex LE-bytes → UTF-16LE encode → then `H(salt || transformed_pw)`. The loop is identical to the `iso` variant.

**DGST_SIZE:** Varies by hash algorithm. SHA-512 needs `DGST_SIZE_8_8` (u64); SHA-1/MD5 use `DGST_SIZE_4_5` / `DGST_SIZE_4_4`. Set dynamically based on `hash_type` or use the largest and zero-pad.

**JIT:** SHA-384/512 kernels: `-D _unroll` on NVIDIA/HIP/ROCM, `OPTI_TYPE_USES_BITS_64`.

---

### Module 37300 — `odf` (OpenDocument PBKDF2)

**Hash name:** Open Document Format (ODF) 1.1/1.2/1.3

**Replaces:** 18400, 18600

**Execution:** `ATTACK_EXEC_OUTSIDE_KERNEL` — PBKDF2-HMAC-SHA1 iterated

**OPTS_TYPE:** `STOCK_MODULE | PT_GENERATE_LE` (+ `DYNAMIC_SHARED` for Blowfish kernel)

**esalt struct:**

```c
typedef struct {
  u32 start_key_type;       // 0=SHA-1, 1=SHA-256
  u32 cipher_type;          // 0=Blowfish-CFB, 1=AES-256-CBC, 2=AES-256-GCM
  u32 key_size;             // 16 (Blowfish) or 32 (AES-256)
  u32 iv[4];                // 8 bytes (Blowfish) or 16 bytes (AES)
  u32 iv_len;
  u32 checksum[8];          // SHA-1 (5 words) or SHA-256 (8 words) or GCM tag (4 words)
  u32 encrypted_data[256];  // first ≤1024 bytes of ciphertext
  u32 encrypted_len;
} odf_t;
```

**tmp struct:**

```c
typedef struct {
  u32 ipad[5];
  u32 opad[5];
  u32 dgst[10];
  u32 out[10];
} odf_tmp_t;
```

PBKDF2-HMAC-SHA1 state: `ipad`/`opad` are the HMAC key schedule, `dgst` is the per-round hash, `out` is the cumulative XOR. Two PBKDF2 blocks tracked in `dgst[0..4]`/`dgst[5..9]` and `out[0..4]`/`out[5..9]`, producing 40 bytes (enough for the 32-byte AES-256 key).

**`kern_type_dynamic` dispatch:**

```c
enum {
  KERN_TYPE_ODF_SHA1_BLOWFISH = 37311,
  KERN_TYPE_ODF_SHA256_AES    = 37321,
  KERN_TYPE_ODF_SHA256_GCM    = 37322,
};
```

**Kernel files and lineage:**

| File | Init | Loop | Comp | Lineage |
|------|------|------|------|---------|
| m37311-pure.cl | SHA-1(pw) → HMAC init → PBKDF2 block 1 | PBKDF2-HMAC-SHA1 (1 block) | Blowfish S-box setup → CFB-64 decrypt → SHA-1/1K | From m18600 |
| m37321-pure.cl | SHA-256(pw) → HMAC init → PBKDF2 blocks 1-2 | PBKDF2-HMAC-SHA1 (2 blocks) | AES-256-CBC decrypt → SHA-256/1K | From m18400 |
| m37322-pure.cl | SHA-256(pw) → HMAC init → PBKDF2 blocks 1-2 | PBKDF2-HMAC-SHA1 (2 blocks) | AES-256-GCM decrypt → tag verify | New |

All three share identical PBKDF2-HMAC-SHA1 loop code (only the block count differs: 1 for Blowfish/16-byte key, 2 for AES-256/32-byte key). The loop code is factored into a shared include.

**JIT for Blowfish kernel (37311):** Complex `FIXED_LOCAL_SIZE_COMP` logic for Blowfish S-box local memory (from m18600). `OPTS_TYPE_DYNAMIC_SHARED` required.

**pw_max:** 51 for Blowfish kernel (StarOffice SHA-1 bug workaround, from m18600).

---

### Module 37400 — `office-vba` (VBA Project Password)

**Hash name:** MS Office VBA Project Password

**Execution:** `ATTACK_EXEC_INSIDE_KERNEL` — single SHA-1 pass

**OPTS_TYPE:** `STOCK_MODULE | PT_GENERATE_BE | ST_ADD80 | ST_ADDBITS15`

**SALT_TYPE:** `SALT_TYPE_GENERIC`

**kern_type:** `110` — reuses mode 110's kernel (`sha1($pass.$salt)`). **No new OpenCL file.**

`module_kern_type()` returns `110`. The 4-byte VBA `Key` goes into `salt_buf`. The 20-byte SHA-1 digest goes into `digest_buf`. No esalt is needed.

**Parser:** Handles `$office-vba$*sha1*<hash_hex>*<salt_hex>`. Decodes the hash (40 hex chars → 20 bytes) into `digest_buf` with big-endian byte swap (SHA-1 is big-endian). Decodes the salt (8 hex chars → 4 bytes) into `salt_buf`. Sets `salt_len = 4`.

**Self-test vector:** A VBA project password whose SHA-1 and Key are known.

---

### Module 37500 — `office-msisam` (MSISAM Page Encryption)

**Hash name:** MS Office MSISAM (Microsoft Money)

**Execution:** `ATTACK_EXEC_INSIDE_KERNEL` — non-iterated

**OPTS_TYPE:** `STOCK_MODULE | PT_GENERATE_LE | PT_UTF16LE`

**esalt struct:**

```c
typedef struct {
  u32 hash_type;         // 0=MD5, 1=SHA-1
  u32 adjustment;        // salt adjustment value
  u32 crypt_check[8];    // encrypted check bytes
  u32 crypt_check_len;
} office_msisam_t;
```

**`kern_type_dynamic` dispatch:**

```c
enum {
  KERN_TYPE_MSISAM_MD5  = 37550,
  KERN_TYPE_MSISAM_SHA1 = 37510,
};
```

**Kernel files:**

| File | Description |
|------|-------------|
| m37550-optimized.cl | Uppercase UTF-16LE(pw) → MD5 → RC4 → decrypt check bytes → compare |
| m37510-optimized.cl | Uppercase UTF-16LE(pw) → SHA-1 → RC4 → decrypt check bytes → compare |

Both are new kernels. The MSISAM KDF uppercases the password before UTF-16LE encoding (unlike every other Office scheme).

## Kernel Numbering Map

```
37000 office-open (ECMA-376, OUTSIDE_KERNEL)
  37011  SHA-1    loop + ECB comp + CBC aux1
  37021  SHA-256  loop + CBC comp
  37031  SHA-384  loop + CBC comp
  37041  SHA-512  loop + CBC comp

37100 office-open-rc4 (password crack, INSIDE_KERNEL)
  37110  SHA-1 + RC4
  37150  MD5 + RC4

37101 office-open-rc4-collider1 (key brute, INSIDE_KERNEL)
  37111  SHA-1 + RC4 key brute
  37151  MD5 + RC4 key brute

37102 office-open-rc4-collider2 (password from key, INSIDE_KERNEL)
  37112  SHA-1 + RC4 password→key
  37152  MD5 + RC4 password→key

37200 office-protect (OUTSIDE_KERNEL)
  37211  SHA-1    iso
  37212  SHA-1    crypt
  37221  SHA-256  iso
  37231  SHA-384  iso
  37241  SHA-512  iso
  37242  SHA-512  crypt
  37251  MD5      iso

37300 odf (OUTSIDE_KERNEL)
  37311  SHA-1 start  + Blowfish-CFB
  37321  SHA-256 start + AES-256-CBC
  37322  SHA-256 start + AES-256-GCM

37400 office-vba (INSIDE_KERNEL)
  110    reuses sha1($pass.$salt) kernel

37500 office-msisam (INSIDE_KERNEL)
  37510  SHA-1 + RC4
  37550  MD5 + RC4
```

**Numbering convention:**

- Base `37x00`: the user-facing module number (-m flag)
- Tens digit (Y): hash algorithm — 1=SHA-1, 2=SHA-256, 3=SHA-384, 4=SHA-512, 5=MD5
- Ones digit (Z): cipher or KDF variant — 0=primary, 1=secondary, 2=tertiary
- The convention is consistent across all modules; room remains for future hash algorithms (Y=6-9) and cipher variants (Z=3-9)

## File Inventory

| Category | Count | Files |
|----------|-------|-------|
| Module C files | 8 | module_37000.c, module_37100.c, module_37101.c, module_37102.c, module_37200.c, module_37300.c, module_37400.c, module_37500.c |
| OpenCL kernels | 22 | m37011, m37021, m37031, m37041, m37110, m37111, m37112, m37150, m37151, m37152, m37211, m37212, m37221, m37231, m37241, m37242, m37251, m37311, m37321, m37322, m37510, m37550 |
| Reused kernel | 1 | m00110 (for module 37400) |
| **Total new files** | **30** | |

## Implementation Order

1. **37200 office-protect** — Simplest kernel family (pure hash, no cipher). Most immediate coverage gap (25300 only handles SHA-512/100000). SHA-512 kernel is nearly verbatim from m25300. Validates the `kern_type_dynamic` plumbing with a straightforward module.

2. **37000 office-open** — Highest value. Validates `kern_type_dynamic` + `deep_comp_kernel` composition. SHA-1 and SHA-512 kernels are copies of m09400/m09500/m09600 with the hardcoded parameter checks stripped.

3. **37300 odf** — Moderate complexity (PBKDF2 + cipher dispatch). Kernels are mostly from m18400/m18600 with the numeric-format hardcoding removed.

4. **37100 office-open-rc4** — Kernels are from m09700/m09800 with `key_bits` parameterization added. Validates inside-kernel `kern_type_dynamic`.

5. **37101/37102 colliders** — Kernels from m09710/m09720/m09810/m09820 with shared esalt struct. Low risk since the kernels are nearly verbatim.

6. **37400 office-vba** — Parser-only module, no kernel. Trivial.

7. **37500 office-msisam** — New kernels, niche target. Last because it has no predecessor to steal from.

## KDF Reference

This section gives the exact key derivation steps for each scheme, with spec section citations. These are the algorithms the kernels implement.

### ECMA-376 Standard Encryption ([MS-OFFCRYPTO] Section 2.3.4.7)

Used by Office 2007. Fixed 50000 iterations, SHA-1, AES-ECB.

```
Input:  password (Unicode), salt (16 bytes), keyBits (128/192/256)
Output: AES key (keyBits/8 bytes)

1. pw = UTF-16LE(password)                              // no BOM, no NUL
2. H0 = SHA-1(salt || pw)                               // salt PREPENDED
3. for i = 0 to 49999:
     H = SHA-1(LE32(i) || H)                            // counter PREPENDED
4. Hfinal = SHA-1(H || LE32(0))                         // block number 0
5. inner = XOR(Hfinal, 0x36 × 64)                       // ipad expansion
   outer = XOR(Hfinal, 0x5C × 64)
   X1 = SHA-1(inner), X2 = SHA-1(outer)
6. key = (X1 || X2)[0 : keyBits/8]                      // first keyBits/8 bytes
```

Verification ([MS-OFFCRYPTO] Section 2.3.4.9): AES-ECB-decrypt `encryptedVerifier` (16 bytes), SHA-1 the plaintext, AES-ECB-encrypt the first block of the hash, compare against `encryptedVerifierHash[0:16]`.

### ECMA-376 Agile Encryption ([MS-OFFCRYPTO] Section 2.3.4.11-2.3.4.13)

Used by Office 2010+ (SHA-1/SHA-256/SHA-384/SHA-512, AES-CBC, variable `spinCount`).

```
Input:  password, salt, spinCount, hashAlgorithm, keyBits, blockKey (8 bytes)
Output: derived key (keyBits/8 bytes)

1. pw = UTF-16LE(password)                              // no BOM, no NUL
2. H0 = H(salt || pw)                                   // H = hashAlgorithm
3. for i = 0 to spinCount-1:
     H = H(LE32(i) || H)                                // counter PREPENDED
4. Hfinal = H(H || blockKey)                            // 8-byte block key APPENDED
5. key = Hfinal[0 : keyBits/8]                          // pad with 0x36 if too short
```

Three block keys derive three independent keys from the same spun hash:
- `0xFEA7D2763B4B9E79` → verifier-input key (decrypts `encryptedVerifierHashInput`)
- `0xD7AA0F6D3061344E` → verifier-value key (decrypts `encryptedVerifierHashValue`)
- `0x146E0BE7ABACD0D6` → intermediate key (unwraps the bulk decryption key)

Verification ([MS-OFFCRYPTO] Section 2.3.4.13): AES-CBC-decrypt `encryptedVerifier` with the verifier-input key (IV = salt), hash the plaintext, AES-CBC-encrypt the first block with the verifier-value key, compare against `encryptedVerifierHash[0:blockSize]`.

### RC4+MD5 40-bit ([MS-OFFCRYPTO] Section 2.3.6.2)

Used by Office 97/2000. Non-iterated. Password max 15 characters.

```
Input:  password, salt (16 bytes), block (u32, 0 for verifier)
Output: 16-byte RC4 key (effective security: 40 bits)

1. H0 = MD5(UTF-16LE(pw))
2. t0 = H0[0:5]                                         // truncate to 40 bits
3. buffer = (t0 || salt) × 16                            // 21 bytes × 16 = 336 bytes
4. H1 = MD5(buffer)
5. t1 = H1[0:5]                                         // truncate again to 40 bits
6. key = MD5(t1 || LE32(block))                          // full 16-byte MD5 output
```

Verification ([MS-OFFCRYPTO] Section 2.3.6.4): RC4(key, `encryptedVerifier` || `encryptedVerifierHash`) as one continuous keystream (cipher state not reset between the two fields), then `MD5(decryptedVerifier) == decryptedHash`.

### RC4 CryptoAPI + SHA-1 ([MS-OFFCRYPTO] Section 2.3.5.2)

Used by Office XP/2003. Non-iterated. Key size 40-128 bits in 8-bit steps.

```
Input:  password, salt (16 bytes), keyBits (40-128), block (u32, 0 for verifier)
Output: RC4 key (keyBits/8 bytes, zero-padded to 16 for 40-bit)

1. H0 = SHA-1(salt || UTF-16LE(pw))                     // salt PREFIXED
2. Hfinal = SHA-1(H0 || LE32(block))
3. if keyBits == 40:
     key = Hfinal[0:5] || 0x00 × 11                     // 5 real + 11 zero bytes
   else:
     key = Hfinal[0 : keyBits/8]                         // truncate to key length
```

The key size is stored in `EncryptionHeader.KeySize` ([MS-OFFCRYPTO] Section 2.3.5.1). The `$oldoffice$` format encodes it lossily as version digit 3 (40-bit) or 4 (everything else), losing the actual value. The unified format carries the exact `key_bits`.

### ISO Write-Protection KDF ([MS-OFFCRYPTO] Section 2.4.2.4)

Used for sheet protection, workbook protection, document protection, write-reservation, and range passwords across all OOXML products.

```
Input:  password, salt, spinCount, algorithmName
Output: digest (algorithmName-dependent length)

1. pw = UTF-16LE(password)                              // no BOM, no NUL
2. H0 = H(salt || pw)                                   // salt PREPENDED
3. for i = 0 to spinCount-1:
     H = H(H || LE32(i))                                // counter APPENDED
4. return H                                             // no block key, no cipher
```

**Critical:** The counter is **appended** (`H || LE32(i)`), the mirror image of the document-open agile KDF which **prepends** it (`LE32(i) || H`). Both start from `H(salt || pw)`. Reversing the order silently produces a wrong digest.

The final digest is compared directly against the stored `hashValue` — there is no cipher verification step. The hash and salt are stored as Base64 XML attributes in the clear (unencrypted package).

**XML locations:** `<sheetProtection>` in `xl/worksheets/sheet*.xml`, `<workbookProtection>` in `xl/workbook.xml`, `<w:documentProtection>` in `word/settings.xml`, `<fileSharing>` in `xl/workbook.xml` or `word/settings.xml`.

### Crypt* documentProtection KDF ([MS-OE376] Section 2.1.410)

Used by Word 2007+ for `<w:documentProtection>` when `cryptAlgorithmSid` / `cryptSpinCount` attributes are present instead of `algorithmName` / `spinCount`.

```
Input:  password, cryptAlgorithmSid, cryptSpinCount, salt (Base64), hash (Base64)
Output: digest

1. legacy = CreatePasswordVerifier_Method2(password)     // [MS-OFFCRYPTO] Section 2.3.7.4
   → 32-bit integer combining XorKey (high 16) and Method1 verifier (low 16)
2. le_hex = legacy as 4 LE bytes, rendered as 8 uppercase hex ASCII chars
3. pre_stage = UTF-16LE(le_hex)                          // 16 bytes
4. H0 = H(salt || pre_stage)                             // salt PREPENDED (empirical)
5. for i = 0 to cryptSpinCount-1:
     H = H(H || LE32(i))                                // counter APPENDED
6. return H
```

**Spec deviation:** [MS-OE376] Section 2.1.410 note f states the salt is appended, but empirical testing against 4 corpus vectors from Office 2007 and 2013 shows it is prepended: `H(salt || X)`, not `H(X || salt)`. The kernel must follow the empirical behavior.

**Note:** `<w:writeProtection>` with `crypt*` attributes uses the standard ISO KDF (no pre-stage), not this variant. The pre-stage applies only to `<w:documentProtection>`.

**cryptAlgorithmSid mapping:** 1=MD2, 2=MD4, 3=MD5, 4=SHA-1 (Word 2007 default), 12=SHA-256, 13=SHA-384, 14=SHA-512.

### ODF Encryption (OASIS OpenDocument v1.2 Part 3 Section 3.4)

Three profiles. All use raw UTF-8 password bytes (not UTF-16LE). The PBKDF2 PRF is always HMAC-SHA1 even in the SHA-256 profile.

```
Input:  password (UTF-8 bytes), manifest parameters
Output: symmetric key

1. start_key = SHA-1(pw)         // ODF 1.1
   start_key = SHA-256(pw)       // ODF 1.2 and 1.3
2. key = PBKDF2-HMAC-SHA1(start_key, salt, iterations, key_size)
3. Decrypt member with key:
   - ODF 1.1: Blowfish-CFB-64 (8-byte IV), checksum = SHA-1 of first ≤1024 plaintext bytes
   - ODF 1.2: AES-256-CBC (16-byte IV), checksum = SHA-256 of first ≤1024 plaintext bytes
   - ODF 1.3: AES-256-GCM (12-byte nonce), verification = 16-byte GCM auth tag
```

**ODF 1.1 `pw_max=51`:** The StarOffice implementation limited the SHA-1 pre-hash to a single compression block (64 bytes minus overhead). Passwords longer than 51 UTF-8 bytes produce wrong start keys in StarOffice but not in modern LibreOffice. The hashcat kernel matches StarOffice behavior for compatibility.

**ODF 1.3 GCM:** The stored member is `IV(12) || ciphertext || tag(16)`. The nonce appears both prepended to the stream and in the manifest `initialisation-vector` attribute; LibreOffice checks they match. The AAD is empty. A wrong password fails the GCM tag.

### VBA Project Password ([MS-OVBA] Section 2.4.4.4)

```
Input:  password, Key (4 bytes), codepage (default cp1252)
Output: 20-byte SHA-1 digest

1. pw_bytes = MBCS_encode(password, codepage)            // NOT UTF-16LE
2. digest = SHA-1(pw_bytes || Key)                       // Key is the salt
```

Single SHA-1 pass. Identical to hashcat mode 110 (`sha1($pass.$salt)`). The Key is stored in the VBA `DPB` field after deobfuscation ([MS-OVBA] Section 2.4.3).

### MSISAM Page Encryption

Used by Microsoft Money 2002+ for Jet/MSISAM database page encryption.

```
Input:  password, salt, adjustment
Output: RC4 key

1. pw_upper = UPPERCASE(password)                        // uppercased BEFORE encoding
2. pw_bytes = UTF-16LE(pw_upper)                         // then UTF-16LE
3. key_hash = MD5(pw_bytes) or SHA-1(pw_bytes)           // algorithm from header
4. adjusted_salt = adjust(salt, adjustment)               // salt modification step
5. RC4-decrypt crypt_check bytes with derived key
6. Compare against expected check bytes
```

No public Microsoft spec. Behavior documented by reverse-engineering the MSISAM ISAM driver (msrd3x40.dll / acecore.dll).

## Password Encoding Rules

Every Office encryption scheme encodes the password differently. Getting the encoding wrong silently produces wrong keys.

| Scheme | Encoding | Max length | Spec reference |
|--------|----------|------------|----------------|
| ECMA-376 Standard (2007) | UTF-16LE, no BOM, no NUL | No spec limit | [MS-OFFCRYPTO] Section 2.3.4.7 |
| ECMA-376 Agile (2010+) | UTF-16LE, no BOM, no NUL | No spec limit | [MS-OFFCRYPTO] Section 2.3.4.11 |
| RC4+MD5 (97/2000) | UTF-16LE, no BOM, no NUL | 15 chars | [MS-OFFCRYPTO] Section 2.3.6; MSDN dd772916 |
| RC4 CryptoAPI+SHA-1 (XP/2003) | UTF-16LE, no BOM, no NUL | 255 chars | [MS-OFFCRYPTO] Section 2.3.5 |
| ISO protection | UTF-16LE, no BOM, no NUL | No spec limit | [MS-OFFCRYPTO] Section 2.4.2.4 |
| Crypt* protection | Legacy Method2 pre-stage, then UTF-16LE | No spec limit | [MS-OE376] Section 2.1.410 |
| ODF 1.1/1.2/1.3 | **Raw UTF-8** (not UTF-16LE), no NUL | 51 for ODF 1.1 (StarOffice bug) | OASIS ODF v1.2 Part 3 |
| VBA project | **MBCS** (Windows-1252 default), not UTF-16LE | 255 chars | [MS-OVBA] Section 2.4.4.4 |
| MSISAM | **Uppercased** then UTF-16LE | No spec limit | Reverse-engineered |

**Key pitfall for kernel authors:** UTF-16LE encoding is set by the `OPTS_TYPE_PT_UTF16LE` flag in the module, not in the kernel. ODF and VBA must NOT set this flag — their kernels receive raw bytes from the wordlist. MSISAM uppercases before the kernel sees the password, which requires either a `module_build_plain_postprocess` hook or an in-kernel transform.

## Spec References

### Microsoft Office

- **[MS-OFFCRYPTO]** — Office Document Cryptography Structure (latest revision: v28.0, 2024-10-14)
  - Section 2.1.4: `\EncryptionInfo` stream version discriminator (vMajor/vMinor select Standard, Agile, or IRM)
  - Section 2.3.1: `EncryptionHeaderFlags` — `fCryptoAPI` (0x04), `fAES` (0x20) bit definitions
  - Section 2.3.2: `EncryptionHeader` — `AlgID`, `AlgIDHash`, `KeySize`, `ProviderType` fields
  - Section 2.3.3: `EncryptionVerifier` — `Salt`, `EncryptedVerifier`, `EncryptedVerifierHash` layout
  - Section 2.3.4.5: Standard encryption header binary layout
  - Section 2.3.4.7: Standard encryption key derivation (SHA-1, ipad/opad expansion, 50000 fixed iterations)
  - Section 2.3.4.9: Standard encryption password verification (AES-ECB decrypt/hash/re-encrypt/compare)
  - Section 2.3.4.10: Agile encryption XML descriptor (`<encryption>` / `<keyData>` / `<keyEncryptor>`)
  - Section 2.3.4.11: Agile key derivation (spin loop with LE32 counter **prepended**, block-key finalization)
  - Section 2.3.4.12: Agile `_fit()` — truncate or pad hash to cipher block size
  - Section 2.3.4.13: Agile block keys for verifier-input, verifier-value, and intermediate keys
  - Section 2.3.4.14: `\EncryptedPackage` stream layout (8-byte LE plaintext-length prefix)
  - Section 2.3.4.15: Agile bulk decryption (4096-byte segments, per-segment IV from `H(keyDataSalt || LE32(segmentIndex))`)
  - Section 2.3.5: RC4 CryptoAPI encryption — `EncryptionVersionInfo` (vMajor ∈ {2,3,4}, vMinor=2), key sizes 40-128 in 8-bit steps
  - Section 2.3.5.1: CryptoAPI `EncryptionHeader` layout with `CSPName` (UTF-16LE, NUL-terminated)
  - Section 2.3.5.2: CryptoAPI key derivation (`SHA-1(salt || pw)`, `SHA-1(H0 || LE32(block))`, key truncation)
  - Section 2.3.5.6: CryptoAPI password verification (continuous RC4 keystream over verifier + hash)
  - Section 2.3.6: RC4 binary document encryption (MD5, 40-bit effective key, Office 97/2000)
  - Section 2.3.6.1: Version words (1,1) for the MD5 scheme
  - Section 2.3.6.2: MD5 key derivation (double truncation to 40 bits, gen336 buffer, block counter)
  - Section 2.3.6.4: MD5 password verification (continuous RC4, MD5 compare)
  - Section 2.3.7.4: `CreatePasswordVerifier_Method2` — the 32-bit legacy hash used by the crypt* KDF pre-stage
  - Section 2.4.2.4: ISO write-protection KDF — reserved algorithm table (SHA-1/256/384/512, MD2/MD4/MD5, RIPEMD-128/160, Whirlpool), counter **appended**, variable `spinCount`, variable salt length

- **[MS-OE376]** — Office Implementation Information for ECMA-376 Standards Support
  - Section 2.1.410: `crypt*` attributes on `<w:documentProtection>` and `<w:writeProtection>` — `cryptAlgorithmSid`, `cryptAlgorithmType`, `cryptSpinCount`, `cryptProviderType` definitions, algorithm SID table (1=MD2 through 14=SHA-512), note f (salt order — spec says appended, empirical evidence says prepended for documentProtection), note h (digest widths by SID), note j (spinCount clamped to 5000000)
  - Section 2.1.438: ISO `algorithmName` reserved-value table — SHA-1, SHA-256, SHA-384, SHA-512, MD5, MD4, MD2

- **[MS-OVBA]** — Office VBA File Format Reference
  - Section 2.3.1.15: `CMG=` — ProjectProtectionState (4-byte bitfield, Data Encryption wrapped)
  - Section 2.3.1.16: `DPB=` — ProjectPassword (cleartext, hash struct, or no-password sentinel)
  - Section 2.3.1.17: `GC=` — ProjectVisibilityState (1-byte flag)
  - Section 2.3.4.2.1.5: `PROJECTCODEPAGE` — code page for MBCS password encoding
  - Section 2.4.3: Data Encryption codec (seeded XOR stream, invertible from public values)
  - Section 2.4.3.1: `ProjKey` computation (byte-sum of ProjectId CLSID ASCII bytes)
  - Section 2.4.4.1: Password Hash Data Structure (29 bytes: Reserved + grbit + KeyNoNulls + HashNoNulls + Terminator)
  - Section 2.4.4.2: Encode Nulls — packs Key + Hash into grbit + no-null byte layout
  - Section 2.4.4.3: Decode Nulls — inverse
  - Section 2.4.4.4: Password hash computation: `SHA-1(MBCS(password, codepage) || Key)`
  - Section 2.4.4.5: Password verification

### OpenDocument Format

- **OASIS OpenDocument v1.2 Part 3: Packages** — Section 3.4: Encryption
  - Manifest XML attributes: `checksum-type`, `algorithm-name`, `key-derivation-name`, `iteration-count`, `key-size`, `salt`, `initialisation-vector`, `start-key-generation-name`
  - PBKDF2 PRF is HMAC-SHA1 for all profiles (the start-key hash is SHA-1 or SHA-256, but the stretch PRF is always SHA-1)
  - Cipher selection: Blowfish CFB (`urn:oasis:names:tc:opendocument:xmlns:manifest:1.0#blowfish`), AES-256-CBC (`http://www.w3.org/2001/04/xmlenc#aes256-cbc`), AES-256-GCM (`http://www.w3.org/2009/xmlenc11#aes256-gcm`)
  - Checksum: SHA-1/1K (`urn:oasis:names:tc:opendocument:xmlns:manifest:1.0#sha1-1k`) or SHA-256/1K (`urn:oasis:names:tc:opendocument:xmlns:manifest:1.0#sha256-1k`)

- **ODF 1.1** — Section 17.3: Encryption (Blowfish CFB, SHA-1 start key, PBKDF2-HMAC-SHA1, default 1024 iterations)

- **ODF 1.3 "Wholesome Encryption"** — LibreOffice 24.8+ (tdf#105844)
  - `loext:argon2-iterations`, `loext:argon2-memory`, `loext:argon2-lanes` manifest attributes (Argon2id KDF — out of scope for these modules; PBKDF2 variant is in scope)
  - AES-256-GCM: stored member layout is `IV(12) || ciphertext || tag(16)`, nonce in both stream prefix and manifest attribute, empty AAD
  - LibreOffice core implementation: `package/source/zipapi/ZipFile.cxx` (Argon2id), `package/source/zipapi/ciphercontext.cxx` (GCM IV/tag handling)
