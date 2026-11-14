#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import struct

import hashlib

import zlib

from Crypto.Cipher import AES

from lib.rar_pack import pack29, unpack29

from lib.test_helpers import random_bytes, random_number

# RAR3, header encryption (type 0) and file encryption (type 1) of a stored entry and of a compressed one, which hashcat has to unpack. The AES-128 key comes from a 0x40000 round SHA1 over the
# UTF-16LE password and salt, with RAR's quirk of hashing the buffer while an in-place SHA1 rewrites
# it, and every 0x4000th round contributes one IV byte. The key is the byte swapped first 16 bytes
# of the final digest. The check value is the first 16 bytes of AES-CBC over a fixed block. A volume
# ends in a 20 byte end header instead, 32 bytes once encrypted, whose second block is all zero.

ITERATIONS = 0x40000

MASK = 0xffffffff

FIXED_RAW_STRING = bytes.fromhex("c43d7b00400700000000000000000000")


def _rotl32(x, n):
  return ((x << n) | (x >> (32 - n))) & MASK


def _mangle_block(block):
  # RAR hashes the password buffer with a SHA1 that also overwrites it, one 64 byte block at a time.
  # The rewritten block is words W[64..79] of the SHA1 message schedule, which depends only on the
  # input bytes, so the hash state is not needed here.

  w = [int.from_bytes(block[k * 4:k * 4 + 4], "big") for k in range(16)]

  for i in range(16, 80):
    w.append(_rotl32(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1))

  return b"".join(w[64 + k].to_bytes(4, "little") for k in range(16))


def _sha1_update_rar29(ctx, buf, length, count):
  ctx.update(bytes(buf))

  j = count & 63

  if (j + length) <= 63:
    return

  i = 64 - j

  if (i + 63) >= length:
    return

  while (i + 63) < length:
    buf[i:i + 64] = _mangle_block(buf[i:i + 64])

    i += 64


def _derive(word, salt):
  # No IS_OPTIMIZED switch here, the oracle always widens each password byte to UTF-16LE.
  buf = bytearray(word.decode("latin-1").encode("utf-16-le") + salt)

  length = len(buf)
  count  = 0

  ctx = hashlib.sha1()
  iv  = b""

  for i in range(ITERATIONS):
    _sha1_update_rar29(ctx, buf, length, count)

    count += length

    ctx.update(struct.pack("<I", i)[0:3])

    count += 3

    if (i & 0x3fff) == 0:
      iv += ctx.copy().digest()[19:20]

  k = ctx.digest()

  # byte swap the first four 32 bit words into the AES-128 key
  key = b"".join(k[t * 4:t * 4 + 4][::-1] for t in range(4))

  return key, iv


def module_test_properties():
  return {
    'constraints': {
      'pure': {
        'password_length': [0, 128],
        'salt_length': [8, 8],
      },
      'optimized': {
        'password_length': [0, 20],
        'salt_length': [8, 8],
      },
      'combined_length': None,
    },
  }


def _volume_end_header():
  # header CRC, type 0x7b, flags (next volume, data CRC, reserved space, volume number), size 0x14,
  # data CRC and volume number, then 7 reserved and 12 padding bytes, all zero

  flags = [0x400f, 0x400e][random_number(0, 1)]

  head = random_bytes(2) + bytes([0x7b]) + struct.pack("<HH", flags, 0x14) + random_bytes(4)

  head += struct.pack("<H", random_number(0, 99))

  return head + bytes(32 - len(head))


def _line0(salt, hash_buf):
  # type 0, header encryption: the encrypted end header behind the fixed CRC, sizes and method 0

  return "$rar$30$*0*%s*c43d7b00*%x*%x*0*%s$/rar$" % (salt.hex(), len(hash_buf), len(hash_buf), hash_buf.hex())


def _line1(word, salt, plaintext, method):
  # type 1, file encryption: a whole entry, zero padded to the AES block size. Method 30 is a
  # stored entry, method 33 one packed as literals.

  key, iv = _derive(word, salt)

  stream = plaintext if method == 0x30 else pack29(plaintext)

  padded = stream + bytes(-len(stream) % 16)

  data = AES.new(key, AES.MODE_CBC, iv).encrypt(padded)

  return "$rar$30$*1*%s*%08x*%x*%x*%x*%s$/rar$" % (salt.hex(), zlib.crc32(plaintext), len(data), len(plaintext), method, data.hex())


def module_generate_hash(word, salt, iterations=None, crypted=None):
  if isinstance(salt, str):
    salt = salt.encode("latin-1")

  if crypted is None and random_number(0, 2) == 0:
    return _line1(word, salt, random_bytes(random_number(1, 100)), [0x30, 0x33][random_number(0, 1)])

  key, iv = _derive(word, salt)

  if crypted is None:
    if random_number(0, 1) == 0:
      hash_buf = AES.new(key, AES.MODE_CBC, iv).encrypt(FIXED_RAW_STRING)
    else:
      hash_buf = AES.new(key, AES.MODE_CBC, iv).encrypt(_volume_end_header())
  elif len(crypted) == 32:
    # re-encrypting what the first block decrypts to, ahead of a zero block, gives the line back
    # only when the password is right

    head = AES.new(key, AES.MODE_CBC, iv).decrypt(crypted)[0:16]

    hash_buf = AES.new(key, AES.MODE_CBC, iv).encrypt(head + bytes(16))
  else:
    hash_buf = AES.new(key, AES.MODE_CBC, iv).encrypt(FIXED_RAW_STRING)

  return _line0(salt, hash_buf)


def module_verify_hash(line):
  idx = line.rfind(b":")

  if idx < 1:
    return None

  hash_in = line[:idx].decode(errors="replace")
  word    = line[idx + 1:]

  if not hash_in.startswith("$rar$30$*") or not hash_in.endswith("$/rar$"):
    return None

  fields = hash_in[9:-6].split("*")

  if len(fields) != 7:
    return None

  try:
    salt = bytes.fromhex(fields[1])
    data = bytes.fromhex(fields[6])
  except ValueError:
    return None

  if fields[0] == "0":
    return (module_generate_hash(word, salt, None, data), word)

  if fields[0] != "1" or fields[5] not in ("30", "33") or len(data) % 16 != 0:
    return None

  key, iv = _derive(word, salt)

  stream = AES.new(key, AES.MODE_CBC, iv).decrypt(data)

  unpack_size = int(fields[4], 16)

  plaintext = stream[:unpack_size] if fields[5] == "30" else unpack29(stream, unpack_size)

  if plaintext is None or zlib.crc32(plaintext) != int(fields[2], 16):
    return None

  return (hash_in, word)
