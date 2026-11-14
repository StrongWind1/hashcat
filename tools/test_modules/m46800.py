#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib
import hmac
import zlib

from Crypto.Cipher import AES

from lib.rar_pack import pack50, unpack50
from lib.test_helpers import random_bytes, random_number, split_hash_word

# RAR5: one PBKDF2-HMAC-SHA256 run gives three values. After 2^n rounds the output is the AES-256
# key, 16 rounds later the key the file checksum is keyed with, and 16 rounds after that the value
# that is folded to the 8 byte password check.
#
# Type 0 lines carry the password check value. Type 1 lines carry a whole entry, stored (method 0)
# or packed as literals (method 3), which hashcat decrypts, unpacks where it has to, and checks against the CRC32 of the file (checktype 0), or against that CRC32
# keyed with HMAC-SHA256 and folded to 4 bytes (checktype 1).


def module_test_properties():
    return {
        "constraints": {
            "pure": {
                "password_length": [0, 256],
                "salt_length": [32, 32],
            },
            "optimized": None,
            "combined_length": None,
        },
    }


def _derive(word, salt, lg2, extra):
    return hashlib.pbkdf2_hmac("sha256", word, bytes.fromhex(salt), (1 << lg2) + extra, 32)


def _psw_check(word, salt, lg2):
    value = _derive(word, salt, lg2, 32)

    return bytes(value[i] ^ value[i + 8] ^ value[i + 16] ^ value[i + 24] for i in range(8))


def _checksum(word, salt, lg2, check_type, plaintext):
    crc = zlib.crc32(plaintext)

    if check_type == 1:
        mac = hmac.new(_derive(word, salt, lg2, 16), crc.to_bytes(4, "little"), hashlib.sha256).digest()

        crc = 0

        for i, b in enumerate(mac):
            crc ^= b << ((i & 3) * 8)

    return crc


def _line0(word, salt, lg2, iv):
    return "$rar$50$*0*%s*%d*%s*%s*0*****$/rar$" % (salt, lg2, iv, _psw_check(word, salt, lg2).hex())


def _line1(word, salt, lg2, iv, check_type, plaintext, method):
    stream = plaintext if method == 0 else pack50(plaintext)

    padded = stream + bytes(-len(stream) % 16)

    data = AES.new(_derive(word, salt, lg2, 0), AES.MODE_CBC, bytes.fromhex(iv)).encrypt(padded)

    return "$rar$50$*1*%s*%d*%s**%d*%08x*%x*%x*%d*%s$/rar$" % (
        salt, lg2, iv, check_type, _checksum(word, salt, lg2, check_type, plaintext), len(data), len(plaintext), method, data.hex()
    )


def module_generate_hash(word, salt, iterations=None):
    lg2 = 15 if iterations is None else int(iterations)

    kind = random_number(0, 2)

    if kind == 0:
        return _line0(word, salt, lg2, "0" * 32)

    return _line1(word, salt, lg2, random_bytes(16).hex(), kind - 1, random_bytes(random_number(1, 100)), [0, 3][random_number(0, 1)])


def module_verify_hash(line):
    parts = split_hash_word(line)

    if parts is None:
        return None

    hash_in, word = parts

    if not hash_in.startswith("$rar$50$*") or not hash_in.endswith("$/rar$"):
        return None

    fields = hash_in[9:-6].split("*")

    if len(fields) != 11:
        return None

    try:
        salt, lg2, iv = fields[1], int(fields[2]), fields[3]

        if fields[0] == "0":
            return (_line0(word, salt, lg2, iv), word)

        check_type = int(fields[5])
        data = bytes.fromhex(fields[10])
        unpack_size = int(fields[8], 16)

        if fields[0] != "1" or check_type > 1 or fields[9] not in ("0", "3") or len(data) % 16 != 0:
            return None

        stream = AES.new(_derive(word, salt, lg2, 0), AES.MODE_CBC, bytes.fromhex(iv)).decrypt(data)

        plaintext = stream[:unpack_size] if fields[9] == "0" else unpack50(stream, unpack_size)

        if plaintext is None:
            return None

        if _checksum(word, salt, lg2, check_type, plaintext) != int(fields[6], 16):
            return None

        return (hash_in, word)
    except ValueError:
        return None
