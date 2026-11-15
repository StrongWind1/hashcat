#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import bz2
import hashlib
import hmac
import lzma
import zlib

from Crypto.Cipher import AES
from Crypto.Util import Counter
from lib.test_helpers import random_bytes, random_number, split_hash_word

# WinZip AES. PBKDF2-HMAC-SHA1 with 1000 iterations gives the cipher key, the authentication key
# and two verifier bytes. A line that holds the whole entry is tested against its authentication
# code. One that holds the start of a long deflate stream is decrypted and inflated, and one that
# holds the start of a bzip2 or xz stream is recognised by the signature it decrypts to.

SIGNATURE = "$zip$2$"
STOP = "$/zip$"

ITERATIONS = 1000

DEFLATE = 8
BZIP2 = 12
XZ = 95


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


def _keys(word, salt, mode):
    key_len = 8 + (8 * mode)

    derived = hashlib.pbkdf2_hmac("sha1", word, salt, ITERATIONS, (key_len * 2) + 2)

    return derived[:key_len], derived[key_len : key_len * 2], derived[key_len * 2 :]


def _crypt(key, data):
    # the counter starts at 1 and is stored little endian
    counter = Counter.new(128, initial_value=1, little_endian=True)

    return AES.new(key, AES.MODE_CTR, counter=counter).encrypt(data)


def _text(size):
    words = [random_bytes(random_number(3, 12)) for _ in range(40)]

    out = bytearray()

    while len(out) < size:
        out += words[random_number(0, 39)]

    return bytes(out[:size])


def _deflate(data):
    packer = zlib.compressobj(random_number(1, 9), zlib.DEFLATED, -15)

    return packer.compress(data) + packer.flush()


def module_generate_hash(word, salt, iterations=None):
    mode = random_number(1, 3)

    salt_bin = bytes.fromhex(salt[: 8 + (mode * 8)])

    cipher_key, auth_key, verifier = _keys(word, salt_bin, mode)

    shape = random_number(0, 9)

    # a hash is passed as one argument, which keeps a line under 128 KB
    if shape <= 3:
        method, stream = DEFLATE, _deflate(_text(random_number(0, 4000)))
    elif shape == 4:
        method, stream = 0, random_bytes(random_number(0, 40000))
    elif shape <= 6:
        method, stream = DEFLATE, _deflate(random_bytes(random_number(70000, 90000)))
    elif shape == 7:
        method, stream = BZIP2, bz2.compress(_text(random_number(1, 2000)))
    elif shape == 8:
        method, stream = (
            XZ,
            lzma.compress(_text(random_number(1, 2000)), format=lzma.FORMAT_XZ),
        )
    else:
        method, stream = DEFLATE, b""

    encrypted = _crypt(cipher_key, stream)

    auth = hmac.new(auth_key, encrypted, hashlib.sha1).digest()[:10]

    packed = len(encrypted)

    if shape in (5, 6):
        # incompressible and deflated: only the start goes into the line
        encrypted = encrypted[: random_number(2000, 40000)]
    elif shape in (7, 8):
        encrypted = encrypted[:32]

    return f"{SIGNATURE}*{mode}*{salt_bin.hex()}*{verifier.hex()}*{auth.hex()}*{method}*{packed:x}*{encrypted.hex()}{STOP}"


def _prefix_ok(stream):
    unpacker = zlib.decompressobj(-15)

    try:
        unpacker.decompress(stream)
    except zlib.error:
        return False

    return not unpacker.eof


def module_verify_hash(line):
    parts = split_hash_word(line)

    if parts is None:
        return None

    hash_in, word = parts

    if not hash_in.startswith(SIGNATURE + "*") or not hash_in.endswith(STOP):
        return None

    fields = hash_in[len(SIGNATURE) + 1 : -len(STOP)].split("*")

    if len(fields) != 7:
        return None

    try:
        mode = int(fields[0])
        salt_bin = bytes.fromhex(fields[1])
        verifier = bytes.fromhex(fields[2])
        auth = bytes.fromhex(fields[3])
        method = int(fields[4])
        packed = int(fields[5], 16)
        data = bytes.fromhex(fields[6])
    except ValueError:
        return None

    if mode not in (1, 2, 3):
        return None

    cipher_key, auth_key, got = _keys(word, salt_bin, mode)

    if got != verifier:
        return None

    if len(data) == packed:
        ok = hmac.new(auth_key, data, hashlib.sha1).digest()[:10] == auth
    elif len(data) == 0:
        ok = True
    else:
        stream = _crypt(cipher_key, data)

        if method == DEFLATE:
            ok = _prefix_ok(stream)
        elif method == BZIP2:
            ok = (
                stream[:3] == b"BZh"
                and (stream[3] & 0xF0) == 0x30
                and stream[4:10] == bytes.fromhex("314159265359")
            )
        elif method == XZ:
            ok = (
                stream[:7] == bytes.fromhex("fd377a585a0000")
                and (stream[7] & 0xF0) == 0
            )
        else:
            ok = False

    if not ok:
        return None

    return (hash_in, word)
