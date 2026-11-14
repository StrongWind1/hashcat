#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import zlib

from lib.rar_legacy import crypt15, hash_line, parse_line
from lib.rar_pack import pack15, unpack15
from lib.test_helpers import random_bytes, random_number, split_hash_word

# RAR 1.5: a stream cipher keyed from the CRC32 of the password. The line carries a whole entry.
# A stored one hashcat decrypts and checks against the CRC32 of the file. A compressed one, the
# lines with method 33, it also unpacks first.

SIGNATURE = "$rar$15$"


def module_test_properties():
    return {
        "constraints": {
            "pure": {
                "password_length": [1, 127],
                "salt_length": None,
            },
            "optimized": None,
            "combined_length": None,
        },
    }


def module_generate_hash(word, salt, iterations=None):
    # mostly small, and now and then some tens of kilobytes, which the kernel still verifies itself
    # when the entry is stored. A hash is passed as one argument, so it cannot grow past that. The
    # host path is taken by the compressed lines.
    size = random_number(1, 2000) if random_number(0, 7) != 0 else random_number(32769, 36000)

    plaintext = random_bytes(size)

    # one line in three holds a compressed entry, which the host has to unpack
    packed = pack15(plaintext) if (size <= 2000 and random_number(0, 2) == 0) else None

    if packed is None:
        return hash_line(SIGNATURE, plaintext, crypt15(word, plaintext))

    return hash_line(SIGNATURE, plaintext, crypt15(word, packed), 0x33)


def module_verify_hash(line):
    parts = split_hash_word(line)

    if parts is None:
        return None

    hash_in, word = parts

    hash_str = hash_in.decode(errors="replace") if isinstance(hash_in, bytes) else hash_in

    parsed = parse_line(SIGNATURE, hash_str)

    if parsed is None:
        return None

    crc, unpack_size, encrypted, method = parsed

    stream = crypt15(word, encrypted)

    if method == 0x30:
        plaintext = stream[:unpack_size]
    elif method == 0x33:
        plaintext = unpack15(stream, unpack_size)
    else:
        return None

    if plaintext is None or zlib.crc32(plaintext) != crc:
        return None

    return (hash_str, word)
