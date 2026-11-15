#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

from lib import zip_traditional as zt
from lib.test_helpers import random_bytes, random_number, split_hash_word

# ZIP traditional encryption: a stream cipher keyed from the password alone. A line carries the
# encryption header of up to eight members and the data of the first. hashcat tests the headers,
# then the data: a stored member by its CRC-32, a deflated one by inflating it (all of it, or the
# start when the line holds only the start), a bzip2 or xz one by the signature it begins with.


def module_test_properties():
    return {
        "constraints": {
            "pure": {
                "password_length": [0, 64],
                "salt_length": None,
            },
            "optimized": None,
            "combined_length": None,
        },
    }


def _text(size):
    # words repeated at random, so deflate has something to refer back to
    words = [random_bytes(random_number(3, 12)) for _ in range(40)]

    out = bytearray()

    while len(out) < size:
        out += words[random_number(0, 39)]

    return bytes(out[:size])


def module_generate_hash(word, salt, iterations=None):
    shape = random_number(0, 9)

    width = 2 if random_number(0, 3) == 0 else 1

    count = random_number(1, 8) if random_number(0, 2) == 0 else 1

    # a hash is passed as one argument, which keeps a line under 128 KB
    if shape <= 2:
        method, plaintext = (
            zt.STORED,
            random_bytes(
                random_number(1, 3000) if shape != 2 else random_number(20000, 40000)
            ),
        )
    elif shape <= 5:
        method, plaintext = (
            zt.DEFLATE,
            _text(
                random_number(1, 4000) if shape != 5 else random_number(60000, 200000)
            ),
        )
    elif shape == 6:
        method, plaintext = zt.DEFLATE, random_bytes(random_number(70000, 90000))
    elif shape == 7:
        method, plaintext = zt.BZIP2, _text(random_number(0, 2000))
    elif shape == 8:
        method, plaintext = zt.XZ, _text(random_number(0, 2000))
    else:
        method, plaintext = zt.STORED, random_bytes(random_number(1, 100))

    # headers alone are a weak test, so a line without data brings all eight of them
    if shape == 9:
        count = 8

    use_time = random_number(0, 4) == 0

    token, stream, crc = zt.member(
        word, method, plaintext, width, use_time, use_time and random_number(0, 1) == 0
    )

    tokens = [token]

    for _ in range(count - 1):
        other_width = 2 if random_number(0, 3) == 0 else 1

        other_token, _, _ = zt.member(
            word,
            zt.STORED,
            random_bytes(random_number(0, 40)),
            other_width,
            random_number(0, 4) == 0,
            random_number(0, 3) == 0,
        )

        tokens.append(other_token)

    packed = len(stream)

    if shape == 6:
        # incompressible and deflated: only the start goes into the line
        stream = stream[: random_number(1000, 40000)]
    elif shape == 9:
        # nothing but the headers
        stream = b""
    elif method in (zt.BZIP2, zt.XZ):
        stream = stream[: max(32, random_number(10, len(stream)))]

    return zt.line(tokens, method, crc, len(plaintext), packed, stream)


def module_verify_hash(line):
    parts = split_hash_word(line)

    if parts is None:
        return None

    hash_in, word = parts

    parsed = zt.parse(hash_in)

    if parsed is None:
        return None

    if not zt.verify(parsed, word):
        return None

    return (hash_in, word)
