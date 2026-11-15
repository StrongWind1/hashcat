#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

from lib import zip_strong
from lib.test_helpers import split_hash_word

# PKWARE strong encryption with AES-256, see lib/zip_strong.py.

BITS = 256


def module_test_properties():
    return {
        "constraints": {
            "pure": {
                "password_length": [0, 256],
                "salt_length": None,
            },
            "optimized": {
                "password_length": [0, 55],
                "salt_length": None,
            },
            "combined_length": None,
        },
    }


def module_generate_hash(word, salt, iterations=None):
    return zip_strong.generate(word, BITS)


def module_verify_hash(line):
    parts = split_hash_word(line)

    if parts is None:
        return None

    hash_in, word = parts

    parsed = zip_strong.parse(hash_in)

    if parsed is None or parsed["bits"] != BITS:
        return None

    if not zip_strong.verify(parsed, word):
        return None

    return (hash_in, word)
