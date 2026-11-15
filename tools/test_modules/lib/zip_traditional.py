##
## Author......: See docs/credits.txt
## License.....: MIT
##

# The $zip$1$ line of ZIP traditional encryption (ZipCrypto) for the test modules of the modes
# that read it. See src/modules/zip_traditional.c for the fields.

import bz2
import lzma
import zlib

from lib.pkzip import ZipCrypto
from lib.test_helpers import random_bytes, random_number

SIGNATURE = "$zip$1$"
STOP = "$/zip$"

STORED = 0
DEFLATE = 8
BZIP2 = 12
XZ = 95

BZIP2_BLOCK = bytes.fromhex("314159265359")
BZIP2_EMPTY = bytes.fromhex("177245385090")
XZ_SIGNATURE = bytes.fromhex("fd377a585a0000")


def deflate(data):
    packer = zlib.compressobj(random_number(1, 9), zlib.DEFLATED, -15)

    return packer.compress(data) + packer.flush()


def inflate(data):
    unpacker = zlib.decompressobj(-15)

    try:
        out = unpacker.decompress(data)
    except zlib.error:
        return None

    if not unpacker.eof:
        return None

    return out


def inflate_prefix(data):
    # the start of a stream: it has to decode without an error and must not have ended yet
    unpacker = zlib.decompressobj(-15)

    try:
        unpacker.decompress(data)
    except zlib.error:
        return False

    return not unpacker.eof


def compress(method, data):
    if method == STORED:
        return data

    if method == DEFLATE:
        return deflate(data)

    if method == BZIP2:
        return bz2.compress(data, random_number(1, 9))

    return lzma.compress(data, format=lzma.FORMAT_XZ, check=lzma.CHECK_CRC32)


def header(word, check, width, salt=None):
    # 12 bytes: random ones, then the value the reader compares, in the last byte or the last two
    body = random_bytes(12 - width) if salt is None else salt[: 12 - width]

    tail = bytes([check >> 8]) if width == 1 else bytes([check & 0xFF, check >> 8])

    return ZipCrypto(word).encrypt(body + tail)


def check_token(encrypted_header, width, value, other=None):
    digits = 2 if width == 1 else 4

    shown = (value >> 8) if width == 1 else value

    token = encrypted_header.hex() + "/" + format(shown, f"0{digits}x")

    if other is not None:
        shown = (other >> 8) if width == 1 else other

        token += "/" + format(shown, f"0{digits}x")

    return token


def member(word, method, plaintext, width=1, use_time=False, alternative=False):
    # returns the check token of a member and its encrypted stream without the header
    crc = zlib.crc32(plaintext)

    from_crc = crc >> 16
    from_time = random_number(0, 0xFFFF)

    value = from_time if use_time else from_crc

    cipher = ZipCrypto(word)

    body = random_bytes(12 - width)

    tail = bytes([value >> 8]) if width == 1 else bytes([value & 0xFF, value >> 8])

    encrypted_header = cipher.encrypt(body + tail)

    stream = cipher.encrypt(compress(method, plaintext))

    if alternative:
        # the order of the two values carries no meaning
        token = (
            check_token(encrypted_header, width, from_time, from_crc)
            if use_time
            else check_token(encrypted_header, width, from_crc, from_time)
        )
    else:
        token = check_token(encrypted_header, width, value)

    return token, stream, crc


def line(tokens, method, crc, unpacked, packed, data):
    return f"{SIGNATURE}*{len(tokens)}*{'*'.join(tokens)}*{method}*{crc:08x}*{unpacked:x}*{packed:x}*{data.hex()}{STOP}"


def parse(text):
    if not text.startswith(SIGNATURE + "*") or not text.endswith(STOP):
        return None

    fields = text[len(SIGNATURE) + 1 : -len(STOP)].split("*")

    try:
        count = int(fields[0])

        if len(fields) != 1 + count + 5:
            return None

        checks = []

        for token in fields[1 : 1 + count]:
            parts = token.split("/")

            if len(parts) not in (2, 3) or len(parts[0]) != 24:
                return None

            width = len(parts[1]) // 2

            checks.append(
                (bytes.fromhex(parts[0]), width, [int(p, 16) for p in parts[1:]])
            )

        at = 1 + count

        return {
            "checks": checks,
            "method": int(fields[at]),
            "crc": int(fields[at + 1], 16),
            "unpacked": int(fields[at + 2], 16),
            "packed": int(fields[at + 3], 16),
            "data": bytes.fromhex(fields[at + 4]),
        }
    except ValueError:
        return None


def verify(parsed, word):
    first = None

    for index, (encrypted_header, width, values) in enumerate(parsed["checks"]):
        cipher = ZipCrypto(word)

        plain = cipher.decrypt(encrypted_header)

        got = plain[11] if width == 1 else (plain[10] | (plain[11] << 8))

        if got not in values:
            return False

        if index == 0:
            first = cipher

    data = parsed["data"]

    if len(data) == 0:
        return True

    stream = first.decrypt(data)

    method = parsed["method"]

    if method == STORED:
        return len(stream) == parsed["unpacked"] and zlib.crc32(stream) == parsed["crc"]

    if method == DEFLATE:
        if len(data) < parsed["packed"]:
            return inflate_prefix(stream)

        out = inflate(stream)

        return (
            out is not None
            and len(out) == parsed["unpacked"]
            and zlib.crc32(out) == parsed["crc"]
        )

    if method == BZIP2:
        return (
            stream[:3] == b"BZh"
            and (stream[3] & 0xF0) == 0x30
            and stream[4:10]
            == (BZIP2_EMPTY if parsed["unpacked"] == 0 else BZIP2_BLOCK)
        )

    if method == XZ:
        return stream[:7] == XZ_SIGNATURE and (stream[7] & 0xF0) == 0

    return False
