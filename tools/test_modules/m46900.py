#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import bz2
import hashlib
import lzma
import struct
import zlib

from Crypto.Cipher import AES
from lib.test_helpers import kernel_charset, random_bytes, random_number

# 7-Zip. The AES-256 key is one SHA-256 over 2^power copies of the UTF-16LE password, each followed
# by an 8 byte little endian counter. The data is packed, then encrypted in CBC mode, and the
# archive stores the CRC-32 of what it unpacks to.
#
#   $7z$*power*salt*crc32*crc_len*join*N*iv*packed*unpacked*chain*data$/7z$
#
# The chain names the coders that run after decryption, in that order, each as id/properties/size.
# Generate packs a random buffer with one of the shapes below, fills the last cipher block with
# random bytes, because nothing says what a writer puts there, and encrypts. Verify decrypts,
# unpacks with the chain the line names and writes the line again with the CRC-32 it found.
#
# The salt the test hands over is the initialisation vector, as many bytes as it has.

ID_LZMA1 = "030101"
ID_LZMA2 = "21"
ID_DEFLATE = "040108"
ID_BZIP2 = "040202"
ID_DELTA = "03"
ID_SWAP2 = "020302"
ID_SWAP4 = "020304"

PACKERS = {ID_LZMA1: lzma.FILTER_LZMA1, ID_LZMA2: lzma.FILTER_LZMA2}

CONVERTERS = {
    "03030103": lzma.FILTER_X86,
    "03030205": lzma.FILTER_POWERPC,
    "03030401": lzma.FILTER_IA64,
    "03030501": lzma.FILTER_ARM,
    "03030701": lzma.FILTER_ARMTHUMB,
    "03030805": lzma.FILTER_SPARC,
}

# A few instructions each branch converter rewrites, so the filter changes the data rather than
# passing random bytes through untouched: an x86 call, a PowerPC bl, an IA64 bundle whose third slot
# holds a branch, an ARM bl, a Thumb bl pair and a SPARC call.

BRANCHES = {
    "03030103": b"\xe8\x10\x20\x30\x00",
    "03030205": b"\x48\x00\x10\x01",
    "03030401": b"\x10" + b"\x00" * 14 + b"\x50",
    "03030501": b"\x10\x20\x30\xeb",
    "03030701": b"\x10\xf0\x20\xf8",
    "03030805": b"\x40\x00\x10\x20",
}

# What a folder is packed with: a packer, or nothing, and a filter that ran in front of it.

SHAPES = [
    (None, None),
    (ID_LZMA1, None),
    (ID_LZMA2, None),
    (ID_DEFLATE, None),
    (ID_BZIP2, None),
    (ID_LZMA1, "03030103"),
    (ID_LZMA2, "03030103"),
    (ID_LZMA2, "03030205"),
    (ID_LZMA2, "03030401"),
    (ID_LZMA2, "03030501"),
    (ID_LZMA2, "03030701"),
    (ID_LZMA2, "03030805"),
    (ID_LZMA2, ID_DELTA),
    (ID_DEFLATE, ID_SWAP2),
    (ID_BZIP2, ID_SWAP4),
    (None, ID_DELTA),
]


def module_test_properties():
    return {
        "constraints": {
            "pure": {
                "password_length": [0, 256],
                "salt_length": [0, 16],
            },
            "optimized": {
                "password_length": [0, 20],
                "salt_length": [0, 16],
            },
            "combined_length": None,
        },
    }


def _derive_key(word, power):
    word_utf16le = word.decode(kernel_charset(), errors="replace").encode("utf-16-le")

    ctx = hashlib.sha256()

    for i in range(1 << power):
        ctx.update(word_utf16le + struct.pack("<Q", i))

    return ctx.digest()


def _swap(data, width):
    out = bytearray(data)

    for i in range(0, len(out) - width + 1, width):
        out[i : i + width] = out[i : i + width][::-1]

    return bytes(out)


def _delta_encode(data, dist):
    out = bytearray(data)

    for i in range(len(out) - 1, dist - 1, -1):
        out[i] = (out[i] - out[i - dist]) & 0xFF

    return bytes(out)


def _delta_decode(data, dist):
    out = bytearray(data)

    for i in range(dist, len(out)):
        out[i] = (out[i] + out[i - dist]) & 0xFF

    return bytes(out)


def _plain_data(conv):
    # The first file is 16 * k + 2 bytes long, so a branch placed 2 bytes before its end sits on the
    # alignment every filter needs and crosses into whatever follows.

    first = bytearray(random_bytes(16 * random_number(4, 16) + 2))

    branch = BRANCHES.get(conv, b"")

    if len(branch) > 0:
        # every 32 bytes, which keeps an IA64 bundle on its 16 byte boundary

        for offset in range(0, len(first) - len(branch), 32):
            first[offset : offset + len(branch)] = branch

    # Half the time the folder holds a second file, and a branch then crosses from the first into it.
    # The CRC covers the first file only, and the filter converts that branch the way the encoder did
    # only when it is given the bytes after the first file.

    if random_number(0, 1) == 0:
        return bytes(first), len(first)

    data = first + bytearray(random_bytes(random_number(16, 64)))

    if len(branch) > 0:
        data[len(first) - 2 : len(first) - 2 + len(branch)] = branch

    return bytes(data), len(first)


def _pack(packer, conv, plain):
    # returns the packed stream and the chain that undoes it, in the order it is undone

    total = len(plain)

    if conv in CONVERTERS:
        # liblzma runs the converter and the packer as one chain

        chain = [
            {"id": CONVERTERS[conv]},
            {"id": PACKERS[packer], "dict_size": 1 << 16},
        ]
        packed = lzma.compress(plain, format=lzma.FORMAT_RAW, filters=chain)
        props = lzma._encode_filter_properties(chain[1])

        return packed, f"{packer}/{props.hex()}/{total:x},{conv}//{total:x}"

    filtered = plain
    tail = ""

    if conv == ID_DELTA:
        dist = random_number(1, 256)
        filtered = _delta_encode(plain, dist)
        tail = f"{ID_DELTA}/{dist - 1:02x}/{total:x}"
    elif conv == ID_SWAP2:
        filtered = _swap(plain, 2)
        tail = f"{ID_SWAP2}//{total:x}"
    elif conv == ID_SWAP4:
        filtered = _swap(plain, 4)
        tail = f"{ID_SWAP4}//{total:x}"

    if packer is None:
        return filtered, tail

    if packer in PACKERS:
        spec = {"id": PACKERS[packer], "dict_size": 1 << 16}
        packed = lzma.compress(filtered, format=lzma.FORMAT_RAW, filters=[spec])
        head = f"{packer}/{lzma._encode_filter_properties(spec).hex()}/{total:x}"
    elif packer == ID_DEFLATE:
        coder = zlib.compressobj(9, zlib.DEFLATED, -15)
        packed = coder.compress(filtered) + coder.flush()
        head = f"{ID_DEFLATE}//{total:x}"
    else:
        packed = bz2.compress(filtered)
        head = f"{ID_BZIP2}//{total:x}"

    return packed, head + ("," + tail if tail else "")


def _unpack(chain, stream):
    # undo a chain. None when the stream is not what the chain says it is

    coders = [entry.split("/") for entry in chain.split(",")] if chain else []

    data = stream

    for pos, (ident, props, size) in enumerate(coders):
        size = int(size, 16)

        try:
            if ident in PACKERS:
                filters = [lzma._decode_filter_properties(PACKERS[ident], bytes.fromhex(props))]

                # a converter behind the packer is one chain with it for liblzma

                if pos + 1 < len(coders) and coders[pos + 1][0] in CONVERTERS:
                    filters.insert(0, {"id": CONVERTERS[coders[pos + 1][0]]})

                data = lzma.LZMADecompressor(format=lzma.FORMAT_RAW, filters=filters).decompress(data, max_length=size)
            elif ident == ID_DEFLATE:
                data = zlib.decompressobj(-15).decompress(data, size)
            elif ident == ID_BZIP2:
                data = bz2.decompress(data)
            elif ident == ID_DELTA:
                data = _delta_decode(data, int(props, 16) + 1)
            elif ident == ID_SWAP2:
                data = _swap(data, 2)
            elif ident == ID_SWAP4:
                data = _swap(data, 4)
            elif ident in CONVERTERS:
                pass
            else:
                return None
        except (lzma.LZMAError, zlib.error, OSError, ValueError, EOFError):
            return None

        if len(data) < size:
            return None

    return data


def _line(power, crc, crc_len, iv, packed, unpacked, chain, data):
    return f"$7z$*{power}**{crc:08x}*{crc_len:x}**1*{iv.hex()}*{packed:x}*{unpacked:x}*{chain}*{data.hex()}$/7z$"


def module_generate_hash(word, salt, power=None, crc_len=None, unpacked=None, chain=None, data=None):
    if isinstance(salt, str):
        salt = salt.encode("latin-1")

    iv = salt + b"\x00" * (16 - len(salt))

    if data is not None:
        key = _derive_key(word, power)

        plain = _unpack(chain, AES.new(key, AES.MODE_CBC, iv).decrypt(data)[:unpacked])

        # a wrong password decrypts to noise, which a decoder refuses or turns into another CRC-32

        crc = 0

        if plain is not None and len(plain) >= crc_len:
            crc = zlib.crc32(plain[:crc_len]) & 0xFFFFFFFF

        return _line(power, crc, crc_len, salt, len(data), unpacked, chain, data)

    power = 14

    packer, conv = SHAPES[random_number(0, len(SHAPES) - 1)]

    plain, crc_len = _plain_data(conv)

    # stored data has no size of its own in the line, so the CRC-32 covers all of it

    if packer is None and conv is None:
        crc_len = len(plain)

    stream, chain = _pack(packer, conv, plain)

    unpacked = len(stream)

    # 7-Zip fills the last cipher block with zeros. Nothing reads them back, and other writers put
    # something else there, so the line is not allowed to depend on them.

    padded = stream + random_bytes((16 - unpacked % 16) % 16)

    data = AES.new(_derive_key(word, power), AES.MODE_CBC, iv).encrypt(padded)

    return _line(
        power,
        zlib.crc32(plain[:crc_len]) & 0xFFFFFFFF,
        crc_len,
        salt,
        len(data),
        unpacked,
        chain,
        data,
    )


def module_verify_hash(line):
    if line[0:5] != b"$7z$*":
        return None

    hash_in = line.split(b"$/7z$:", 1)

    if len(hash_in) != 2:
        return None

    fields = hash_in[0].decode(errors="replace")[5:].split("*")

    # power, salt, crc32, crc_len, join, N, iv, packed, unpacked, chain, data

    if len(fields) != 11 or fields[1] != "" or fields[4] != "" or fields[5] != "1":
        return None

    word = hash_in[1]

    new_hash = module_generate_hash(
        word,
        bytes.fromhex(fields[6]),
        int(fields[0]),
        int(fields[3], 16),
        int(fields[8], 16),
        fields[9],
        bytes.fromhex(fields[10]),
    )

    return (new_hash, word)
