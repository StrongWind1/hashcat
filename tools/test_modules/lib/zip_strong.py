##
## Author......: See docs/credits.txt
## License.....: MIT
##

# PKWARE strong encryption with an AES cipher, for the test modules of modes 46300, 46310 and
# 46320. See src/modules/zip_strong.c for the fields of the line.
#
# A password is hashed with SHA-1 and stretched the way CryptDeriveKey does it: the digest is
# XORed into a block of 0x36 and into a block of 0x5c, both blocks are hashed, and the key is the
# start of the two digests put together. That key encrypts random data, which ends in a whole block
# of padding. The random data and the initialisation vector give the key of the file the same way,
# and that key encrypts a short piece of validation data that ends with its own CRC-32.

import hashlib
import struct
import zlib

from Crypto.Cipher import AES

from lib.test_helpers import random_bytes, random_number

SIGNATURE = "$zip$3$"
STOP = "$/zip$"

ALG_ID = {128: 0x660E, 192: 0x660F, 256: 0x6610}


def derive_key(digest, size):
    def half(fill):
        block = bytearray([fill] * 64)

        for i, b in enumerate(digest):
            block[i] ^= b

        return hashlib.sha1(bytes(block)).digest()

    return (half(0x36) + half(0x5C))[:size]


def master_key(word, bits):
    return derive_key(hashlib.sha1(word).digest(), bits // 8)


def file_key(iv, random_data, bits):
    return derive_key(hashlib.sha1(iv + random_data).digest(), bits // 8)


def cbc(key, iv, data, decrypt=False):
    cipher = AES.new(key, AES.MODE_CBC, iv.ljust(16, b"\0"))

    return cipher.decrypt(data) if decrypt else cipher.encrypt(data)


def header(word, bits, iv, random_data, validation=None):
    # returns the encrypted random data, the encrypted validation data and the key of the file
    erd = cbc(master_key(word, bits), iv, random_data + bytes([16] * 16))

    key = file_key(iv, random_data, bits)

    if validation is None:
        validation = random_bytes(12)

    vdata = cbc(key, iv, validation + struct.pack("<I", zlib.crc32(validation)))

    return erd, vdata, key


def line(bits, iv, erd, vdata, flags=1):
    return f"{SIGNATURE}*{ALG_ID[bits]:04x}*{bits}*{flags:x}*{iv.hex()}*{erd.hex()}*{vdata.hex()}{STOP}"


def generate(word, bits):
    # the vector is stored (16 bytes) or stands for the CRC-32 and the size of the entry (12 bytes)
    iv = random_bytes(16 if random_number(0, 2) != 0 else 12)

    random_data = random_bytes(16 * random_number(0, 8))

    erd, vdata, _ = header(word, bits, iv, random_data)

    return line(bits, iv, erd, vdata)


def parse(text):
    if not text.startswith(SIGNATURE + "*") or not text.endswith(STOP):
        return None

    fields = text[len(SIGNATURE) + 1 : -len(STOP)].split("*")

    if len(fields) != 6:
        return None

    try:
        return {
            "alg_id": int(fields[0], 16),
            "bits": int(fields[1]),
            "flags": int(fields[2], 16),
            "iv": bytes.fromhex(fields[3]),
            "erd": bytes.fromhex(fields[4]),
            "vdata": bytes.fromhex(fields[5]),
        }
    except ValueError:
        return None


def verify(parsed, word):
    bits = parsed["bits"]

    if ALG_ID.get(bits) != parsed["alg_id"]:
        return False

    erd = parsed["erd"]

    if len(erd) < 16 or len(erd) % 16 != 0:
        return False

    plain = cbc(master_key(word, bits), parsed["iv"], erd, decrypt=True)

    if plain[-16:] != bytes([16] * 16):
        return False

    vdata = parsed["vdata"]

    if len(vdata) < 16 or len(vdata) % 16 != 0:
        # a line without validation data rests on the padding alone
        return True

    valid = cbc(
        file_key(parsed["iv"], plain[:-16], bits), parsed["iv"], vdata, decrypt=True
    )

    return struct.unpack("<I", valid[-4:])[0] == zlib.crc32(valid[:-4])


def archive(word, bits, name, content, method=8, store_iv=True):
    # a whole ZIP archive with one entry, the way the reader in 7-Zip expects it
    crc = zlib.crc32(content)

    if method == 8:
        packer = zlib.compressobj(6, zlib.DEFLATED, -15)

        packed = packer.compress(content) + packer.flush()
    else:
        packed = content

    iv = random_bytes(16) if store_iv else struct.pack("<IQ", crc, len(content))

    erd, vdata, key = header(word, bits, iv, random_bytes(128))

    # the data follows the validation data in one CBC stream, so it starts from its last block
    pad = 16 - (len(packed) % 16)

    body = AES.new(key, AES.MODE_CBC, vdata[-16:]).encrypt(packed + bytes([pad] * pad))

    fields = (
        struct.pack("<HHHHH", 3, ALG_ID[bits], bits, 1, len(erd))
        + erd
        + struct.pack("<IH", 0, len(vdata))
        + vdata
    )

    decryption = (
        (struct.pack("<H", 16) + iv if store_iv else struct.pack("<H", 0))
        + struct.pack("<I", len(fields))
        + fields
    )

    data = decryption + body

    extra = struct.pack("<HHHHHH", 0x0017, 8, 2, ALG_ID[bits], bits, 1)

    flags = 0x0041

    local = (
        struct.pack(
            "<IHHHHHIIIHH",
            0x04034B50,
            51,
            flags,
            method,
            0x6000,
            0x5821,
            crc,
            len(data),
            len(content),
            len(name),
            len(extra),
        )
        + name
        + extra
    )

    central = (
        struct.pack(
            "<IHHHHHHIIIHHHHHII",
            0x02014B50,
            0x003F,
            51,
            flags,
            method,
            0x6000,
            0x5821,
            crc,
            len(data),
            len(content),
            len(name),
            len(extra),
            0,
            0,
            0,
            0,
            0,
        )
        + name
        + extra
    )

    end = struct.pack(
        "<IHHHHIIH", 0x06054B50, 0, 0, 1, 1, len(central), len(local) + len(data), 0
    )

    return local + data + central + end
