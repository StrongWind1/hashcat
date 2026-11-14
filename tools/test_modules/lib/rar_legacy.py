##
## Author......: See docs/credits.txt
## License.....: MIT
##

# RAR 1.5 and RAR 2.0 ciphers, shared by the test modules of modes 46500 and 46600. Both hash
# lines are $rar$NN$*crc*us*ds*data$/rar$: the CRC32 of the unpacked file, its size, the size of the
# encrypted entry and the entry itself. The entries generated here are stored, not compressed.

# The two ciphers follow UnRAR 7.3.2 (crypt1.cpp and crypt2.cpp).
#
# UnRAR's license, paragraph 2, which has to accompany code derived from its source:
#
#   UnRAR source code may be used in any software to handle
#   RAR archives without limitations free of charge, but cannot be
#   used to develop RAR (WinRAR) compatible archiver and to
#   re-create RAR compression algorithm, which is proprietary.
#   Distribution of modified UnRAR source code in separate form
#   or as a part of other software is permitted, provided that
#   full text of this paragraph, starting from "UnRAR source code"
#   words, is included in license, or in documentation if license
#   is not available, and in source code comments of resulting package.
#
# The full license is in docs/license_libs/UNRAR_LICENSE.txt.

import zlib

MASK16 = 0xFFFF
MASK32 = 0xFFFFFFFF

CRC_TABLE = []

for _i in range(256):
    _c = _i
    for _ in range(8):
        _c = (_c >> 1) ^ (0xEDB88320 if (_c & 1) else 0)
    CRC_TABLE.append(_c)


def crc32_raw(data):
    # the CRC32 register after the data, without the final inversion
    crc = MASK32
    for b in data:
        crc = (crc >> 8) ^ CRC_TABLE[(crc ^ b) & 0xFF]
    return crc


def crypt15(password, data):
    # SetKey15 + Crypt15. The same call encrypts and decrypts.
    psw_crc = crc32_raw(password)
    k0 = psw_crc & MASK16
    k1 = (psw_crc >> 16) & MASK16
    k2 = 0
    k3 = 0
    for p in password:
        k2 = (k2 ^ p ^ CRC_TABLE[p]) & MASK16
        k3 = (k3 + p + (CRC_TABLE[p] >> 16)) & MASK16
    out = bytearray()
    for byte in data:
        k0 = (k0 + 0x1234) & MASK16
        t = CRC_TABLE[(k0 & 0x1FE) >> 1]
        k1 = (k1 ^ t) & MASK16
        k2 = (k2 - (t >> 16)) & MASK16
        k0 = (k0 ^ k2) & MASK16
        k3 = (((k3 >> 1) | (k3 << 15)) & MASK16) ^ k1
        k3 = ((k3 >> 1) | (k3 << 15)) & MASK16
        k0 = (k0 ^ k3) & MASK16
        out.append(byte ^ (k0 >> 8))
    return bytes(out)


INIT_SUBST = bytes(
    [
        215,
        19,
        149,
        35,
        73,
        197,
        192,
        205,
        249,
        28,
        16,
        119,
        48,
        221,
        2,
        42,
        232,
        1,
        177,
        233,
        14,
        88,
        219,
        25,
        223,
        195,
        244,
        90,
        87,
        239,
        153,
        137,
        255,
        199,
        147,
        70,
        92,
        66,
        246,
        13,
        216,
        40,
        62,
        29,
        217,
        230,
        86,
        6,
        71,
        24,
        171,
        196,
        101,
        113,
        218,
        123,
        93,
        91,
        163,
        178,
        202,
        67,
        44,
        235,
        107,
        250,
        75,
        234,
        49,
        167,
        125,
        211,
        83,
        114,
        157,
        144,
        32,
        193,
        143,
        36,
        158,
        124,
        247,
        187,
        89,
        214,
        141,
        47,
        121,
        228,
        61,
        130,
        213,
        194,
        174,
        251,
        97,
        110,
        54,
        229,
        115,
        57,
        152,
        94,
        105,
        243,
        212,
        55,
        209,
        245,
        63,
        11,
        164,
        200,
        31,
        156,
        81,
        176,
        227,
        21,
        76,
        99,
        139,
        188,
        127,
        17,
        248,
        51,
        207,
        120,
        189,
        210,
        8,
        226,
        41,
        72,
        183,
        203,
        135,
        165,
        166,
        60,
        98,
        7,
        122,
        38,
        155,
        170,
        69,
        172,
        252,
        238,
        39,
        134,
        59,
        128,
        236,
        27,
        240,
        80,
        131,
        3,
        85,
        206,
        145,
        79,
        154,
        142,
        159,
        220,
        201,
        133,
        74,
        64,
        20,
        129,
        224,
        185,
        138,
        103,
        173,
        182,
        43,
        34,
        254,
        82,
        198,
        151,
        231,
        180,
        58,
        10,
        118,
        26,
        102,
        12,
        50,
        132,
        22,
        191,
        136,
        111,
        162,
        179,
        45,
        4,
        148,
        108,
        161,
        56,
        78,
        126,
        242,
        222,
        15,
        175,
        146,
        23,
        33,
        241,
        181,
        190,
        77,
        225,
        0,
        46,
        169,
        186,
        68,
        95,
        237,
        65,
        53,
        208,
        253,
        168,
        9,
        18,
        100,
        52,
        116,
        184,
        160,
        96,
        109,
        37,
        30,
        106,
        140,
        104,
        150,
        5,
        204,
        117,
        112,
        84,
    ]
)


def _rol32(x, n):
    return ((x << n) | (x >> (32 - n))) & MASK32


def _subst(t, st):
    return (
        st[t & 0xFF]
        | (st[(t >> 8) & 0xFF] << 8)
        | (st[(t >> 16) & 0xFF] << 16)
        | (st[(t >> 24) & 0xFF] << 24)
    )


def _block20(key, subst, block, decrypt):
    a = int.from_bytes(block[0:4], "little") ^ key[0]
    b = int.from_bytes(block[4:8], "little") ^ key[1]
    c = int.from_bytes(block[8:12], "little") ^ key[2]
    d = int.from_bytes(block[12:16], "little") ^ key[3]
    for i in range(32):
        k = key[((31 - i) if decrypt else i) & 3]
        ta = a ^ _subst(((c + _rol32(d, 11)) & MASK32) ^ k, subst)
        tb = b ^ _subst(((d ^ _rol32(c, 17)) + k) & MASK32, subst)
        a, b, c, d = c, d, ta, tb
    out = b"".join(
        v.to_bytes(4, "little")
        for v in (c ^ key[0], d ^ key[1], a ^ key[2], b ^ key[3])
    )
    # the key moves on with the ciphertext, whichever direction this is
    ct = block if decrypt else out
    for i in range(0, 16, 4):
        key[0] ^= CRC_TABLE[ct[i + 0]]
        key[1] ^= CRC_TABLE[ct[i + 1]]
        key[2] ^= CRC_TABLE[ct[i + 2]]
        key[3] ^= CRC_TABLE[ct[i + 3]]
    return out


def _set_key20(password):
    subst = bytearray(INIT_SUBST)
    key = [0xD3A3B879, 0x3F6D12F7, 0x7515A235, 0xA4E7F123]
    # zero filled, so an odd length reads a zero for its missing pair byte and the last block is padded
    psw = bytearray(password) + bytes(17)
    for j in range(256):
        for i in range(0, len(password), 2):
            n1 = CRC_TABLE[(psw[i] - j) & 0xFF] & 0xFF
            n2 = CRC_TABLE[(psw[i + 1] + j) & 0xFF] & 0xFF
            k = 1
            while n1 != n2:
                other = (n1 + i + k) & 0xFF
                subst[n1], subst[other] = subst[other], subst[n1]
                n1 = (n1 + 1) & 0xFF
                k += 1
    for i in range(0, len(password), 16):
        psw[i : i + 16] = _block20(key, subst, bytes(psw[i : i + 16]), False)
    return key, subst


def crypt20(password, data, decrypt):
    # data is a multiple of 16 bytes
    key, subst = _set_key20(password)
    out = bytearray()
    for off in range(0, len(data), 16):
        out += _block20(key, subst, data[off : off + 16], decrypt)
    return bytes(out)


def hash_line(signature, plaintext, encrypted, method=0x30):
    # method 0x30: a stored entry, 0x31 to 0x35: a compressed one
    return f"{signature}*{zlib.crc32(plaintext):08x}*{len(plaintext):x}*{len(encrypted):x}*{method:x}*{encrypted.hex()}$/rar$"


def parse_line(signature, hash_str):
    # returns (crc, unpack_size, encrypted, method) or None
    if not hash_str.startswith(signature + "*") or not hash_str.endswith("$/rar$"):
        return None
    fields = hash_str[len(signature) + 1 : -6].split("*")
    # the method field is optional, older lines do not have it and hold a stored entry
    method = 0x30
    try:
        if len(fields) == 5:
            method = int(fields[3], 16)
            del fields[3]
        if len(fields) != 4:
            return None
        crc = int(fields[0], 16)
        unpack_size = int(fields[1], 16)
        data_size = int(fields[2], 16)
        encrypted = bytes.fromhex(fields[3])
    except ValueError:
        return None
    if len(encrypted) != data_size:
        return None
    return crc, unpack_size, encrypted, method
