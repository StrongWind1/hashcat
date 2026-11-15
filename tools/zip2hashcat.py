#!/usr/bin/env python3
# /// script
# requires-python = ">=3.8"
# dependencies = []
# ///

#
# Author......: See docs/credits.txt
# License.....: MIT
#

"""Read a password protected ZIP archive and write the hash lines for hashcat modes 46100 to 46320.

The lines are the ones ArchiveWolf writes, field for field:

    $zip$1$*N*check_1*...*check_N*method*crc32*unpacked*packed*data$/zip$   traditional (ZipCrypto)   -m 46100
    $zip$2$*strength*salt*verifier*auth*method*packed*data$/zip$            WinZip AES                -m 46200
    $zip$3$*algorithm*bits*flags*iv*erd*vdata$/zip$                         PKWARE strong encryption  -m 46300 (AES-128), 46310 (AES-192), 46320 (AES-256)

Which entry is picked, and how much of it goes into the line, follows ArchiveWolf:

  * Traditional encryption. The entries are ranked: one whose stream proves the password by
    decoding (deflate, bzip2, xz) first, then a stored one, whose CRC-32 does, then one that offers
    nothing but the check byte of its 12 byte header. Within a rank the smaller entry wins. A
    deflate stream of up to a megabyte goes in whole, a longer one is cut there, and a megabyte
    that still inflates under a wrong key does not happen. A stored entry goes in whole up to
    4 MiB. A line that rests on a CRC-32 or on check bytes alone also carries the header of up to
    seven other entries, which assumes they share the password.
  * WinZip AES. The entry with the least data wins, and a line holds all of it up to 4 MiB, which
    is checked against the authentication code. A longer entry gives the start of its stream when
    that is deflate, bzip2 or xz, and nothing but the two verifier bytes otherwise.
  * Strong encryption. Only the AES ciphers have a line. No password recovery tool reads the
    others, and an entry that is encrypted to certificates has no password.
  * --all-hashes writes a line for every encrypted entry, each on its own, for the archives whose
    entries do not share one password.

An entry that claims to be encrypted and unpacks to its CRC-32 as it is has no password and no
line. A self-extracting archive is read from wherever its central directory is.
"""

from __future__ import annotations

import argparse
import struct
import sys
import zlib
from dataclasses import dataclass, field

EOCD_SIG = 0x06054B50
EOCD_MAX_SEARCH = 22 + 65535
ZIP64_LOCATOR_SIG = 0x07064B50
ZIP64_EOCD_SIG = 0x06064B50
CD_SIG = 0x02014B50
LOCAL_SIG = 0x04034B50

ZIP64_SENTINEL_32 = 0xFFFFFFFF

FLAG_ENCRYPTED = 0x0001
FLAG_DATA_DESCRIPTOR = 0x0008
FLAG_STRONG_ENCRYPTION = 0x0040
FLAG_CD_ENCRYPTED = 0x2000

EXTRA_ZIP64 = 0x0001
EXTRA_PKWARE_SES = 0x0017
EXTRA_WINZIP_AES = 0x9901

CRYPT_NONE = 0
CRYPT_ZIPCRYPTO = 1
CRYPT_WINZIP_AES = 2
CRYPT_PKWARE_SES = 3
CRYPT_CD_ENCRYPTED = 4

METHOD_STORED = 0
METHOD_DEFLATE = 8
METHOD_BZIP2 = 12
METHOD_XZ = 95

# What a line can prove, best first.

PROOF_STREAM = 0
PROOF_CHECKSUM = 1
PROOF_HEADER_ONLY = 2

ZIPCRYPTO_HEADER = 12
ZIP1_MAX_CHECKS = 8

MAX_INLINE_DATA = 4 * 1024 * 1024
ZIP_DEFLATE_DATA = 1024 * 1024
ZIP_MAGIC_DATA = 32

MAX_DECOMPRESS_SIZE = 10_000_000

SES_AES = (0x660E, 0x660F, 0x6610)

SES_NAMES = {
    0x6601: "DES",
    0x6602: "RC2 (pre-5.2)",
    0x6603: "3DES-168",
    0x6609: "3DES-112",
    0x6702: "RC2",
    0x6720: "Blowfish",
    0x6721: "Twofish",
    0x6801: "RC4",
    0xFFFF: "an unknown algorithm",
}


class ZipError(Exception):
    """The file is not a ZIP archive this tool can read."""


@dataclass
class Entry:
    """One entry of the central directory."""

    name: bytes = b""
    version_made_by: int = 0
    version_needed: int = 0
    flags: int = 0
    method: int = 0
    mod_time: int = 0
    crc32: int = 0
    packed: int = 0
    unpacked: int = 0
    offset: int = 0
    encryption: int = CRYPT_NONE
    aes_strength: int = 0
    aes_method: int = 0
    ses_alg: int = 0
    ses_bits: int = 0
    ses_flags: int = 0
    extra: list = field(default_factory=list)


def u16(buf: bytes, off: int) -> int:
    """Read a little endian 16 bit number."""
    if off < 0 or off + 2 > len(buf):
        raise ZipError("truncated")
    return struct.unpack_from("<H", buf, off)[0]


def u32(buf: bytes, off: int) -> int:
    """Read a little endian 32 bit number."""
    if off < 0 or off + 4 > len(buf):
        raise ZipError("truncated")
    return struct.unpack_from("<I", buf, off)[0]


def u64(buf: bytes, off: int) -> int:
    """Read a little endian 64 bit number."""
    if off < 0 or off + 8 > len(buf):
        raise ZipError("truncated")
    return struct.unpack_from("<Q", buf, off)[0]


def find_eocd(data: bytes) -> int:
    """Find the end of central directory record: the one whose comment ends the file."""
    if len(data) < 22:
        raise ZipError("file too small for a ZIP archive")

    stop = max(len(data) - EOCD_MAX_SEARCH, 0)
    sig = struct.pack("<I", EOCD_SIG)
    pos = len(data) - 4

    while True:
        if data[pos : pos + 4] == sig and pos + 22 <= len(data) and pos + 22 + u16(data, pos + 20) == len(data):
            return pos
        if pos == stop:
            break
        pos -= 1

    raise ZipError("not a ZIP archive")


def parse_extra(raw: bytes, entry: Entry) -> dict:
    """Read the extra fields that say how an entry is encrypted, and the ZIP64 sizes."""
    zip64 = {}
    off = 0
    aes = None
    ses = None

    while off + 4 <= len(raw):
        ident = u16(raw, off)
        size = u16(raw, off + 2)
        if off + 4 + size > len(raw):
            break
        body = raw[off + 4 : off + 4 + size]

        if ident == EXTRA_WINZIP_AES and len(body) >= 7 and aes is None:
            aes = (body[4], u16(body, 5))
        elif ident == EXTRA_PKWARE_SES and len(body) >= 8 and ses is None:
            ses = (u16(body, 2), u16(body, 4), u16(body, 6))
        elif ident == EXTRA_ZIP64 and not zip64:
            zip64["present"] = True
            if len(body) >= 8:
                zip64["unpacked"] = u64(body, 0)
            if len(body) >= 16:
                zip64["packed"] = u64(body, 8)
            if len(body) >= 24:
                zip64["offset"] = u64(body, 16)

        off += 4 + size

    if entry.flags & FLAG_CD_ENCRYPTED:
        entry.encryption = CRYPT_CD_ENCRYPTED
    elif entry.flags & (FLAG_ENCRYPTED | FLAG_STRONG_ENCRYPTION) == 0:
        entry.encryption = CRYPT_NONE
    else:
        version = entry.version_needed & 0xFF
        ses_by_version = version in (51, 52) or version >= 61

        if entry.flags & FLAG_ENCRYPTED and entry.method == 99 and aes is not None:
            entry.encryption = CRYPT_WINZIP_AES
            entry.aes_strength, entry.aes_method = aes
        elif (entry.flags & FLAG_STRONG_ENCRYPTION or (entry.flags & FLAG_ENCRYPTED and ses_by_version)) and ses is not None:
            entry.encryption = CRYPT_PKWARE_SES
            entry.ses_alg, entry.ses_bits, entry.ses_flags = ses
        elif entry.flags & FLAG_ENCRYPTED:
            entry.encryption = CRYPT_ZIPCRYPTO
        else:
            entry.encryption = CRYPT_NONE

    return zip64


def parse_zip(data: bytes) -> list[Entry]:
    """Read the central directory, from the end of the file."""
    eocd = find_eocd(data)

    count = u16(data, eocd + 10)
    cd_size = u32(data, eocd + 12)
    cd_offset = u32(data, eocd + 16)

    if eocd >= 20 and u32(data, eocd - 20) == ZIP64_LOCATOR_SIG:
        z64 = u64(data, eocd - 20 + 8)
        if u32(data, z64) != ZIP64_EOCD_SIG:
            raise ZipError("ZIP64 end of central directory record not found")
        count = u64(data, z64 + 32)
        cd_size = u64(data, z64 + 40)
        cd_offset = u64(data, z64 + 48)

    # a self-extracting archive has a program in front, which shifts every offset by its size
    shift = 0
    at_declared = cd_offset + cd_size <= len(data) and data[cd_offset : cd_offset + 4] == struct.pack("<I", CD_SIG)
    if not at_declared:
        actual = eocd - cd_size
        if actual < 0 or data[actual : actual + 4] != struct.pack("<I", CD_SIG) or actual < cd_offset:
            raise ZipError("central directory not found")
        shift = actual - cd_offset

    entries = []
    pos = cd_offset + shift

    for index in range(count):
        if pos + 46 > len(data) or u32(data, pos) != CD_SIG:
            raise ZipError(f"central directory entry {index} is damaged")

        entry = Entry()
        entry.version_made_by = u16(data, pos + 4)
        entry.version_needed = u16(data, pos + 6)
        entry.flags = u16(data, pos + 8)
        entry.method = u16(data, pos + 10)
        entry.mod_time = u16(data, pos + 12)
        entry.crc32 = u32(data, pos + 16)
        packed = u32(data, pos + 20)
        unpacked = u32(data, pos + 24)
        name_len = u16(data, pos + 28)
        extra_len = u16(data, pos + 30)
        comment_len = u16(data, pos + 32)
        offset = u32(data, pos + 42)

        if pos + 46 + name_len + extra_len + comment_len > len(data):
            raise ZipError(f"central directory entry {index} is damaged")

        entry.name = data[pos + 46 : pos + 46 + name_len]
        zip64 = parse_extra(data[pos + 46 + name_len : pos + 46 + name_len + extra_len], entry)

        entry.packed = zip64.get("packed", packed) if packed == ZIP64_SENTINEL_32 else packed
        entry.unpacked = zip64.get("unpacked", unpacked) if unpacked == ZIP64_SENTINEL_32 else unpacked
        entry.offset = (zip64.get("offset", offset) if offset == ZIP64_SENTINEL_32 else offset) + shift

        entries.append(entry)
        pos += 46 + name_len + extra_len + comment_len

    return entries


def data_start(data: bytes, entry: Entry) -> int | None:
    """Where the data of an entry starts, behind its local header. None when that header is damaged."""
    off = entry.offset
    if off + 30 > len(data) or u32(data, off) != LOCAL_SIG:
        return None
    start = off + 30 + u16(data, off + 26) + u16(data, off + 28)
    if start > len(data):
        return None
    return start


def entry_stream(data: bytes, entry: Entry) -> bytes | None:
    """All the stored data of an entry, or None when it does not lie inside the file."""
    start = data_start(data, entry)
    if start is None or start + entry.packed > len(data):
        return None
    return data[start : start + entry.packed]


def unpacks_to_crc(entry: Entry, raw: bytes) -> bool:
    """Whether the bytes are the entry itself: stored or deflated, with the right CRC-32."""
    if entry.method == METHOD_STORED:
        plain = raw
    elif entry.method == METHOD_DEFLATE:
        limit = min(entry.unpacked, MAX_DECOMPRESS_SIZE)
        unpacker = zlib.decompressobj(-15)
        try:
            plain = unpacker.decompress(raw, limit + 1)
        except zlib.error:
            return False
        if not unpacker.eof or len(plain) > limit:
            return False
    else:
        return False
    return zlib.crc32(plain) == entry.crc32


def really_encrypted(data: bytes, entry: Entry) -> bool:
    """Tell an encrypted entry from one that only has the flag set, and from one that has neither."""
    flagged = entry.flags & FLAG_ENCRYPTED != 0

    if entry.encryption in (CRYPT_WINZIP_AES, CRYPT_PKWARE_SES, CRYPT_CD_ENCRYPTED):
        return True
    if entry.unpacked > MAX_DECOMPRESS_SIZE:
        return flagged

    start = data_start(data, entry)
    if start is None:
        return flagged
    if start + entry.packed <= len(data):
        if unpacks_to_crc(entry, data[start : start + entry.packed]):
            return False
        if flagged and entry.packed >= ZIPCRYPTO_HEADER and unpacks_to_crc(entry, data[start + ZIPCRYPTO_HEADER : start + entry.packed]):
            return False

    return flagged


def plan_zipcrypto(entry: Entry) -> tuple[int, int]:
    """How many bytes of the stream a line takes (-1 for all of it) and what they prove."""
    stream = entry.packed - ZIPCRYPTO_HEADER
    if stream <= 0:
        return 0, PROOF_HEADER_ONLY
    if entry.method == METHOD_STORED and stream <= MAX_INLINE_DATA:
        return -1, PROOF_CHECKSUM
    if entry.method == METHOD_DEFLATE:
        return (-1 if stream <= ZIP_DEFLATE_DATA else ZIP_DEFLATE_DATA), PROOF_STREAM
    if entry.method == METHOD_BZIP2 and stream >= 10:
        return ZIP_MAGIC_DATA, PROOF_STREAM
    if entry.method == METHOD_XZ and stream >= 8:
        return ZIP_MAGIC_DATA, PROOF_STREAM
    return 0, PROOF_HEADER_ONLY


def order_zipcrypto(entry: Entry) -> tuple[int, int, int]:
    """Rank a ZipCrypto entry, best first."""
    _, proof = plan_zipcrypto(entry)
    # a deflate stream of a few bytes proves little, so it ranks with the checksums
    tiny = proof == PROOF_STREAM and entry.method == METHOD_DEFLATE and entry.packed < 12 + 24
    if proof == PROOF_STREAM and not tiny:
        rank = 0
    elif proof in (PROOF_STREAM, PROOF_CHECKSUM):
        rank = 1
    else:
        rank = 2
    return rank, entry.packed, 1 if entry.flags & FLAG_DATA_DESCRIPTOR else 0


def aes_ciphertext_len(entry: Entry) -> int:
    """Size of the encrypted data of a WinZip AES entry, without salt, verifier and code."""
    return max(entry.packed - (4 * entry.aes_strength + 4 + 2 + 10), 0)


def plan_winzip_aes(method: int, ciphertext: int) -> tuple[int, int]:
    """How many bytes of ciphertext a line takes (-1 for all of it) and what they prove."""
    if ciphertext <= MAX_INLINE_DATA:
        return -1, PROOF_CHECKSUM
    if method == METHOD_DEFLATE:
        return ZIP_DEFLATE_DATA, PROOF_STREAM
    if method in (METHOD_BZIP2, METHOD_XZ):
        return ZIP_MAGIC_DATA, PROOF_STREAM
    return 0, PROOF_HEADER_ONLY


def order_winzip_aes(entry: Entry) -> tuple[int, int, int]:
    """Rank a WinZip AES entry, best first."""
    length = aes_ciphertext_len(entry)
    take, proof = plan_winzip_aes(entry.aes_method, length)
    return (
        1 if proof == PROOF_HEADER_ONLY else 0,
        length if take < 0 else min(take, length),
        entry.aes_strength,
    )


def order_ses(entry: Entry) -> tuple[int, int, int]:
    """Rank a strong encryption entry, best first."""
    if entry.ses_alg in SES_AES:
        rank = 0
    elif entry.ses_alg == 0x6801:
        rank = 2
    elif entry.ses_alg == 0xFFFF:
        rank = 3
    else:
        rank = 1
    return rank, entry.packed, 0 if entry.ses_flags == 1 else 1


def check_token(data: bytes, entry: Entry) -> str | None:
    """The encryption header of a ZipCrypto entry and what its end decrypts to."""
    stream = entry_stream(data, entry)
    if stream is None or len(stream) < ZIPCRYPTO_HEADER:
        return None

    from_crc = entry.crc32 >> 16
    two_bytes = (entry.version_made_by & 0xFF) < 20

    def show(value: int) -> str:
        return f"{value:04x}" if two_bytes else f"{value >> 8:02x}"

    # a writer that did not know the CRC-32 yet used the file time, which the data descriptor tells
    if entry.flags & FLAG_DATA_DESCRIPTOR == 0:
        values = [show(from_crc)]
    else:
        values = [show(entry.mod_time)]
        if show(from_crc) != values[0]:
            values.append(show(from_crc))

    return stream[:ZIPCRYPTO_HEADER].hex() + "/" + "/".join(values)


def line_zip1(data: bytes, entry: Entry, others: list[Entry]) -> tuple[str, int] | None:
    """The $zip$1$ line of an entry and the number of headers it tests."""
    first = check_token(data, entry)
    stream = entry_stream(data, entry)
    if first is None or stream is None:
        return None
    stream = stream[ZIPCRYPTO_HEADER:]

    take, _ = plan_zipcrypto(entry)
    taken = stream if take < 0 else stream[:take]

    tokens = [first]
    for other in others:
        token = check_token(data, other)
        if token is not None and len(tokens) < ZIP1_MAX_CHECKS:
            tokens.append(token)

    line = f"$zip$1$*{len(tokens)}*{'*'.join(tokens)}*{entry.method}*{entry.crc32:08x}*{entry.unpacked:x}*{len(stream):x}*{taken.hex()}$/zip$"
    return line, len(tokens)


def line_zip2(data: bytes, entry: Entry) -> str | None:
    """The $zip$2$ line of a WinZip AES entry."""
    if entry.aes_strength not in (1, 2, 3):
        return None
    stream = entry_stream(data, entry)
    salt_len = 4 * entry.aes_strength + 4
    if stream is None or len(stream) < salt_len + 2 + 10:
        return None

    ciphertext = stream[salt_len + 2 : len(stream) - 10]
    take, _ = plan_winzip_aes(entry.aes_method, len(ciphertext))
    taken = ciphertext if take < 0 else ciphertext[:take]

    return f"$zip$2$*{entry.aes_strength}*{stream[:salt_len].hex()}*{stream[salt_len : salt_len + 2].hex()}*{stream[len(stream) - 10 :].hex()}*{entry.aes_method}*{len(ciphertext):x}*{taken.hex()}$/zip$"


def line_zip3(data: bytes, entry: Entry) -> str:
    """The $zip$3$ line of a strong encryption entry. Raises ZipError with the reason when there is none."""
    start = data_start(data, entry)
    if start is None:
        raise ZipError("its local header is damaged")
    head = data[start:]

    pos = 0
    iv_size = u16(head, pos)
    pos += 2
    if pos + iv_size > len(head):
        raise ZipError("its decryption header is cut short")
    iv = head[pos : pos + iv_size]
    pos += iv_size + 4

    if u16(head, pos) != 3:
        raise ZipError("its decryption header has an unknown format")
    alg_id = u16(head, pos + 2)
    bits = u16(head, pos + 4)
    flags = u16(head, pos + 6)
    erd_size = u16(head, pos + 8)
    pos += 10

    # the random data is wrapped with 3DES when this flag is set, whatever encrypts the file
    erd_alg = 0x6603 if flags & 0x4000 else alg_id
    block = 0 if erd_alg == 0x6801 else (8 if erd_alg in (0x6601, 0x6602, 0x6603, 0x6609, 0x6702, 0x6720) else 16)
    if block and (erd_size == 0 or erd_size % block != 0):
        raise ZipError("its encrypted random data is not a whole number of cipher blocks")
    if pos + erd_size > len(head):
        raise ZipError("its decryption header is cut short")
    erd = head[pos : pos + erd_size]
    pos += erd_size

    if u32(head, pos) != 0:
        raise ZipError("it is encrypted to certificates, which no password opens")
    pos += 4

    vdata_size = u16(head, pos)
    pos += 2
    if pos + vdata_size > len(head):
        raise ZipError("its decryption header is cut short")
    vdata = head[pos : pos + vdata_size]

    if flags & 1 == 0:
        raise ZipError("it is encrypted to certificates only, which no password opens")
    if len(vdata) < 4:
        raise ZipError("its validation data is too short to hold its CRC-32")

    if not iv:
        # no stored vector: the CRC-32 and the 64 bit size of the entry stand in for it
        iv = struct.pack("<IQ", entry.crc32, entry.unpacked)

    return f"$zip$3$*{alg_id:04x}*{bits}*{flags:x}*{iv.hex()}*{erd.hex()}*{vdata.hex()}$/zip$"


def hashes_of(data: bytes, all_hashes: bool, notes: list[str]) -> list[str]:
    """Return the hash lines of an archive. What a line cannot prove, and why one is missing, goes to notes."""
    entries = [entry for entry in parse_zip(data) if really_encrypted(data, entry)]

    lines: list[str] = []

    def add(line: str) -> None:
        if line not in lines:
            lines.append(line)

    def name_of(entry: Entry) -> str:
        return entry.name.decode("utf-8", "replace")

    zipcrypto = sorted(
        (entry for entry in entries if entry.encryption == CRYPT_ZIPCRYPTO),
        key=order_zipcrypto,
    )

    for pos, entry in enumerate(zipcrypto if all_hashes else zipcrypto[:1]):
        _, proof = plan_zipcrypto(entry)
        # a stream that decodes proves the password by itself; anything weaker also tests the
        # headers of the other entries
        others = [] if all_hashes or proof == PROOF_STREAM else [other for i, other in enumerate(zipcrypto) if i != pos]
        built = line_zip1(data, entry, others)
        if built is None:
            notes.append(f"{name_of(entry)}: its data does not lie inside the file")
            continue
        line, checks = built
        if proof == PROOF_HEADER_ONLY:
            if entry.packed <= ZIPCRYPTO_HEADER:
                why = "it is empty"
            elif entry.method == METHOD_STORED:
                why = f"its {entry.packed} stored bytes exceed the {MAX_INLINE_DATA} a hash can carry, and a CRC-32 needs all of them"
            else:
                why = f"hashcat has no decoder for compression method {entry.method}"
            notes.append(f"weak hash: {name_of(entry)}: {why}, so the line tests only the check byte of {checks} header(s); about one wrong password in 256 passes each")
        elif proof == PROOF_CHECKSUM and checks == 1:
            notes.append(f"note: {name_of(entry)} is stored and the archive has no other entry to test against, so a cracked password is confirmed by 40 bits")
        add(line)

    winzip = sorted(
        (entry for entry in entries if entry.encryption == CRYPT_WINZIP_AES),
        key=order_winzip_aes,
    )

    for entry in winzip if all_hashes else winzip[:1]:
        line2 = line_zip2(data, entry)
        if line2 is None:
            notes.append(f"{name_of(entry)}: its data does not lie inside the file")
            continue
        if plan_winzip_aes(entry.aes_method, aes_ciphertext_len(entry))[1] == PROOF_HEADER_ONLY:
            notes.append(f"weak hash: {name_of(entry)}: its {aes_ciphertext_len(entry)} bytes exceed the {MAX_INLINE_DATA} a hash can carry and method {entry.aes_method} cannot be tested from its start, so the line tests only the 16 bit verifier; about one wrong password in 65,536 passes")
        add(line2)

    ses = sorted(
        (entry for entry in entries if entry.encryption == CRYPT_PKWARE_SES),
        key=order_ses,
    )

    for entry in ses if all_hashes else ses[:1]:
        if entry.ses_alg not in SES_AES:
            notes.append(f"no hash: {name_of(entry)}: strong encryption with {SES_NAMES.get(entry.ses_alg, 'this algorithm')} is not supported by any password recovery tool")
            continue
        try:
            add(line_zip3(data, entry))
        except ZipError as error:
            notes.append(f"no hash: {name_of(entry)}: {error}")

    if any(entry.encryption == CRYPT_CD_ENCRYPTED for entry in entries):
        notes.append("no hash: the central directory is encrypted")

    return lines


def main() -> int:
    """Write the hash lines of every archive named on the command line."""
    parser = argparse.ArgumentParser(description="Write the hashcat lines of password protected ZIP archives, for modes 46100 (traditional encryption), 46200 (WinZip AES) and 46300, 46310, 46320 (PKWARE strong encryption with AES-128, AES-192, AES-256).")
    parser.add_argument(
        "archives",
        metavar="ARCHIVE",
        nargs="+",
        help="a ZIP archive, or a self-extracting one",
    )
    parser.add_argument(
        "-a",
        "--all-hashes",
        action="store_true",
        help="write a line for every encrypted entry, each on its own, not only for the best one",
    )
    parser.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="do not say on stderr what a line cannot prove or why an entry has none",
    )
    args = parser.parse_args()

    status = 0

    for path in args.archives:
        notes: list[str] = []
        try:
            with open(path, "rb") as handle:
                data = handle.read()
            lines = hashes_of(data, args.all_hashes, notes)
        except (OSError, ZipError) as error:
            sys.stderr.write(f"{path}: {error}\n")
            status = 1
            continue

        for line in lines:
            sys.stdout.write(line + "\n")

        if not args.quiet:
            for note in notes:
                sys.stderr.write(f"{path}: {note}\n")

    return status


if __name__ == "__main__":
    sys.exit(main())
