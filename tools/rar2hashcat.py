#!/usr/bin/env python3
# /// script
# requires-python = ">=3.8"
# dependencies = []
# ///

#
# Author......: See docs/credits.txt
# License.....: MIT
#

"""Read a password protected RAR archive and write the hash lines for hashcat modes 46500 to 46800.

The lines are the ones ArchiveWolf writes, field for field:

    $rar$15$*crc*us*ds*method*data$/rar$                             RAR 1.5        -m 46500
    $rar$20$*crc*us*ds*method*data$/rar$                             RAR 2.0        -m 46600
    $rar$30$*type*salt*crc*ps*us*method*data$/rar$                   RAR 3.x - 4.x  -m 46700
    $rar$50$*type*salt*lg2*iv*pswcheck*ct*cksum*ps*us*method*data$/rar$  RAR 5, RAR 7  -m 46800

It grew out of tools/rar32hashcat.py and reads the same RAR 1.5 to 4.x layout, written from the
published RAR 3.93 technical note, and adds the RAR 5 layout from the RAR 5.0 archive format
description. Which entry is picked, and what is left out, follows ArchiveWolf:

  * An archive with encrypted headers (rar -hp) gets one line. For RAR 3.x that is the encrypted
    end header from the last 24 bytes of the file. For RAR 5 it is the password check value, or the
    first encrypted header blocks where the archive carries none.
  * Otherwise the encrypted entries are ranked and the best one gets a line: a RAR 5 entry with a
    password check value first, then an entry that fits the preferred size, a stored one before a
    compressed one, a small one before a large one. --all-hashes writes a line for every entry.
  * An entry gets no line when no password could be confirmed from it: an empty file, one whose
    encrypted data is over 4 MiB, a compressed member of a solid archive that needs the files
    before it, or one that continues in another volume.
  * RAR 1.3 and 1.4 archives get none. Their key is 24 bits, which ArchiveWolf searches itself.

A self-extracting archive is read from its RAR signature on, searched for in the first megabyte.
"""

from __future__ import annotations

import argparse
import hashlib
import sys
from dataclasses import dataclass

SIGNATURE_RAR14 = b"RE~^"
SIGNATURE_RAR15 = b"Rar!\x1a\x07\x00"
SIGNATURE_RAR50 = b"Rar!\x1a\x07\x01\x00"

SFX_SEARCH_LIMIT = 1024 * 1024

FORMAT_RAR14 = 14
FORMAT_RAR15 = 15
FORMAT_RAR50 = 50

# The encryption of one entry. RAR 1.5 to 4.x archives name it by the version needed to unpack.

CRYPT_NONE = 0
CRYPT_RAR13 = 13
CRYPT_RAR15 = 15
CRYPT_RAR20 = 20
CRYPT_RAR30 = 30
CRYPT_RAR50 = 50

# RAR 1.5 to 4.x blocks

HEAD3_MAIN = 0x73
HEAD3_FILE = 0x74

LONG_BLOCK = 0x8000

MHD_SOLID = 0x0008
MHD_PASSWORD = 0x0080

LHD_SPLIT_BEFORE = 0x0001
LHD_SPLIT_AFTER = 0x0002
LHD_PASSWORD = 0x0004
LHD_SOLID = 0x0010
LHD_LARGE = 0x0100
LHD_SALT = 0x0400

SALT3_SIZE = 8

METHOD3_STORE = 0x30

# RAR 5 blocks

HEAD5_FILE = 2
HEAD5_SERVICE = 3
HEAD5_CRYPT = 4
HEAD5_EOARC = 5

HFL_EXTRA = 0x0001
HFL_DATA = 0x0002
HFL_SPLIT_BEFORE = 0x0008
HFL_SPLIT_AFTER = 0x0010

FHFL_UTIME = 0x0002
FHFL_CRC32 = 0x0004

FHEXTRA_CRYPT = 0x01
FHEXTRA_HASH = 0x02

CRYPT5_PSWCHECK = 0x0001
CRYPT5_HASHMAC = 0x0002

SALT5_SIZE = 16
IV5_SIZE = 16
PSWCHECK_SIZE = 8
PSWCHECK_CSUM_SIZE = 4
BLAKE2_DIGEST_SIZE = 32

LG2_COUNT_MAX = 24

# The name ArchiveWolf gives the entry it makes for the archive encryption header of RAR 5.

HEADER_ENCRYPTED_NAME = b"<header-encrypted>"

# The CRC32 field of a type 0 $rar$30$ line: the first bytes of the end header every archive has.

RAR30_HEADER_CRC = 0xC43D7B00

# What a hash prefers to carry and what it can carry at most. hashcat verifies a stored RAR 1.5 or
# 2.0 entry of up to 256 KiB on the GPU, and its parser takes lines with up to 4 MiB of data.

PREFERRED_LEGACY_DATA = 256 * 1024
PREFERRED_HASH_DATA = 327680
MAX_INLINE_DATA = 4 * 1024 * 1024

# How many bytes of encrypted headers a RAR 5 line carries when the archive has no check value.

RAR5_HEADER_DATA = 256

TIER_PSWCHECK = 0
TIER_DATA = 1
TIER_UNUSABLE = 2


class RarError(Exception):
    """The file is not a RAR archive, or its headers cannot be read."""


@dataclass
class Entry:
    """One file or service header, or the archive encryption header of RAR 5."""

    name: bytes = b""
    compressed_size: int = 0
    uncompressed_size: int = 0
    crc32: int = 0
    encryption: int = CRYPT_NONE
    method: int = 0
    salt: bytes = b""
    iv: bytes = b""
    lg2count: int = 0
    has_psw_check: bool = False
    psw_check: bytes | None = None
    psw_check_csum: bytes | None = None
    data_offset: int = 0
    has_hashmac: bool = False
    blake2sp: bytes | None = None
    header_type: int = 0
    split_before: bool = False
    split_after: bool = False
    solid: bool = False


@dataclass
class Archive:
    """What the headers of an archive say."""

    version: int
    entries: list[Entry]
    header_encrypted: bool = False


def u8(buf: bytes, off: int) -> int:
    """Read one byte."""
    if off < 0 or off >= len(buf):
        msg = "read past the end of the file"
        raise RarError(msg)
    return buf[off]


def u16(buf: bytes, off: int) -> int:
    """Read a little endian 16 bit number."""
    if off < 0 or off + 2 > len(buf):
        msg = "read past the end of the file"
        raise RarError(msg)
    return int.from_bytes(buf[off : off + 2], "little")


def u32(buf: bytes, off: int) -> int:
    """Read a little endian 32 bit number."""
    if off < 0 or off + 4 > len(buf):
        msg = "read past the end of the file"
        raise RarError(msg)
    return int.from_bytes(buf[off : off + 4], "little")


def vint(buf: bytes, off: int) -> tuple[int, int]:
    """Read a RAR 5 variable length number: 7 bits a byte, least significant first. Returns it and its length."""
    value = 0
    shift = 0
    used = 0
    while True:
        byte = u8(buf, off + used)
        used += 1
        if shift >= 64:
            msg = "variable length number too long"
            raise RarError(msg)
        value |= ((byte & 0x7F) << shift) & 0xFFFFFFFFFFFFFFFF
        shift += 7
        if byte & 0x80 == 0:
            break
        if used >= 10:
            msg = "variable length number too long"
            raise RarError(msg)
    return value, used


def padded(buf: bytes, size: int) -> bytes:
    """Cut or zero fill to size bytes."""
    return buf[:size].ljust(size, b"\x00")


# ---- where the archive starts ----


def rar_offset(data: bytes) -> int:
    """Return where the RAR signature is: 0, or further in for a self-extracting archive."""
    if data.startswith((SIGNATURE_RAR50, SIGNATURE_RAR15, SIGNATURE_RAR14)):
        return 0
    if data.startswith((b"MZ", b"\x7fELF")):
        found = data.find(b"Rar!", 0, min(len(data), SFX_SEARCH_LIMIT))
        if found >= 0:
            return found
    return 0


def rar_format(data: bytes) -> int:
    """Return the archive format the signature at the start of data names."""
    if data.startswith(SIGNATURE_RAR50):
        return FORMAT_RAR50
    if data.startswith(SIGNATURE_RAR15):
        return FORMAT_RAR15
    if data.startswith(SIGNATURE_RAR14):
        return FORMAT_RAR14
    msg = "not a RAR archive"
    raise RarError(msg)


# ---- RAR 1.5 to 4.x ----


def crypt3_method(unp_ver: int) -> int:
    """Return the cipher an entry uses, by the version needed to unpack it."""
    if unp_ver == 13:
        return CRYPT_RAR13
    if unp_ver == 15:
        return CRYPT_RAR15
    if unp_ver in (20, 26):
        return CRYPT_RAR20
    return CRYPT_RAR30


def parse_rar3_file(data: bytes, pos: int, flags: int, head_size: int) -> Entry:
    """Read a file header of a RAR 1.5 to 4.x archive."""
    compressed_size = u32(data, pos + 7)
    uncompressed_size = u32(data, pos + 11)
    crc32 = u32(data, pos + 16)
    unp_ver = u8(data, pos + 24)
    method = u8(data, pos + 25)
    name_size = u16(data, pos + 26)

    header_end = pos + 32

    if flags & LHD_LARGE and header_end + 8 <= len(data):
        compressed_size |= u32(data, header_end) << 32
        uncompressed_size |= u32(data, header_end + 4) << 32
        header_end += 8

    name_end = min(header_end + name_size, pos + head_size)
    name = data[header_end:name_end]

    encrypted = flags & LHD_PASSWORD != 0

    # The salt follows the name.

    salt = b""
    if encrypted and flags & LHD_SALT and name_end + SALT3_SIZE <= pos + head_size:
        salt = data[name_end : name_end + SALT3_SIZE]

    return Entry(
        name=name,
        compressed_size=compressed_size,
        uncompressed_size=uncompressed_size,
        crc32=crc32,
        encryption=crypt3_method(unp_ver) if encrypted else CRYPT_NONE,
        method=method,
        salt=salt,
        data_offset=pos + head_size,
        header_type=HEAD3_FILE,
        split_before=flags & LHD_SPLIT_BEFORE != 0,
        split_after=flags & LHD_SPLIT_AFTER != 0,
        solid=flags & LHD_SOLID != 0,
    )


def parse_rar3(data: bytes) -> Archive:
    """Walk the blocks of a RAR 1.5 to 4.x archive."""
    if len(data) <= len(SIGNATURE_RAR15):
        msg = "file too small"
        raise RarError(msg)

    archive = Archive(FORMAT_RAR15, [])
    archive_solid = False
    pos = len(SIGNATURE_RAR15)

    while pos + 7 <= len(data):
        head_type = u8(data, pos + 2)
        flags = u16(data, pos + 3)
        head_size = u16(data, pos + 5)

        if head_size < 7:
            break

        if head_type == HEAD3_MAIN:
            if flags & MHD_PASSWORD:
                archive.header_encrypted = True
                break
            archive_solid = flags & MHD_SOLID != 0
        elif head_type == HEAD3_FILE:
            if pos + 32 > len(data) or head_size < 32:
                break
            entry = parse_rar3_file(data, pos, flags, head_size)
            archive.entries.append(entry)
            pos += head_size + entry.compressed_size
            continue
        elif flags & LONG_BLOCK and head_size >= 11:
            # A service block, such as a comment or a recovery record, is followed by its data.
            pos += head_size + u32(data, pos + 7)
            continue

        pos += head_size

    # RAR 2.0 and later flag every member that needs the ones before it. RAR 1.5 has only the flag
    # for the whole archive, where that is every member but the first.

    if archive_solid:
        for entry in archive.entries[1:]:
            if entry.encryption in (CRYPT_RAR13, CRYPT_RAR15):
                entry.solid = True

    return archive


# ---- RAR 5 ----


def parse_rar5_crypt_record(data: bytes, start: int, rec_end: int, entry: Entry) -> None:
    """Read the encryption record in the extra area of a file header."""
    cpos = start

    try:
        enc_ver, used = vint(data, cpos)
    except RarError:
        enc_ver, used = 0, 1
    cpos += used

    if enc_ver > 0:
        return

    try:
        enc_flags, used = vint(data, cpos)
    except RarError:
        enc_flags, used = 0, 1
    cpos += used

    entry.has_hashmac = enc_flags & CRYPT5_HASHMAC != 0

    lg2count = data[cpos] if cpos < len(data) else 15
    cpos += 1

    if lg2count > LG2_COUNT_MAX:
        return

    if cpos + SALT5_SIZE <= rec_end:
        entry.salt = data[cpos : cpos + SALT5_SIZE]
        cpos += SALT5_SIZE

    if cpos + IV5_SIZE <= rec_end:
        entry.iv = data[cpos : cpos + IV5_SIZE]
        cpos += IV5_SIZE

    has_psw_check = enc_flags & CRYPT5_PSWCHECK != 0

    if has_psw_check and cpos + PSWCHECK_SIZE <= rec_end:
        entry.psw_check = data[cpos : cpos + PSWCHECK_SIZE]
        cpos += PSWCHECK_SIZE
        if cpos + PSWCHECK_CSUM_SIZE <= rec_end:
            entry.psw_check_csum = data[cpos : cpos + PSWCHECK_CSUM_SIZE]

    entry.lg2count = lg2count
    entry.has_psw_check = has_psw_check
    entry.encryption = CRYPT_RAR50


def parse_rar5_extra(data: bytes, hpos: int, hdr_end: int, extra_size: int, entry: Entry) -> None:
    """Read the records of the extra area, which ends the header."""
    if extra_size <= 0 or hpos >= hdr_end or extra_size > hdr_end:
        return

    epos = max(hdr_end - extra_size, hpos)

    while epos < hdr_end:
        try:
            rec_size, used = vint(data, epos)
        except RarError:
            break
        rec_start = epos + used
        rec_end = rec_start + rec_size
        if rec_end > hdr_end:
            break
        try:
            rec_type, used = vint(data, rec_start)
        except RarError:
            break

        if rec_type == FHEXTRA_CRYPT:
            parse_rar5_crypt_record(data, rec_start + used, rec_end, entry)
        elif rec_type == FHEXTRA_HASH:
            cpos = rec_start + used
            try:
                hash_type, used = vint(data, cpos)
            except RarError:
                hash_type, used = 0xFF, 1
            cpos += used
            if hash_type == 0 and cpos + BLAKE2_DIGEST_SIZE <= rec_end:
                entry.blake2sp = data[cpos : cpos + BLAKE2_DIGEST_SIZE]

        epos = rec_end


def parse_rar5_file(
    data: bytes,
    start: int,
    hdr_end: int,
    hflags: int,
    data_size: int,
    extra_size: int,
    header_type: int,
) -> Entry:
    """Read a file or service header of a RAR 5 archive."""
    hpos = start

    file_flags, used = vint(data, hpos)
    hpos += used
    uncompressed_size, used = vint(data, hpos)
    hpos += used
    _attributes, used = vint(data, hpos)
    hpos += used

    if file_flags & FHFL_UTIME:
        u32(data, hpos)
        hpos += 4

    crc32 = 0
    if file_flags & FHFL_CRC32:
        crc32 = u32(data, hpos)
        hpos += 4

    compression, used = vint(data, hpos)
    hpos += used
    _host_os, used = vint(data, hpos)
    hpos += used
    name_size, used = vint(data, hpos)
    hpos += used

    name = data[hpos : hpos + name_size]
    hpos += name_size

    entry = Entry(
        name=name,
        compressed_size=data_size,
        uncompressed_size=uncompressed_size,
        crc32=crc32,
        method=(compression >> 7) & 0x07,
        data_offset=hdr_end,
        header_type=header_type,
        split_before=hflags & HFL_SPLIT_BEFORE != 0,
        split_after=hflags & HFL_SPLIT_AFTER != 0,
        solid=compression & 0x0040 != 0,
    )

    parse_rar5_extra(data, hpos, hdr_end, extra_size, entry)

    return entry


def parse_rar5_crypt_header(data: bytes, start: int, hdr_end: int) -> Entry | None:
    """Read the archive encryption header. Returns None where it cannot be used."""
    hpos = start

    enc_ver, used = vint(data, hpos)
    hpos += used
    if enc_ver > 0:
        return None

    enc_flags, used = vint(data, hpos)
    hpos += used

    lg2count = u8(data, hpos)
    hpos += 1
    if lg2count > LG2_COUNT_MAX:
        return None

    if hpos + SALT5_SIZE > hdr_end:
        return None

    entry = Entry(
        name=HEADER_ENCRYPTED_NAME,
        encryption=CRYPT_RAR50,
        lg2count=lg2count,
        header_type=HEAD5_CRYPT,
    )

    entry.salt = data[hpos : hpos + SALT5_SIZE]
    hpos += SALT5_SIZE

    if enc_flags & CRYPT5_PSWCHECK and hpos + PSWCHECK_SIZE <= len(data):
        entry.has_psw_check = True
        entry.psw_check = data[hpos : hpos + PSWCHECK_SIZE]
        hpos += PSWCHECK_SIZE
        if hpos + PSWCHECK_CSUM_SIZE <= len(data):
            entry.psw_check_csum = data[hpos : hpos + PSWCHECK_CSUM_SIZE]

    return entry


def parse_rar5(data: bytes) -> Archive:
    """Walk the blocks of a RAR 5 archive."""
    if len(data) <= len(SIGNATURE_RAR50):
        msg = "file too small"
        raise RarError(msg)

    archive = Archive(FORMAT_RAR50, [])
    crypt_entry = None
    pos = len(SIGNATURE_RAR50)

    while pos + 4 < len(data):
        hdr_size, used = vint(data, pos + 4)
        hdr_start = pos + 4 + used
        hdr_end = hdr_start + hdr_size

        if hdr_end > len(data):
            break

        hpos = hdr_start
        head_type, used = vint(data, hpos)
        hpos += used
        hflags, used = vint(data, hpos)
        hpos += used

        extra_size = 0
        if hflags & HFL_EXTRA:
            extra_size, used = vint(data, hpos)
            hpos += used

        data_size = 0
        if hflags & HFL_DATA:
            data_size, used = vint(data, hpos)
            hpos += used

        if head_type == HEAD5_CRYPT:
            archive.header_encrypted = True
            crypt_entry = parse_rar5_crypt_header(data, hpos, hdr_end)
            break

        if head_type in (HEAD5_FILE, HEAD5_SERVICE):
            archive.entries.append(parse_rar5_file(data, hpos, hdr_end, hflags, data_size, extra_size, head_type))
        elif head_type == HEAD5_EOARC:
            break

        pos = hdr_end + data_size

    if crypt_entry is not None:
        archive.entries.append(crypt_entry)

    return archive


# ---- which entry gets a line ----


def is_stored(entry: Entry) -> bool:
    """Say whether the entry needs no decompressor once it is decrypted."""
    if entry.encryption in (CRYPT_RAR50, CRYPT_RAR13):
        return entry.method == 0
    return entry.method == METHOD3_STORE


def score(entry: Entry) -> tuple[int, bool, bool, bool, int, int]:
    """Rank an entry as something to crack. Lower is better, and the fields compare in order."""
    unusable = (TIER_UNUSABLE, True, True, True, 0xFF, 0xFFFFFFFFFFFFFFFF)

    if entry.split_before:
        return unusable

    compressed = not is_stored(entry)
    chain_dependent = entry.solid and compressed

    if entry.encryption == CRYPT_RAR50 and entry.has_psw_check:
        return (TIER_PSWCHECK, False, False, False, entry.lg2count, 0)

    if entry.encryption == CRYPT_NONE:
        return unusable

    lg2count = entry.lg2count if entry.encryption == CRYPT_RAR50 else 0
    preferred = PREFERRED_LEGACY_DATA if entry.encryption in (CRYPT_RAR15, CRYPT_RAR20) else PREFERRED_HASH_DATA
    oversize = entry.compressed_size > preferred
    too_large = entry.compressed_size > MAX_INLINE_DATA

    # An empty file has nothing to check a password against, an entry over the ceiling cannot be
    # carried whole, and a compressed solid member cannot be unpacked without the files before it.

    unusable_entry = entry.uncompressed_size == 0 or entry.compressed_size == 0 or too_large or chain_dependent

    return (
        TIER_UNUSABLE if unusable_entry else TIER_DATA,
        chain_dependent,
        oversize,
        compressed,
        lg2count,
        entry.compressed_size,
    )


def why_no_hash(entry: Entry, chain_dependent: bool) -> str:
    """Say why an entry gets no line."""
    if entry.uncompressed_size == 0 or entry.compressed_size == 0:
        return "it is empty, so every password would match"
    if chain_dependent and entry.compressed_size <= MAX_INLINE_DATA:
        return "it is a compressed solid member, which cannot be unpacked without the files before it"
    return f"its {entry.compressed_size} bytes of encrypted data exceed the {MAX_INLINE_DATA} a hash can carry, and a cut stream cannot be checked"


# ---- the lines ----


def line_rar50_pswcheck(entry: Entry) -> str | None:
    """Type 0 of $rar$50$: the password check value."""
    if entry.encryption != CRYPT_RAR50 or not entry.has_psw_check or entry.psw_check is None:
        return None

    # RAR 5.21 writes service headers with the flag set and the value zeroed, which every password
    # would match.

    if entry.header_type == HEAD5_SERVICE and entry.psw_check == bytes(PSWCHECK_SIZE):
        return None

    # The value carries its own checksum, the start of its SHA-256.

    if entry.psw_check_csum is not None and hashlib.sha256(entry.psw_check).digest()[:PSWCHECK_CSUM_SIZE] != entry.psw_check_csum:
        return None

    return f"$rar$50$*0*{padded(entry.salt, SALT5_SIZE).hex()}*{entry.lg2count}*{bytes(IV5_SIZE).hex()}*{entry.psw_check.hex()}*0*****$/rar$"


def line_rar50_data(data: bytes, entry: Entry) -> str | None:
    """Type 1 of $rar$50$: the whole encrypted entry and the checksum of the file."""
    start = entry.data_offset
    size = entry.compressed_size

    if size > MAX_INLINE_DATA or start + size > len(data):
        return None

    if entry.blake2sp is not None:
        check_type = 3 if entry.has_hashmac else 2
        checksum = entry.blake2sp.hex()
    else:
        check_type = 1 if entry.has_hashmac else 0
        checksum = f"{entry.crc32:08x}"

    salt = padded(entry.salt, SALT5_SIZE).hex()
    iv = padded(entry.iv, IV5_SIZE).hex()

    return f"$rar$50$*1*{salt}*{entry.lg2count}*{iv}**{check_type}*{checksum}*{size:x}*{entry.uncompressed_size:x}*{entry.method:x}*{data[start : start + size].hex()}$/rar$"


def line_rar50_header(data: bytes, archive: Archive) -> str | None:
    """Type 1 of $rar$50$ with check type 4: the first encrypted header blocks of an archive without a check value."""
    entry = next((e for e in archive.entries if e.encryption == CRYPT_RAR50), None)
    if entry is None:
        return None

    pos = len(SIGNATURE_RAR50)

    try:
        while pos + 4 < len(data):
            hdr_size, used = vint(data, pos + 4)
            hdr_start = pos + 4 + used
            hdr_end = hdr_start + hdr_size
            if hdr_end > len(data):
                break

            hpos = hdr_start
            head_type, used = vint(data, hpos)
            hpos += used
            hflags, used = vint(data, hpos)
            hpos += used

            data_size = vint(data, hpos)[0] if hflags & HFL_DATA else 0

            if head_type == HEAD5_CRYPT:
                # What follows the encryption header is an IV and then the encrypted headers.
                iv_start = hdr_end
                enc_start = iv_start + IV5_SIZE
                if enc_start > len(data):
                    return None
                size = min(RAR5_HEADER_DATA, len(data) - enc_start) & ~0xF
                if size < 16:
                    return None
                salt = padded(entry.salt, SALT5_SIZE).hex()
                iv = data[iv_start:enc_start].hex()
                return f"$rar$50$*1*{salt}*{entry.lg2count}*{iv}**4**{size:x}*{size:x}*0*{data[enc_start : enc_start + size].hex()}$/rar$"

            pos = hdr_end + data_size
    except RarError:
        return None

    return None


def line_rar30_header(data: bytes) -> str | None:
    """Type 0 of $rar$30$: the salt and the encrypted end header, the last 24 bytes of the archive."""
    if len(data) < 24:
        return None
    tail = data[-24:]
    return f"$rar$30$*0*{tail[:SALT3_SIZE].hex()}*{RAR30_HEADER_CRC:08x}*10*10*0*{tail[SALT3_SIZE:].hex()}$/rar$"


def line_rar30_data(data: bytes, entry: Entry) -> str | None:
    """Type 1 of $rar$30$: the whole encrypted entry and the CRC32 of the file."""
    start = entry.data_offset
    size = entry.compressed_size

    if size < 16 or size > MAX_INLINE_DATA or start + size > len(data):
        return None

    return f"$rar$30$*1*{padded(entry.salt, SALT3_SIZE).hex()}*{entry.crc32:08x}*{size:x}*{entry.uncompressed_size:x}*{entry.method:x}*{data[start : start + size].hex()}$/rar$"


def line_legacy(data: bytes, entry: Entry) -> str | None:
    """Write $rar$15$ or $rar$20$: the whole encrypted entry and the CRC32 of the file."""
    start = entry.data_offset
    size = entry.compressed_size

    # RAR 2.0 encrypts whole blocks of 16 bytes.

    if entry.encryption == CRYPT_RAR20:
        size &= ~0xF

    if size <= 0 or start + size > len(data):
        return None

    return f"$rar${entry.encryption}$*{entry.crc32:08x}*{entry.uncompressed_size:x}*{size:x}*{entry.method:x}*{data[start : start + size].hex()}$/rar$"


def line_for_entry(data: bytes, entry: Entry) -> str | None:
    """Return the line for one entry, by its encryption."""
    if entry.encryption == CRYPT_RAR50:
        return line_rar50_pswcheck(entry) if entry.has_psw_check else line_rar50_data(data, entry)
    if entry.encryption == CRYPT_RAR30:
        return line_rar30_data(data, entry)
    if entry.encryption in (CRYPT_RAR15, CRYPT_RAR20):
        return line_legacy(data, entry)
    return None


def lines_header_encrypted(data: bytes, archive: Archive) -> list[str]:
    """Return the one line of an archive with encrypted headers."""
    if archive.version == FORMAT_RAR15:
        line = line_rar30_header(data)
        return [] if line is None else [line]

    for entry in archive.entries:
        line = line_rar50_pswcheck(entry)
        if line is not None:
            return [line]

    line = line_rar50_header(data, archive)
    return [] if line is None else [line]


def hashes_of(data: bytes, all_hashes: bool, notes: list[str]) -> list[str]:
    """Return the hash lines of an archive. Reasons for an entry without one go to notes."""
    data = data[rar_offset(data) :]
    version = rar_format(data)

    if version == FORMAT_RAR14:
        notes.append("RAR 1.3 and 1.4 archives have no hash, their key is short enough to search")
        return []

    archive = parse_rar3(data) if version == FORMAT_RAR15 else parse_rar5(data)

    if archive.header_encrypted:
        return lines_header_encrypted(data, archive)

    candidates = []
    whole_entry_missing = False

    for index, entry in enumerate(archive.entries):
        if entry.name == HEADER_ENCRYPTED_NAME or entry.encryption == CRYPT_NONE:
            continue
        split = entry.split_before or entry.split_after
        if split and not (entry.encryption == CRYPT_RAR50 and entry.has_psw_check):
            whole_entry_missing = whole_entry_missing or entry.encryption != CRYPT_RAR13
            continue
        candidates.append((score(entry), index))

    if not candidates:
        if whole_entry_missing:
            notes.append("the encrypted entry continues in another volume, a hash needs the volume that holds the whole entry")
        return []

    candidates.sort()

    lines = []

    for rank, index in candidates if all_hashes else candidates[:1]:
        entry = archive.entries[index]
        name = entry.name.decode("utf-8", "replace")
        if rank[0] == TIER_UNUSABLE:
            notes.append(f"{name}: {why_no_hash(entry, rank[1])}")
            continue
        line = line_for_entry(data, entry)
        # Entries that share a salt and a check value give the same line, which is written once.
        if line is not None and line not in lines:
            lines.append(line)

    return lines


def main() -> int:
    """Write the hash lines of every archive named on the command line."""
    parser = argparse.ArgumentParser(description="Write the hashcat lines of password protected RAR archives, for modes 46500 (RAR 1.5), 46600 (RAR 2.0), 46700 (RAR 3.x to 4.x) and 46800 (RAR 5 and 7).")
    parser.add_argument(
        "archives",
        metavar="ARCHIVE",
        nargs="+",
        help="a RAR archive, or a self-extracting one",
    )
    parser.add_argument(
        "-a",
        "--all-hashes",
        action="store_true",
        help="write a line for every encrypted entry, not only for the best one",
    )
    parser.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="do not say on stderr why an entry has no line",
    )
    args = parser.parse_args()

    status = 0

    for path in args.archives:
        notes: list[str] = []
        try:
            with open(path, "rb") as handle:
                data = handle.read()
            lines = hashes_of(data, args.all_hashes, notes)
        except (OSError, RarError) as error:
            sys.stderr.write(f"{path}: {error}\n")
            status = 1
            continue

        for line in lines:
            sys.stdout.write(line + "\n")

        if not args.quiet:
            for note in notes:
                sys.stderr.write(f"{path}: no hash: {note}\n")

    return status


if __name__ == "__main__":
    sys.exit(main())
