#!/usr/bin/env python3
# /// script
# requires-python = ">=3.8"
# dependencies = []
# ///

#
# Author......: See docs/credits.txt
# License.....: MIT
#

"""Read a password protected 7z archive and write the hash line for hashcat mode 46900.

The line is the one ArchiveWolf writes, field for field:

    $7z$*power*salt*crc32*crc_len*join*N*stream_1*...*stream_N$/7z$

    stream  =  iv*packed*unpacked*chain*data

    power     NumCyclesPower of the key derivation, decimal: 2^power rounds of SHA-256
    salt      hex, usually empty
    crc32     CRC-32 of the first crc_len bytes the folder unpacks to, 8 hex digits. Empty when
              the line rests on the stream alone, and the word header when what is unpacked is
              the header of an archive that stores no CRC-32 for it
    crc_len   hex
    join      the coders that run after the streams have been joined, empty for a folder with one
              stream
    N         number of packed streams, 1, or 4 for a folder that uses BCJ2
    iv        initialisation vector of the stream, hex, as many bytes as the archive stores
    packed    size of the encrypted stream, hex. A stream of BCJ2 can be empty
    unpacked  size of what it decrypts to, hex: the rest of the last cipher block is padding
    chain     the coders that run on this stream after decryption, in that order
    data      the encrypted stream, or the start of it

A chain is a list of coders separated by commas. A coder is id/properties/size, the id and the
properties in hex as the archive stores them and the size of its output in hex.

Which folder is picked, and how much of it goes into the line, follows ArchiveWolf:

  * An archive with encrypted headers has one line, made from the header. Its files cannot be
    listed without the password. Where the archive stores no CRC-32 for the header, the line
    tests that what is decrypted is one: 7-Zip tells a wrong password the same way.
  * Otherwise the encrypted folders are ranked: one with a CRC-32 before one without, one stream
    before four, then the one whose first file is the smallest, since that file is what every
    candidate has to be unpacked to.
  * A stream goes in whole when the CRC-32 covers all of the folder. When it covers the first file
    of several, the line holds as much of the stream as that file can take up at worst.
  * A stream of more than 4 MiB gives its first megabyte. The line then tests that this start
    unpacks without an error, which LZMA, LZMA2, Deflate and BZip2 allow and PPMd, Zstandard and
    stored data do not. For LZMA2 and Deflate it takes the whole megabyte: a shorter start can
    be data stored as it is, which unpacks to anything.
  * --all-hashes writes a line for every encrypted folder, for the archives whose folders do not
    share one password.

A self-extracting archive is read from where its 7z signature is.
"""

from __future__ import annotations

import argparse
import lzma
import struct
import sys
import zlib
from dataclasses import dataclass, field

SIGNATURE = b"7z\xbc\xaf\x27\x1c"
SIGNATURE_SEARCH = 1 << 23

K_END = 0x00
K_HEADER = 0x01
K_ARCHIVE_PROPERTIES = 0x02
K_ADDITIONAL_STREAMS_INFO = 0x03
K_MAIN_STREAMS_INFO = 0x04
K_FILES_INFO = 0x05
K_PACK_INFO = 0x06
K_UNPACK_INFO = 0x07
K_SUBSTREAMS_INFO = 0x08
K_SIZE = 0x09
K_CRC = 0x0A
K_FOLDER = 0x0B
K_CODERS_UNPACK_SIZE = 0x0C
K_NUM_UNPACK_STREAM = 0x0D
K_EMPTY_STREAM = 0x0E
K_NAMES = 0x11
K_ENCODED_HEADER = 0x17

ID_COPY = b"\x00"
ID_DELTA = b"\x03"
ID_ARM64 = b"\x0a"
ID_RISCV = b"\x0b"
ID_LZMA2 = b"\x21"
ID_SWAP2 = b"\x02\x03\x02"
ID_SWAP4 = b"\x02\x03\x04"
ID_LZMA = b"\x03\x01\x01"
ID_PPMD = b"\x03\x04\x01"
ID_BCJ = b"\x03\x03\x01\x03"
ID_BCJ2 = b"\x03\x03\x01\x1b"
ID_PPC = b"\x03\x03\x02\x05"
ID_IA64 = b"\x03\x03\x04\x01"
ID_ARM = b"\x03\x03\x05\x01"
ID_ARMT = b"\x03\x03\x07\x01"
ID_SPARC = b"\x03\x03\x08\x05"
ID_DEFLATE = b"\x04\x01\x08"
ID_DEFLATE64 = b"\x04\x01\x09"
ID_BZIP2 = b"\x04\x02\x02"
ID_ZSTD = b"\x04\xf7\x11\x01"
ID_AES = b"\x06\xf1\x07\x01"

COMPRESSORS = (ID_LZMA, ID_LZMA2, ID_PPMD, ID_DEFLATE, ID_DEFLATE64, ID_BZIP2, ID_ZSTD)
FILTERS = (
    ID_DELTA,
    ID_ARM64,
    ID_RISCV,
    ID_SWAP2,
    ID_SWAP4,
    ID_BCJ,
    ID_PPC,
    ID_IA64,
    ID_ARM,
    ID_ARMT,
    ID_SPARC,
)

# The start of these streams says something about the key: random bytes are not one of them for
# more than a few bytes. A PPMd stream takes anything, stored data is anything, and the library
# hashcat unpacks Zstandard with does not say how far it came.

START_TELLS = (ID_LZMA, ID_LZMA2, ID_DEFLATE, ID_DEFLATE64, ID_BZIP2)

# Of these, the ones whose start is a test only when a full megabyte of it is there.

START_NEEDS_ALL = (ID_LZMA2, ID_DEFLATE, ID_DEFLATE64)

NAMES = {
    ID_COPY: "Copy",
    ID_DELTA: "Delta",
    ID_ARM64: "ARM64",
    ID_RISCV: "RISCV",
    ID_LZMA2: "LZMA2",
    ID_SWAP2: "Swap2",
    ID_SWAP4: "Swap4",
    ID_LZMA: "LZMA",
    ID_PPMD: "PPMd",
    ID_BCJ: "BCJ",
    ID_BCJ2: "BCJ2",
    ID_PPC: "PPC",
    ID_IA64: "IA64",
    ID_ARM: "ARM",
    ID_ARMT: "ARMT",
    ID_SPARC: "SPARC",
    ID_DEFLATE: "Deflate",
    ID_DEFLATE64: "Deflate64",
    ID_BZIP2: "BZip2",
    ID_ZSTD: "Zstandard",
    ID_AES: "7zAES",
}

AES_BLOCK = 16

MAX_INLINE_DATA = 4 * 1024 * 1024
START_DATA = 1024 * 1024

# hashcat unpacks a candidate to at most this many bytes to test a CRC-32.

MAX_UNPACK = 64 * 1024 * 1024

# A CRC-32 on fewer than this many bytes has fewer possible inputs than the CRC has values, so it
# does not fully confirm the password.  Rank these below folders with a full CRC.

FULL_CRC_BYTES = 4

# A branch converter looks this far past the bytes it has been asked for.

FILTER_LOOKAHEAD = 16

MAX_HEADER_SIZE = 1 << 28
MAX_FOLDERS = 1 << 20

# What a line can prove, best first.

PROOF_CRC = 0
PROOF_HEADER = 1
PROOF_END = 2
PROOF_START = 3


class SevenZipError(Exception):
    """The file is not a 7z archive this tool can read."""


class NoLine(Exception):
    """A folder that has no line. The message says why."""


class Reader:
    """A cursor over the bytes of a header."""

    def __init__(self, data: bytes) -> None:
        self.data = data
        self.pos = 0

    def take(self, count: int) -> bytes:
        """Return the next bytes."""
        if count < 0 or self.pos + count > len(self.data):
            raise SevenZipError("header is cut short")
        out = self.data[self.pos : self.pos + count]
        self.pos += count
        return out

    def byte(self) -> int:
        """Return the next byte."""
        return self.take(1)[0]

    def u32(self) -> int:
        """Return a little endian 32 bit number."""
        return struct.unpack("<I", self.take(4))[0]

    def number(self) -> int:
        """Return a number in the variable length form of the format."""
        first = self.byte()
        mask = 0x80
        value = 0
        for i in range(8):
            if first & mask == 0:
                return value | ((first & (mask - 1)) << (8 * i))
            value |= self.byte() << (8 * i)
            mask >>= 1
        return value

    def count(self, limit: int) -> int:
        """Return a number that counts something, which a damaged header can make absurd."""
        value = self.number()
        if value > limit:
            raise SevenZipError("header holds an impossible count")
        return value

    def bits(self, count: int) -> list[bool]:
        """Return a vector of booleans, one bit each, the high bit first."""
        out = []
        value = 0
        mask = 0
        for _ in range(count):
            if mask == 0:
                value = self.byte()
                mask = 0x80
            out.append(value & mask != 0)
            mask >>= 1
        return out

    def defined(self, count: int) -> list[bool]:
        """Return a vector of booleans that may be given as "all of them"."""
        if self.byte() != 0:
            return [True] * count
        return self.bits(count)

    def digests(self, count: int) -> list[int | None]:
        """Return a list of CRC-32 values, None where the archive stores none."""
        have = self.defined(count)
        return [self.u32() if flag else None for flag in have]


@dataclass
class Coder:
    """One coder of a folder."""

    ident: bytes
    inputs: int
    props: bytes


@dataclass
class Folder:
    """A folder: the coders that turn its packed streams into its files."""

    coders: list[Coder] = field(default_factory=list)
    bonds: list[tuple[int, int]] = field(default_factory=list)
    packed: list[int] = field(default_factory=list)
    sizes: list[int] = field(default_factory=list)
    crc: int | None = None
    first_pack: int = 0
    sub_sizes: list[int] = field(default_factory=list)
    sub_crcs: list[int | None] = field(default_factory=list)
    names: list[str] = field(default_factory=list)


@dataclass
class Streams:
    """What a StreamsInfo block describes."""

    pack_pos: int = 0
    pack_sizes: list[int] = field(default_factory=list)
    folders: list[Folder] = field(default_factory=list)


@dataclass
class Stream:
    """One packed stream of a folder, ready for the line."""

    power: int
    salt: bytes
    iv: bytes
    offset: int
    packed: int
    unpacked: int
    chain: list[tuple[bytes, bytes, int]]


@dataclass
class Plan:
    """Everything a line carries."""

    streams: list[Stream]
    join: list[tuple[bytes, bytes, int]]
    crc: int | None
    crc_len: int
    total: int
    what: str
    header: bool = False


def read_folder(reader: Reader) -> Folder:
    """Read the coders of one folder and how they are connected."""
    folder = Folder()

    coders = reader.count(64)
    if coders == 0:
        raise SevenZipError("folder without a coder")

    inputs = 0
    for _ in range(coders):
        flags = reader.byte()
        if flags & 0xC0:
            raise SevenZipError("coder with unknown flags")
        ident = reader.take(flags & 0x0F)
        count = 1
        if flags & 0x10:
            count = reader.count(64)
            if reader.number() != 1:
                raise SevenZipError("coder with more than one output")
        props = reader.take(reader.count(MAX_HEADER_SIZE)) if flags & 0x20 else b""
        folder.coders.append(Coder(ident, count, props))
        inputs += count

    for _ in range(coders - 1):
        folder.bonds.append((reader.number(), reader.number()))

    packed = inputs - (coders - 1)
    if packed < 1:
        raise SevenZipError("folder without a packed stream")
    if packed == 1:
        bound = {bond[0] for bond in folder.bonds}
        free = [index for index in range(inputs) if index not in bound]
        if len(free) != 1:
            raise SevenZipError("folder with damaged connections")
        folder.packed = free
    else:
        folder.packed = [reader.number() for _ in range(packed)]

    return folder


def read_streams(reader: Reader) -> Streams:
    """Read a StreamsInfo block: packed sizes, folders and the files inside each folder."""
    streams = Streams()
    seen_substreams = False

    while True:
        ident = reader.byte()

        if ident == K_END:
            break

        if ident == K_PACK_INFO:
            streams.pack_pos = reader.number()
            count = reader.count(MAX_FOLDERS)
            while True:
                part = reader.byte()
                if part == K_END:
                    break
                if part == K_SIZE:
                    streams.pack_sizes = [reader.number() for _ in range(count)]
                elif part == K_CRC:
                    reader.digests(count)
                else:
                    raise SevenZipError("unknown field in the pack information")
            if len(streams.pack_sizes) != count:
                raise SevenZipError("pack information without sizes")

        elif ident == K_UNPACK_INFO:
            if reader.byte() != K_FOLDER:
                raise SevenZipError("unpack information without folders")
            count = reader.count(MAX_FOLDERS)
            if reader.byte() != 0:
                raise SevenZipError("folders stored outside the header are not supported")
            streams.folders = [read_folder(reader) for _ in range(count)]

            first = 0
            for folder in streams.folders:
                folder.first_pack = first
                first += len(folder.packed)

            while True:
                part = reader.byte()
                if part == K_END:
                    break
                if part == K_CODERS_UNPACK_SIZE:
                    for folder in streams.folders:
                        folder.sizes = [reader.number() for _ in folder.coders]
                elif part == K_CRC:
                    for folder, crc in zip(streams.folders, reader.digests(count)):
                        folder.crc = crc
                else:
                    raise SevenZipError("unknown field in the unpack information")

        elif ident == K_SUBSTREAMS_INFO:
            seen_substreams = True
            counts = [1] * len(streams.folders)
            part = reader.byte()

            if part == K_NUM_UNPACK_STREAM:
                counts = [reader.count(MAX_FOLDERS) for _ in streams.folders]
                part = reader.byte()

            for folder, count in zip(streams.folders, counts):
                total = final_size(folder)
                if count == 0:
                    continue
                sizes = [reader.number() for _ in range(count - 1)] if part == K_SIZE else []
                if part != K_SIZE and count > 1:
                    raise SevenZipError("folder with several files and no sizes")
                if sum(sizes) > total:
                    raise SevenZipError("files larger than their folder")
                folder.sub_sizes = [*sizes, total - sum(sizes)]

            if part == K_SIZE:
                part = reader.byte()

            # a folder that holds one file and has a CRC-32 of its own does not repeat it here
            missing = [folder for folder, count in zip(streams.folders, counts) if not (count == 1 and folder.crc is not None) for _ in range(count)]

            for folder, count in zip(streams.folders, counts):
                folder.sub_crcs = [folder.crc] if count == 1 and folder.crc is not None else [None] * count

            if part == K_CRC:
                values = reader.digests(len(missing))
                position: dict[int, int] = {}
                for folder, crc in zip(missing, values):
                    index = position.get(id(folder), 0)
                    folder.sub_crcs[index] = crc
                    position[id(folder)] = index + 1
                part = reader.byte()

            if part != K_END:
                raise SevenZipError("unknown field in the substream information")

        else:
            raise SevenZipError("unknown field in the stream information")

    if not seen_substreams:
        for folder in streams.folders:
            folder.sub_sizes = [final_size(folder)]
            folder.sub_crcs = [folder.crc]

    if sum(len(folder.packed) for folder in streams.folders) > len(streams.pack_sizes):
        raise SevenZipError("more packed streams used than stored")

    return streams


def root_coder(folder: Folder) -> int:
    """The coder whose output is the output of the folder."""
    bound = {bond[1] for bond in folder.bonds}
    free = [index for index in range(len(folder.coders)) if index not in bound]
    if len(free) != 1:
        raise SevenZipError("folder with damaged connections")
    return free[0]


def final_size(folder: Folder) -> int:
    """Size of what the folder unpacks to."""
    if len(folder.sizes) != len(folder.coders):
        raise SevenZipError("folder without sizes")
    return folder.sizes[root_coder(folder)]


def aes_properties(props: bytes) -> tuple[int, bytes, bytes]:
    """Split the properties of the 7zAES coder into power, salt and initialisation vector."""
    if not props:
        raise NoLine("its 7zAES coder has no properties")
    first = props[0]
    power = first & 0x3F
    if first & 0xC0 == 0:
        return power, b"", b""
    if len(props) < 2:
        raise NoLine("the properties of its 7zAES coder are cut short")
    salt_len = ((first >> 7) & 1) + (props[1] >> 4)
    iv_len = ((first >> 6) & 1) + (props[1] & 0x0F)
    if len(props) < 2 + salt_len + iv_len:
        raise NoLine("the properties of its 7zAES coder are cut short")
    return power, props[2 : 2 + salt_len], props[2 + salt_len : 2 + salt_len + iv_len]


def is_encrypted(folder: Folder) -> bool:
    """Whether a folder has a 7zAES coder."""
    return any(coder.ident == ID_AES for coder in folder.coders)


def resolve(folder: Folder, streams: Streams) -> tuple[list[Stream], list[tuple[bytes, bytes, int]]]:
    """Follow the connections of a folder from its output back to its packed streams.

    Returns the packed streams, each with the coders that run on it alone, and the coders that run
    after the streams have been joined. Raises NoLine for a layout no line can describe.
    """
    base = []
    total = 0
    for coder in folder.coders:
        base.append(total)
        total += coder.inputs

    feeds = dict(folder.bonds)
    pack_of = {index: number for number, index in enumerate(folder.packed)}

    offsets = []
    position = 0
    for size in streams.pack_sizes:
        offsets.append(position)
        position += size

    def entry(index: int) -> tuple[bytes, bytes, int]:
        coder = folder.coders[index]
        return coder.ident, coder.props, folder.sizes[index]

    def branch(start: int) -> Stream:
        # walk one input of the joining coder, or the folder's only path, down to its packed stream
        chain: list[int] = []
        source = start
        while True:
            if source in pack_of:
                break
            if source not in feeds:
                raise SevenZipError("folder with damaged connections")
            index = feeds[source]
            if folder.coders[index].inputs != 1:
                raise NoLine("it joins streams more than once")
            chain.append(index)
            source = base[index]
            if len(chain) > len(folder.coders):
                raise SevenZipError("folder with circular connections")

        if not chain or folder.coders[chain[-1]].ident != ID_AES:
            raise NoLine("one of its streams is not encrypted, or is encrypted before it is packed")
        if any(folder.coders[index].ident == ID_AES for index in chain[:-1]):
            raise NoLine("it is encrypted twice")

        aes = chain[-1]
        power, salt, iv = aes_properties(folder.coders[aes].props)
        number = folder.first_pack + pack_of[source]
        decode = [entry(index) for index in reversed(chain[:-1]) if folder.coders[index].ident != ID_COPY]
        return Stream(
            power,
            salt,
            iv,
            streams.pack_pos + offsets[number],
            streams.pack_sizes[number],
            folder.sizes[aes],
            decode,
        )

    # the path from the output down to the coder that takes more than one stream, if there is one
    tail: list[int] = []
    index = root_coder(folder)
    while folder.coders[index].inputs == 1 and base[index] in feeds:
        tail.append(index)
        index = feeds[base[index]]
        if len(tail) > len(folder.coders):
            raise SevenZipError("folder with circular connections")

    if folder.coders[index].inputs == 1:
        # one stream: index is the coder that reads it, so the walk starts at its output
        fake = -1
        feeds[fake] = root_coder(folder)
        return [branch(fake)], []

    if any(folder.coders[i].ident == ID_AES for i in [*tail, index]):
        raise NoLine("it is encrypted after its streams are joined")

    found = [branch(base[index] + n) for n in range(folder.coders[index].inputs)]
    join = [entry(index)] + [entry(i) for i in reversed(tail) if folder.coders[i].ident != ID_COPY]
    return found, join


def worst_case(ident: bytes, wanted: int) -> int:
    """How many packed bytes the first `wanted` unpacked bytes can take up at the very most."""
    if ident in (ID_LZMA, ID_LZMA2):
        # the bound the LZMA encoder itself gives for data that does not compress
        return wanted + wanted // 3 + 128 + 64
    if ident in (ID_DEFLATE, ID_DEFLATE64):
        # a rare literal costs up to 15 bits, and a block starts with its code tables
        return 2 * wanted + 1024
    if ident == ID_BZIP2:
        # nothing comes out before a whole block of up to 900,000 bytes has gone in
        return wanted + wanted // 50 + 920_000
    if ident == ID_ZSTD:
        # nothing comes out before a whole block of up to 128 KiB has gone in
        return wanted + wanted // 1000 + 131_072 + 64
    # stored data. PPMd has no bound worth the name and never gets here
    return wanted


def plan_folder(folder: Folder, streams: Streams, what: str) -> Plan:
    """Decide what the line of a folder carries. Raises NoLine when there is none."""
    total = final_size(folder)
    if total == 0:
        raise NoLine("it is empty")

    found, join = resolve(folder, streams)

    first = found[0]
    if any((s.power, s.salt) != (first.power, first.salt) for s in found):
        raise NoLine("its streams do not share one key")
    if first.power == 0x3F:
        raise NoLine("its key is the password itself, with no key derivation, which 7-Zip reads and never writes and hashcat does not test")
    if first.power > 24:
        raise NoLine(f"its key derivation asks for 2^{first.power} rounds, which 7-Zip itself refuses")

    for stream in found:
        if stream.packed == 0 and len(found) > 1 and stream.unpacked == 0:
            continue
        if stream.packed == 0 or stream.packed % AES_BLOCK != 0:
            raise NoLine("an encrypted stream is not a whole number of cipher blocks")
        if stream.unpacked > stream.packed or stream.packed - stream.unpacked >= AES_BLOCK:
            raise NoLine("the sizes of an encrypted stream do not fit each other")

    for ident, _, _ in [*join, *(c for s in found for c in s.chain)]:
        if ident not in COMPRESSORS and ident not in FILTERS and ident != ID_BCJ2:
            raise NoLine(f"it uses the coder {ident.hex()}, which hashcat cannot unpack")

    if len(found) > 1 and (len(found) != 4 or not join or join[0][0] != ID_BCJ2):
        raise NoLine("it joins streams with a coder other than BCJ2")
    if len(found) == 1 and any(ident == ID_BCJ2 for ident, _, _ in first.chain):
        raise NoLine("it uses BCJ2 on a single stream")

    crc = None
    crc_len = total

    if folder.sub_sizes and folder.sub_crcs and folder.sub_crcs[0] is not None and folder.sub_sizes[0] > 0:
        crc = folder.sub_crcs[0]
        crc_len = folder.sub_sizes[0]
    elif folder.crc is not None:
        crc = folder.crc

    return Plan(found, join, crc, crc_len, total, what)


def take_of(plan: Plan, stream: Stream) -> tuple[int, int, str]:
    """How many bytes of a stream the line takes, what they prove, and why that is less than a CRC-32."""
    if plan.crc is None:
        why = "the archive stores no CRC-32 for it"
    elif plan.crc_len + FILTER_LOOKAHEAD > MAX_UNPACK:
        why = f"its first file unpacks to {plan.crc_len} bytes, more than the {MAX_UNPACK} hashcat unpacks for a candidate"
    else:
        why = ""

    if len(plan.streams) > 1:
        if why:
            raise NoLine(f"it uses BCJ2 and {why}")
        if stream.packed > MAX_INLINE_DATA:
            raise NoLine(f"it uses BCJ2 and one of its streams has {stream.packed} bytes, more than the {MAX_INLINE_DATA} a hash can carry")
        return stream.packed, PROOF_CRC, ""

    compressor = next((ident for ident, _, _ in stream.chain if ident in COMPRESSORS), ID_COPY)
    filtered = any(ident in FILTERS for ident, _, _ in stream.chain)

    if not why:
        need = stream.packed

        if plan.crc_len < plan.total and compressor != ID_PPMD:
            wanted = plan.crc_len + (FILTER_LOOKAHEAD if filtered else 0)
            need = min(stream.packed, -(-worst_case(compressor, wanted) // AES_BLOCK) * AES_BLOCK)

        if need <= MAX_INLINE_DATA:
            return need, PROOF_CRC, ""

        why = f"testing its CRC-32 takes {need} bytes of it, more than the {MAX_INLINE_DATA} a hash can carry"

    name = NAMES.get(compressor, "stored")

    # a header says by its structure whether it is one, however it is packed
    if plan.header and plan.crc is None and stream.packed <= MAX_INLINE_DATA and plan.total <= MAX_UNPACK:
        return stream.packed, PROOF_HEADER, why

    if compressor == ID_COPY:
        raise NoLine(f"{why}, and stored data says nothing about the key by itself")

    # all of a stream that is short enough: it has to unpack to its size and end there
    if plan.crc is None and stream.packed <= MAX_INLINE_DATA and plan.total <= MAX_UNPACK:
        return stream.packed, PROOF_END, why

    if compressor not in START_TELLS:
        raise NoLine(f"{why}, and the start of {name} data says nothing about the key")

    # LZMA2 and Deflate can store data as it is, in chunks of up to 64 KiB that nothing checks. A
    # megabyte holds enough chunk headers for a wrong key to fail on one of them. Less does not.
    if compressor in START_NEEDS_ALL and stream.packed < START_DATA:
        raise NoLine(f"{why}, and its {stream.packed} bytes of {name} data are too few to say anything about the key by their start")

    return min(stream.packed, START_DATA), PROOF_START, why


def show_chain(chain: list[tuple[bytes, bytes, int]]) -> str:
    """Write a list of coders the way the line holds it."""
    return ",".join(f"{ident.hex()}/{props.hex()}/{size:x}" for ident, props, size in chain)


def line_of(data: bytes, base: int, plan: Plan, notes: list[str]) -> str:
    """Build the line of a plan. Raises NoLine when a stream cannot go into one."""
    first = plan.streams[0]
    taken = []
    weakest = PROOF_CRC
    reason = ""

    for stream in plan.streams:
        take, proof, why = take_of(plan, stream)
        if proof > weakest:
            weakest = proof
            reason = why
        start = base + stream.offset
        if start + stream.packed > len(data):
            raise NoLine("its data does not lie inside the file")
        taken += [stream.iv.hex(), f"{stream.packed:x}", f"{stream.unpacked:x}", show_chain(stream.chain), data[start : start + take].hex()]

    # a line that does not rest on the CRC-32 does not carry it: hashcat tests what the line holds
    crc = f"{plan.crc:08x}" if plan.crc is not None and weakest == PROOF_CRC else ""

    if weakest == PROOF_HEADER:
        crc = "header"
    elif weakest == PROOF_END:
        notes.append(f"note: {plan.what}: {reason}, so the line tests that the stream unpacks to its size and ends there")
    elif weakest == PROOF_START:
        notes.append(f"note: {plan.what}: {reason}, so the line tests that the start of the stream unpacks without an error")

    return "$7z$*" + "*".join([str(first.power), first.salt.hex(), crc, f"{plan.crc_len:x}", show_chain(plan.join), str(len(plan.streams)), *taken]) + "$/7z$"


def unpack_header(data: bytes, base: int, streams: Streams) -> bytes:
    """Unpack a header that is stored packed and not encrypted."""
    if len(streams.folders) != 1:
        raise SevenZipError("packed header with more than one folder")
    folder = streams.folders[0]
    found, join = resolve_plain(folder, streams)
    size = final_size(folder)
    if size > MAX_HEADER_SIZE:
        raise SevenZipError("header of an impossible size")
    start = base + found[0]
    raw = data[start : start + found[1]]
    if len(raw) != found[1]:
        raise SevenZipError("packed header does not lie inside the file")

    if join is None:
        plain = raw[:size]
    else:
        ident, props = join
        if ident == ID_LZMA:
            if len(props) != 5 or props[0] >= 9 * 5 * 5:
                raise SevenZipError("packed header with damaged LZMA properties")
            d = props[0]
            spec = {"id": lzma.FILTER_LZMA1, "lc": d % 9, "lp": (d // 9) % 5, "pb": d // 45, "dict_size": max(struct.unpack("<I", props[1:5])[0], 4096)}
        else:
            if len(props) != 1 or props[0] > 40:
                raise SevenZipError("packed header with damaged LZMA2 properties")
            spec = {"id": lzma.FILTER_LZMA2, "dict_size": 0xFFFFFFFF if props[0] == 40 else (2 | (props[0] & 1)) << (props[0] // 2 + 11)}
        try:
            plain = lzma.LZMADecompressor(format=lzma.FORMAT_RAW, filters=[spec]).decompress(raw, size)
        except lzma.LZMAError as error:
            raise SevenZipError("packed header does not unpack") from error

    if len(plain) != size or (folder.crc is not None and zlib.crc32(plain) != folder.crc):
        raise SevenZipError("packed header does not unpack")
    return plain


def resolve_plain(folder: Folder, streams: Streams) -> tuple[tuple[int, int], tuple[bytes, bytes] | None]:
    """Where a header that is packed and not encrypted lies, and the coder that packed it."""
    if len(folder.coders) != 1 or len(folder.packed) != 1:
        raise SevenZipError("packed header with an unsupported layout")
    coder = folder.coders[0]
    offset = streams.pack_pos + sum(streams.pack_sizes[: folder.first_pack])
    where = (offset, streams.pack_sizes[folder.first_pack])
    if coder.ident == ID_COPY:
        return where, None
    if coder.ident in (ID_LZMA, ID_LZMA2):
        return where, (coder.ident, coder.props)
    raise SevenZipError(f"packed header uses the coder {coder.ident.hex()}")


def read_names(reader: Reader, streams: Streams) -> None:
    """Read the file names of a header and give each folder the names of its files."""
    files = reader.count(MAX_FOLDERS * 16)
    empty = [False] * files
    names: list[str] = []

    while True:
        ident = reader.byte()
        if ident == K_END:
            break
        size = reader.count(MAX_HEADER_SIZE)
        body = Reader(reader.take(size))
        if ident == K_EMPTY_STREAM:
            empty = body.bits(files)
        elif ident == K_NAMES:
            if body.byte() != 0:
                continue
            text = body.data[body.pos :].decode("utf-16-le", "replace")
            names = text.split("\x00")[:files]

    with_data = [name for name, flag in zip(names, empty) if not flag]
    position = 0
    for folder in streams.folders:
        count = len(folder.sub_sizes)
        folder.names = with_data[position : position + count]
        position += count


def parse(data: bytes) -> tuple[int, Streams, bool]:
    """Read an archive. Returns where it starts, its streams and whether its header is encrypted."""
    start = data.find(SIGNATURE, 0, SIGNATURE_SEARCH)
    while start >= 0:
        head = data[start : start + 32]
        if len(head) == 32 and zlib.crc32(head[12:32]) == struct.unpack_from("<I", head, 8)[0]:
            break
        start = data.find(SIGNATURE, start + 1, SIGNATURE_SEARCH)
    if start < 0:
        raise SevenZipError("not a 7z archive")

    offset, size, crc = struct.unpack_from("<QQI", data, start + 12)
    base = start + 32

    if size == 0:
        return base, Streams(), False
    if size > MAX_HEADER_SIZE or base + offset + size > len(data):
        raise SevenZipError("its header does not lie inside the file: a volume of a split archive, or a file that is cut short")

    header = data[base + offset : base + offset + size]
    if zlib.crc32(header) != crc:
        raise SevenZipError("its header is damaged")

    for _ in range(4):
        reader = Reader(header)
        ident = reader.byte()

        if ident == K_ENCODED_HEADER:
            streams = read_streams(reader)
            if any(is_encrypted(folder) for folder in streams.folders):
                return base, streams, True
            header = unpack_header(data, base, streams)
            continue

        if ident != K_HEADER:
            raise SevenZipError("its header starts with an unknown field")

        streams = Streams()
        while True:
            part = reader.byte()
            if part == K_END:
                break
            if part == K_ARCHIVE_PROPERTIES:
                while reader.byte() != K_END:
                    reader.take(reader.count(MAX_HEADER_SIZE))
            elif part == K_ADDITIONAL_STREAMS_INFO:
                read_streams(reader)
            elif part == K_MAIN_STREAMS_INFO:
                streams = read_streams(reader)
            elif part == K_FILES_INFO:
                try:
                    read_names(reader, streams)
                except SevenZipError:
                    pass
                break
            else:
                raise SevenZipError("its header holds an unknown field")
        return base, streams, False

    raise SevenZipError("its header is packed too many times")


def order(plan: Plan) -> tuple[int, int, int, int]:
    """Rank a folder, best first."""
    if plan.crc is not None and plan.crc_len >= FULL_CRC_BYTES:
        tier = 0
    elif plan.crc is None:
        tier = 1
    else:
        tier = 2
    return (
        tier,
        len(plan.streams),
        plan.crc_len,
        sum(stream.packed for stream in plan.streams),
    )


def hashes_of(data: bytes, all_hashes: bool, notes: list[str]) -> list[str]:
    """Return the hash lines of an archive. What a line cannot prove, and why one is missing, goes to notes."""
    base, streams, header_encrypted = parse(data)

    lines: list[str] = []
    plans: list[Plan] = []

    for number, folder in enumerate(streams.folders):
        if not is_encrypted(folder):
            continue
        if header_encrypted:
            what = "the header"
        else:
            what = f"folder {number}" + (f" ({folder.names[0]})" if folder.names else "")
        try:
            plan = plan_folder(folder, streams, what)
            plan.header = header_encrypted
            plans.append(plan)
        except NoLine as reason:
            notes.append(f"no hash: {what}: {reason}")

    plans.sort(key=order)

    for plan in plans:
        try:
            line = line_of(data, base, plan, notes)
        except NoLine as reason:
            notes.append(f"no hash: {plan.what}: {reason}")
            continue
        if line not in lines:
            lines.append(line)
        if not all_hashes:
            break

    return lines


def main() -> int:
    """Write the hash lines of every archive named on the command line."""
    parser = argparse.ArgumentParser(description="Write the hashcat lines of password protected 7z archives, for mode 46900.")
    parser.add_argument(
        "archives",
        metavar="ARCHIVE",
        nargs="+",
        help="a 7z archive, or a self-extracting one",
    )
    parser.add_argument(
        "-a",
        "--all-hashes",
        action="store_true",
        help="write a line for every encrypted folder, not only for the best one",
    )
    parser.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="do not say on stderr what a line cannot prove or why a folder has none",
    )
    args = parser.parse_args()

    status = 0

    for path in args.archives:
        notes: list[str] = []
        try:
            with open(path, "rb") as handle:
                data = handle.read()
            lines = hashes_of(data, args.all_hashes, notes)
        except (OSError, SevenZipError) as error:
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
