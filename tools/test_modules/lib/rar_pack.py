##
## Author......: See docs/credits.txt
## License.....: MIT
##

# Packers for the RAR test modules: they turn a plaintext into a stream the RAR 2.0, RAR 3.x and
# RAR 5.x decompressors unpack back to it. Nothing is compressed. Every byte is written as a
# literal under a fixed Huffman code, which is all a test needs to send a candidate through the
# decompressor of a module instead of only through its stored path.
#
# All three formats describe a Huffman code by the bit length of each symbol, assign the codes in
# order of length and then of symbol, and read them most significant bit first. The lengths are
# themselves sent under a small code of 19 or 20 symbols, where a symbol below 16 is a length.
# That small code is given 4 bits for each of the symbols 0 to 15 here, so a length goes out as
# its own value in 4 bits and the run length symbols are never needed.


# The stream layouts written here are those the decompressors of UnRAR 7.3.2 read (unpack15.cpp,
# unpack20.cpp, unpack30.cpp and unpack50.cpp). The packers exist to test hashcat's unpacking and
# write literals only.
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


class BitWriter:
    def __init__(self):
        self.bits = []

    def put(self, value, count):
        for shift in range(count - 1, -1, -1):
            self.bits.append((value >> shift) & 1)

    def align(self):
        while len(self.bits) % 8 != 0:
            self.bits.append(0)

    def bit_count(self):
        return len(self.bits)

    def to_bytes(self):
        padded = self.bits + [0] * (-len(self.bits) % 8)
        out = bytearray()
        for pos in range(0, len(padded), 8):
            byte = 0
            for bit in padded[pos : pos + 8]:
                byte = (byte << 1) | bit
            out.append(byte)
        return bytes(out)


def canonical_codes(lengths):
    # returns {symbol: (code, length)} for the symbols with a length
    codes = {}
    code = 0
    for length in range(1, 16):
        for symbol, symbol_length in enumerate(lengths):
            if symbol_length == length:
                codes[symbol] = (code, length)
                code += 1
        code <<= 1
    return codes


def _literal_lengths(table_size, with_end):
    # A complete code over the 256 literals. With the end of block symbol 256 in it, four symbols
    # move to 9 bits to make room: 254, 255, 256 and 257, the last of which is never written.
    lengths = [0] * table_size
    for symbol in range(256):
        lengths[symbol] = 8
    if with_end:
        for symbol in (254, 255, 256, 257):
            lengths[symbol] = 9
    return lengths


def _put_lengths(writer, lengths):
    for length in lengths:
        writer.put(length, 4)


def pack20(data):
    # RAR 2.0, one block: no audio, no old tables, then the tables and the literals. The unpacker
    # stops at the unpacked size, so nothing marks the end.
    table_size = 298 + 48 + 28
    lengths = _literal_lengths(table_size, False)
    codes = canonical_codes(lengths)
    writer = BitWriter()
    writer.put(0, 2)
    _put_lengths(writer, [4] * 16 + [0] * 3)
    _put_lengths(writer, lengths)
    for byte in data:
        writer.put(*codes[byte])
    # the unpacker reads ahead of what it decodes
    return writer.to_bytes() + bytes(32)


def pack29(data):
    # RAR 3.x, one LZ block: not PPMd, no old tables, the tables, the literals, then the end of
    # block symbol saying that the file ends here.
    table_size = 299 + 60 + 17 + 28
    lengths = _literal_lengths(table_size, True)
    codes = canonical_codes(lengths)
    writer = BitWriter()
    writer.put(0, 2)
    _put_lengths(writer, [4] * 16 + [0] * 4)
    _put_lengths(writer, lengths)
    for byte in data:
        writer.put(*codes[byte])
    writer.put(*codes[256])
    writer.put(0, 2)
    return writer.to_bytes() + bytes(8)


def pack50(data):
    # RAR 5.x, one block, the last one, with tables. Its header: a flags byte (bits 0 to 2 the
    # number of bits used in the last byte less one, bits 3 and 4 the size of the size field less
    # one, bit 6 last block, bit 7 tables present), a checksum byte, then the block size in bytes.
    table_size = 306 + 64 + 16 + 44
    lengths = _literal_lengths(table_size, False)
    codes = canonical_codes(lengths)
    writer = BitWriter()
    _put_lengths(writer, [4] * 16 + [0] * 4)
    _put_lengths(writer, lengths)
    for byte in data:
        writer.put(*codes[byte])
    block = writer.to_bytes()
    last_bits = writer.bit_count() % 8
    if last_bits == 0:
        last_bits = 8
    size = len(block).to_bytes(3, "little")
    flags = (last_bits - 1) | (2 << 3) | 0x40 | 0x80
    checksum = 0x5A ^ flags ^ size[0] ^ size[1] ^ size[2]
    return bytes([flags, checksum]) + size + block


def _read_literals(packed, first_bit, lengths, size):
    # the literals behind the tables, or None where the stream holds something else
    by_code = {code: symbol for symbol, code in canonical_codes(lengths).items()}
    out = bytearray()
    pos = first_bit
    while len(out) < size:
        code = 0
        length = 0
        symbol = None
        while length < 9:
            if pos >= len(packed) * 8:
                return None
            code = (code << 1) | ((packed[pos // 8] >> (7 - (pos % 8))) & 1)
            pos += 1
            length += 1
            symbol = by_code.get((code, length))
            if symbol is not None:
                break
        if symbol is None or symbol > 255:
            return None
        out.append(symbol)
    return bytes(out)


def _unpack(packer, packed, first_bit, lengths, size):
    # Only what the packer above wrote is read back: the literals are decoded, and packing them
    # again has to give the stream that came in, any padding behind it aside.
    plain = _read_literals(packed, first_bit, lengths, size)
    if plain is None:
        return None
    again = packer(plain)
    if packed[: len(again)] != again:
        return None
    return plain


def unpack20(packed, size):
    return _unpack(
        pack20, packed, 2 + 19 * 4 + 374 * 4, _literal_lengths(374, False), size
    )


def unpack29(packed, size):
    return _unpack(
        pack29, packed, 2 + 20 * 4 + 404 * 4, _literal_lengths(404, True), size
    )


def unpack50(packed, size):
    return _unpack(
        pack50, packed, 5 * 8 + 20 * 4 + 430 * 4, _literal_lengths(430, False), size
    )


# RAR 1.5 has no tables in the stream. Its unpacker keeps the byte values in a list that it
# reorders as it goes and reads the position of the next byte under one of five fixed codes, picked
# by a running average of the positions seen. A packer therefore has to keep the same state and
# take the same steps the unpacker will. This one writes literals only: every flag byte it sends
# is 0xff, which reads as "a literal follows" eight times over.

_DEC_HF0 = [0x8000, 0xC000, 0xE000, 0xF200, 0xF200, 0xF200, 0xF200, 0xF200, 0xFFFF]
_POS_HF0 = [0, 0, 0, 0, 0, 8, 16, 24, 33, 33, 33, 33, 33]
_DEC_HF1 = [0x2000, 0xC000, 0xE000, 0xF000, 0xF200, 0xF200, 0xF7E0, 0xFFFF]
_POS_HF1 = [0, 0, 0, 0, 0, 0, 4, 44, 60, 76, 80, 80, 127]
_DEC_HF2 = [0x1000, 0x2400, 0x8000, 0xC000, 0xFA00, 0xFFFF, 0xFFFF, 0xFFFF]
_POS_HF2 = [0, 0, 0, 0, 0, 0, 2, 7, 53, 117, 233, 0, 0]
_DEC_HF3 = [0x0800, 0x2400, 0xEE00, 0xFE80, 0xFFFF, 0xFFFF, 0xFFFF]
_POS_HF3 = [0, 0, 0, 0, 0, 0, 0, 2, 16, 218, 251, 0, 0]
_DEC_HF4 = [0xFF00, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF]
_POS_HF4 = [0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 0, 0, 0]


def _put_num15(writer, value, start_pos, dec_tab, pos_tab):
    # the reverse of the unpacker's DecodeNum; False where this code has no word for the value
    base = 0
    for index, limit in enumerate(dec_tab):
        length = start_pos + index
        count = (min(limit, 0xFFF0 + (1 << (16 - length))) - base) >> (16 - length)
        if pos_tab[length] <= value < pos_tab[length] + count:
            word = base + ((value - pos_tab[length]) << (16 - length))
            if word > 0xFFF0 or (word & 0xFFF0) < base or (limit <= (word & 0xFFF0)):
                return False
            writer.put(word >> (16 - length), length)
            return True
        base = limit
    return False


def _corr_huff15(char_set, num_to_place):
    pos = 0
    for n in range(8):
        for _ in range(32):
            char_set[pos] = (char_set[pos] & 0xFF00) | (7 - n)
            pos += 1
    for rank in range(256):
        num_to_place[rank] = (7 - rank) * 32 if rank < 7 else 0


class _Pack15:
    def __init__(self):
        self.writer = BitWriter()
        self.ch_set = [i << 8 for i in range(256)]
        self.ch_set_c = [((0 - i) & 0xFF) << 8 for i in range(256)]
        self.n_to_pl = [0] * 256
        self.n_to_pl_c = [0] * 256
        self.avr_plc = 0x3500
        self.nhfb = 0x80
        self.num_huf = 0
        self.st_mode = False
        self.flags_cnt = 0

    def put_flags(self):
        # a flag byte of 0xff, wherever the unpacker's list has it by now
        place = next(i for i, entry in enumerate(self.ch_set_c) if (entry >> 8) == 0xFF)
        if not _put_num15(self.writer, place, 5, _DEC_HF2, _POS_HF2):
            return False
        while True:
            flags = self.ch_set_c[place]
            new_place = self.n_to_pl_c[flags & 0xFF]
            self.n_to_pl_c[flags & 0xFF] = (new_place + 1) & 0xFF
            flags = (flags + 1) & 0xFFFF
            if (flags & 0xFF) != 0:
                break
            _corr_huff15(self.ch_set_c, self.n_to_pl_c)
        self.ch_set_c[place] = self.ch_set_c[new_place]
        self.ch_set_c[new_place] = flags
        return True

    def put_place(self, place):
        if self.avr_plc > 0x75FF:
            return _put_num15(self.writer, place, 8, _DEC_HF4, _POS_HF4)
        if self.avr_plc > 0x5DFF:
            return _put_num15(self.writer, place, 6, _DEC_HF3, _POS_HF3)
        if self.avr_plc > 0x35FF:
            return _put_num15(self.writer, place, 5, _DEC_HF2, _POS_HF2)
        if self.avr_plc > 0x0DFF:
            return _put_num15(self.writer, place, 5, _DEC_HF1, _POS_HF1)
        return _put_num15(self.writer, place, 4, _DEC_HF0, _POS_HF0)

    def put_literal(self, byte):
        index = next(i for i, entry in enumerate(self.ch_set) if (entry >> 8) == byte)
        if self.st_mode and index == 255:
            # Out of reach in this mode, where the position is sent one higher. Position 0 and a
            # set bit leave the mode, and the flag bytes take over again.
            if not self.put_place(0):
                return False
            self.writer.put(1, 1)
            self.num_huf = 0
            self.st_mode = False
        if self.st_mode:
            if not self.put_place(index + 1):
                return False
        else:
            self.flags_cnt -= 1
            if self.flags_cnt < 0:
                if not self.put_flags():
                    return False
                self.flags_cnt = 7
            if not self.put_place(index):
                return False
            if self.num_huf >= 16 and self.flags_cnt == 0:
                self.st_mode = True
            self.num_huf += 1
        self.avr_plc += index
        self.avr_plc -= self.avr_plc >> 8
        self.nhfb += 16
        if self.nhfb > 0xFF:
            self.nhfb = 0x90
        while True:
            cur = self.ch_set[index]
            new_place = self.n_to_pl[cur & 0xFF]
            self.n_to_pl[cur & 0xFF] = (new_place + 1) & 0xFF
            cur = (cur + 1) & 0xFFFF
            if (cur & 0xFF) <= 0xA1:
                break
            _corr_huff15(self.ch_set, self.n_to_pl)
        self.ch_set[index] = self.ch_set[new_place]
        self.ch_set[new_place] = cur
        return True


def pack15(data):
    # RAR 1.5. None where a position has no word in the code in force, which the caller answers
    # with another plaintext.
    packer = _Pack15()
    if len(data) > 0:
        if not packer.put_flags():
            return None
        packer.flags_cnt = 8
    for byte in data:
        if not packer.put_literal(byte):
            return None
    # the unpacker reads ahead of what it decodes
    return packer.writer.to_bytes() + bytes(8)


def _get_num15(packed, pos, start_pos, dec_tab, pos_tab):
    # the unpacker's DecodeNum: returns (value, bits used)
    word = 0
    for offset in range(16):
        bit_pos = pos + offset
        bit = (
            (packed[bit_pos // 8] >> (7 - (bit_pos % 8))) & 1
            if bit_pos < len(packed) * 8
            else 0
        )
        word = (word << 1) | bit
    num = word & 0xFFF0
    length = start_pos
    index = 0
    while dec_tab[index] <= num:
        length += 1
        index += 1
    base = dec_tab[index - 1] if index > 0 else 0
    return ((num - base) >> (16 - length)) + pos_tab[length], length


def unpack15(packed, size):
    # Reads back what pack15 wrote. The positions are decoded while a packer is fed the bytes
    # they stand for, so that its state stays that of the unpacker, and it writes the flag bytes
    # where pack15 did. Packing the result again has to give the stream
    # that came in.
    state = _Pack15()
    if size > 0:
        if not state.put_flags():
            return None
        state.flags_cnt = 8
    out = bytearray()
    while len(out) < size:
        pos = state.writer.bit_count()
        if pos + 16 > len(packed) * 8:
            return None
        if not state.st_mode and state.flags_cnt - 1 < 0:
            # a flag byte comes first, and pack15 only ever sends the one
            probe = _Pack15.__new__(_Pack15)
            probe.__dict__.update(
                {
                    k: (list(v) if isinstance(v, list) else v)
                    for k, v in state.__dict__.items()
                }
            )
            probe.writer = BitWriter()
            if not probe.put_flags():
                return None
            pos += probe.writer.bit_count()
        if state.avr_plc > 0x75FF:
            place, _ = _get_num15(packed, pos, 8, _DEC_HF4, _POS_HF4)
        elif state.avr_plc > 0x5DFF:
            place, _ = _get_num15(packed, pos, 6, _DEC_HF3, _POS_HF3)
        elif state.avr_plc > 0x35FF:
            place, _ = _get_num15(packed, pos, 5, _DEC_HF2, _POS_HF2)
        elif state.avr_plc > 0x0DFF:
            place, _ = _get_num15(packed, pos, 5, _DEC_HF1, _POS_HF1)
        else:
            place, _ = _get_num15(packed, pos, 4, _DEC_HF0, _POS_HF0)
        place &= 0xFF
        if state.st_mode:
            # position 0 leaves the mode, which pack15 does only ahead of the entry at 255
            index = 255 if place == 0 else place - 1
        else:
            index = place
        byte = state.ch_set[index] >> 8
        if not state.put_literal(byte):
            return None
        out.append(byte)
    again = state.writer.to_bytes()
    if packed[: len(again)] != again:
        return None
    return bytes(out)
