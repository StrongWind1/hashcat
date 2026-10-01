#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

# WPA-PBKDF2-PMKID+EAPOL. Six type codes:
#
#   01  WPA2-PSK-PMKID       HMAC-SHA1 PMKID
#   02  WPA1/WPA2-PSK-EAPOL  keyver-driven MIC (1=MD5, 2=SHA1, 3=CMAC)
#   03  PSK-SHA256-PMKID     HMAC-SHA256 PMKID
#   04  PSK-SHA256-EAPOL     KDF-SHA256 PTK, AES-128-CMAC MIC
#   05  FT-PSK-PMKID         SHA-256 FT chain -> PMKR1Name
#   06  FT-PSK-EAPOL         SHA-256 FT chain -> AES-128-CMAC MIC
#
# All types share PBKDF2-HMAC-SHA1 (4096 iterations) for PMK derivation.

import hashlib
import hmac
import struct

from Crypto.Hash import CMAC
from Crypto.Cipher import AES

from lib.test_helpers import random_number, random_bytes

FT_TYPES = frozenset({5, 6})
PMKID_TYPES = frozenset({1, 3, 5})
EAPOL_TYPES = frozenset({2, 4, 6})


def module_constraints():
    return [[8, 63], [-1, -1], [-1, -1], [-1, -1], [-1, -1]]


# --- crypto primitives --------------------------------------------------------


def _pmk(word, essid_bin):
    return hashlib.pbkdf2_hmac("sha1", word, essid_bin, 4096, 32)


def _sorted_pair(a, b):
    return a + b if a < b else b + a


def _prf_sha1(pmk, ctx, nbytes):
    out = bytearray()
    i = 0
    while len(out) < nbytes:
        out += hmac.new(
            pmk, b"Pairwise key expansion\x00" + ctx + bytes([i]), hashlib.sha1
        ).digest()
        i += 1
    return bytes(out[:nbytes])


def _kdf_sha256(key, label, context, n_bits):
    n_bytes = n_bits // 8
    out = bytearray()
    counter = 1
    while len(out) < n_bytes:
        msg = (
            counter.to_bytes(2, "little")
            + label.encode("ascii")
            + context
            + n_bits.to_bytes(2, "little")
        )
        out += hmac.new(key, msg, hashlib.sha256).digest()
        counter += 1
    return bytes(out[:n_bytes])


def _mic_cmac(kck16, frame):
    c = CMAC.new(kck16, ciphermod=AES)
    c.update(frame)
    return c.digest()[:16]


def _ft_chain(pmk, ssid, mdid, r0kh, r1kh, sta):
    ctx_r0 = bytes([len(ssid)]) + ssid + mdid + bytes([len(r0kh)]) + r0kh + sta
    r0_full = _kdf_sha256(pmk, "FT-R0", ctx_r0, 384)
    pmk_r0 = r0_full[:32]
    salt = r0_full[32:48]
    pmk_r0_name = hashlib.sha256(b"FT-R0N" + salt).digest()[:16]
    pmk_r1 = _kdf_sha256(pmk_r0, "FT-R1", r1kh + sta, 256)
    pmk_r1_name = hashlib.sha256(b"FT-R1N" + pmk_r0_name + r1kh + sta).digest()[:16]
    return pmk_r1, pmk_r1_name


# --- EAPOL frame generation --------------------------------------------------


def _gen_random_wpa_eapol(keyver, snonce):
    ret = b""

    ret += struct.pack("B", 1)  # version: 802.1X-2001
    ret += struct.pack("B", 3)  # type: key information

    length = 119 if keyver == 1 else 117
    ret += struct.pack(">H", length)

    descriptor_type = 254 if keyver == 1 else 1
    ret += struct.pack("B", descriptor_type)

    key_info = 0
    key_info |= 1 << 8  # key MIC
    key_info |= 1 << 3  # pairwise key

    if keyver == 1:
        key_info |= 1
    elif keyver == 2:
        key_info |= 2
    elif keyver == 3:
        key_info |= 3

    ret += struct.pack(">H", key_info)

    key_length = 32 if keyver == 1 else 0
    ret += struct.pack(">H", key_length)

    ret += struct.pack(">Q", 1)  # replay counter

    ret += snonce
    ret += b"\x00" * 16  # key IV
    ret += b"\x00" * 8  # key RSC
    ret += b"\x00" * 8  # key ID
    ret += b"\x00" * 16  # key MIC

    key_data_len = 24 if keyver == 1 else 22
    ret += struct.pack(">H", key_data_len)

    if keyver == 1:
        # WPA info, vendor specific tag
        key_data = b""
        key_data += struct.pack("B", 221)  # vendor specific tag
        key_data += struct.pack("B", 22)  # tag length
        key_data += bytes.fromhex("0050f2")  # microsoft OUI
        key_data += struct.pack("B", 1)  # WPA Information Element
        key_data += struct.pack("<H", 1)  # WPA version
        key_data += bytes.fromhex("0050f2")
        key_data += struct.pack("B", 2)  # multicast TKIP
        key_data += struct.pack("<H", 1)  # unicast count
        key_data += bytes.fromhex("0050f2")
        key_data += struct.pack("B", 2)  # unicast TKIP
        key_data += struct.pack("<H", 1)  # AKM count
        key_data += bytes.fromhex("0050f2")
        key_data += struct.pack("B", 2)  # AKM PSK
    else:
        # RSN info
        key_data = b""
        key_data += struct.pack("B", 48)  # RSN info tag
        key_data += struct.pack("B", 20)  # tag length
        key_data += struct.pack("<H", 1)  # RSN version
        key_data += bytes.fromhex("000fac")
        key_data += struct.pack("B", 4)  # group cipher AES (CCM)
        key_data += struct.pack("<H", 1)  # pairwise count
        key_data += bytes.fromhex("000fac")
        key_data += struct.pack("B", 4)  # pairwise AES (CCM)
        key_data += struct.pack("<H", 1)  # AKM count
        key_data += bytes.fromhex("000fac")
        key_data += struct.pack("B", 2)  # AKM PSK
        key_data += bytes.fromhex("0000")  # RSN capabilities

    ret += key_data

    return ret


# --- hash generation ----------------------------------------------------------


def module_generate_hash(
    word,
    salt=None,
    type=None,
    macap=None,
    macsta=None,
    essid=None,
    anonce=None,
    eapol=None,
    mp=None,
    mdid=None,
    r0kh=None,
    r1kh=None,
):
    if type is None:
        type = random_number(1, 6)
    else:
        type = int(type)

    # --- type 01: PMKID HMAC-SHA1 (unchanged from original) ---

    if type == 1:
        if macap is None:
            macap = random_bytes(6).hex()
        if macsta is None:
            macsta = random_bytes(6).hex()
        if essid is None:
            essid = random_bytes(random_number(0, 32) & 0x1E).hex()

        essid_bin = bytes.fromhex(essid)

        pmk = _pmk(word, essid_bin)

        data = b"PMK Name" + bytes.fromhex(macap) + bytes.fromhex(macsta)

        pmkid = hmac.new(pmk, data, hashlib.sha1).hexdigest()

        return "WPA*%02x*%s*%s*%s*%s***" % (type, pmkid[:32], macap, macsta, essid)

    # --- type 02: EAPOL keyver-driven MIC (unchanged from original) ---

    if type == 2:
        if macap is None:
            macap = random_bytes(6)
        else:
            macap = bytes.fromhex(macap)

        if macsta is None:
            macsta = random_bytes(6)
        else:
            macsta = bytes.fromhex(macsta)

        if mp is None:
            mp = b"\x00"
        else:
            mp = bytes.fromhex(mp)

        if eapol is None:
            keyver = random_number(1, 3)
            snonce = random_bytes(32)
            eapol = _gen_random_wpa_eapol(keyver, snonce)
        else:
            eapol = bytes.fromhex(eapol)
            key_info = struct.unpack(">H", eapol[5:7])[0]
            keyver = key_info & 3
            snonce = eapol[17:49]

        if anonce is None:
            anonce = random_bytes(32)
        else:
            anonce = bytes.fromhex(anonce)

        if essid is None:
            essid = random_bytes(random_number(0, 32) & 0x1E).hex()

        essid_bin = bytes.fromhex(essid)

        pmk = _pmk(word, essid_bin)

        ctx = _sorted_pair(macap, macsta) + _sorted_pair(snonce, anonce)

        if keyver in (1, 2):
            ptk = _prf_sha1(pmk, ctx, 48)[:16]
        else:
            ptk = _kdf_sha256(pmk, "Pairwise key expansion", ctx, 384)[:16]

        if keyver == 1:
            mic = hmac.new(ptk, eapol, hashlib.md5).digest()
        elif keyver == 2:
            mic = hmac.new(ptk, eapol, hashlib.sha1).digest()
        elif keyver == 3:
            mic = _mic_cmac(ptk, eapol)

        mic = mic[:16]

        return "WPA*%02x*%s*%s*%s*%s*%s*%s*%s" % (
            type,
            mic.hex(),
            macap.hex(),
            macsta.hex(),
            essid,
            anonce.hex(),
            eapol.hex(),
            mp.hex(),
        )

    # --- type 03: PSK-SHA256-PMKID ---

    if type == 3:
        if macap is None:
            macap = random_bytes(6).hex()
        if macsta is None:
            macsta = random_bytes(6).hex()
        if essid is None:
            essid = random_bytes(random_number(0, 32) & 0x1E).hex()

        essid_bin = bytes.fromhex(essid)

        pmk = _pmk(word, essid_bin)

        data = b"PMK Name" + bytes.fromhex(macap) + bytes.fromhex(macsta)

        pmkid = hmac.new(pmk, data, hashlib.sha256).hexdigest()

        return "WPA*%02x*%s*%s*%s*%s***" % (type, pmkid[:32], macap, macsta, essid)

    # --- type 04: PSK-SHA256-EAPOL (KDF-SHA256 PTK, AES-128-CMAC MIC) ---

    if type == 4:
        if macap is None:
            macap = random_bytes(6)
        else:
            macap = bytes.fromhex(macap)

        if macsta is None:
            macsta = random_bytes(6)
        else:
            macsta = bytes.fromhex(macsta)

        if mp is None:
            mp = b"\x00"
        else:
            mp = bytes.fromhex(mp)

        if eapol is None:
            snonce = random_bytes(32)
            eapol = _gen_random_wpa_eapol(3, snonce)
        else:
            eapol = bytes.fromhex(eapol)
            snonce = eapol[17:49]

        if anonce is None:
            anonce = random_bytes(32)
        else:
            anonce = bytes.fromhex(anonce)

        if essid is None:
            essid = random_bytes(random_number(0, 32) & 0x1E).hex()

        essid_bin = bytes.fromhex(essid)

        pmk = _pmk(word, essid_bin)

        ctx = _sorted_pair(macap, macsta) + _sorted_pair(snonce, anonce)

        ptk = _kdf_sha256(pmk, "Pairwise key expansion", ctx, 384)[:16]

        mic = _mic_cmac(ptk, eapol)

        return "WPA*%02x*%s*%s*%s*%s*%s*%s*%s" % (
            type,
            mic.hex(),
            macap.hex(),
            macsta.hex(),
            essid,
            anonce.hex(),
            eapol.hex(),
            mp.hex(),
        )

    # --- type 05: FT-PSK-PMKID (SHA-256 FT chain -> PMKR1Name) ---

    if type == 5:
        if macap is None:
            macap = random_bytes(6).hex()
        if macsta is None:
            macsta = random_bytes(6).hex()
        if essid is None:
            essid = random_bytes(random_number(0, 32) & 0x1E).hex()
        if mdid is None:
            mdid = random_bytes(2).hex()
        if r0kh is None:
            r0kh = random_bytes(random_number(1, 48)).hex()
        if r1kh is None:
            r1kh = random_bytes(6).hex()

        essid_bin = bytes.fromhex(essid)

        pmk = _pmk(word, essid_bin)

        _, pmk_r1_name = _ft_chain(
            pmk,
            essid_bin,
            bytes.fromhex(mdid),
            bytes.fromhex(r0kh),
            bytes.fromhex(r1kh),
            bytes.fromhex(macsta),
        )

        return "WPA*%02x*%s*%s*%s*%s***%s*%s*%s*%s" % (
            type,
            pmk_r1_name.hex(),
            macap,
            macsta,
            essid,
            "20",
            mdid,
            r0kh,
            r1kh,
        )

    # --- type 06: FT-PSK-EAPOL (SHA-256 FT chain -> AES-128-CMAC MIC) ---

    if type == 6:
        if macap is None:
            macap = random_bytes(6)
        else:
            macap = bytes.fromhex(macap)

        if macsta is None:
            macsta = random_bytes(6)
        else:
            macsta = bytes.fromhex(macsta)

        if mp is None:
            mp = b"\x00"
        else:
            mp = bytes.fromhex(mp)

        if eapol is None:
            snonce = random_bytes(32)
            eapol = _gen_random_wpa_eapol(3, snonce)
        else:
            eapol = bytes.fromhex(eapol)
            snonce = eapol[17:49]

        if anonce is None:
            anonce = random_bytes(32)
        else:
            anonce = bytes.fromhex(anonce)

        if essid is None:
            essid = random_bytes(random_number(0, 32) & 0x1E).hex()
        if mdid is None:
            mdid = random_bytes(2).hex()
        if r0kh is None:
            r0kh = random_bytes(random_number(1, 48)).hex()
        if r1kh is None:
            r1kh = random_bytes(6).hex()

        essid_bin = bytes.fromhex(essid)

        pmk = _pmk(word, essid_bin)

        mdid_bin = bytes.fromhex(mdid)
        r0kh_bin = bytes.fromhex(r0kh)
        r1kh_bin = bytes.fromhex(r1kh)

        pmk_r1, _ = _ft_chain(pmk, essid_bin, mdid_bin, r0kh_bin, r1kh_bin, macsta)

        mp_int = mp[0] if isinstance(mp, bytes) else int(mp, 16)
        snonce_ptk = anonce if (mp_int & 0x10) else snonce
        anonce_ptk = snonce if (mp_int & 0x10) else anonce
        ctx = snonce_ptk + anonce_ptk + macap + macsta
        ft_ptk = _kdf_sha256(pmk_r1, "FT-PTK", ctx, 384)[:16]

        mic = _mic_cmac(ft_ptk, eapol)

        return "WPA*%02x*%s*%s*%s*%s*%s*%s*%s*%s*%s*%s" % (
            type,
            mic.hex(),
            macap.hex(),
            macsta.hex(),
            essid,
            anonce.hex(),
            eapol.hex(),
            mp.hex(),
            mdid,
            r0kh,
            r1kh,
        )

    return None


# --- verification -------------------------------------------------------------


def module_verify_hash(line):
    idx1 = line.find(b":")

    if idx1 < 1:
        return None

    word = line[idx1 + 1 :]
    hash_in = line[:idx1].decode(errors="replace")

    data = hash_in.split("*")

    if len(data) < 6:
        return None

    signature = data[0]
    type = data[1]
    macap = data[3]
    macsta = data[4]
    essid = data[5]
    anonce = data[6] if len(data) > 6 else None
    eapol = data[7] if len(data) > 7 else None
    mp = data[8] if len(data) > 8 else None

    mdid = data[9] if len(data) > 9 else None
    r0kh = data[10] if len(data) > 10 else None
    r1kh = data[11] if len(data) > 11 else None

    if signature != "WPA":
        return None

    # PMKID records carry empty trailing fields, so treat those as absent
    anonce = anonce or None
    eapol = eapol or None
    mp = mp or None

    new_hash = module_generate_hash(
        word, None, type, macap, macsta, essid, anonce, eapol, mp, mdid, r0kh, r1kh
    )

    return (new_hash, word)
