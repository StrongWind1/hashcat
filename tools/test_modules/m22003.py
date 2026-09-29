#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

# WPA-PMK Universal mode (22003): PMK-direct input, no PBKDF2.
# The "password" is the 32-byte PMK as a 64-character hex string.
# Hash format is identical to 22002:
# WPA*TT*<hash>*<ap>*<sta>*<essid>*<anonce>*<eapol>*<mp>[*<mdid>*<r0kh>*<r1kh>]

import hashlib
import hmac
import struct

from cryptography.hazmat.primitives.ciphers import algorithms
from cryptography.hazmat.primitives.cmac import CMAC
from lib.test_helpers import random_bytes, random_number

TYPE_FAMILY = {
    1: "sha1",
    2: "sha1",
    3: "sha1",
    4: "sha256",
    5: "sha256",
    6: "sha256",
    7: "sha256",
    8: "sha384",
    9: "sha384",
    10: "sha384",
    11: "sha384",
}

FT_TYPES = frozenset({6, 7, 10, 11})
PMKID_TYPES = frozenset({2, 4, 6, 8, 10})
EAPOL_TYPES = frozenset({1, 3, 5, 7, 9, 11})

FRAME_NONCE_OFF = 17
FRAME_NONCE_LEN = 32


def module_constraints():
    return [[64, 64], [-1, -1], [-1, -1], [-1, -1], [-1, -1]]


# --- crypto primitives -------------------------------------------------------


def sorted_pair(a, b):
    return a + b if a < b else b + a


def prf_sha1(pmk, ctx, nbytes):
    out = bytearray()
    i = 0
    while len(out) < nbytes:
        out += hmac.new(
            pmk, b"Pairwise key expansion\x00" + ctx + bytes([i]), hashlib.sha1
        ).digest()
        i += 1
    return bytes(out[:nbytes])


def kdf_hash(key, label, context, n_bits, hash_name):
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
        out += hmac.new(key, msg, hash_name).digest()
        counter += 1
    return bytes(out[:n_bytes])


def pmkid_hmac(pmk, ap, sta, hash_name):
    return hmac.new(pmk, b"PMK Name" + ap + sta, hash_name).digest()[:16]


def mic_hmac(kck, frame, hash_name, out_len):
    return hmac.new(kck, frame, hash_name).digest()[:out_len]


def mic_cmac(kck16, frame):
    c = CMAC(algorithms.AES(kck16))
    c.update(frame)
    return c.finalize()[:16]


def kck_len(t):
    return 24 if TYPE_FAMILY[t] == "sha384" else 16


def mic_len(t):
    return 24 if t in (9, 11) else 16


def ft_chain(family, pmk, ssid, mdid, r0kh, r1kh, sta):
    hfn = {"sha256": hashlib.sha256, "sha384": hashlib.sha384}[family]
    r0_bits = 384 if family == "sha256" else 512
    r1_bits = 256 if family == "sha256" else 384
    r0_len = r0_bits // 8 - 16
    ctx_r0 = bytes([len(ssid)]) + ssid + mdid + bytes([len(r0kh)]) + r0kh + sta
    r0_full = kdf_hash(pmk, "FT-R0", ctx_r0, r0_bits, family)
    pmk_r0, salt = r0_full[:r0_len], r0_full[r0_len : r0_len + 16]
    pmk_r0_name = hfn(b"FT-R0N" + salt).digest()[:16]
    pmk_r1 = kdf_hash(pmk_r0, "FT-R1", r1kh + sta, r1_bits, family)
    pmk_r1_name = hfn(b"FT-R1N" + pmk_r0_name + r1kh + sta).digest()[:16]
    return pmk_r1, pmk_r1_name


def ptk_kck(t, pmk, ap, sta, ext_nonce, frame_nonce):
    ctx = sorted_pair(ap, sta) + sorted_pair(ext_nonce, frame_nonce)
    if t in (1, 3):
        return prf_sha1(pmk, ctx, 48)[:16]
    if t == 5:
        return kdf_hash(pmk, "Pairwise key expansion", ctx, 384, "sha256")[:16]
    if t == 9:
        return kdf_hash(pmk, "Pairwise key expansion", ctx, 704, "sha384")[:24]
    raise ValueError(f"type {t} not a non-FT EAPOL type")


def ft_ptk_kck(t, pmk_r1, ap, sta, ext_nonce, frame_nonce, mp):
    snonce = ext_nonce if (mp & 0x10) else frame_nonce
    anonce = frame_nonce if (mp & 0x10) else ext_nonce
    ctx = snonce + anonce + ap + sta
    family = TYPE_FAMILY[t]
    bits = 384 if family == "sha256" else 704
    return kdf_hash(pmk_r1, "FT-PTK", ctx, bits, family)[: kck_len(t)]


def compute_hash_value(t, pmk, essid, ap, sta, ext_nonce, frame, mp, mdid, r0kh, r1kh):
    family = TYPE_FAMILY[t]

    if t in (2, 4, 8):
        return pmkid_hmac(pmk, ap, sta, family)

    if t in (6, 10):
        _, r1_name = ft_chain(family, pmk, essid, mdid, r0kh, r1kh, sta)
        return r1_name

    frame_nonce = frame[FRAME_NONCE_OFF : FRAME_NONCE_OFF + FRAME_NONCE_LEN]

    if t in (1, 3, 5, 9):
        kck = ptk_kck(t, pmk, ap, sta, ext_nonce, frame_nonce)
    else:
        pmk_r1, _ = ft_chain(family, pmk, essid, mdid, r0kh, r1kh, sta)
        kck = ft_ptk_kck(t, pmk_r1, ap, sta, ext_nonce, frame_nonce, mp)

    if t == 1:
        return mic_hmac(kck, frame, "md5", 16)
    if t == 3:
        return mic_hmac(kck, frame, "sha1", 16)
    if t in (5, 7):
        return mic_cmac(kck, frame)
    return mic_hmac(kck, frame, "sha384", 24)


# --- EAPOL frame generation --------------------------------------------------


def gen_eapol_frame(keyver, snonce):
    frame = bytearray()

    frame += b"\x01"  # version
    frame += b"\x03"  # type = EAPOL-Key
    body_len = 119 if keyver == 1 else 117
    frame += struct.pack(">H", body_len)  # body length

    frame += b"\xfe" if keyver == 1 else b"\x01"  # descriptor type

    key_info = (1 << 8) | (1 << 3)  # MIC + pairwise
    if keyver == 1:
        key_info |= 1
    elif keyver == 2:
        key_info |= 2
    elif keyver == 3:
        key_info |= 3
    frame += struct.pack(">H", key_info)

    key_length = 32 if keyver == 1 else 0
    frame += struct.pack(">H", key_length)

    frame += struct.pack(">Q", 1)  # replay counter
    frame += snonce  # key nonce (32 bytes)
    frame += b"\x00" * 16  # key IV
    frame += b"\x00" * 8  # key RSC
    frame += b"\x00" * 8  # key ID
    frame += b"\x00" * 16  # key MIC (zeroed for computation)

    if keyver == 1:
        frame += struct.pack(">H", 24)  # key data length
        frame += b"\xdd\x16\x00\x50\xf2\x01\x01\x00"
        frame += b"\x00\x50\xf2\x02\x01\x00\x00\x50\xf2\x02\x01\x00\x00\x50\xf2\x02"
    else:
        frame += struct.pack(">H", 22)  # key data length
        frame += b"\x30\x14\x01\x00\x00\x0f\xac\x04"
        frame += b"\x01\x00\x00\x0f\xac\x04\x01\x00\x00\x0f\xac\x02\x00\x00"

    return bytes(frame)


# --- hash generation and verification ----------------------------------------


def module_generate_hash(
    word,
    salt,
    wpa_type=None,
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

    if wpa_type is None:
        wpa_type = random_number(1, 11)

    t = int(wpa_type)

    if macap is None:
        macap = random_bytes(6)
    elif isinstance(macap, str):
        macap = bytes.fromhex(macap)

    if macsta is None:
        macsta = random_bytes(6)
    elif isinstance(macsta, str):
        macsta = bytes.fromhex(macsta)

    if essid is None:
        elen = random_number(2, 16) * 2
        essid = random_bytes(elen)
    elif isinstance(essid, str):
        essid = bytes.fromhex(essid)

    if anonce is None:
        anonce = random_bytes(32)
    elif isinstance(anonce, str):
        anonce = bytes.fromhex(anonce)

    if mp is None:
        mp = 0
    else:
        mp = int(mp, 16) if isinstance(mp, str) else int(mp)

    if t in FT_TYPES:
        if mdid is None:
            mdid = random_bytes(2)
        elif isinstance(mdid, str):
            mdid = bytes.fromhex(mdid)

        if r0kh is None:
            r0kh_len = random_number(1, 48)
            r0kh = random_bytes(r0kh_len)
        elif isinstance(r0kh, str):
            r0kh = bytes.fromhex(r0kh)

        if r1kh is None:
            r1kh = random_bytes(6)
        elif isinstance(r1kh, str):
            r1kh = bytes.fromhex(r1kh)
    else:
        mdid = b""
        r0kh = b""
        r1kh = b""

    if t in EAPOL_TYPES:
        if eapol is None:
            if t == 1:
                keyver = 1
            elif t == 3:
                keyver = 2
            else:
                keyver = 3
            snonce = random_bytes(32)
            eapol = gen_eapol_frame(keyver, snonce)
        elif isinstance(eapol, str):
            eapol = bytes.fromhex(eapol)
    else:
        eapol = b""

    # Mode 22003: word IS the PMK as a 64-char hex string, no PBKDF2.
    if isinstance(word, bytes):
        pmk = bytes.fromhex(word.decode("ascii"))
    else:
        pmk = bytes.fromhex(word)

    hash_val = compute_hash_value(
        t, pmk, essid, macap, macsta, anonce, eapol, mp, mdid, r0kh, r1kh
    )

    anonce_hex = anonce.hex() if anonce else ""
    eapol_hex = eapol.hex() if eapol else ""

    line = f"WPA*{t:02d}*{hash_val.hex()}*{macap.hex()}*{macsta.hex()}*{essid.hex()}*{anonce_hex}*{eapol_hex}*{mp:02x}"

    if t in FT_TYPES:
        line += f"*{mdid.hex()}*{r0kh.hex()}*{r1kh.hex()}"

    return line


def module_verify_hash(line):
    idx = line.find(b":")

    if idx < 1:
        return None

    hash_in = line[:idx]
    word = line[idx + 1 :]

    try:
        parts = hash_in.decode("ascii").split("*")
    except UnicodeDecodeError:
        return None

    if len(parts) < 9:
        return None

    if parts[0] != "WPA":
        return None

    wpa_type = parts[1]
    macap = parts[3]
    macsta = parts[4]
    essid = parts[5]
    anonce = parts[6]
    eapol = parts[7]
    mp = parts[8]

    mdid = parts[9] if len(parts) > 9 else None
    r0kh = parts[10] if len(parts) > 10 else None
    r1kh = parts[11] if len(parts) > 11 else None

    new_hash = module_generate_hash(
        word,
        None,
        wpa_type=wpa_type,
        macap=macap,
        macsta=macsta,
        essid=essid,
        anonce=anonce,
        eapol=eapol if eapol else None,
        mp=mp,
        mdid=mdid,
        r0kh=r0kh,
        r1kh=r1kh,
    )

    return (new_hash, word)
