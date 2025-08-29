#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
POCO PSI recovery (pro edition)
- Supports PSI-1 header detection and optional images.db (PST-... salt)
- Brute-forces common lightweight schemes used by legacy gallery lockers
- Tries multiple offsets / header-only vs full, and key-derivation variants

Usage:
  python poco_psi_recover.py \
    --in ~/Playground/PocoTest/poco_psi \
    --out ~/Playground/PocoTest/poco_out \
    --gesture 2-4-3-5-7-6-8-9-1 \
    --db ~/Playground/PocoTest/poco_psi/images.db \
    --limit 50

Tip: start with --limit to get quick feedback. If outputs look good, remove it for full run.
"""

import argparse
import hashlib
from pathlib import Path

MAGICS = {
    b"\xFF\xD8\xFF": ".jpg",
    b"\x89PNG\r\n\x1a\n": ".png",
    b"GIF89a": ".gif",
    b"GIF87a": ".gif",
}

# Common JPEG header bytes we can use as "crib" (SOI + 'JFIF' or 'Exif')
JPEG_CRIBS = [
    # positions relative to SOI: (index, expected_byte)
    {0:0xFF, 1:0xD8, 2:0xFF, 3:0xE0, 6:0x4A, 7:0x46, 8:0x49, 9:0x46, 10:0x00},  # JFIF via APP0
    {0:0xFF, 1:0xD8, 2:0xFF, 3:0xE1, 6:0x45, 7:0x78, 8:0x69, 9:0x66, 10:0x00},  # Exif via APP1
]


# ---- format salvage helpers ----

def find_jpeg_bounds(b: bytes, start: int = 0) -> tuple[int, int] | None:
    """Return (soi, eoi_exclusive) byte indices for a JPEG stream if found.
    - soi: index of 0xFFD8FF (SOI) starting at or after `start`
    - eoi_exclusive: index just after 0xFFD9 (EOI). If no EOI found, return None.
    Prefer the LAST EOI after SOI to capture full-length image.
    """
    soi = b.find(b"\xFF\xD8\xFF", start)
    if soi == -1:
        return None
    # Prefer the LAST EOI after this SOI to capture full-length image
    last = b.rfind(b"\xFF\xD9")
    if last != -1 and last > soi:
        return soi, last + 2
    # Fallback to first EOI
    first = b.find(b"\xFF\xD9", soi + 3)
    if first == -1:
        return None
    return soi, first + 2


def trim_to_image_ext(data: bytes, ext: str) -> bytes | None:
    """If possible, trim the transformed payload to a valid image stream by ext.
    Currently implemented for JPEG (SOI..EOI). PNG/GIF are usually clean already.
    Returns trimmed bytes or None if not salvageable.
    """
    if ext == ".jpg":
        rng = find_jpeg_bounds(data, 0)
        if rng:
            a, b = rng
            return data[a:b]
        # If no EOI found, as a last resort, cut from SOI to end and append EOI
        soi = data.find(b"\xFF\xD8\xFF")
        if soi != -1:
            return data[soi:] + b"\xFF\xD9"
        return None
    else:
        return data


# ---- JPEG validator & bytewise helpers ----

def validate_jpeg(buf: bytes, max_steps: int = 20000) -> bool:
    """Stricter JPEG walk: must encounter SOS before accepting entropy data.
    Returns True only if structure looks sane and an EOI exists after SOS.
    """
    n = len(buf)
    if n < 4 or not buf.startswith(b"\xFF\xD8\xFF"):
        return False
    i = 2  # after 0xFFD8
    steps = 0
    saw_sos = False
    while i + 3 < n and steps < max_steps:
        steps += 1
        if buf[i] != 0xFF:
            # If we haven't seen SOS yet, this is invalid header noise
            return False
        # skip fill bytes FF FF FF...
        while i < n and buf[i] == 0xFF:
            i += 1
        if i >= n:
            return False
        marker = buf[i]
        i += 1
        if marker == 0xD9:  # EOI
            # EOI before SOS -> invalid
            return saw_sos
        if marker == 0xDA:  # SOS -> the rest should be entropy-coded data until EOI
            saw_sos = True
            eoi = buf.find(b"\xFF\xD9", i)
            return eoi != -1
        # stand-alone markers without length
        if marker in (0x01, 0xD0,0xD1,0xD2,0xD3,0xD4,0xD5,0xD6,0xD7):
            continue
        if i + 2 > n:
            return False
        seglen = int.from_bytes(buf[i:i+2], 'big')
        if seglen < 2 or i + seglen > n:
            return False
        i += seglen
    return False

# Tiny helper to detect SOS presence
def has_sos(buf: bytes) -> bool:
    return buf.find(b"\xFF\xDA") != -1

# ---- plausibility helpers ----
def parse_sof0_dims(buf: bytes) -> tuple[int,int] | None:
    i = buf.find(b"\xFF\xC0")
    if i == -1 or i + 9 >= len(buf):
        return None
    L = int.from_bytes(buf[i+2:i+4], 'big')
    if i + 2 + L > len(buf):
        return None
    H = int.from_bytes(buf[i+5:i+7], 'big')
    W = int.from_bytes(buf[i+7:i+9], 'big')
    return (W, H)

def looks_plausible_jpeg(buf: bytes) -> bool:
    """Require valid structure + plausible SOF0 dimensions to accept a JPEG."""
    if not validate_jpeg(buf):
        return False
    dims = parse_sof0_dims(buf)
    if not dims:
        return False
    W, H = dims
    if not (32 <= W <= 20000 and 32 <= H <= 20000):
        return False
    ar = max(W, H) / max(1, min(W, H))
    if ar > 25:
        return False
    return True


def nibble_swap_bytes(b: bytes) -> bytes:
    return bytes(((x & 0x0F) << 4) | (x >> 4) for x in b)


def rol1(b: bytes) -> bytes:
    return bytes(((x << 1) & 0xFF) | (x >> 7) for x in b)


def ror1(b: bytes) -> bytes:
    return bytes(((x >> 1) | ((x & 1) << 7)) for x in b)


def looks_like_image(buf: bytes) -> str:
    for magic, ext in MAGICS.items():
        if buf.startswith(magic):
            return ext
    return ""


def md5(b: bytes) -> bytes:
    return hashlib.md5(b).digest()


def sha1(b: bytes) -> bytes:
    return hashlib.sha1(b).digest()


def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


# ---- salt helpers ----

def parse_salt_arg(s: str) -> bytes:
    """Parse --salt input. If it looks like hex, decode; otherwise treat as raw ASCII.
    Empty/None -> b"".
    """
    if not s:
        return b""
    t = s.strip()
    # allow optional 0x prefix and spaces
    t2 = t.lower().removeprefix("0x").replace(" ", "")
    try:
        if all(c in "0123456789abcdef" for c in t2) and len(t2) % 2 == 0:
            return bytes.fromhex(t2)
    except Exception:
        pass
    return t.encode()


# ---- crypto primitives ----
# Minimal RC4

def rc4(key: bytes, data: bytes) -> bytes:
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    i = j = 0
    out = bytearray()
    for b in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        K = S[(S[i] + S[j]) % 256]
        out.append(b ^ K)
    return bytes(out)


def repxor(data: bytes, key: bytes) -> bytes:
    if not key:
        return data
    out = bytearray(len(data))
    k = len(key)
    for i, b in enumerate(data):
        out[i] = b ^ key[i % k]
    return bytes(out)


def single_xor(data: bytes, k: int) -> bytes:
    return bytes((b ^ k) for b in data)


# A simple LCG keystream (some lockers used it historically)

def lcg_stream(seed: int, n: int, a=1103515245, c=12345, m=2 ** 32) -> bytes:
    s = seed & 0xFFFFFFFF
    out = bytearray(n)
    for i in range(n):
        s = (a * s + c) & 0xFFFFFFFF
        out[i] = (s >> 16) & 0xFF
    return bytes(out)


# ---- gesture variants (D8 symmetries + reverse) ----

def idx_to_rc(i: int) -> tuple[int,int]:
    i -= 1
    return i // 3, i % 3

def rc_to_idx(r: int, c: int) -> int:
    return r * 3 + c + 1

def transform_idx(i: int, rot: int = 0, mirror_x: bool = False) -> int:
    r, c = idx_to_rc(i)
    # optional horizontal mirror (left-right)
    if mirror_x:
        c = 2 - c
    # rotate rot times 90 degrees clockwise
    for _ in range(rot % 4):
        r, c = c, 2 - r
    return rc_to_idx(r, c)

def generate_gesture_variants(gesture: str) -> list[str]:
    # normalize to digits only (keep original with dashes as well later)
    digits = [ch for ch in gesture if ch.isdigit()]
    if not digits:
        return [gesture]
    nums = list(map(int, digits))
    variants: list[list[int]] = []
    for rot in range(4):
        for mirror in (False, True):
            v = [transform_idx(x, rot=rot, mirror_x=mirror) for x in nums]
            variants.append(v)
            variants.append(list(reversed(v)))
    # de-dup while preserving order
    seqs: list[str] = []
    seen = set()
    for v in variants:
        s1 = "-".join(map(str, v))
        s2 = "".join(map(str, v))
        for s in (s1, s2):
            if s not in seen:
                seen.add(s)
                seqs.append(s)
    # also include the raw inputs (as-is)
    raw_with_dash = gesture
    raw_plain = "".join(digits)
    for s in (raw_with_dash, raw_plain):
        if s not in seen:
            seen.add(s)
            seqs.append(s)
    return seqs

# ---- key material ----

def derive_keys(gesture: str, salt: bytes) -> list[bytes]:
    
    global __FAST_MODE__
    fast = globals().get("__FAST_MODE__", False)

    # Build candidate strings from gesture variants (D8 + reverse)
    cand_strings = generate_gesture_variants(gesture)

    def enc_variants(s: str) -> list[bytes]:
        out: list[bytes] = []
        encs = ("utf-8",) if fast else ("utf-8", "utf-16le", "utf-16be")
        for enc in encs:
            try:
                out.append(s.encode(enc))
            except Exception:
                pass
        return out

    prefixes = ["", "PST-", "POCO", "POCO-", "PRIVATE-ALBUM", "POCO-LOCK"]
    suffixes = ["", "-LOCK", "_LOCK"]

    # Base byte pieces from encodings and with prefix/suffix combos
    pieces: list[bytes] = []
    for s in cand_strings:
        for b in enc_variants(s):
            pieces.append(b)
            # ASCII-like encodings will work with ASCII prefixes; for UTF-16 variants, prefix will also be encoded accordingly
            for enc in (("utf-8",) if fast else ("utf-8", "utf-16le", "utf-16be")):
                try:
                    sb = s.encode(enc)
                    for pre in prefixes:
                        for suf in suffixes:
                            pb = pre.encode(enc) + sb + suf.encode(enc)
                            pieces.append(pb)
                except Exception:
                    continue

    # Add digests (binary and hex ascii, both lower/upper)
    digests: list[bytes] = []
    for src in pieces:
        d_md5 = md5(src); d_sha1 = sha1(src); d_sha256 = sha256(src)
        digests += [d_md5, d_sha1, d_sha256]
        digests += [d_md5.hex().encode(), d_sha1.hex().encode(), d_sha256.hex().encode()]
        digests += [d_md5.hex().upper().encode(), d_sha1.hex().upper().encode(), d_sha256.hex().upper().encode()]

    base = pieces + digests

    keys: list[bytes] = []
    for b in base:
        keys.append(b)
        if salt:
            keys += [
                b + salt,
                salt + b,
                md5(b + salt),
                sha1(b + salt),
                sha256(b + salt),
            ]

    # de-dup while preserving order
    seen = set()
    uniq: list[bytes] = []
    for k in keys:
        if k not in seen:
            uniq.append(k)
            seen.add(k)
    return uniq


# ---- format helpers ----

def guess_offsets(buf: bytes) -> list[int]:

    fast = globals().get("__FAST_MODE__", False)

    # If file starts with b"PSI-1", treat it as a POCO header; test common header sizes
    bases = [0, 8, 12, 16, 24, 28, 32, 40, 48, 64, 96, 128, 192, 256, 512, 1024, 1536, 2048, 3072, 4096, 6144, 8192, 12288, 16384]
    out = set()
    n = len(buf)
    for b in bases:
        if b < n:
            out.add(b)
            # explore small jitters around each base (handle quirky headers)
            for d in range(1, 9 if fast else 65):
                if b + d < n: out.add(b + d)
                if b - d >= 0: out.add(b - d)
    # sort to keep stable order
    return sorted(out)


def find_magic_positions(data: bytes, max_scan: int = 65536) -> list[tuple[int, str]]:
    """Scan the first max_scan bytes for known image magics.
    Returns list of (pos, ext)."""
    window = data[:max_scan]
    hits = []
    for magic, ext in MAGICS.items():
        start = 0
        while True:
            i = window.find(magic, start)
            if i == -1:
                break
            hits.append((i, ext))
            start = i + 1
    hits.sort(key=lambda x: x[0])
    return hits

def extract_all_images_from_payload(payload: bytes, base_out: Path, ext_hint: str, args) -> int:
    """Scan payload for multiple embedded images and write each one.
    Returns count written. Uses salvage/strict/xorfix heuristics per item.
    """
    hits = find_magic_positions(payload, len(payload))
    count = 0
    used_ranges = []
    for pos, ext in hits:
        candidate = payload[pos:]
        to_write = candidate
        if ext == ".jpg" and args.salvage:
            trimmed = trim_to_image_ext(candidate, ".jpg")
            if trimmed:
                to_write = trimmed
            # If the trimmed result is still tiny (<128KB), try SOI..LAST-EOI span
            if len(to_write) < 131072:
                soi2 = candidate.find(b"\xFF\xD8\xFF")
                last2 = candidate.rfind(b"\xFF\xD9")
                if soi2 != -1 and last2 != -1 and last2 > soi2:
                    alt = candidate[soi2:last2+2]
                    if len(alt) > len(to_write):
                        to_write = alt
        if ext == ".jpg" and args.strict and not validate_jpeg(to_write):
            xf = xorfix_after_pos(to_write, 0)
            if xf:
                fixed, pivot, k = xf
                if args.salvage:
                    t2 = trim_to_image_ext(fixed, ".jpg")
                    if t2:
                        fixed = t2
                if validate_jpeg(fixed):
                    to_write = fixed
        if len(to_write) < 5120:
            continue
        end_est = pos + len(to_write)
        overlapped = any(not (end_est <= a or pos >= b) for a, b in used_ranges)
        if overlapped:
            continue
        used_ranges.append((pos, end_est))
        out_path = base_out
        if count > 0:
            out_path = base_out.with_name(base_out.stem + f"_{count}" + base_out.suffix)
        try:
            if ext == ".jpg" and args.strict and not looks_plausible_jpeg(to_write):
                xf = xorfix_after_pos(to_write, 0)
                if xf:
                    fixed, pivot, k = xf
                    if args.salvage:
                        t2 = trim_to_image_ext(fixed, ".jpg")
                        if t2:
                            fixed = t2
                    if looks_plausible_jpeg(fixed):
                        to_write = fixed
                if not looks_plausible_jpeg(to_write):
                    bad_path = out_path.with_suffix(".bad.jpg")
                    try:
                        bad_path.write_bytes(to_write)
                    except Exception:
                        pass
                    if args.emit_stages:
                        print("[i] skipped a non-plausible JPEG in multi-extract (kept .bad for inspection)")
                    continue
            out_path.write_bytes(to_write)
            count += 1
        except Exception:
            pass
    return count


def xorfix_after_pos(payload: bytes, start_pos: int, scan_window: int = 131072) -> tuple[bytes, int, int] | None:
    """Brute-force a late-stage single-byte XOR starting at some pivot so that
    the bytes at the pivot become an SOS marker (FF DA) and an EOI exists after it.
    Returns (fixed_bytes, pivot_index, xor_key) or None.
    """
    n = len(payload)
    lo = max(0, start_pos)
    hi = min(n - 2, start_pos + scan_window)
    for i in range(lo, hi):
        b1 = payload[i]
        b2 = payload[i + 1]
        # try all keys 0..255 to see if these two bytes could become FF DA
        for k in range(256):
            if (b1 ^ k) == 0xFF and (b2 ^ k) == 0xDA:
                fixed = payload[:i] + bytes((x ^ k) for x in payload[i:])
                eoi = fixed.rfind(b"\xFF\xD9")
                if eoi > i:
                    return fixed, i, k
    return None

# ---- hard repair: try global transforms to restore markers ----

def coarse_jpeg_score(b: bytes, max_scan: int = 262144) -> int:
    """Heuristic: look in first max_scan for SOI, FFDB (DQT), FFC0/FFC2 (SOF), FFC4 (DHT), SOS, EOI order.
    Returns a score; higher is better. Not a full validator.
    """
    w = b[:max_scan]
    score = 0
    soi = w.find(b"\xFF\xD8\xFF")
    if soi != -1:
        score += 3
        if w.find(b"\xFF\xDB", soi) != -1: score += 2
        if w.find(b"\xFF\xC4", soi) != -1: score += 2
        if w.find(b"\xFF\xC0", soi) != -1 or w.find(b"\xFF\xC2", soi) != -1: score += 2
        if w.find(b"\xFF\xDA", soi) != -1: score += 4
        if w.rfind(b"\xFF\xD9") > soi: score += 2
    return score


# ---- JPEG surgery: insert default DHT, segment-wise pivot/transform ----

# Standard JPEG Huffman tables (as used by many cameras) — from Annex K (short form)
# We'll inject as a single DHT segment before SOS when no DHT is present.
STD_DHT = bytes.fromhex(
    "FFC4"  # marker
    "01A2"  # length 0x01A2 (418)
    # Luminance DC
    "00" "00 01 05 01 01 01 01 01 01 00 00 00 00 00 00 00"
    "00 01 02 03 04 05 06 07 08 09 0A 0B"
    # Chrominance DC
    "01" "00 03 01 01 01 01 01 01 01 01 01 00 00 00 00 00"
    "00 01 02 03 04 05 06 07 08 09 0A 0B"
    # Luminance AC
    "10" "00 02 01 03 03 02 04 03 05 05 04 04 00 00 01 7D"
    "01 02 03 00 04 11 05 12 21 31 41 06 13 51 61 07 22 71 14 32 81 91 A1 08 23 42 B1 C1"
    "15 52 D1 F0 24 33 62 72 82 09 0A 16 17 18 19 1A 25 26 27 28 29 2A 34 35 36 37 38 39 3A"
    "43 44 45 46 47 48 49 4A 53 54 55 56 57 58 59 5A 63 64 65 66 67 68 69 6A 73 74 75 76 77 78 79 7A"
    "83 84 85 86 87 88 89 8A 92 93 94 95 96 97 98 99 9A A2 A3 A4 A5 A6 A7 A8 A9 AA B2 B3 B4 B5 B6 B7 B8 B9 BA"
    "C2 C3 C4 C5 C6 C7 C8 C9 CA D2 D3 D4 D5 D6 D7 D8 D9 DA E1 E2 E3 E4 E5 E6 E7 E8 E9 EA F1 F2 F3 F4 F5 F6 F7 F8 F9 FA"
    # Chrominance AC
    "11" "00 02 01 02 04 04 03 04 07 05 04 04 00 01 02 77"
    "00 01 02 03 11 04 05 21 31 06 12 41 51 07 61 71 13 22 32 81 08 14 42 91 A1 B1 C1 09 23 33 52 F0 15 62 72 D1"
    "0A 16 24 34 E1 25 F1 17 18 19 1A 26 27 28 29 2A 35 36 37 38 39 3A 43 44 45 46 47 48 49 4A 53 54 55 56 57 58 59 5A"
    "63 64 65 66 67 68 69 6A 73 74 75 76 77 78 79 7A 82 83 84 85 86 87 88 89 8A 92 93 94 95 96 97 98 99 9A A2 A3 A4 A5 A6 A7 A8 A9 AA"
    "B2 B3 B4 B5 B6 B7 B8 B9 BA C2 C3 C4 C5 C6 C7 C8 C9 CA D2 D3 D4 D5 D6 D7 D8 D9 DA E2 E3 E4 E5 E6 E7 E8 E9 EA F2 F3 F4 F5 F6 F7 F8 F9 FA"
)


def has_dht(buf: bytes) -> bool:
    i = 2
    n = len(buf)
    while i + 3 < n:
        if buf[i] != 0xFF:
            return False
        while i < n and buf[i] == 0xFF:
            i += 1
        if i >= n:
            return False
        marker = buf[i]; i += 1
        if marker == 0xDA:  # SOS -> stop parsing tables
            return False
        if marker == 0xC4:  # DHT
            return True
        if marker in (0x01, 0xD0,0xD1,0xD2,0xD3,0xD4,0xD5,0xD6,0xD7):
            continue
        if i + 2 > n: return False
        seglen = int.from_bytes(buf[i:i+2], 'big')
        if seglen < 2 or i + seglen > n: return False
        i += seglen
    return False


def insert_default_dht(buf: bytes) -> bytes | None:
    """Insert STD_DHT just before the first SOS marker."""
    sos = buf.find(b"\xFF\xDA")
    if sos == -1:
        return None
    return buf[:sos] + STD_DHT + buf[sos:]


def segment_pivot_repair(fullbuf: bytes) -> tuple[str, bytes] | None:
    """Locate SOI..last EOI slice; if no SOS, try pivot+XOR/ROL/ROR/NIBBLE from various positions.
    Return (label, repaired_fullslice) or None.
    """
    rng = find_jpeg_bounds(fullbuf, 0)
    if not rng:
        return None
    a, b = rng
    s = bytearray(fullbuf[a:b])
    # If already has SOS and validates, nothing to do
    if has_sos(s) and validate_jpeg(bytes(s)):
        return ("none", bytes(s))
    # try transforms from multiple pivots (every 1024 bytes after SOI up to 256KB window)
    n = len(s)
    pivots = list(range(0, min(n, 262144), 1024))
    def apply_from(i, f):
        return bytes(s[:i]) + f(bytes(s[i:]))
    # candidate transforms
    def _xor(k):
        return lambda t: bytes((x ^ k) for x in t)
    cands = []
    for i in pivots:
        for k in range(256):
            cands.append((i, f"xor0x{k:02X}", _xor(k)))
        cands.append((i, "nibble", lambda t: bytes(((x & 0x0F) << 4) | (x >> 4) for x in t)))
        cands.append((i, "rol1", lambda t: bytes(((x << 1) & 0xFF) | (x >> 7) for x in t)))
        cands.append((i, "ror1", lambda t: bytes(((x >> 1) | ((x & 1) << 7)) for x in t)))
    for i, tag, f in cands:
        fixed = apply_from(i, f)
        if not has_sos(fixed):
            continue
        if not validate_jpeg(fixed):
            continue
        return (f"pivot@{i}:{tag}", fixed)
    return None

def hard_repair_fullbuf(fullbuf: bytes, max_scan: int = 262144):
    """Try expensive global transforms to make a valid-looking JPEG appear.
    Returns tuple(label, repaired_fullbuf) or (None, None) if not improved.
    """
    base_score = coarse_jpeg_score(fullbuf, max_scan)
    best = (base_score, 'identity', fullbuf)

    # 1) global single-byte XOR 0..255
    for k in range(256):
        x = bytes((b ^ k) for b in fullbuf)
        s = coarse_jpeg_score(x, max_scan)
        if s > best[0]:
            best = (s, f'xor0x{k:02X}', x)
            if s >= 13:  # SOI+DQT+DHT+SOF+SOS+EOI likely
                break
    # 2) nibble swap / rotations on best-so-far
    cands = [best[2]]
    def _ns(b): return bytes(((v & 0x0F) << 4) | (v >> 4) for v in b)
    def _rol1(b): return bytes(((v << 1) & 0xFF) | (v >> 7) for v in b)
    def _ror1(b): return bytes(((v >> 1) | ((v & 1) << 7)) for v in b)
    for f, tag in [(_ns,'nibble'), (_rol1,'rol1'), (_ror1,'ror1')]:
        x = f(best[2])
        s = coarse_jpeg_score(x, max_scan)
        if s > best[0]:
            best = (s, best[1] + '+' + tag, x)

    if best[0] > base_score:
        return best[1], best[2]
    return None, None

# ---- smart repeating-XOR probe (crib-based) ----
def smart_repxor_probe(buf: bytes, offsets: list[int], kmin: int = 2, kmax: int = 32, max_scan: int = 65536):
    """
    Fast path for repeating-XOR schemes using known JPEG header bytes as crib.
    For each offset and key length, derive the key from the crib and validate.
    Returns (desc, off, trimmed, '.jpg', full_transformed) or None.
    """
    n = len(buf)
    for off in offsets:
        # Need at least 16 bytes for crib at the offset
        if off + 16 >= n:
            continue
        enc = buf[off: off + 64]  # small window is enough to derive/check
        for crib in JPEG_CRIBS:
            for klen in range(kmin, kmax + 1):
                key = [None] * klen
                ok = True
                for idx, eb in crib.items():
                    if idx >= len(enc):
                        ok = False; break
                    kb = enc[idx] ^ eb
                    p = idx % klen
                    if key[p] is None:
                        key[p] = kb
                    elif key[p] != kb:
                        ok = False; break
                if not ok:
                    continue
                # fill unknown key bytes with 0 for now
                key_bytes = bytes((b if b is not None else 0) for b in key)
                # derive full payload via repeating XOR from this offset
                dec = repxor(buf[off:], key_bytes)
                # Check quick magic + structural plausibility
                if looks_like_image(dec[:16]) == ".jpg":
                    trimmed = trim_to_image_ext(dec, ".jpg")
                    if trimmed and looks_plausible_jpeg(trimmed):
                        return (f"smart-repxor klen={klen} off={off}", off, trimmed, ".jpg", dec)
                # sliding scan on transformed (in case crib not at exact start)
                sd = find_magic_positions(dec, max_scan)
                if sd and sd[0][1] == ".jpg":
                    pos = sd[0][0]
                    trimmed = trim_to_image_ext(dec, ".jpg")
                    if trimmed and looks_plausible_jpeg(trimmed):
                        return (f"smart-repxor klen={klen} off={off} scan@{pos}", off + pos, trimmed, ".jpg", dec)
    return None

def try_all(buf: bytes, keys: list[bytes], offsets: list[int], max_scan: int):

    fast = globals().get("__FAST_MODE__", False)
    SKIP_RC4 = globals().get("__SKIP_RC4__", False)
    SKIP_REPXOR = globals().get("__SKIP_REPXOR__", False)
    SKIP_LCG = globals().get("__SKIP_LCG__", False)

    # Sliding scan (no transform) — in case payload starts well past header
    hits = find_magic_positions(buf, max_scan)
    if hits:
        pos, ext = hits[0]
        if ext == ".jpg":
            trimmed = trim_to_image_ext(buf, ".jpg")
            if trimmed and looks_plausible_jpeg(trimmed):
                yield (f"scan_plain@{pos}", pos, trimmed, ext, buf)
                return
        else:
            yield (f"scan_plain@{pos}", pos, buf[pos:], ext, buf)
            return

    # 0) plain slice checks
    for off in offsets:
        ext = looks_like_image(buf[off:off + 8])
        if ext == ".jpg":
            trimmed = trim_to_image_ext(buf, ".jpg")
            if trimmed and looks_plausible_jpeg(trimmed):
                yield (f"slice@{off}", off, trimmed, ext, buf)
                return
        elif ext:
            yield (f"slice@{off}", off, buf[off:], ext, buf)
            return

    # Smart repeating-XOR probe (crib-based). Huge speedup if PSI used repxor with short key.
    res = smart_repxor_probe(buf, offsets, kmin=2, kmax=32, max_scan=max_scan)
    if res:
        yield res
        return

    # 1) single-byte XORs (header-first then full)
    common_ks = [0xFF, 0xA5, 0x5A, 0x33, 0x66, 0x99] + list(range(0, 256, 17))
    for off in offsets:
        # header-only up to 2048
        for k in common_ks:
            hdr_n = max(off, 2048)
            head = single_xor(buf[:hdr_n], k) + buf[hdr_n:]
            ext = looks_like_image(head[off:off + 16])
            if ext == ".jpg":
                trimmed = trim_to_image_ext(head, ".jpg")
                if trimmed and looks_plausible_jpeg(trimmed):
                    yield (f"single_xor k={k} hdr<=2048 off={off}", off, trimmed, ext, head)
                    return
            elif ext:
                yield (f"single_xor k={k} hdr<=2048 off={off}", off, head[off:], ext, head)
                return
            # sliding scan on transformed (header-only)
            sh = find_magic_positions(head, max_scan)
            if sh:
                pos, ext2 = sh[0]
                if ext2 == ".jpg":
                    trimmed = trim_to_image_ext(head, ".jpg")
                    if trimmed and looks_plausible_jpeg(trimmed):
                        yield (f"single_xor k={k} hdr<=2048 scan@{pos}", pos, trimmed, ext2, head)
                        return
                else:
                    yield (f"single_xor k={k} hdr<=2048 scan@{pos}", pos, head[pos:], ext2, head)
                    return
        # full
        for k in common_ks[:32]:
            dec = single_xor(buf[off:], k)
            ext = looks_like_image(dec[:16])
            if ext == ".jpg":
                trimmed = trim_to_image_ext(dec, ".jpg")
                if trimmed and looks_plausible_jpeg(trimmed):
                    yield (f"single_xor k={k} full off={off}", off, trimmed, ext, dec)
                    return
            elif ext:
                yield (f"single_xor k={k} full off={off}", off, dec, ext, dec)
                return
            # sliding scan on transformed (full)
            sd = find_magic_positions(dec, max_scan)
            if sd:
                pos, ext2 = sd[0]
                if ext2 == ".jpg":
                    trimmed = trim_to_image_ext(dec, ".jpg")
                    if trimmed and looks_plausible_jpeg(trimmed):
                        yield (f"single_xor k={k} full scan@{pos}", pos, trimmed, ext2, dec)
                        return
                else:
                    yield (f"single_xor k={k} full scan@{pos}", pos, dec[pos:], ext2, dec)
                    return
                

    # 2) repxor & RC4 (header-first then full)
    if not (SKIP_REPXOR and SKIP_RC4):
        for off in offsets:
            payload = buf[off:]
            for key in keys:
                # --- repeating XOR path ---
                if not SKIP_REPXOR:
                    # header-only transforms
                    for hdr_n in [256, 512, 1024, 2048]:
                        head = repxor(buf[:hdr_n], key) + buf[hdr_n:]
                        ext = looks_like_image(head[off:off + 16])
                        if ext == ".jpg":
                            trimmed = trim_to_image_ext(head, ".jpg")
                            if trimmed and looks_plausible_jpeg(trimmed):
                                yield (f"repxor keylen={len(key)} hdr={hdr_n} off={off}", off, trimmed, ext, head)
                                return
                        elif ext:
                            yield (f"repxor keylen={len(key)} hdr={hdr_n} off={off}", off, head[off:], ext, head)
                            return
                        # sliding scan on transformed (header-only)
                        sh = find_magic_positions(head, max_scan)
                        if sh:
                            pos, ext2 = sh[0]
                            if ext2 == ".jpg":
                                trimmed = trim_to_image_ext(head, ".jpg")
                                if trimmed and looks_plausible_jpeg(trimmed):
                                    yield (f"repxor keylen={len(key)} hdr={hdr_n} scan@{pos}", pos, trimmed, ext2, head)
                                    return
                            else:
                                yield (f"repxor keylen={len(key)} hdr={hdr_n} scan@{pos}", pos, head[pos:], ext2, head)
                                return
                    # full transform
                    dec = repxor(payload, key)
                    ext = looks_like_image(dec[:16])
                    if ext == ".jpg":
                        trimmed = trim_to_image_ext(dec, ".jpg")
                        if trimmed and looks_plausible_jpeg(trimmed):
                            yield (f"repxor keylen={len(key)} full off={off}", off, trimmed, ext, dec)
                            return
                    elif ext:
                        yield (f"repxor keylen={len(key)} full off={off}", off, dec, ext, dec)
                        return
                    # sliding scan on transformed (full)
                    sd = find_magic_positions(dec, max_scan)
                    if sd:
                        pos, ext2 = sd[0]
                        if ext2 == ".jpg":
                            trimmed = trim_to_image_ext(dec, ".jpg")
                            if trimmed and looks_plausible_jpeg(trimmed):
                                yield (f"repxor keylen={len(key)} full scan@{pos}", pos, trimmed, ext2, dec)
                                return
                        else:
                            yield (f"repxor keylen={len(key)} full scan@{pos}", pos, dec[pos:], ext2, dec)
                            return

                # --- RC4 path ---
                if not SKIP_RC4:
                    # full transform
                    dec = rc4(key, payload)
                    ext = looks_like_image(dec[:16])
                    if ext == ".jpg":
                        trimmed = trim_to_image_ext(dec, ".jpg")
                        if trimmed and looks_plausible_jpeg(trimmed):
                            yield (f"rc4 keylen={len(key)} full off={off}", off, trimmed, ext, dec)
                            return
                    elif ext:
                        yield (f"rc4 keylen={len(key)} full off={off}", off, dec, ext, dec)
                        return
                    # sliding scan on transformed (full)
                    sd = find_magic_positions(dec, max_scan)
                    if sd:
                        pos, ext2 = sd[0]
                        if ext2 == ".jpg":
                            trimmed = trim_to_image_ext(dec, ".jpg")
                            if trimmed and looks_plausible_jpeg(trimmed):
                                yield (f"rc4 keylen={len(key)} full scan@{pos}", pos, trimmed, ext2, dec)
                                return
                        else:
                            yield (f"rc4 keylen={len(key)} full scan@{pos}", pos, dec[pos:], ext2, dec)
                            return
                    # header-only transforms
                    for hdr_n in [256, 512, 1024, 2048]:
                        head = rc4(key, buf[:hdr_n]) + buf[hdr_n:]
                        ext = looks_like_image(head[off:off + 16])
                        if ext == ".jpg":
                            trimmed = trim_to_image_ext(head, ".jpg")
                            if trimmed and looks_plausible_jpeg(trimmed):
                                yield (f"rc4 keylen={len(key)} hdr={hdr_n} off={off}", off, trimmed, ext, head)
                                return
                        elif ext:
                            yield (f"rc4 keylen={len(key)} hdr={hdr_n} off={off}", off, head[off:], ext, head)
                            return
                        # sliding scan on transformed (header-only)
                        sh = find_magic_positions(head, max_scan)
                        if sh:
                            pos, ext2 = sh[0]
                            if ext2 == ".jpg":
                                trimmed = trim_to_image_ext(head, ".jpg")
                                if trimmed and looks_plausible_jpeg(trimmed):
                                    yield (f"rc4 keylen={len(key)} hdr={hdr_n} scan@{pos}", pos, trimmed, ext2, head)
                                    return
                            else:
                                yield (f"rc4 keylen={len(key)} hdr={hdr_n} scan@{pos}", pos, head[pos:], ext2, head)
                                return

    # 3) LCG XOR variants
    for off in offsets:
        for seed in [0, 1, 0x12345678]:
            stream = lcg_stream(seed, len(buf) - off)
            dec = repxor(buf[off:], stream)
            ext = looks_like_image(dec[:16])
            if ext == ".jpg":
                trimmed = trim_to_image_ext(dec, ".jpg")
                if trimmed and looks_plausible_jpeg(trimmed):
                    yield (f"lcg(seed={seed}) off={off}", off, trimmed, ext, dec)
                    return
            elif ext:
                yield (f"lcg(seed={seed}) off={off}", off, dec, ext, dec)
                return
            # sliding scan on transformed (full)
            sd = find_magic_positions(dec, max_scan)
            if sd:
                pos, ext2 = sd[0]
                if ext2 == ".jpg":
                    trimmed = trim_to_image_ext(dec, ".jpg")
                    if trimmed and looks_plausible_jpeg(trimmed):
                        yield (f"lcg(seed={seed}) scan@{pos}", pos, trimmed, ext2, dec)
                        return
                else:
                    yield (f"lcg(seed={seed}) scan@{pos}", pos, dec[pos:], ext2, dec)
                    return


def main():
    ap = argparse.ArgumentParser(description="Recover images from POCO .psi files with multiple strategies.")
    ap.add_argument("--in", dest="indir", required=True, help="Folder containing .psi files")
    ap.add_argument("--out", dest="outdir", required=True, help="Folder to write recovered images")
    ap.add_argument("--gesture", required=True, help="Nine-grid gesture, e.g. 2-4-3-5-7-6-8-9-1")
    ap.add_argument("--db", dest="dbfile", default=None, help="Optional images.db for salt (starts with 'PST-')")
    ap.add_argument("--salt", dest="salt", default=None, help="Override salt (hex or ascii). If set, skips reading images.db")
    ap.add_argument("--limit", type=int, default=0, help="Only process first N files (0=all)")
    ap.add_argument("--max-scan", type=int, default=65536, help="Scan this many leading bytes for image headers (default 65536)")
    ap.add_argument("--salvage", action="store_true", help="Trim payload to valid image bounds (e.g., SOI..EOI for JPEG) and append EOI when missing")
    ap.add_argument("--strict", action="store_true", help="Only write images that pass a quick JPEG structural validation; otherwise try repair recipes")
    ap.add_argument("--emit-stages", action="store_true", help="For debugging: write intermediate transformed payloads and extract ALL embedded images found in a payload")
    ap.add_argument("--full-extract", action="store_true", help="After the winning transform, re-scan the FULL transformed buffer and extract ALL embedded images (not just the first hit slice)")
    ap.add_argument("--repair-hard", action="store_true", help="Try expensive global transforms (XOR 0..255, nibble-swap, bit-rot) on the FULL buffer to restore markers, then extract")
    ap.add_argument("--surgery", action="store_true", help="Perform JPEG surgery: try segment-wise pivot transforms and insert default DHT if tables are missing")
    ap.add_argument("--fast", action="store_true", help="Reduce search breadth: small offset jitter, UTF-8-only in first pass")
    ap.add_argument("--keys-cap", type=int, default=0, help="Cap number of derived keys to try (0 = no cap)")
    ap.add_argument("--skip-rc4", action="store_true", help="Skip RC4 transforms")
    ap.add_argument("--skip-repxor", action="store_true", help="Skip repeating-XOR transforms")
    ap.add_argument("--skip-lcg", action="store_true", help="Skip LCG XOR transforms")
    ap.add_argument("--probe-only", action="store_true", help="Only run the smart repeating-XOR probe (skip other transforms)")
    args = ap.parse_args()

    indir = Path(args.indir).expanduser()
    outdir = Path(args.outdir).expanduser()
    outdir.mkdir(parents=True, exist_ok=True)

    # Resolve salt (priority: --salt > images.db > cached sidecar)
    salt = b""
    sidecar = indir / ".poco_salt.txt"

    if args.salt:
        salt = parse_salt_arg(args.salt)
        print(f"[i] using --salt override: {salt!r}")
    else:
        db_path = None
        if args.dbfile:
            db_path = Path(args.dbfile).expanduser()
        else:
            # if not provided, try default images.db in indir
            cand = indir / "images.db"
            if cand.exists():
                db_path = cand
        if db_path and db_path.exists():
            try:
                b = db_path.read_bytes()
                if b.startswith(b"PST-"):
                    salt = b[4:4 + 64].split(b"\x00", 1)[0].strip()
                    print(f"[i] images.db salt: {salt!r}")
            except Exception as e:
                print(f"[!] Failed to read images.db: {e}")
        if not salt and sidecar.exists():
            try:
                salt_txt = sidecar.read_text(encoding="utf-8").strip()
                salt = parse_salt_arg(salt_txt)
                if salt:
                    print(f"[i] using cached sidecar salt: {salt!r}")
            except Exception:
                pass

    # if we got a salt and no sidecar yet, cache it for reuse
    if salt and not sidecar.exists():
        try:
            sidecar.write_text(salt.hex(), encoding="utf-8")
            # silent cache; no noisy print
        except Exception:
            pass

    # wire fast/skip flags to module-level toggles
    globals()["__FAST_MODE__"] = bool(args.fast)
    globals()["__SKIP_RC4__"] = bool(args.skip_rc4)
    globals()["__SKIP_REPXOR__"] = bool(args.skip_repxor)
    globals()["__SKIP_LCG__"] = bool(args.skip_lcg)

    keys = derive_keys(args.gesture, salt)

    if args.keys_cap and args.keys_cap > 0:
        keys = keys[:args.keys_cap]
        print(f"[i] keys-cap in effect: trying first {len(keys)} keys")

    files = [p for p in sorted(indir.iterdir()) if p.is_file() and p.suffix.lower() == ".psi"]
    if args.limit:
        files = files[:args.limit]

    total = 0
    ok = 0
    for p in files:
        total += 1
        raw = p.read_bytes()
        # offsets to try (PSI-1 headers often small)
        offsets = guess_offsets(raw)
        if args.probe_only:
            res = smart_repxor_probe(raw, offsets, kmin=2, kmax=32, max_scan=args.max_scan)
            if res:
                desc, off, payload, ext, fullbuf = res
                out = outdir / (p.stem + ext)
                if args.salvage:
                    t = trim_to_image_ext(payload, ext)
                    if t: payload = t
                out.write_bytes(payload)
                ok += 1
                print(f"[OK] {p.name} -> {out.name} via {desc}")
            else:
                print(f"[??] {p.name} smart-probe no hit")
            continue
        hit = None
        for res in try_all(raw, keys, offsets, args.max_scan):
            hit = res
            break
        if hit:
            if len(hit) == 5:
                desc, off, payload, ext, fullbuf = hit
            else:
                desc, off, payload, ext = hit
                fullbuf = payload
            out = outdir / (p.stem + ext)
            i = 1
            while out.exists():
                out = outdir / f"{p.stem}_{i}{ext}"
                i += 1
            # Optional: try hard repair on the FULL transformed buffer before any slicing
            if args.repair_hard and not validate_jpeg(fullbuf):
                label, repaired = hard_repair_fullbuf(fullbuf, args.max_scan)
                if repaired:
                    fullbuf = repaired
                    desc = desc + f" | hard-repair={label}"

            # JPEG surgery on full buffer (before slicing): try segment pivot/transform and default DHT insertion
            if args.surgery:
                rng = find_jpeg_bounds(fullbuf, 0)
                if rng:
                    a, b = rng
                    fullslice = fullbuf[a:b]
                    changed = False
                    if not has_sos(fullslice):
                        sp = segment_pivot_repair(fullbuf)
                        if sp:
                            label, repaired_slice = sp
                            fullbuf = repaired_slice  # note: now fullbuf is a slice
                            desc += f" | surgery={label}"
                            changed = True
                    # if still no DHT, insert a default
                    chk = fullbuf if changed else fullslice
                    if not has_dht(chk):
                        inj = insert_default_dht(chk)
                        if inj:
                            fullbuf = inj
                            desc += " | insertDHT"
                            changed = True
                    if changed:
                        # prefer trimming from this repaired buffer
                        payload = fullbuf
            # Optional: emit stage payload and extract ALL embedded images we can find
            if args.emit_stages:
                stage_out = out.with_suffix(".stage.bin")
                try:
                    stage_out.write_bytes(fullbuf)
                except Exception:
                    pass
                _n = extract_all_images_from_payload(fullbuf, out, ext, args)
                if _n > 0:
                    ok += 1
                    print(f"[OK] {p.name} -> {out.name} (+{_n-1} siblings) via {desc}")
                    continue

            # If requested, always run multi-extract on FULL buffer (even without stage dump)
            if args.full_extract:
                _n = extract_all_images_from_payload(fullbuf, out, ext, args)
                if _n > 0:
                    ok += 1
                    print(f"[OK] {p.name} -> {out.name} (+{_n-1} siblings) via {desc}")
                    try:
                        bb = out.read_bytes()
                        dims = parse_sof0_dims(bb)
                        if dims:
                            print(f"[i] dims={dims[0]}x{dims[1]}")
                    except Exception:
                        pass
                    continue

            to_write = payload
            src_for_trim = fullbuf if (args.repair_hard or args.surgery) else payload
            if ext == ".jpg":
                # optional salvage (trim to SOI..EOI)
                if args.salvage:
                    trimmed = trim_to_image_ext(src_for_trim, ext)
                    if trimmed:
                        to_write = trimmed
                    # Try SOI..LAST-EOI span if result seems too small
                    if len(to_write) < 131072:
                        soi2 = src_for_trim.find(b"\xFF\xD8\xFF")
                        last2 = src_for_trim.rfind(b"\xFF\xD9")
                        if soi2 != -1 and last2 != -1 and last2 > soi2:
                            alt = src_for_trim[soi2:last2+2]
                            if len(alt) > len(to_write):
                                to_write = alt
                print(f"[i] slice size after-trim={len(to_write)} hasSOS={has_sos(to_write)}")
                dims = parse_sof0_dims(to_write)
                if dims:
                    print(f"[i] dims={dims[0]}x{dims[1]}")
                # If the slice has no SOS at all, attempt XOR-fix first (common in POCO PSI)
                if not has_sos(to_write):
                    xf = xorfix_after_pos(to_write, 0)
                    if xf:
                        fixed, pivot, k = xf
                        if args.salvage:
                            t2 = trim_to_image_ext(fixed, ext)
                            if t2:
                                fixed = t2
                        to_write = fixed
                        print(f"[i] pre-validate xorfix applied pivot={pivot} k=0x{k:02X}")
                # validate; if invalid, try light repair transforms
                if args.strict and not validate_jpeg(to_write):
                    # try bitwise fixes on header-only and full
                    candidates = []
                    candidates.append(to_write)
                    candidates.append(nibble_swap_bytes(to_write))
                    candidates.append(rol1(to_write))
                    candidates.append(ror1(to_write))
                    # last resort: ensure EOI exists
                    if not to_write.endswith(b"\xFF\xD9"):
                        candidates.append(to_write + b"\xFF\xD9")
                    repaired = None
                    for c in candidates:
                        if validate_jpeg(c):
                            repaired = c
                            break
                    if repaired is not None:
                        to_write = repaired
                    else:
                        # as a fallback, still write but mark as .bad.jpg alongside
                        bad = out.with_suffix(".bad.jpg")
                        try:
                            bad.write_bytes(to_write)
                        except Exception:
                            pass
            # Heuristic: if still not a structurally valid JPEG, try XOR-after-hit repair
            if ext == ".jpg" and (not validate_jpeg(to_write)):
                xf = xorfix_after_pos(to_write, 0)
                if xf:
                    fixed, pivot, k = xf
                    if args.salvage:
                        trimmed = trim_to_image_ext(fixed, ext)
                        if trimmed:
                            fixed = trimmed
                    if validate_jpeg(fixed):
                        to_write = fixed
                        print(f"[i] xorfix applied pivot={pivot} k=0x{k:02X}")
            out.write_bytes(to_write)
            ok += 1
            size_note = f" {len(to_write)}B" if to_write is not None else ""
            print(f"[OK] {p.name} -> {out.name}{size_note} via {desc}")
        else:
            print(f"[??] {p.name} no method matched")

    print(f"\nDone. {ok}/{total} files produced image headers.")


if __name__ == "__main__":
    main()
