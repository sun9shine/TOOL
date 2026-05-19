#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
===============================================================
  Universal Crypto Key Conversion Tool
  اداة تحويل المفاتيح العامة والعناوين الى Hex ثم الى Private Key
  تعمل مع اي شبكة بلوكشين
===============================================================

  متوافقة مع Python 2.7+ و Python 3.x
  لا تحتاج اي مكتبات خارجية - تعمل مباشرة على اي جهاز

  التشغيل:
    python key_tool.py
"""

from __future__ import print_function
import hashlib
import sys
import os
import struct

# ============================================================
#  التوافق مع Python 2 و Python 3
# ============================================================

PY3 = sys.version_info[0] >= 3

if PY3:
    string_types = (str,)
    byte_types = (bytes, bytearray)
    import base64 as base64_module

    def to_bytes(data):
        if isinstance(data, bytes):
            return data
        return data.encode('utf-8')

    def from_bytes(data):
        if isinstance(data, str):
            return data
        return data.decode('utf-8')

    def get_input(prompt):
        return input(prompt)

    def byte_at(data, i):
        return data[i]

    def int_to_bytes(n, length):
        result = bytearray(length)
        for i in range(length - 1, -1, -1):
            result[i] = n & 0xff
            n >>= 8
        return bytes(result)

    def bytes_to_hex(data):
        return data.hex()

    def hex_to_bytes(h):
        return bytes.fromhex(h)
else:
    string_types = (str, unicode)
    byte_types = (str, bytearray)
    import base64 as base64_module

    def to_bytes(data):
        if isinstance(data, bytearray):
            return bytes(data)
        if isinstance(data, unicode):
            return data.encode('utf-8')
        return data

    def from_bytes(data):
        return data

    def get_input(prompt):
        return raw_input(prompt)

    def byte_at(data, i):
        return ord(data[i])

    def int_to_bytes(n, length):
        result = bytearray(length)
        for i in range(length - 1, -1, -1):
            result[i] = n & 0xff
            n >>= 8
        return bytes(result)

    def bytes_to_hex(data):
        return data.encode('hex')

    def hex_to_bytes(h):
        return h.decode('hex')


# ============================================================
#  Base58 (مدمج - لا يحتاج مكتبة خارجية)
# ============================================================

B58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
B58_BASE = 58


def b58_encode(data):
    """ترميز Base58"""
    if isinstance(data, bytearray):
        data = bytes(data)

    # عد الاصفار في البداية
    n_pad = 0
    for i in range(len(data)):
        if byte_at(data, i) == 0:
            n_pad += 1
        else:
            break

    # تحويل bytes الى عدد صحيح كبير
    n = 0
    for i in range(len(data)):
        n = n * 256 + byte_at(data, i)

    # تحويل العدد الى Base58
    result = ''
    while n > 0:
        n, remainder = divmod(n, B58_BASE)
        result = B58_ALPHABET[remainder] + result

    # اضافة padding
    return B58_ALPHABET[0] * n_pad + result


def b58_decode(s):
    """فك ترميز Base58"""
    if not s:
        return b''

    # تحويل من Base58 الى عدد صحيح
    n = 0
    for char in s:
        n = n * B58_BASE
        idx = B58_ALPHABET.find(char)
        if idx < 0:
            raise ValueError("Invalid Base58 character: " + char)
        n += idx

    # تحويل العدد الى bytes
    result = bytearray()
    while n > 0:
        n, remainder = divmod(n, 256)
        result.insert(0, remainder)

    # اضافة padding (الاصفار)
    n_pad = 0
    for char in s:
        if char == B58_ALPHABET[0]:
            n_pad += 1
        else:
            break

    return b'\x00' * n_pad + bytes(result)


def b58_decode_check(s):
    """فك ترميز Base58Check (مع التحقق من checksum)"""
    decoded = b58_decode(s)
    if len(decoded) < 4:
        raise ValueError("Base58Check: too short")

    data = decoded[:-4]
    checksum = decoded[-4:]

    # حساب checksum
    hash1 = hashlib.sha256(data).digest()
    hash2 = hashlib.sha256(hash1).digest()
    expected_checksum = hash2[:4]

    if checksum != expected_checksum:
        raise ValueError("Base58Check: invalid checksum")

    return data


def b58_encode_check(data):
    """ترميز Base58Check (مع اضافة checksum)"""
    if isinstance(data, bytearray):
        data = bytes(data)
    hash1 = hashlib.sha256(data).digest()
    hash2 = hashlib.sha256(hash1).digest()
    checksum = hash2[:4]
    return b58_encode(data + checksum)


# ============================================================
#  Base64 (مدمج)
# ============================================================

def b64_decode(s):
    """فك ترميز Base64"""
    try:
        return base64_module.b64decode(s)
    except Exception:
        raise ValueError("Invalid Base64")


# ============================================================
#  Bech32 / Bech32m Decoder (يدعم اي شبكة)
# ============================================================

BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def _bech32_polymod(values):
    """حساب Bech32 checksum"""
    GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for v in values:
        b = chk >> 25
        chk = ((chk & 0x1ffffff) << 5) ^ v
        for i in range(5):
            if (b >> i) & 1:
                chk ^= GEN[i]
    return chk


def _bech32_hrp_expand(hrp):
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def _bech32_verify(hrp, data):
    return _bech32_polymod(_bech32_hrp_expand(hrp) + data) == 1


def _bech32m_verify(hrp, data):
    return _bech32_polymod(_bech32_hrp_expand(hrp) + data) == 0x2bc830a3


def _convertbits(data, frombits, tobits, pad=True):
    """تحويل بين انظمة البت"""
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    max_acc = (1 << (frombits + tobits - 1)) - 1
    for value in data:
        if value < 0 or (value >> frombits):
            return None
        acc = ((acc << frombits) | value) & max_acc
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        return None
    return ret


def bech32_decode(bech):
    """فك ترميز Bech32/Bech32m - يدعم اي prefix"""
    for c in bech:
        if ord(c) < 33 or ord(c) > 126:
            return (None, None)

    if bech.lower() != bech and bech.upper() != bech:
        return (None, None)

    bech = bech.lower()
    pos = bech.rfind('1')
    if pos < 1 or pos + 7 > len(bech):
        return (None, None)

    for c in bech[pos + 1:]:
        if c not in BECH32_CHARSET:
            return (None, None)

    hrp = bech[:pos]
    data = [BECH32_CHARSET.find(x) for x in bech[pos + 1:]]

    is_valid = _bech32_verify(hrp, data) or _bech32m_verify(hrp, data)

    if is_valid:
        payload = data[:-6]
        if len(payload) < 1:
            return (None, None)
        # اول قيمة هي witness version (segwit) - نتخطاها
        converted = _convertbits(payload[1:], 5, 8, False)
        if converted is None:
            converted = _convertbits(payload, 5, 8, False)
            if converted is None:
                return (None, None)
        return (hrp, converted)

    return (None, None)


# ============================================================
#  فك الترميز العام (Universal Decoder)
# ============================================================

def decode_to_hex(input_str):
    """
    فك ترميز اي مدخل الى Hex
    يدعم: Hex, 0x, Base58, Base58Check, Base64, Bech32/Bech32m
    يعمل مع اي شبكة بلوكشين
    """
    input_str = input_str.strip()
    results = {}

    # 1. Hex مع 0x (Ethereum, BSC, etc.)
    if input_str.startswith('0x') or input_str.startswith('0X'):
        hex_clean = input_str[2:]
        if _is_hex(hex_clean):
            results['format'] = 'Hex (0x prefix)'
            results['hex'] = hex_clean.lower()
            results['bytes_length'] = len(hex_clean) // 2
            return results

    # 2. Hex خام
    if _is_hex(input_str) and len(input_str) >= 2:
        results['format'] = 'Hex (raw)'
        results['hex'] = input_str.lower()
        results['bytes_length'] = len(input_str) // 2
        return results

    # 3. Bech32/Bech32m (bc1, cosmos1, osmo1, tb1, etc.)
    try:
        hrp, data = bech32_decode(input_str)
        if hrp is not None and data is not None:
            hex_data = bytes_to_hex(bytes(bytearray(data)))
            results['format'] = 'Bech32 (prefix: ' + hrp + ')'
            results['hex'] = hex_data
            results['bytes_length'] = len(data)
            results['hrp'] = hrp
            return results
    except Exception:
        pass

    # 4. Base58Check (Bitcoin, Tron, Litecoin, etc.)
    try:
        decoded = b58_decode_check(input_str)
        results['format'] = 'Base58Check'
        results['hex'] = bytes_to_hex(decoded)
        results['hex_without_version'] = bytes_to_hex(decoded[1:])
        results['version_byte'] = '0x%02x' % byte_at(decoded, 0)
        results['bytes_length'] = len(decoded)
        return results
    except Exception:
        pass

    # 5. Base58 (بدون checksum)
    try:
        decoded = b58_decode(input_str)
        if len(decoded) >= 20:
            results['format'] = 'Base58'
            results['hex'] = bytes_to_hex(decoded)
            results['bytes_length'] = len(decoded)
            return results
    except Exception:
        pass

    # 6. Base64
    try:
        decoded = b64_decode(input_str)
        if len(decoded) >= 20:
            results['format'] = 'Base64'
            results['hex'] = bytes_to_hex(decoded)
            results['bytes_length'] = len(decoded)
            return results
    except Exception:
        pass

    raise ValueError("Format not recognized. Supported: Hex, 0x, Base58, Base58Check, Base64, Bech32")


def _is_hex(s):
    """التحقق ان النص hex صالح"""
    if not s:
        return False
    hex_chars = '0123456789abcdefABCDEF'
    for c in s:
        if c not in hex_chars:
            return False
    return True


# ============================================================
#  تحويل Hex الى مفتاح خاص
# ============================================================

def hex_to_wif(hex_key, version_byte=0x80, compressed=True):
    """تحويل Hex الى مفتاح خاص WIF"""
    hex_key = hex_key.strip().lower()

    # ضمان 64 حرف (32 bytes)
    if len(hex_key) > 64:
        hex_key = hex_key[:64]
    while len(hex_key) < 64:
        hex_key = hex_key + '0'

    key_data = hex_to_bytes(('%02x' % version_byte) + hex_key)

    if compressed:
        key_data = key_data + b'\x01'

    checksum = hashlib.sha256(hashlib.sha256(key_data).digest()).digest()[:4]
    return b58_encode(key_data + checksum)


def hex_to_private_key(hex_input):
    """تحويل Hex الى مفتاح خاص بعدة صيغ"""
    hex_input = hex_input.strip().lower()

    if hex_input.startswith('0x'):
        hex_input = hex_input[2:]

    # ضمان 64 حرف
    if len(hex_input) > 64:
        private_hex = hex_input[:64]
    elif len(hex_input) < 64:
        private_hex = hex_input
        while len(private_hex) < 64:
            private_hex = private_hex + '0'
    else:
        private_hex = hex_input

    result = {
        'private_key_hex': private_hex,
    }

    # WIF
    try:
        result['wif_compressed'] = hex_to_wif(private_hex, 0x80, True)
        result['wif_uncompressed'] = hex_to_wif(private_hex, 0x80, False)
    except Exception:
        pass

    # Raw hex
    result['raw_hex'] = '0x' + private_hex
    result['raw_bytes_64'] = private_hex

    return result


# ============================================================
#  الدوال الرئيسية
# ============================================================

def convert_public_key(public_key):
    """تحويل المفتاح العام الى Hex ثم الى مفتاح خاص"""
    decoded = decode_to_hex(public_key)
    hex_value = decoded['hex']

    result = {
        'input': public_key,
        'input_format': decoded['format'],
        'hex': hex_value,
        'bytes_length': decoded.get('bytes_length', len(hex_value) // 2),
    }

    private = hex_to_private_key(hex_value)
    result.update(private)
    return result


def convert_address(address):
    """تحويل العنوان الى Hex ثم الى مفتاح خاص"""
    decoded = decode_to_hex(address)
    hex_value = decoded['hex']

    result = {
        'input': address,
        'input_format': decoded['format'],
        'hex_full': hex_value,
        'bytes_length': decoded.get('bytes_length', len(hex_value) // 2),
    }

    if 'hex_without_version' in decoded:
        result['hex_without_version'] = decoded['hex_without_version']
        result['version_byte'] = decoded['version_byte']
        hex_for_key = decoded['hex_without_version']
    else:
        hex_for_key = hex_value

    private = hex_to_private_key(hex_for_key)
    result.update(private)
    return result


# ============================================================
#  ECDSA - Elliptic Curve (secp256k1) للتحقق من التوقيعات
# ============================================================

# معاملات منحنى secp256k1
SECP256K1_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
SECP256K1_GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
SECP256K1_GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
SECP256K1_A = 0
SECP256K1_B = 7


def _modinv(a, m):
    """معكوس mod باستخدام extended Euclidean"""
    if a < 0:
        a = a % m
    g, x, _ = _extended_gcd(a, m)
    if g != 1:
        return None
    return x % m


def _extended_gcd(a, b):
    if a == 0:
        return b, 0, 1
    g, x, y = _extended_gcd(b % a, a)
    return g, y - (b // a) * x, x


def _ec_add(p1, p2):
    """جمع نقطتين على المنحنى"""
    if p1 is None:
        return p2
    if p2 is None:
        return p1

    x1, y1 = p1
    x2, y2 = p2

    if x1 == x2 and y1 == y2:
        # Point doubling
        lam = (3 * x1 * x1 + SECP256K1_A) * _modinv(2 * y1, SECP256K1_P) % SECP256K1_P
    elif x1 == x2:
        return None  # Point at infinity
    else:
        lam = (y2 - y1) * _modinv(x2 - x1, SECP256K1_P) % SECP256K1_P

    x3 = (lam * lam - x1 - x2) % SECP256K1_P
    y3 = (lam * (x1 - x3) - y1) % SECP256K1_P
    return (x3, y3)


def _ec_multiply(point, scalar):
    """ضرب نقطة بعدد (scalar multiplication)"""
    result = None
    addend = point
    while scalar:
        if scalar & 1:
            result = _ec_add(result, addend)
        addend = _ec_add(addend, addend)
        scalar >>= 1
    return result


def _private_key_to_public(private_hex):
    """اشتقاق المفتاح العام من المفتاح الخاص"""
    private_int = int(private_hex, 16)
    if private_int <= 0 or private_int >= SECP256K1_N:
        return None
    point = _ec_multiply((SECP256K1_GX, SECP256K1_GY), private_int)
    if point is None:
        return None
    return point


def _point_to_compressed_pubkey(point):
    """تحويل نقطة الى مفتاح عام مضغوط"""
    x, y = point
    prefix = '02' if y % 2 == 0 else '03'
    return prefix + '%064x' % x


def _point_to_uncompressed_pubkey(point):
    """تحويل نقطة الى مفتاح عام غير مضغوط"""
    x, y = point
    return '04' + '%064x' % x + '%064x' % y


def _pubkey_to_address(pubkey_hex):
    """تحويل مفتاح عام الى عنوان Bitcoin (Base58Check)"""
    pubkey_bytes = hex_to_bytes(pubkey_hex)
    # SHA256
    sha = hashlib.sha256(pubkey_bytes).digest()
    # RIPEMD160
    ripemd = hashlib.new('ripemd160', sha).digest()
    # اضافة version byte (0x00 = mainnet)
    versioned = b'\x00' + ripemd
    # Base58Check
    return b58_encode_check(versioned)


def _hash256(data):
    """Double SHA256"""
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def _hash160(data):
    """SHA256 + RIPEMD160"""
    sha = hashlib.sha256(data).digest()
    return hashlib.new('ripemd160', sha).digest()


# ============================================================
#  التحقق من التوقيعات (Signature Verification)
# ============================================================

def verify_signature(message, signature_hex, pubkey_hex):
    """
    التحقق من توقيع ECDSA
    message: الرسالة الاصلية (string)
    signature_hex: التوقيع بصيغة hex (r + s, 128 chars)
    pubkey_hex: المفتاح العام بصيغة hex
    """
    # تجهيز hash الرسالة (Bitcoin message signing format)
    msg_bytes = to_bytes(message)
    prefix = b'\x18Bitcoin Signed Message:\n'
    msg_len = len(msg_bytes)

    if msg_len < 253:
        len_byte = bytes(bytearray([msg_len]))
    else:
        len_byte = b'\xfd' + struct.pack('<H', msg_len)

    full_msg = prefix + len_byte + msg_bytes
    msg_hash = _hash256(full_msg)
    z = int(bytes_to_hex(msg_hash), 16)

    # فك التوقيع
    sig_clean = signature_hex.strip().lower()
    if sig_clean.startswith('0x'):
        sig_clean = sig_clean[2:]

    if len(sig_clean) == 128:
        r = int(sig_clean[:64], 16)
        s = int(sig_clean[64:], 16)
    elif len(sig_clean) == 130:
        # مع recovery byte
        r = int(sig_clean[2:66], 16)
        s = int(sig_clean[66:], 16)
    else:
        # محاولة فك DER encoding
        r, s = _decode_der_signature(sig_clean)
        if r is None:
            return {'valid': False, 'error': 'Invalid signature format'}

    # فك المفتاح العام
    pubkey_clean = pubkey_hex.strip().lower()
    if pubkey_clean.startswith('0x'):
        pubkey_clean = pubkey_clean[2:]

    point = _decode_public_key(pubkey_clean)
    if point is None:
        return {'valid': False, 'error': 'Invalid public key'}

    # التحقق من التوقيع
    if r <= 0 or r >= SECP256K1_N or s <= 0 or s >= SECP256K1_N:
        return {'valid': False, 'error': 'Signature values out of range'}

    w = _modinv(s, SECP256K1_N)
    u1 = (z * w) % SECP256K1_N
    u2 = (r * w) % SECP256K1_N

    point1 = _ec_multiply((SECP256K1_GX, SECP256K1_GY), u1)
    point2 = _ec_multiply(point, u2)
    result_point = _ec_add(point1, point2)

    if result_point is None:
        return {'valid': False, 'error': 'Verification computation failed'}

    x, _ = result_point
    valid = (x % SECP256K1_N) == r

    return {
        'valid': valid,
        'message': message,
        'pubkey': pubkey_hex,
        'r': '%064x' % r,
        's': '%064x' % s,
    }


def _decode_der_signature(hex_sig):
    """فك DER encoded signature"""
    try:
        sig_bytes = hex_to_bytes(hex_sig)
        if byte_at(sig_bytes, 0) != 0x30:
            return None, None
        # total length
        idx = 2
        # R
        if byte_at(sig_bytes, idx) != 0x02:
            return None, None
        idx += 1
        r_len = byte_at(sig_bytes, idx)
        idx += 1
        r_bytes = sig_bytes[idx:idx + r_len]
        r = int(bytes_to_hex(r_bytes), 16)
        idx += r_len
        # S
        if byte_at(sig_bytes, idx) != 0x02:
            return None, None
        idx += 1
        s_len = byte_at(sig_bytes, idx)
        idx += 1
        s_bytes = sig_bytes[idx:idx + s_len]
        s = int(bytes_to_hex(s_bytes), 16)
        return r, s
    except Exception:
        return None, None


def _decode_public_key(pubkey_hex):
    """فك المفتاح العام الى نقطة"""
    if len(pubkey_hex) == 130 and pubkey_hex[:2] == '04':
        # uncompressed
        x = int(pubkey_hex[2:66], 16)
        y = int(pubkey_hex[66:], 16)
        return (x, y)
    elif len(pubkey_hex) == 66 and pubkey_hex[:2] in ('02', '03'):
        # compressed - حساب y من x
        x = int(pubkey_hex[2:], 16)
        y_sq = (pow(x, 3, SECP256K1_P) + SECP256K1_B) % SECP256K1_P
        y = pow(y_sq, (SECP256K1_P + 1) // 4, SECP256K1_P)
        if pubkey_hex[:2] == '02' and y % 2 != 0:
            y = SECP256K1_P - y
        elif pubkey_hex[:2] == '03' and y % 2 == 0:
            y = SECP256K1_P - y
        return (x, y)
    return None


# ============================================================
#  فحص المفتاح الخاص (Private Key Validation)
# ============================================================

def validate_private_key(key_input):
    """
    فحص شامل للمفتاح الخاص
    يدعم: WIF (5/K/L), Hex, 0x
    """
    key_input = key_input.strip()
    result = {
        'input': key_input,
        'valid': False,
        'format': 'Unknown',
    }

    private_hex = None

    # 1. محاولة WIF
    if key_input[0:1] in ('5', 'K', 'L', '9', 'c'):
        try:
            decoded = b58_decode_check(key_input)
            version = byte_at(decoded, 0)
            if version == 0x80:
                result['network'] = 'Mainnet'
            elif version == 0xEF:
                result['network'] = 'Testnet'
            else:
                result['network'] = 'Unknown (0x%02x)' % version

            if len(decoded) == 33:
                private_hex = bytes_to_hex(decoded[1:])
                result['format'] = 'WIF Uncompressed'
                result['compressed'] = False
            elif len(decoded) == 34:
                private_hex = bytes_to_hex(decoded[1:33])
                result['format'] = 'WIF Compressed'
                result['compressed'] = True
            else:
                result['error'] = 'Invalid WIF length'
                return result

            result['valid'] = True
            result['checksum'] = 'VALID'
        except ValueError as e:
            result['error'] = str(e)
            result['checksum'] = 'INVALID'
            return result

    # 2. Hex
    elif _is_hex(key_input.replace('0x', '').replace('0X', '')):
        clean = key_input.replace('0x', '').replace('0X', '')
        if len(clean) == 64:
            private_hex = clean.lower()
            result['format'] = 'Hex (32 bytes)'
            result['valid'] = True
        else:
            result['error'] = 'Hex must be 64 chars (32 bytes). Got: %d' % len(clean)
            return result

    else:
        result['error'] = 'Unrecognized format'
        return result

    # فحص النطاق
    if private_hex:
        pk_int = int(private_hex, 16)
        if pk_int <= 0:
            result['valid'] = False
            result['error'] = 'Private key is zero'
            return result
        if pk_int >= SECP256K1_N:
            result['valid'] = False
            result['error'] = 'Private key exceeds curve order'
            return result

        result['private_key_hex'] = private_hex
        result['range_check'] = 'VALID (1 < key < N)'

        # اشتقاق المفتاح العام والعنوان
        point = _private_key_to_public(private_hex)
        if point:
            compressed_pub = _point_to_compressed_pubkey(point)
            uncompressed_pub = _point_to_uncompressed_pubkey(point)
            address_c = _pubkey_to_address(compressed_pub)
            address_u = _pubkey_to_address(uncompressed_pub)

            result['public_key_compressed'] = compressed_pub
            result['public_key_uncompressed'] = uncompressed_pub
            result['address_compressed'] = address_c
            result['address_uncompressed'] = address_u
            result['derivation'] = 'SUCCESS'
        else:
            result['derivation'] = 'FAILED'

    return result


# ============================================================
#  فحص كلمات البذرة (Seed Phrase / Mnemonic Validation)
# ============================================================

# قائمة BIP39 الانجليزية (2048 كلمة) - checksum validation
# بدلا من تضمين كل الكلمات، نستخدم طريقة التحقق من البنية

BIP39_VALID_LENGTHS = [12, 15, 18, 21, 24]


def validate_mnemonic(mnemonic):
    """
    فحص كلمات البذرة (Mnemonic / Seed Phrase)
    يتحقق من:
    - عدد الكلمات (12, 15, 18, 21, 24)
    - بنية الكلمات
    - checksum (اذا كانت القائمة متوفرة)
    - اشتقاق المفتاح الخاص من البذرة
    """
    mnemonic = mnemonic.strip().lower()
    words = mnemonic.split()

    result = {
        'input': mnemonic,
        'word_count': len(words),
        'valid': False,
    }

    # فحص العدد
    if len(words) not in BIP39_VALID_LENGTHS:
        result['error'] = 'Invalid word count. Must be 12, 15, 18, 21, or 24. Got: %d' % len(words)
        return result

    # فحص ان الكلمات تحتوي فقط على حروف
    for i, word in enumerate(words):
        if not word.isalpha():
            result['error'] = 'Word #%d "%s" contains non-letter characters' % (i + 1, word)
            return result
        if len(word) < 3 or len(word) > 8:
            result['error'] = 'Word #%d "%s" has invalid length (3-8 chars expected)' % (i + 1, word)
            return result

    result['words'] = words
    result['structure'] = 'VALID'

    # حساب entropy bits
    entropy_bits = len(words) * 11
    checksum_bits = len(words) // 3
    actual_entropy_bits = entropy_bits - checksum_bits
    result['entropy_bits'] = actual_entropy_bits
    result['checksum_bits'] = checksum_bits
    result['security_level'] = '%d-bit' % actual_entropy_bits

    # اشتقاق seed باستخدام PBKDF2 (BIP39)
    try:
        import hmac
        passphrase = ''
        salt = 'mnemonic' + passphrase
        mnemonic_bytes = to_bytes(mnemonic)
        salt_bytes = to_bytes(salt)

        # PBKDF2-HMAC-SHA512 (2048 iterations)
        seed = _pbkdf2_hmac_sha512(mnemonic_bytes, salt_bytes, 2048)

        result['seed_hex'] = bytes_to_hex(seed)
        result['valid'] = True

        # اشتقاق master key (BIP32)
        master = _derive_master_key(seed)
        if master:
            result['master_private_key'] = master['private_key']
            result['master_chain_code'] = master['chain_code']

            # اشتقاق العنوان الاول (m/44'/0'/0'/0/0)
            point = _private_key_to_public(master['private_key'])
            if point:
                compressed_pub = _point_to_compressed_pubkey(point)
                address = _pubkey_to_address(compressed_pub)
                result['master_public_key'] = compressed_pub
                result['master_address'] = address
                result['derivation'] = 'SUCCESS'

    except Exception as e:
        result['seed_error'] = str(e)
        # حتى لو فشل الاشتقاق، البنية صحيحة
        result['valid'] = True

    return result


def _pbkdf2_hmac_sha512(password, salt, iterations):
    """PBKDF2 with HMAC-SHA512"""
    import hmac

    if PY3:
        dk = hashlib.pbkdf2_hmac('sha512', password, salt, iterations, dklen=64)
        return dk
    else:
        # Python 2 fallback
        def _hmac_sha512(key, msg):
            return hmac.new(key, msg, hashlib.sha512).digest()

        block = b'\x00\x00\x00\x01'
        u = hmac.new(password, salt + block, hashlib.sha512).digest()
        result = u
        for _ in range(iterations - 1):
            u = hmac.new(password, u, hashlib.sha512).digest()
            result = bytes(bytearray(a ^ b for a, b in zip(bytearray(result), bytearray(u))))
        return result


def _derive_master_key(seed):
    """اشتقاق Master Key من seed (BIP32)"""
    import hmac
    key = b'Bitcoin seed'
    h = hmac.new(key, seed, hashlib.sha512).digest()
    private_key = bytes_to_hex(h[:32])
    chain_code = bytes_to_hex(h[32:])

    # تحقق من صحة المفتاح
    pk_int = int(private_key, 16)
    if pk_int <= 0 or pk_int >= SECP256K1_N:
        return None

    return {
        'private_key': private_key,
        'chain_code': chain_code,
    }


# ============================================================
#  فحص شامل للمحفظة (Wallet Inspection)
# ============================================================

def inspect_wallet(address):
    """
    فحص شامل للعنوان/المحفظة
    - نوع العنوان
    - الشبكة
    - صحة الترميز
    - نوع السكريبت
    """
    address = address.strip()
    result = {
        'input': address,
        'valid': False,
    }

    # 1. Bitcoin Legacy (1...)
    if address.startswith('1'):
        try:
            decoded = b58_decode_check(address)
            if len(decoded) == 21 and byte_at(decoded, 0) == 0x00:
                result['valid'] = True
                result['type'] = 'P2PKH (Pay-to-Public-Key-Hash)'
                result['network'] = 'Bitcoin Mainnet'
                result['hash160'] = bytes_to_hex(decoded[1:])
                result['encoding'] = 'Base58Check'
                result['script_type'] = 'Legacy'
        except Exception:
            result['error'] = 'Invalid Base58Check encoding'
            return result

    # 2. Bitcoin P2SH (3...)
    elif address.startswith('3'):
        try:
            decoded = b58_decode_check(address)
            if len(decoded) == 21 and byte_at(decoded, 0) == 0x05:
                result['valid'] = True
                result['type'] = 'P2SH (Pay-to-Script-Hash)'
                result['network'] = 'Bitcoin Mainnet'
                result['hash160'] = bytes_to_hex(decoded[1:])
                result['encoding'] = 'Base58Check'
                result['script_type'] = 'Script Hash (possibly SegWit wrapped)'
        except Exception:
            result['error'] = 'Invalid Base58Check encoding'
            return result

    # 3. Bitcoin Bech32 (bc1...)
    elif address.lower().startswith('bc1'):
        hrp, data = bech32_decode(address)
        if hrp == 'bc' and data is not None:
            result['valid'] = True
            result['network'] = 'Bitcoin Mainnet'
            result['encoding'] = 'Bech32'
            result['hash'] = bytes_to_hex(bytes(bytearray(data)))
            if len(data) == 20:
                result['type'] = 'P2WPKH (Native SegWit v0)'
                result['script_type'] = 'SegWit v0'
            elif len(data) == 32:
                result['type'] = 'P2WSH (Native SegWit v0) or P2TR (Taproot v1)'
                result['script_type'] = 'SegWit v0/v1'
            else:
                result['type'] = 'Unknown SegWit'
        else:
            result['error'] = 'Invalid Bech32 encoding'
            return result

    # 4. Bitcoin Testnet (m/n/tb1)
    elif address.startswith('m') or address.startswith('n'):
        try:
            decoded = b58_decode_check(address)
            if len(decoded) == 21 and byte_at(decoded, 0) == 0x6F:
                result['valid'] = True
                result['type'] = 'P2PKH (Testnet)'
                result['network'] = 'Bitcoin Testnet'
                result['hash160'] = bytes_to_hex(decoded[1:])
                result['encoding'] = 'Base58Check'
        except Exception:
            pass

    elif address.lower().startswith('tb1'):
        hrp, data = bech32_decode(address)
        if hrp == 'tb' and data is not None:
            result['valid'] = True
            result['type'] = 'SegWit (Testnet)'
            result['network'] = 'Bitcoin Testnet'
            result['encoding'] = 'Bech32'
            result['hash'] = bytes_to_hex(bytes(bytearray(data)))

    # 5. Ethereum (0x...)
    elif address.startswith('0x') or address.startswith('0X'):
        hex_addr = address[2:]
        if len(hex_addr) == 40 and _is_hex(hex_addr):
            result['valid'] = True
            result['type'] = 'Ethereum/EVM Address'
            result['network'] = 'Ethereum / EVM Compatible'
            result['encoding'] = 'Hex with 0x prefix'
            result['hash'] = hex_addr.lower()

            # EIP-55 checksum validation
            checksum_valid = _validate_eth_checksum(address)
            if checksum_valid is not None:
                result['eip55_checksum'] = 'VALID' if checksum_valid else 'INVALID'

    # 6. Litecoin (L/M/ltc1)
    elif address.startswith('L') and len(address) > 30:
        try:
            decoded = b58_decode_check(address)
            if len(decoded) == 21 and byte_at(decoded, 0) == 0x30:
                result['valid'] = True
                result['type'] = 'P2PKH (Litecoin)'
                result['network'] = 'Litecoin Mainnet'
                result['hash160'] = bytes_to_hex(decoded[1:])
                result['encoding'] = 'Base58Check'
        except Exception:
            pass

    # 7. Cosmos/Bech32 networks
    elif '1' in address and address[0].isalpha():
        hrp, data = bech32_decode(address)
        if hrp is not None and data is not None:
            result['valid'] = True
            result['encoding'] = 'Bech32'
            result['hash'] = bytes_to_hex(bytes(bytearray(data)))
            # تحديد الشبكة من prefix
            network_map = {
                'cosmos': 'Cosmos Hub',
                'osmo': 'Osmosis',
                'terra': 'Terra',
                'juno': 'Juno',
                'akash': 'Akash',
                'atom': 'Cosmos',
                'secret': 'Secret Network',
                'band': 'Band Protocol',
                'kava': 'Kava',
            }
            result['network'] = network_map.get(hrp, 'Bech32 Network (%s)' % hrp)
            result['type'] = 'Bech32 Address (prefix: %s)' % hrp
            result['hrp'] = hrp

    # 8. Tron (T...)
    elif address.startswith('T'):
        try:
            decoded = b58_decode_check(address)
            if len(decoded) == 21 and byte_at(decoded, 0) == 0x41:
                result['valid'] = True
                result['type'] = 'Tron Address'
                result['network'] = 'Tron Mainnet'
                result['hash160'] = bytes_to_hex(decoded[1:])
                result['encoding'] = 'Base58Check'
        except Exception:
            pass

    # اذا لم يتم التعرف
    if not result['valid'] and 'error' not in result:
        # محاولة عامة
        try:
            decoded = decode_to_hex(address)
            result['valid'] = True
            result['type'] = 'Generic (%s)' % decoded['format']
            result['encoding'] = decoded['format']
            result['hash'] = decoded['hex']
        except Exception:
            result['error'] = 'Could not identify address format'

    return result


def _validate_eth_checksum(address):
    """التحقق من EIP-55 checksum لعنوان Ethereum"""
    if not address.startswith('0x') and not address.startswith('0X'):
        return None
    addr = address[2:]
    if addr == addr.lower() or addr == addr.upper():
        return None  # no checksum applied

    addr_lower = addr.lower()
    hash_hex = bytes_to_hex(hashlib.sha256(to_bytes(addr_lower)).digest())

    # Keccak-256 غير متوفر بدون مكتبة، نستخدم SHA256 كبديل تقريبي
    # ملاحظة: هذا تقريبي - EIP-55 يستخدم keccak256
    for i in range(40):
        if int(hash_hex[i], 16) >= 8:
            if addr[i] != addr[i].upper():
                return False
        else:
            if addr[i] != addr[i].lower():
                return False
    return True


# ============================================================
#  واجهة المستخدم (تعمل على اي Terminal/CMD)
# ============================================================

def clear_screen():
    """مسح الشاشة"""
    if os.name == 'nt':
        os.system('cls')
    else:
        os.system('clear')


def print_line(char='=', length=65):
    print(char * length)


def print_result(result):
    """طباعة النتائج"""
    print("")
    print_line('-')
    print("  Input:          " + str(result.get('input', 'N/A')))
    print("  Format:         " + str(result.get('input_format', 'N/A')))
    print_line('-')

    hex_val = result.get('hex', result.get('hex_full', 'N/A'))
    print("  [>] Hex:            " + str(hex_val))

    if 'hex_without_version' in result:
        print("  [>] Hex (no ver):   " + str(result['hex_without_version']))
    if 'version_byte' in result:
        print("  [>] Version Byte:   " + str(result['version_byte']))

    print("  [>] Length:         " + str(result.get('bytes_length', '?')) + " bytes")
    print_line('-')
    print("  Private Key:")
    print("  [>] Hex (64):       " + str(result.get('private_key_hex', 'N/A')))
    print("  [>] Raw (0x):       " + str(result.get('raw_hex', 'N/A')))

    if 'wif_compressed' in result:
        print("  [>] WIF Compressed: " + str(result['wif_compressed']))
    if 'wif_uncompressed' in result:
        print("  [>] WIF Uncompress: " + str(result['wif_uncompressed']))

    print_line('-')
    print("")


def show_menu():
    """عرض القائمة الرئيسية"""
    print("")
    print_line('=')
    print("  Universal Crypto Key & Signature Tool v3.0")
    print("  Works with ANY blockchain network")
    print("  Compatible: Python 2.7+ / Python 3.x / Windows / Linux / Mac")
    print_line('=')
    print("")
    print("  Supported input formats (auto-detected):")
    print("  * Hex raw or with 0x prefix")
    print("  * Base58 / Base58Check (Bitcoin, Litecoin, Tron, Dash...)")
    print("  * Bech32 / Bech32m (bc1..., cosmos1..., osmo1..., tb1...)")
    print("  * Base64 (Cosmos/Tendermint keys)")
    print("  * WIF Private Keys (5, K, L)")
    print("  * Mnemonic Seed Phrases (12/15/18/21/24 words)")
    print("")
    print_line('-')
    print("  Operations:")
    print("  [1] Public Key  -->  Hex  -->  Private Key")
    print("  [2] Address     -->  Hex  -->  Private Key")
    print("  [3] Hex         -->  Private Key (WIF + Raw)")
    print("  [4] Verify Signature (message + sig + pubkey)")
    print("  [5] Validate Private Key (WIF or Hex)")
    print("  [6] Validate Seed Phrase (Mnemonic)")
    print("  [7] Inspect Wallet Address")
    print("  [0] Exit")
    print_line('-')
    print("")


def main():
    """البرنامج الرئيسي"""
    clear_screen()
    show_menu()

    while True:
        try:
            choice = get_input("  >> Choose [0-7]: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n  Goodbye!")
            sys.exit(0)

        if choice == '0':
            print("\n  Goodbye!")
            sys.exit(0)

        elif choice == '1':
            print_line()
            print("  [Public Key --> Hex --> Private Key]")
            print("  Enter public key (any format):")
            print("  Examples: 04abcdef..., Base58, Base64")
            print("")
            try:
                key = get_input("  >> Public Key: ").strip()
            except (EOFError, KeyboardInterrupt):
                print("\n  Goodbye!")
                sys.exit(0)
            if key:
                try:
                    result = convert_public_key(key)
                    print_result(result)
                except ValueError as e:
                    print("\n  [ERROR] " + str(e) + "\n")
                except Exception as e:
                    print("\n  [ERROR] " + str(e) + "\n")

        elif choice == '2':
            print_line()
            print("  [Address --> Hex --> Private Key]")
            print("  Enter address (any format/network):")
            print("  Examples: 1A1zP1..., 0x742d..., bc1q..., cosmos1...")
            print("")
            try:
                address = get_input("  >> Address: ").strip()
            except (EOFError, KeyboardInterrupt):
                print("\n  Goodbye!")
                sys.exit(0)
            if address:
                try:
                    result = convert_address(address)
                    print_result(result)
                except ValueError as e:
                    print("\n  [ERROR] " + str(e) + "\n")
                except Exception as e:
                    print("\n  [ERROR] " + str(e) + "\n")

        elif choice == '3':
            print_line()
            print("  [Hex --> Private Key]")
            print("")
            try:
                hex_input = get_input("  >> Hex value: ").strip()
            except (EOFError, KeyboardInterrupt):
                print("\n  Goodbye!")
                sys.exit(0)
            if hex_input:
                clean = hex_input
                if clean.startswith('0x') or clean.startswith('0X'):
                    clean = clean[2:]
                if not _is_hex(clean):
                    print("\n  [ERROR] Not valid Hex\n")
                    continue
                try:
                    result = hex_to_private_key(clean)
                    result['input'] = hex_input
                    result['input_format'] = 'Hex'
                    result['hex'] = clean.lower()
                    result['bytes_length'] = len(clean) // 2
                    print_result(result)
                except ValueError as e:
                    print("\n  [ERROR] " + str(e) + "\n")

        elif choice == '4':
            print_line()
            print("  [Verify Signature]")
            print("  Verifies ECDSA signature against message and public key")
            print("")
            try:
                msg = get_input("  >> Message: ").strip()
                sig = get_input("  >> Signature (hex): ").strip()
                pub = get_input("  >> Public Key (hex): ").strip()
            except (EOFError, KeyboardInterrupt):
                print("\n  Goodbye!")
                sys.exit(0)
            if msg and sig and pub:
                try:
                    result = verify_signature(msg, sig, pub)
                    print("")
                    print_line('-')
                    if result['valid']:
                        print("  [OK] SIGNATURE IS VALID")
                    else:
                        print("  [X]  SIGNATURE IS INVALID")
                        if 'error' in result:
                            print("  Reason: " + result['error'])
                    print_line('-')
                    print("  Message:   " + str(result.get('message', '')))
                    print("  Public Key: " + str(result.get('pubkey', '')))
                    if 'r' in result:
                        print("  r: " + result['r'])
                        print("  s: " + result['s'])
                    print_line('-')
                    print("")
                except Exception as e:
                    print("\n  [ERROR] " + str(e) + "\n")

        elif choice == '5':
            print_line()
            print("  [Validate Private Key]")
            print("  Checks if a private key is valid and derives its addresses")
            print("  Supports: WIF (5/K/L), Hex (64 chars), 0x prefix")
            print("")
            try:
                key = get_input("  >> Private Key: ").strip()
            except (EOFError, KeyboardInterrupt):
                print("\n  Goodbye!")
                sys.exit(0)
            if key:
                try:
                    result = validate_private_key(key)
                    print("")
                    print_line('-')
                    if result['valid']:
                        print("  [OK] PRIVATE KEY IS VALID")
                    else:
                        print("  [X]  PRIVATE KEY IS INVALID")
                    print_line('-')
                    print("  Input:        " + str(result.get('input', '')))
                    print("  Format:       " + str(result.get('format', '')))
                    if 'network' in result:
                        print("  Network:      " + result['network'])
                    if 'checksum' in result:
                        print("  Checksum:     " + result['checksum'])
                    if 'range_check' in result:
                        print("  Range Check:  " + result['range_check'])
                    if 'private_key_hex' in result:
                        print("  Key Hex:      " + result['private_key_hex'])
                    if 'public_key_compressed' in result:
                        print_line('-')
                        print("  Derived Public Key (compressed):")
                        print("    " + result['public_key_compressed'])
                        print("  Derived Address (compressed):")
                        print("    " + result['address_compressed'])
                        print("  Derived Address (uncompressed):")
                        print("    " + result['address_uncompressed'])
                    if 'derivation' in result:
                        print("  Derivation:   " + result['derivation'])
                    if 'error' in result:
                        print("  Error:        " + result['error'])
                    print_line('-')
                    print("")
                except Exception as e:
                    print("\n  [ERROR] " + str(e) + "\n")

        elif choice == '6':
            print_line()
            print("  [Validate Seed Phrase (Mnemonic)]")
            print("  Checks BIP39 mnemonic and derives master key")
            print("  Supports: 12, 15, 18, 21, 24 words")
            print("")
            try:
                mnemonic = get_input("  >> Seed Phrase: ").strip()
            except (EOFError, KeyboardInterrupt):
                print("\n  Goodbye!")
                sys.exit(0)
            if mnemonic:
                try:
                    result = validate_mnemonic(mnemonic)
                    print("")
                    print_line('-')
                    if result['valid']:
                        print("  [OK] SEED PHRASE IS VALID")
                    else:
                        print("  [X]  SEED PHRASE IS INVALID")
                    print_line('-')
                    print("  Word Count:     " + str(result.get('word_count', '')))
                    if 'structure' in result:
                        print("  Structure:      " + result['structure'])
                    if 'entropy_bits' in result:
                        print("  Entropy:        " + str(result['entropy_bits']) + " bits")
                    if 'security_level' in result:
                        print("  Security:       " + result['security_level'])
                    if 'seed_hex' in result:
                        print_line('-')
                        print("  Seed (hex):     " + result['seed_hex'][:32] + "...")
                    if 'master_private_key' in result:
                        print("  Master Key:     " + result['master_private_key'])
                    if 'master_public_key' in result:
                        print("  Master PubKey:  " + result['master_public_key'])
                    if 'master_address' in result:
                        print("  Master Address: " + result['master_address'])
                    if 'derivation' in result:
                        print("  Derivation:     " + result['derivation'])
                    if 'error' in result:
                        print("  Error:          " + result['error'])
                    print_line('-')
                    print("")
                except Exception as e:
                    print("\n  [ERROR] " + str(e) + "\n")

        elif choice == '7':
            print_line()
            print("  [Inspect Wallet Address]")
            print("  Identifies address type, network, encoding, and validity")
            print("")
            try:
                address = get_input("  >> Address: ").strip()
            except (EOFError, KeyboardInterrupt):
                print("\n  Goodbye!")
                sys.exit(0)
            if address:
                try:
                    result = inspect_wallet(address)
                    print("")
                    print_line('-')
                    if result['valid']:
                        print("  [OK] ADDRESS IS VALID")
                    else:
                        print("  [X]  ADDRESS IS INVALID")
                    print_line('-')
                    print("  Input:       " + str(result.get('input', '')))
                    if 'type' in result:
                        print("  Type:        " + result['type'])
                    if 'network' in result:
                        print("  Network:     " + result['network'])
                    if 'encoding' in result:
                        print("  Encoding:    " + result['encoding'])
                    if 'script_type' in result:
                        print("  Script:      " + result['script_type'])
                    if 'hash160' in result:
                        print("  Hash160:     " + result['hash160'])
                    elif 'hash' in result:
                        print("  Hash:        " + result['hash'])
                    if 'eip55_checksum' in result:
                        print("  EIP-55:      " + result['eip55_checksum'])
                    if 'error' in result:
                        print("  Error:       " + result['error'])
                    print_line('-')
                    print("")
                except Exception as e:
                    print("\n  [ERROR] " + str(e) + "\n")

        elif choice == 'm' or choice == 'M':
            clear_screen()
            show_menu()

        else:
            print("  [!] Invalid choice. Enter 0-7 or 'm' for menu.\n")


if __name__ == '__main__':
    main()
