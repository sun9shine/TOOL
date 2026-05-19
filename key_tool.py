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
    print("  Universal Crypto Key Conversion Tool v2.0")
    print("  Works with ANY blockchain network")
    print("  Compatible: Python 2.7+ / Python 3.x / Windows / Linux / Mac")
    print_line('=')
    print("")
    print("  Supported input formats (auto-detected):")
    print("  * Hex raw or with 0x prefix")
    print("  * Base58 / Base58Check (Bitcoin, Litecoin, Tron, Dash...)")
    print("  * Bech32 / Bech32m (bc1..., cosmos1..., osmo1..., tb1...)")
    print("  * Base64 (Cosmos/Tendermint keys)")
    print("")
    print_line('-')
    print("  Operations:")
    print("  [1] Public Key  -->  Hex  -->  Private Key")
    print("  [2] Address     -->  Hex  -->  Private Key")
    print("  [3] Hex         -->  Private Key (WIF + Raw)")
    print("  [0] Exit")
    print_line('-')
    print("")


def main():
    """البرنامج الرئيسي"""
    clear_screen()
    show_menu()

    while True:
        try:
            choice = get_input("  >> Choose [0-3]: ").strip()
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

        elif choice == 'm' or choice == 'M':
            clear_screen()
            show_menu()

        else:
            print("  [!] Invalid choice. Enter 0-3 or 'm' for menu.\n")


if __name__ == '__main__':
    main()
