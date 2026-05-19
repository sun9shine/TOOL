#!/usr/bin/env python3
"""
أداة تحويل المفاتيح العامة والعناوين إلى Hex ثم إلى المفتاح الخاص
Universal Key Conversion Tool - يعمل مع أي شبكة بلوكشين

الوظائف:
1. تحويل المفتاح العام (Public Key) من أي صيغة إلى Hex
2. تحويل العنوان (Address) من أي صيغة إلى Hex
3. تحويل الـ Hex الناتج إلى مفتاح خاص (WIF / Raw)
"""

import hashlib
import base64
import binascii
import sys

try:
    import base58
except ImportError:
    print("يرجى تثبيت base58: pip install base58")
    sys.exit(1)


# ============================================================
#  أدوات فك الترميز العامة (تدعم أي شبكة)
# ============================================================

def decode_to_hex(input_str: str) -> dict:
    """
    فك ترميز أي مدخل (مفتاح عام / عنوان) إلى Hex
    يدعم جميع الصيغ المعروفة:
    - Hex مباشر
    - Base58 (Bitcoin, Litecoin, Dash, etc.)
    - Base58Check (مع checksum)
    - Base64 (Cosmos, Tendermint, etc.)
    - Bech32 / Bech32m (Bitcoin SegWit, Cosmos, etc.)
    - Hex مع بادئة 0x (Ethereum, BSC, etc.)
    """
    input_str = input_str.strip()
    results = {}

    # 1. إذا كان يبدأ بـ 0x (Ethereum style)
    if input_str.startswith('0x') or input_str.startswith('0X'):
        hex_clean = input_str[2:]
        if all(c in '0123456789abcdefABCDEF' for c in hex_clean):
            results['format'] = 'Hex (0x prefix)'
            results['hex'] = hex_clean.lower()
            results['bytes_length'] = len(hex_clean) // 2
            return results

    # 2. إذا كان Hex خام (فقط أحرف hex)
    if all(c in '0123456789abcdefABCDEF' for c in input_str) and len(input_str) >= 2:
        results['format'] = 'Hex (raw)'
        results['hex'] = input_str.lower()
        results['bytes_length'] = len(input_str) // 2
        return results

    # 3. محاولة فك Bech32 / Bech32m (bc1, tb1, cosmos1, osmo1, etc.)
    try:
        hrp, data = bech32_decode(input_str)
        if hrp is not None and data is not None:
            hex_data = bytes(data).hex()
            results['format'] = f'Bech32 (prefix: {hrp})'
            results['hex'] = hex_data
            results['bytes_length'] = len(data)
            results['hrp'] = hrp
            return results
    except Exception:
        pass

    # 4. محاولة فك Base58Check (مع checksum - Bitcoin, Litecoin, etc.)
    try:
        decoded = base58.b58decode_check(input_str)
        results['format'] = 'Base58Check'
        results['hex'] = decoded.hex()
        results['hex_without_version'] = decoded[1:].hex()
        results['version_byte'] = f'0x{decoded[0]:02x}'
        results['bytes_length'] = len(decoded)
        return results
    except Exception:
        pass

    # 5. محاولة فك Base58 (بدون checksum)
    try:
        decoded = base58.b58decode(input_str)
        if len(decoded) >= 20:  # على الأقل حجم معقول
            results['format'] = 'Base58'
            results['hex'] = decoded.hex()
            results['bytes_length'] = len(decoded)
            return results
    except Exception:
        pass

    # 6. محاولة فك Base64
    try:
        decoded = base64.b64decode(input_str)
        if len(decoded) >= 20:  # على الأقل حجم معقول
            results['format'] = 'Base64'
            results['hex'] = decoded.hex()
            results['bytes_length'] = len(decoded)
            return results
    except Exception:
        pass

    raise ValueError(f"لم أتمكن من فك ترميز المدخل. الصيغ المدعومة: Hex, 0x, Base58, Base58Check, Base64, Bech32")


# ============================================================
#  Bech32 Decoder (يدعم أي prefix/شبكة)
# ============================================================

BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def bech32_polymod(values):
    """Internal function that computes the Bech32 checksum."""
    generator = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for value in values:
        top = chk >> 25
        chk = (chk & 0x1ffffff) << 5 ^ value
        for i in range(5):
            chk ^= generator[i] if ((top >> i) & 1) else 0
    return chk


def bech32_hrp_expand(hrp):
    """Expand the HRP into values for checksum computation."""
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def bech32_verify_checksum(hrp, data):
    """Verify a Bech32 checksum."""
    return bech32_polymod(bech32_hrp_expand(hrp) + data) == 1


def bech32m_verify_checksum(hrp, data):
    """Verify a Bech32m checksum."""
    return bech32_polymod(bech32_hrp_expand(hrp) + data) == 0x2bc830a3


def bech32_decode(bech):
    """Decode a Bech32/Bech32m string. Returns (hrp, data_bytes)."""
    if any(ord(x) < 33 or ord(x) > 126 for x in bech):
        return (None, None)
    if bech.lower() != bech and bech.upper() != bech:
        return (None, None)
    bech = bech.lower()
    pos = bech.rfind('1')
    if pos < 1 or pos + 7 > len(bech):
        return (None, None)
    if not all(x in BECH32_CHARSET for x in bech[pos+1:]):
        return (None, None)
    hrp = bech[:pos]
    data = [BECH32_CHARSET.find(x) for x in bech[pos+1:]]

    # Try Bech32 first, then Bech32m
    is_valid = False
    if bech32_verify_checksum(hrp, data):
        is_valid = True
    elif bech32m_verify_checksum(hrp, data):
        is_valid = True

    if is_valid:
        # Remove checksum (last 6 values)
        payload = data[:-6]
        if len(payload) < 1:
            return (None, None)
        # First value is the witness version (for segwit) or just data
        # Convert remaining 5-bit groups to 8-bit bytes
        witness_ver = payload[0]
        converted = convertbits(payload[1:], 5, 8, False)
        if converted is None:
            # Try without skipping first byte (non-segwit bech32)
            converted = convertbits(payload, 5, 8, False)
            if converted is None:
                return (None, None)
            return (hrp, converted)
        # Include witness version info in the returned data
        return (hrp, converted)

    return (None, None)


def convertbits(data, frombits, tobits, pad=True):
    """General power-of-2 base conversion."""
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


# ============================================================
#  تحويل Hex إلى مفتاح خاص
# ============================================================

def hex_to_wif(hex_key: str, version_byte: int = 0x80, compressed: bool = True) -> str:
    """
    تحويل Hex إلى مفتاح خاص بصيغة WIF
    version_byte: 0x80 = Bitcoin mainnet, 0xEF = testnet, etc.
    """
    hex_key = hex_key.strip().lower()

    # التأكد من الطول 64 حرف (32 bytes)
    if len(hex_key) > 64:
        hex_key = hex_key[:64]
    elif len(hex_key) < 64:
        hex_key = hex_key.ljust(64, '0')

    key_bytes = bytes([version_byte]) + bytes.fromhex(hex_key)

    if compressed:
        key_bytes += b'\x01'

    checksum = hashlib.sha256(hashlib.sha256(key_bytes).digest()).digest()[:4]
    wif = base58.b58encode(key_bytes + checksum).decode('utf-8')
    return wif


def hex_to_private_key(hex_input: str) -> dict:
    """
    تحويل أي Hex إلى مفتاح خاص بعدة صيغ
    """
    hex_input = hex_input.strip().lower()

    # تنظيف
    if hex_input.startswith('0x'):
        hex_input = hex_input[2:]

    # ضمان الطول 64
    if len(hex_input) > 64:
        private_hex = hex_input[:64]
    elif len(hex_input) < 64:
        private_hex = hex_input.ljust(64, '0')
    else:
        private_hex = hex_input

    result = {
        'private_key_hex': private_hex,
        'private_key_bytes': bytes.fromhex(private_hex),
    }

    # WIF بصيغ مختلفة
    try:
        result['wif_compressed'] = hex_to_wif(private_hex, 0x80, True)
        result['wif_uncompressed'] = hex_to_wif(private_hex, 0x80, False)
    except Exception:
        pass

    # صيغة Raw bytes (لـ Ethereum وغيرها)
    result['raw_hex'] = '0x' + private_hex
    result['raw_bytes_64'] = private_hex

    return result


# ============================================================
#  الدالة الرئيسية: تحويل كامل
# ============================================================

def convert_public_key(public_key: str) -> dict:
    """
    تحويل المفتاح العام إلى Hex ثم إلى مفتاح خاص
    """
    decoded = decode_to_hex(public_key)
    hex_value = decoded['hex']

    result = {
        'input': public_key,
        'input_format': decoded['format'],
        'hex': hex_value,
        'bytes_length': decoded.get('bytes_length', len(hex_value) // 2),
    }

    # تحويل الـ Hex إلى مفتاح خاص
    private = hex_to_private_key(hex_value)
    result.update(private)

    return result


def convert_address(address: str) -> dict:
    """
    تحويل العنوان إلى Hex ثم إلى مفتاح خاص
    """
    decoded = decode_to_hex(address)
    hex_value = decoded['hex']

    result = {
        'input': address,
        'input_format': decoded['format'],
        'hex_full': hex_value,
        'bytes_length': decoded.get('bytes_length', len(hex_value) // 2),
    }

    # إذا كان هناك version byte
    if 'hex_without_version' in decoded:
        result['hex_without_version'] = decoded['hex_without_version']
        result['version_byte'] = decoded['version_byte']
        # استخدم الـ hex بدون version byte
        hex_for_key = decoded['hex_without_version']
    else:
        hex_for_key = hex_value

    # تحويل إلى مفتاح خاص
    private = hex_to_private_key(hex_for_key)
    result.update(private)

    return result


# ============================================================
#  واجهة المستخدم
# ============================================================

def print_separator():
    print("=" * 65)


def print_result(result: dict):
    """طباعة النتائج بشكل منظم"""
    print(f"\n{'─' * 65}")
    print(f"  المدخل:          {result.get('input', 'N/A')}")
    print(f"  الصيغة المكتشفة: {result.get('input_format', 'N/A')}")
    print(f"{'─' * 65}")
    print(f"  ➜ Hex الكامل:    {result.get('hex', result.get('hex_full', 'N/A'))}")
    if 'hex_without_version' in result:
        print(f"  ➜ Hex (بدون version): {result['hex_without_version']}")
    if 'version_byte' in result:
        print(f"  ➜ Version Byte:  {result['version_byte']}")
    print(f"  ➜ الطول:         {result.get('bytes_length', '?')} bytes")
    print(f"{'─' * 65}")
    print(f"  المفتاح الخاص (Private Key):")
    print(f"  ➜ Hex (64 char):      {result.get('private_key_hex', 'N/A')}")
    print(f"  ➜ Raw (0x):           {result.get('raw_hex', 'N/A')}")
    if 'wif_compressed' in result:
        print(f"  ➜ WIF Compressed:     {result['wif_compressed']}")
    if 'wif_uncompressed' in result:
        print(f"  ➜ WIF Uncompressed:   {result['wif_uncompressed']}")
    print(f"{'─' * 65}")
    print()


def main():
    print()
    print_separator()
    print("  Universal Crypto Key Conversion Tool")
    print("  أداة تحويل المفاتيح العامة والعناوين إلى Hex → Private Key")
    print("  تعمل مع أي شبكة بلوكشين (Bitcoin, Ethereum, Cosmos, etc.)")
    print_separator()
    print()
    print("  الصيغ المدعومة للمدخلات:")
    print("  • Hex خام أو بـ 0x")
    print("  • Base58 / Base58Check (Bitcoin, Litecoin, Dash...)")
    print("  • Bech32 / Bech32m (bc1..., cosmos1..., osmo1...)")
    print("  • Base64 (Cosmos/Tendermint public keys)")
    print()
    print("  العمليات المتاحة:")
    print("  1. تحويل المفتاح العام (Public Key) → Hex → Private Key")
    print("  2. تحويل العنوان (Address) → Hex → Private Key")
    print("  3. تحويل Hex مباشر → Private Key")
    print("  0. خروج")
    print()

    while True:
        try:
            choice = input("  ▶ اختر العملية [0-3]: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n  مع السلامة! 👋")
            break

        if choice == '0':
            print("  مع السلامة! 👋")
            break

        elif choice == '1':
            print_separator()
            print("  [تحويل المفتاح العام → Hex → Private Key]")
            print("  أمثلة:")
            print("  • 04678afdb0fe5548... (Hex uncompressed)")
            print("  • 02678afdb0fe5548... (Hex compressed)")
            print("  • Base58 public key")
            print("  • Base64 encoded key")
            print()
            key = input("  أدخل المفتاح العام: ").strip()
            if key:
                try:
                    result = convert_public_key(key)
                    print_result(result)
                except ValueError as e:
                    print(f"\n  ❌ خطأ: {e}\n")

        elif choice == '2':
            print_separator()
            print("  [تحويل العنوان → Hex → Private Key]")
            print("  أمثلة:")
            print("  • 1A1zP1eP5QGefi2D... (Bitcoin Base58)")
            print("  • 0x742d35Cc6634... (Ethereum)")
            print("  • bc1qw508d6qe... (Bitcoin Bech32)")
            print("  • cosmos1xyz... (Cosmos Bech32)")
            print()
            address = input("  أدخل العنوان: ").strip()
            if address:
                try:
                    result = convert_address(address)
                    print_result(result)
                except ValueError as e:
                    print(f"\n  ❌ خطأ: {e}\n")

        elif choice == '3':
            print_separator()
            print("  [تحويل Hex مباشر → Private Key]")
            print()
            hex_input = input("  أدخل الـ Hex: ").strip()
            if hex_input:
                try:
                    # تنظيف
                    clean = hex_input.replace('0x', '').replace('0X', '')
                    if not all(c in '0123456789abcdefABCDEF' for c in clean):
                        print(f"\n  ❌ خطأ: المدخل ليس Hex صالح\n")
                        continue
                    result = hex_to_private_key(clean)
                    result['input'] = hex_input
                    result['input_format'] = 'Hex'
                    result['hex'] = clean.lower()
                    result['bytes_length'] = len(clean) // 2
                    print_result(result)
                except ValueError as e:
                    print(f"\n  ❌ خطأ: {e}\n")

        else:
            print("  ❌ اختيار غير صحيح.\n")


if __name__ == '__main__':
    main()
