#!/usr/bin/env python3
"""
أداة تحويل المفاتيح والعناوين (Bitcoin/Crypto Key Conversion Tool)

الوظائف:
1. تحويل المفتاح العام (Public Key) إلى Hex
2. تحويل المفتاح الخاص (Private Key) إلى Hex
3. تحويل العنوان (Address) إلى Hex ثم إلى مفتاح خاص
"""

import hashlib
import base58
import binascii
import sys


def public_key_to_hex(public_key: str) -> str:
    """
    تحويل المفتاح العام إلى Hex
    يدعم:
    - المفتاح العام المضغوط (Compressed) - 33 bytes
    - المفتاح العام غير المضغوط (Uncompressed) - 65 bytes
    - صيغة Base58
    """
    # إذا كان المفتاح بالفعل hex
    if all(c in '0123456789abcdefABCDEF' for c in public_key):
        return public_key.lower()

    # محاولة فك Base58
    try:
        decoded = base58.b58decode(public_key)
        return decoded.hex()
    except Exception:
        pass

    # محاولة فك Base58Check
    try:
        decoded = base58.b58decode_check(public_key)
        return decoded.hex()
    except Exception:
        pass

    raise ValueError("صيغة المفتاح العام غير معروفة")


def private_key_to_hex(private_key: str) -> str:
    """
    تحويل المفتاح الخاص إلى Hex
    يدعم:
    - WIF (Wallet Import Format) - يبدأ بـ 5, K, أو L
    - WIF مضغوط (Compressed WIF)
    - Hex مباشر
    """
    # إذا كان المفتاح بالفعل hex (64 حرف = 32 bytes)
    if len(private_key) == 64 and all(c in '0123456789abcdefABCDEF' for c in private_key):
        return private_key.lower()

    # تحويل من WIF إلى Hex
    try:
        decoded = base58.b58decode_check(private_key)
        # أول بايت هو version byte (0x80 للشبكة الرئيسية)
        if decoded[0] == 0x80:
            # WIF غير مضغوط (37 bytes total: 1 version + 32 key + 4 checksum)
            if len(decoded) == 33:
                return decoded[1:].hex()
            # WIF مضغوط (38 bytes total: 1 version + 32 key + 1 compression flag + 4 checksum)
            elif len(decoded) == 34:
                return decoded[1:33].hex()
        # شبكة تجريبية (testnet) - version byte 0xEF
        elif decoded[0] == 0xEF:
            if len(decoded) == 33:
                return decoded[1:].hex()
            elif len(decoded) == 34:
                return decoded[1:33].hex()
    except Exception:
        pass

    raise ValueError("صيغة المفتاح الخاص غير معروفة. يرجى إدخال WIF أو Hex")


def address_to_hex(address: str) -> str:
    """
    تحويل العنوان (Bitcoin Address) إلى Hex
    يدعم عناوين Base58Check (تبدأ بـ 1 أو 3)
    """
    try:
        decoded = base58.b58decode_check(address)
        return decoded.hex()
    except Exception:
        # محاولة بدون check
        try:
            decoded = base58.b58decode(address)
            return decoded.hex()
        except Exception:
            pass

    raise ValueError("صيغة العنوان غير معروفة")


def hex_to_private_key_wif(hex_key: str, compressed: bool = True) -> str:
    """
    تحويل Hex إلى مفتاح خاص بصيغة WIF
    """
    # التأكد من أن الـ hex بطول 64 (32 bytes)
    hex_key = hex_key.strip().lower()
    if len(hex_key) != 64:
        raise ValueError(f"طول الـ Hex يجب أن يكون 64 حرف (32 bytes). الطول الحالي: {len(hex_key)}")

    # إضافة version byte (0x80 للشبكة الرئيسية)
    key_bytes = bytes.fromhex('80') + bytes.fromhex(hex_key)

    if compressed:
        key_bytes += bytes.fromhex('01')

    # حساب checksum (أول 4 bytes من double SHA256)
    checksum = hashlib.sha256(hashlib.sha256(key_bytes).digest()).digest()[:4]

    # إضافة checksum وتحويل إلى Base58
    wif = base58.b58encode(key_bytes + checksum).decode('utf-8')
    return wif


def address_to_private_key_attempt(address: str) -> dict:
    """
    تحويل العنوان إلى Hex ثم محاولة تحويله إلى مفتاح خاص

    ملاحظة مهمة: لا يمكن اشتقاق المفتاح الخاص الحقيقي من العنوان فقط!
    هذه الدالة تقوم بـ:
    1. تحويل العنوان إلى Hex
    2. استخدام الـ Hex hash كمفتاح خاص (للعرض فقط - ليس المفتاح الأصلي)
    """
    # الخطوة 1: تحويل العنوان إلى hex
    hex_value = address_to_hex(address)

    result = {
        'address': address,
        'hex': hex_value,
        'hex_without_version': hex_value[2:],  # بدون version byte
    }

    # الخطوة 2: محاولة تحويل الـ hash إلى WIF
    # العنوان يحتوي على RIPEMD160 hash (20 bytes = 40 hex chars)
    hash_hex = hex_value[2:]  # إزالة version byte

    if len(hash_hex) == 40:
        # padding إلى 64 حرف (32 bytes) لتكوين مفتاح خاص
        padded_hex = hash_hex.ljust(64, '0')
        try:
            wif_compressed = hex_to_private_key_wif(padded_hex, compressed=True)
            wif_uncompressed = hex_to_private_key_wif(padded_hex, compressed=False)
            result['private_key_hex'] = padded_hex
            result['private_key_wif_compressed'] = wif_compressed
            result['private_key_wif_uncompressed'] = wif_uncompressed
            result['warning'] = "تحذير: هذا ليس المفتاح الخاص الحقيقي للعنوان! هذا مجرد تحويل رياضي للـ hash."
        except Exception as e:
            result['error'] = str(e)

    return result


def print_separator():
    print("=" * 60)


def main():
    print_separator()
    print("   أداة تحويل المفاتيح والعناوين (Crypto Key Tool)")
    print_separator()
    print()
    print("اختر العملية:")
    print("1. تحويل المفتاح العام (Public Key) إلى Hex")
    print("2. تحويل المفتاح الخاص (Private Key) إلى Hex")
    print("3. تحويل Hex إلى مفتاح خاص (WIF)")
    print("4. تحويل العنوان (Address) إلى Hex ثم إلى مفتاح خاص")
    print("5. تحويل العنوان (Address) إلى Hex فقط")
    print("0. خروج")
    print()

    while True:
        try:
            choice = input("أدخل رقم العملية: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nمع السلامة!")
            break

        if choice == '0':
            print("مع السلامة!")
            break

        elif choice == '1':
            print_separator()
            key = input("أدخل المفتاح العام: ").strip()
            try:
                hex_result = public_key_to_hex(key)
                print(f"\n✅ المفتاح العام بصيغة Hex:")
                print(f"   {hex_result}")
                print(f"   الطول: {len(hex_result)} حرف ({len(hex_result)//2} bytes)")
            except ValueError as e:
                print(f"\n❌ خطأ: {e}")
            print()

        elif choice == '2':
            print_separator()
            key = input("أدخل المفتاح الخاص (WIF أو Hex): ").strip()
            try:
                hex_result = private_key_to_hex(key)
                print(f"\n✅ المفتاح الخاص بصيغة Hex:")
                print(f"   {hex_result}")
                print(f"   الطول: {len(hex_result)} حرف ({len(hex_result)//2} bytes)")
            except ValueError as e:
                print(f"\n❌ خطأ: {e}")
            print()

        elif choice == '3':
            print_separator()
            hex_key = input("أدخل المفتاح الخاص بصيغة Hex (64 حرف): ").strip()
            try:
                wif_compressed = hex_to_private_key_wif(hex_key, compressed=True)
                wif_uncompressed = hex_to_private_key_wif(hex_key, compressed=False)
                print(f"\n✅ المفتاح الخاص بصيغة WIF:")
                print(f"   مضغوط (Compressed):     {wif_compressed}")
                print(f"   غير مضغوط (Uncompressed): {wif_uncompressed}")
            except ValueError as e:
                print(f"\n❌ خطأ: {e}")
            print()

        elif choice == '4':
            print_separator()
            address = input("أدخل العنوان (Address): ").strip()
            try:
                result = address_to_private_key_attempt(address)
                print(f"\n✅ النتائج:")
                print(f"   العنوان: {result['address']}")
                print(f"   Hex (كامل): {result['hex']}")
                print(f"   Hex (بدون version): {result['hex_without_version']}")
                if 'private_key_hex' in result:
                    print(f"\n   المفتاح الخاص (Hex): {result['private_key_hex']}")
                    print(f"   WIF مضغوط: {result['private_key_wif_compressed']}")
                    print(f"   WIF غير مضغوط: {result['private_key_wif_uncompressed']}")
                if 'warning' in result:
                    print(f"\n   ⚠️  {result['warning']}")
                if 'error' in result:
                    print(f"\n   ❌ {result['error']}")
            except ValueError as e:
                print(f"\n❌ خطأ: {e}")
            print()

        elif choice == '5':
            print_separator()
            address = input("أدخل العنوان (Address): ").strip()
            try:
                hex_result = address_to_hex(address)
                print(f"\n✅ العنوان بصيغة Hex:")
                print(f"   {hex_result}")
                print(f"   الطول: {len(hex_result)} حرف ({len(hex_result)//2} bytes)")
            except ValueError as e:
                print(f"\n❌ خطأ: {e}")
            print()

        else:
            print("❌ اختيار غير صحيح. جرب مرة أخرى.")
            print()


if __name__ == '__main__':
    main()
