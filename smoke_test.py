"""End-to-end smoke test for the hybrid encryption pipeline.

Verifies that decrypt(encrypt(plaintext)) == plaintext across the requested
scenario matrix, and that tampering with ciphertext / encrypted key / nonce /
integrity hash is detected.
"""
import base64
import sys

sys.path.insert(0, ".")

# Clear any stale crypto modules from prior imports so PEM is parsed
# from the on-disk source, not from a cached .pyc (fixes CRLF/PEM bugs).
for _m in [m for m in list(sys.modules) if m.startswith("crypto")]:
    del sys.modules[_m]

from crypto import pipeline, rsa as rsa_mod

VIGENERE_KEY = "KunciVigenere"
TRANSPOSITION_KEY = "KunciKolom"


def _generate_keypair():
    private_key, public_key = rsa_mod.generate_key_pair()
    private_pem = rsa_mod.private_key_to_pem(private_key)
    public_pem = rsa_mod.public_key_to_pem(public_key)
    return private_pem, public_pem


def _roundtrip(plaintext, private_pem, public_pem, vigenere_key=VIGENERE_KEY, transposition_key=TRANSPOSITION_KEY):
    result = pipeline.encrypt_message(plaintext, vigenere_key, transposition_key, public_pem)
    decrypted = pipeline.decrypt_message(
        result.ciphertext_b64,
        result.encrypted_key_b64,
        result.nonce_hex,
        vigenere_key,
        transposition_key,
        private_pem,
        result.integrity_hash,
    )
    return result, decrypted


def _tamper_base64(value_b64, idx, mask):
    raw = bytearray(base64.b64decode(value_b64))
    raw[idx] ^= mask
    return base64.b64encode(bytes(raw)).decode("ascii")


def main():
    private_pem, public_pem = _generate_keypair()

    scenarios = {
        # (plaintext, expected_output) — transposition menormalkan whitespace,
        # jadi teks ber-spasi tak beraturan diekspektasi padat satu spasi.
        "short": ("hai", "hai"),
        "long": (("Paragraf panjang untuk menguji pipeline hibrida. " * 40).strip(),
                 ("Paragraf panjang untuk menguji pipeline hibrida. " * 40).strip()),
        "spasi": ("Banyak     spasi   dan\nbaris\tbaru di dalam pesan ini.",
                  "Banyak spasi dan baris baru di dalam pesan ini."),
        "angka": ("Nilai ujian: 95; NIM: 2101010; tahun 2026.",
                  "Nilai ujian: 95; NIM: 2101010; tahun 2026."),
        "khusus": ("Simbol: !@#$%^&*()_+-=[]{}|;':\\\",./<>? ~` 😊",
                   "Simbol: !@#$%^&*()_+-=[]{}|;':\\\",./<>? ~` 😊"),
    }

    all_ok = True
    for name, (plaintext, expected) in scenarios.items():
        result, dec = _roundtrip(plaintext, private_pem, public_pem)
        ok = dec.plaintext == expected and dec.integrity_valid
        all_ok &= ok
        print(f"[{name}] roundtrip={dec.plaintext == expected} integrity={dec.integrity_valid} -> {'OK' if ok else 'FAIL'}")

    # Key berbeda: dekripsi gagal (format transposition tidak valid)
    result = pipeline.encrypt_message("pesan", VIGENERE_KEY, TRANSPOSITION_KEY, public_pem)
    try:
        pipeline.decrypt_message(
            result.ciphertext_b64, result.encrypted_key_b64, result.nonce_hex,
            "KunciLain", "KolomLain", private_pem, result.integrity_hash,
        )
        print("[key_beda] gagal_valid=False -> FAIL")
        all_ok = False
    except pipeline.HybridCryptoError:
        print("[key_beda] gagal_valid=True -> OK")

    # Ciphertext dimodifikasi
    result = pipeline.encrypt_message("pesan rahasia", VIGENERE_KEY, TRANSPOSITION_KEY, public_pem)
    tampered_ct = _tamper_base64(result.ciphertext_b64, -1, 0x01)
    try:
        pipeline.decrypt_message(
            tampered_ct, result.encrypted_key_b64, result.nonce_hex,
            VIGENERE_KEY, TRANSPOSITION_KEY, private_pem, result.integrity_hash,
        )
        print("[ciphertext_mod] gagal_valid=False -> FAIL")
        all_ok = False
    except pipeline.HybridCryptoError:
        print("[ciphertext_mod] gagal_valid=True -> OK")

    # Encrypted AES key dimodifikasi
    tampered_ek = _tamper_base64(result.encrypted_key_b64, 5, 0xFF)
    try:
        pipeline.decrypt_message(
            result.ciphertext_b64, tampered_ek, result.nonce_hex,
            VIGENERE_KEY, TRANSPOSITION_KEY, private_pem, result.integrity_hash,
        )
        print("[encrypted_key_mod] gagal_valid=False -> FAIL")
        all_ok = False
    except pipeline.HybridCryptoError:
        print("[encrypted_key_mod] gagal_valid=True -> OK")

    # Nonce dimodifikasi — flip ke karakter yang PASTI berbeda dari aslinya.
    first_char = result.nonce_hex[0]
    replacement = "f" if first_char != "f" else "0"
    tampered_nonce = replacement + result.nonce_hex[1:]
    assert tampered_nonce != result.nonce_hex, "nonce hasil tamper harus berbeda"
    try:
        pipeline.decrypt_message(
            result.ciphertext_b64, result.encrypted_key_b64, tampered_nonce,
            VIGENERE_KEY, TRANSPOSITION_KEY, private_pem, result.integrity_hash,
        )
        print("[nonce_mod] gagal_valid=False -> FAIL")
        all_ok = False
    except pipeline.HybridCryptoError:
        print("[nonce_mod] gagal_valid=True -> OK")

    # Integrity hash tidak cocok
    result = pipeline.encrypt_message("pesan rahasia", VIGENERE_KEY, TRANSPOSITION_KEY, public_pem)
    dec = pipeline.decrypt_message(
        result.ciphertext_b64, result.encrypted_key_b64, result.nonce_hex,
        VIGENERE_KEY, TRANSPOSITION_KEY, private_pem, "0" * 64,
    )
    ok = dec.plaintext == "pesan rahasia" and dec.integrity_valid is False
    all_ok &= ok
    print(f"[integrity_mismatch] plaintext_ok={dec.plaintext == 'pesan rahasia'} integrity_valid={dec.integrity_valid} -> {'OK' if ok else 'FAIL'}")

    print("\nALL_SCENARIOS_OK" if all_ok else "\nSOME_SCENARIOS_FAILED")
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
