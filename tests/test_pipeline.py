"""Test pipeline hibrida end-to-end: decrypt(encrypt(x)) == x.

Mencakup 10 skenario wajib spesifikasi tugas: plaintext pendek, panjang,
dengan spasi, angka, karakter khusus, key berbeda, ciphertext dimodifikasi,
encrypted AES key dimodifikasi, nonce dimodifikasi, hash integritas tidak cocok.
"""

import pytest

from crypto import pipeline
from crypto.exceptions import HybridCryptoError
from crypto import rsa as rsa_mod

VIGENERE_KEY = "KunciVigenere"
TRANSPOSITION_KEY = "KunciKolom"


@pytest.fixture(scope="module")
def keypair():
    return rsa_mod.generate_key_pair()


@pytest.fixture(scope="module")
def public_pem(keypair):
    return rsa_mod.public_key_to_pem(keypair[1])


@pytest.fixture(scope="module")
def private_pem(keypair):
    return rsa_mod.private_key_to_pem(keypair[0])


def _roundtrip(plaintext, public_pem, private_pem):
    result = pipeline.encrypt_message(plaintext, VIGENERE_KEY, TRANSPOSITION_KEY, public_pem)
    decrypted = pipeline.decrypt_message(
        result.ciphertext_b64,
        result.encrypted_key_b64,
        result.nonce_hex,
        VIGENERE_KEY,
        TRANSPOSITION_KEY,
        private_pem,
        result.integrity_hash,
    )
    return result, decrypted


def test_1_plaintext_pendek(public_pem, private_pem):
    _, dec = _roundtrip("hai", public_pem, private_pem)
    assert dec.plaintext == "hai" and dec.integrity_valid


def test_2_plaintext_panjang(public_pem, private_pem):
    plaintext = ("Paragraf panjang untuk menguji pipeline hibrida. " * 40).strip()
    _, dec = _roundtrip(plaintext, public_pem, private_pem)
    assert dec.plaintext == plaintext and dec.integrity_valid


def test_3_plaintext_dengan_spasi(public_pem, private_pem):
    plaintext = "Banyak     spasi   dan\nbaris\tbaru di dalam pesan ini."
    _, dec = _roundtrip(plaintext, public_pem, private_pem)
    # Normalisasi transposition memadatkan whitespace menjadi satu spasi.
    assert dec.plaintext == "Banyak spasi dan baris baru di dalam pesan ini."


def test_4_plaintext_dengan_angka(public_pem, private_pem):
    plaintext = "Nilai ujian: 95; NIM: 2101010; tahun 2026."
    _, dec = _roundtrip(plaintext, public_pem, private_pem)
    assert dec.plaintext == plaintext and dec.integrity_valid


def test_5_plaintext_karakter_khusus(public_pem, private_pem):
    plaintext = "Simbol: !@#$%^&*()_+-=[]{}|;':\",./<>? ~` 😊"
    _, dec = _roundtrip(plaintext, public_pem, private_pem)
    assert dec.plaintext == plaintext and dec.integrity_valid


def test_6_pasangan_kunci_berbeda(public_pem, private_pem):
    result = pipeline.encrypt_message("pesan", VIGENERE_KEY, TRANSPOSITION_KEY, public_pem)
    # Dekripsi dengan kunci klasik berbeda: jumlah kolom berbeda sehingga
    # format ciphertext transposition tidak valid dan dekripsi gagal sebelum
    # sampai ke AES. Ini adalah perilaku yang diharapkan karena kunci yang
    # berbeda mengubah struktur matriks transposition.
    with pytest.raises(HybridCryptoError):
        pipeline.decrypt_message(
            result.ciphertext_b64, result.encrypted_key_b64, result.nonce_hex,
            "KunciLain", "KolomLain", private_pem, result.integrity_hash,
        )


def test_7_ciphertext_dimodifikasi(public_pem, private_pem):
    result = pipeline.encrypt_message("pesan rahasia", VIGENERE_KEY, TRANSPOSITION_KEY, public_pem)
    raw = bytearray(__import__("base64").b64decode(result.ciphertext_b64))
    raw[-1] ^= 0x01
    tampered = __import__("base64").b64encode(bytes(raw)).decode()
    with pytest.raises(HybridCryptoError):
        pipeline.decrypt_message(
            tampered, result.encrypted_key_b64, result.nonce_hex,
            VIGENERE_KEY, TRANSPOSITION_KEY, private_pem, result.integrity_hash,
        )


def test_8_encrypted_aes_key_dimodifikasi(public_pem, private_pem):
    result = pipeline.encrypt_message("pesan rahasia", VIGENERE_KEY, TRANSPOSITION_KEY, public_pem)
    raw = bytearray(__import__("base64").b64decode(result.encrypted_key_b64))
    raw[5] ^= 0xFF
    tampered = __import__("base64").b64encode(bytes(raw)).decode()
    with pytest.raises(HybridCryptoError):
        pipeline.decrypt_message(
            result.ciphertext_b64, tampered, result.nonce_hex,
            VIGENERE_KEY, TRANSPOSITION_KEY, private_pem, result.integrity_hash,
        )


def test_9_nonce_dimodifikasi(public_pem, private_pem):
    result = pipeline.encrypt_message("pesan rahasia", VIGENERE_KEY, TRANSPOSITION_KEY, public_pem)
    nonce = result.nonce_hex
    tampered = ("0" if nonce[0] != "0" else "1") + nonce[1:]
    with pytest.raises(HybridCryptoError):
        pipeline.decrypt_message(
            result.ciphertext_b64, result.encrypted_key_b64, tampered,
            VIGENERE_KEY, TRANSPOSITION_KEY, private_pem, result.integrity_hash,
        )


def test_10_hash_integritas_tidak_cocok(public_pem, private_pem):
    result = pipeline.encrypt_message("pesan rahasia", VIGENERE_KEY, TRANSPOSITION_KEY, public_pem)
    hash_salah = "0" * 64
    dec = pipeline.decrypt_message(
        result.ciphertext_b64, result.encrypted_key_b64, result.nonce_hex,
        VIGENERE_KEY, TRANSPOSITION_KEY, private_pem, hash_salah,
    )
    assert dec.plaintext == "pesan rahasia"
    assert dec.integrity_valid is False


def test_rsa_key_tidak_valid_ditolak(public_pem):
    with pytest.raises(HybridCryptoError):
        pipeline.encrypt_message("x", VIGENERE_KEY, TRANSPOSITION_KEY, "bukan pem")


def test_input_kosong_ditolak(public_pem):
    with pytest.raises(HybridCryptoError):
        pipeline.encrypt_message("", VIGENERE_KEY, TRANSPOSITION_KEY, public_pem)
    with pytest.raises(HybridCryptoError):
        pipeline.encrypt_message("x", "", TRANSPOSITION_KEY, public_pem)
    with pytest.raises(HybridCryptoError):
        pipeline.encrypt_message("x", VIGENERE_KEY, "", public_pem)


def test_detail_langkah_tersedia(public_pem, private_pem):
    result, dec = _roundtrip("demo", public_pem, private_pem)
    # Enkrisi: 5 langkah (hash, vigenere, transposition, AES, RSA-wrap).
    # Dekripsi: 6 langkah (RSA-buka, validasi nonce, AES-decrypt,
    # transposition balik, vigenere balik, verifikasi integritas).
    assert len(result.steps) == 5
    assert len(dec.steps) == 6
