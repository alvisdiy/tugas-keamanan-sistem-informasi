"""Test Layer 3: AES-256-GCM."""

import pytest

from crypto import aes
from crypto.exceptions import DecryptionError


def test_roundtrip_dasar():
    key = aes.generate_session_key()
    payload = aes.encrypt("Pesan rahasia", key)
    assert aes.decrypt(payload, key) == "Pesan rahasia"


def test_ukuran_kunci_dan_nonce():
    assert len(aes.generate_session_key()) == 32
    assert len(aes.generate_nonce()) == 12


def test_kunci_selalu_acak():
    assert aes.generate_session_key() != aes.generate_session_key()


def test_nonce_unik_per_enkripsi():
    key = aes.generate_session_key()
    p1 = aes.encrypt("teks sama", key)
    p2 = aes.encrypt("teks sama", key)
    assert p1[:12] != p2[:12], "Nonce tidak boleh statis"
    assert p1 != p2


def test_ciphertext_dimodifikasi_gagal_autentikasi():
    key = aes.generate_session_key()
    payload = bytearray(aes.encrypt("integritas", key))
    payload[15] ^= 0xFF  # ubah satu byte setelah nonce (area ciphertext)
    with pytest.raises(DecryptionError):
        aes.decrypt(bytes(payload), key)


def test_nonce_dimodifikasi_gagal_autentikasi():
    key = aes.generate_session_key()
    payload = bytearray(aes.encrypt("integritas", key))
    payload[0] ^= 0x01  # nonce byte pertama
    with pytest.raises(DecryptionError):
        aes.decrypt(bytes(payload), key)


def test_kunci_salah_gagal_autentikasi():
    payload = aes.encrypt("rahasia", aes.generate_session_key())
    with pytest.raises(DecryptionError):
        aes.decrypt(payload, aes.generate_session_key())


def test_payload_terpotong_ditolak():
    key = aes.generate_session_key()
    with pytest.raises(DecryptionError):
        aes.decrypt(b"\x00" * 20, key)


def test_panjang_kunci_salah_ditolak():
    with pytest.raises(DecryptionError):
        aes.encrypt("x", b"kunci-pendek")
