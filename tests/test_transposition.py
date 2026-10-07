"""Test Layer 2: Modified Transposition Cipher."""

import pytest

from crypto.exceptions import TranspositionError
from crypto.transposition import (
    modified_transposition_decrypt,
    modified_transposition_encrypt,
    normalize_text,
)


@pytest.mark.parametrize(
    "plaintext",
    [
        "hai",
        "Pesan pendek sekali",
        "Pesan yang jauh lebih panjang dari jumlah kolom kunci mana pun " * 3,
        "Teks dengan    spasi   tidak beraturan.",
        "Angka 0123456789 dan simbol !@#$%^&*()",
    ],
)
def test_roundtrip_reversibel(plaintext):
    ciphertext = modified_transposition_encrypt(plaintext, "KUNCI")
    assert modified_transposition_decrypt(ciphertext, "KUNCI") == normalize_text(plaintext)


def test_normalisasi_whitespace():
    assert normalize_text("  a\n\nb\t c  ") == "a b c"


def test_output_berubah_dibanding_input():
    # Permutasi harus benar-benar mengacak posisi untuk teks yang cukup panjang.
    plaintext = "abcdefghijklmnopqrstuvwxyz"
    assert modified_transposition_encrypt(plaintext, "BACA") != plaintext


def test_kunci_berbeda_hasil_berbeda_dan_tidak_terdekripsi_salah():
    plaintext = "Kriptografi itu menyenangkan ketika reversibilitas terjaga."
    ct_a = modified_transposition_encrypt(plaintext, "SATU")
    ct_b = modified_transposition_encrypt(plaintext, "DUA")
    assert ct_a != ct_b
    with pytest.raises(TranspositionError):
        modified_transposition_decrypt(ct_a, "DUA")


def test_kunci_dengan_duplikat_masih_reversibel():
    plaintext = "Kunci berulang tetap harus bisa kembali dengan utuh."
    ct = modified_transposition_encrypt(plaintext, "BAAC")
    assert modified_transposition_decrypt(ct, "BAAC") == normalize_text(plaintext)


def test_padding_sentinel_dibuang():
    plaintext = "habis"  # 5 huruf, kunci 4 kolom -> butuh padding
    ct = modified_transposition_encrypt(plaintext, "ABCD")
    assert "\x01" not in modified_transposition_decrypt(ct, "ABCD")


def test_ciphertext_termodifikasi_ditolak():
    plaintext = "Data penting yang harus tetap utuh setelah dipulihkan."
    ct = modified_transposition_encrypt(plaintext, "KUNCI")
    # Mengubah jumlah segmen (membuang karakter pemisah \\x1F di tengah)
    # harus membuat dekripsi gagal karena jumlah kolom tidak cocok.
    tampered = ct.replace("\x1f", "", 1)
    with pytest.raises(TranspositionError):
        modified_transposition_decrypt(tampered, "KUNCI")


def test_kunci_kosong_ditolak():
    with pytest.raises(TranspositionError):
        modified_transposition_encrypt("abc", "")
    with pytest.raises(TranspositionError):
        modified_transposition_encrypt("abc", "  ")
