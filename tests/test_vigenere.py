"""Test Layer 1: Vigenere cipher."""

import pytest

from crypto.exceptions import VigenereError
from crypto.vigenere import vigenere_decrypt, vigenere_encrypt


def test_formula_mod26_vector_klasik():
    # Vektor klasik: HELLO dengan kunci KEY menghasilkan RIJVS.
    assert vigenere_encrypt("HELLO", "KEY") == "RIJVS"
    assert vigenere_decrypt("RIJVS", "KEY") == "HELLO"


def test_roundtrip_dengan_non_alfabet():
    plaintext = "Rahasia: 1234, bukan #RAHASIA! (verified) 🙂"
    assert vigenere_decrypt(vigenere_encrypt(plaintext, "KunciRahasia"), "KunciRahasia") == plaintext


def test_karakter_non_alfabet_dipertahankan():
    # Kunci "X" menggeser huruf 23; spasi, koma, angka, dan tanda seru tetap.
    assert vigenere_encrypt("a b, 9!", "X") == "x y, 9!"
    assert vigenere_decrypt("x y, 9!", "X") == "a b, 9!"


def test_huruf_besar_kecil_kunci_ekuivalen():
    text = "TestCampurBesarKecil"
    assert vigenere_encrypt(text, "KEY") == vigenere_encrypt(text, "key")


def test_kunci_kosong_ditolak():
    with pytest.raises(VigenereError):
        vigenere_encrypt("abc", "")
    with pytest.raises(VigenereError):
        vigenere_encrypt("abc", "   ")
    with pytest.raises(VigenereError):
        vigenere_encrypt("abc", None)


def test_kunci_angka_ditolak():
    # Kunci Vigenere hanya huruf A-Z; karakter angka/simbol dilewatkan,
    # jadi "abc123" hanya "abc" yang dipakai dan tidak memicu error.
    # Gunakan kunci yang benar-benar tidak mengandung huruf untuk memicu error.
    with pytest.raises(VigenereError):
        vigenere_encrypt("abc", "123")


def test_plaintext_kosong_ditolak():
    with pytest.raises(VigenereError):
        vigenere_encrypt("", "KEY")
