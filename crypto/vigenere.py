"""Layer 1: Vigenere Cipher (implementasi mandiri, tanpa library pihak ketiga).

Formula klasik yang diterapkan hanya pada huruf A-Z:

    Enkripsi: C = (P + K) mod 26
    Dekripsi: P = (C - K) mod 26

Karakter non-alfabet (spasi, angka, tanda baca, emoji) DILEWATI dan
disalin apa adanya, sehingga bentuk asli pesan tetap terlihat pada
layer ini. Indeks kunci hanya maju ketika sebuah huruf benar-benar
diproses, agar pesan berisi simbol tetap terdekripsi secara konsisten.

Perbandingan huruf tidak sensitif terhadap besar-kecil: huruf kunci
"RAHASIA" dan "rahasia" menghasilkan aliran kunci yang sama. Huruf
plaintext mempertahankan huruf besar/kecilnya.
"""

from crypto.exceptions import VigenereError

_ALPHABET_SIZE = 26
_UPPER_A = ord("A")
_LOWER_A = ord("a")


def _shift_for(key_char: str) -> int:
    """Konversi satu karakter kunci menjadi geseran 0-25 (a/A = 0)."""
    ch_lower = key_char.lower()
    if "a" <= ch_lower <= "z":
        return ord(ch_lower) - _LOWER_A
    raise VigenereError(
        f"Kunci Vigenere hanya boleh berisi huruf A-Z. "
        f"Karakter tidak valid: {key_char!r}"
    )


def _normalize_key(key: str) -> list[int]:
    """Validasi kunci dan ubah menjadi daftar nilai geseran 0-25."""
    if key is None:
        raise VigenereError("Kunci Vigenere tidak boleh kosong.")
    stripped = key.strip()
    if not stripped:
        raise VigenereError("Kunci Vigenere tidak boleh kosong.")
    shifts = []
    for ch in stripped:
        if ch.isalpha():
            shifts.append(_shift_for(ch))
    if not shifts:
        raise VigenereError(
            "Kunci Vigenere harus mengandung setidaknya satu huruf A-Z."
        )
    return shifts


def _transform(text: str, key: str, direction: int) -> str:
    """Proses inti: direction = +1 untuk enkripsi, -1 untuk dekripsi."""
    shifts = _normalize_key(key)
    if not text:
        raise VigenereError("Teks Vigenere tidak boleh kosong.")

    out: list[str] = []
    key_index = 0
    for ch in text:
        if "A" <= ch <= "Z":
            base = _UPPER_A
        elif "a" <= ch <= "z":
            base = _LOWER_A
        else:
            # Karakter non-alfabet disalin apa adanya; aliran kunci tidak maju.
            out.append(ch)
            continue

        shift = shifts[key_index % len(shifts)]
        value = ord(ch) - base
        transformed = (value + direction * shift) % _ALPHABET_SIZE
        out.append(chr(base + transformed))
        key_index += 1

    return "".join(out)


def vigenere_encrypt(plaintext: str, key: str) -> str:
    """Enkripsi dengan formula C = (P + K) mod 26 pada huruf alfabet."""
    return _transform(plaintext, key, +1)


def vigenere_decrypt(ciphertext: str, key: str) -> str:
    """Dekripsi dengan formula P = (C - K) mod 26 pada huruf alfabet."""
    return _transform(ciphertext, key, -1)
