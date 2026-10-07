"""Helper penyandian Base64 untuk pertukaran data antar tab di UI.

Base64 adalah PENYANDIAN (encoding), bukan enkripsi: tidak ada kunci,
siapa pun dapat mengembalikan nilainya. Di aplikasi ini Base64 hanya
dipakai agar byte biner (ciphertext AES, encrypted AES key, nonce)
dapat disalin sebagai teks yang aman ditempel, bukan untuk menjaga
rahasia.
"""

from base64 import b64decode, b64encode

from crypto.exceptions import HybridCryptoError


def b64_encode(data: bytes) -> str:
    """Sandikan bytes menjadi string Base64 ASCII."""
    return b64encode(data).decode("ascii")


def b64_decode(text: str) -> bytes:
    """Pulihkan bytes dari string Base64; lempar error ramah bila rusak."""
    if text is None or not text.strip():
        raise HybridCryptoError("Nilai Base64 tidak boleh kosong.")
    try:
        return b64decode(text.strip(), validate=True)
    except Exception as exc:
        raise HybridCryptoError(
            "Nilai Base64 tidak valid (kemungkinan terpotong atau "
            "termodifikasi saat disalin)."
        ) from exc


def b64_is_valid(text: str) -> bool:
    """Cek cepat apakah string tampak seperti Base64 valid."""
    try:
        b64_decode(text)
        return True
    except HybridCryptoError:
        return False
