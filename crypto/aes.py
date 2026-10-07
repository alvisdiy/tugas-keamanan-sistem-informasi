"""Layer 3: AES-256-GCM, enkripsi utama terautentikasi.

Format payload (disandikan Base64):
    base64( nonce(12 bytes) || ciphertext+tag )

Library `cryptography` menggabungkan authentication tag (16 byte) di
akhir ciphertext (format dokumentasi resmi: enkripsi menghasilkan
bytes ciphertext yang diakhiri tag). Dengan menyandingkan nonce di
depan, payload tunggal ini cukup untuk dekripsi asalkan kunci benar.

- Kunci selalu dibangkitkan os.urandom(32) (CSPRNG), 256-bit.
- Nonce selalu dibangkitkan os.urandom(12) untuk setiap proses
  enkripsi; tidak pernah statis dan tidak digunakan ulang dengan
  kunci yang sama.
- Mode GCM memberikan kerahasiaan sekaligus autentikasi: perubahan
  satu bit pada ciphertext maupun nonce membuat dekripsi gagal
  (InvalidTag).
"""

import os
from base64 import b64decode, b64encode

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from crypto.exceptions import DecryptionError, ValidationError

_KEY_BYTES = 32  # 256-bit
_NONCE_BYTES = 12

# Konstanta publik untuk pipeline dan UI
KEY_SIZE_BYTES = _KEY_BYTES
NONCE_SIZE_BYTES = _NONCE_BYTES


def generate_session_key() -> bytes:
    """Bangkitkan AES session key 256-bit dari CSPRNG."""
    return AESGCM.generate_key(bit_length=256)


def generate_nonce() -> bytes:
    """Bangkitkan nonce 96-bit acak (dipakai sekali per enkripsi)."""
    return os.urandom(_NONCE_BYTES)


def encrypt(plaintext: str, key: bytes, nonce: bytes | None = None) -> bytes:
    """Enkripsi string UTF-8 dengan AES-256-GCM.

    Mengembalikan nonce(12) || ciphertext+tag(16). Parameter nonce
    sengaja disediakan untuk pengujian, pemanggil aplikasi sebaiknya
    membiarkannya None agar selalu acak.
    """
    if not plaintext:
        from crypto.exceptions import ValidationError

        raise ValidationError("Plaintext AES tidak boleh kosong.")
    if len(key) != _KEY_BYTES:
        raise DecryptionError(
            f"Panjang kunci AES harus {_KEY_BYTES} byte, dapat {len(key)} byte."
        )
    if nonce is None:
        nonce = generate_nonce()
    if len(nonce) != _NONCE_BYTES:
        raise DecryptionError(
            f"Panjang nonce harus {_NONCE_BYTES} byte, dapat {len(nonce)} byte."
        )

    aes = AESGCM(key)
    sealed = aes.encrypt(nonce, plaintext.encode("utf-8"), None)
    return nonce + sealed


def decrypt(payload: bytes, key: bytes) -> str:
    """Dekripsi payload nonce||ciphertext+tag; lempar DecryptionError bila gagal.

    Gagal autentikasi (kunci salah, ciphertext/nonce termodifikasi)
    muncul sebagai InvalidTag dari library dan dipetakan ke
    DecryptionError agar UI dapat menampilkan pesan yang jelas.
    """
    if len(key) != _KEY_BYTES:
        raise DecryptionError(
            f"Panjang kunci AES harus {_KEY_BYTES} byte, dapat {len(key)} byte."
        )
    if len(payload) < _NONCE_BYTES + 16:
        raise DecryptionError(
            "Payload AES terlalu pendek untuk memuat nonce dan tag; "
            "data kemungkinan rusak atau terpotong."
        )

    nonce, sealed = payload[:_NONCE_BYTES], payload[_NONCE_BYTES:]
    try:
        plain_bytes = AESGCM(key).decrypt(nonce, sealed, None)
    except Exception as exc:  # InvalidTag dari cryptography
        raise DecryptionError(
            "AES-GCM gagal: autentikasi tag tidak cocok. Ciphertext, nonce, "
            "atau kunci AES kemungkinan dimodifikasi/salah."
        ) from exc
    return plain_bytes.decode("utf-8")
