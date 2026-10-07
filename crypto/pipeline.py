"""Orkestrator pipeline enkripsi/dekripsi hibrida.

Alur ENKRIPSI:
    plaintext
      -> SHA-256 hash (untuk verifikasi integritas)
      -> Vigenere (substitusi, formula C = (P+K) mod 26)
      -> Modified Transposition (permutasi posisi berbasis urutan kolom kunci)
      -> AES-256-GCM (kunci session acak, nonce unik, tag autentikasi)
      -> RSA-OAEP membungkus session key
    menghasilkan bundle: ciphertext b64, encrypted key b64, nonce hex,
    hash hex, dan detail langkah untuk demonstrasi.

Alur DEKRIPSI: kebalikan persis, dengan verifikasi integritas di akhir.

Keamanan:
- AES session key 256-bit dari CSPRNG, baru setiap enkripsi.
- Nonce 96-bit acak baru setiap enkripsi.
- RSA-OAEP(SHA-256) tanpa textbook RSA.
- GCM mengautentikasi ciphertext + nonce: perubahan sekecil apa pun
  terdeteksi sebagai kegagalan autentikasi.
"""

from dataclasses import dataclass, field

from crypto import aes, integrity, rsa, transposition, vigenere
from crypto.exceptions import HybridCryptoError
from utils.encoding import b64_decode, b64_encode


@dataclass
class EncryptResult:
    """Hasil satu proses enkripsi lengkap dengan detail demonstrasi."""

    ciphertext_b64: str
    encrypted_key_b64: str
    nonce_hex: str
    integrity_hash: str
    steps: list[dict] = field(default_factory=list)
    aes_key_b64: str = ""  # hanya untuk demo pembelajaran; JANGAN dikirim


@dataclass
class DecryptResult:
    """Hasil dekripsi beserta status integritas dan detail langkah."""

    plaintext: str
    integrity_valid: bool
    steps: list[dict] = field(default_factory=list)


def _steps_to_tuples(steps: list[dict]) -> list[tuple[str, str]]:
    """Sederhanakan langkah jadi pasangan (nama, cuplikan) untuk UI."""
    return [(s["name"], s["output"]) for s in steps]


def encrypt_message(
    plaintext: str,
    vigenere_key: str,
    transposition_key: str,
    public_key_pem: str,
) -> EncryptResult:
    """Jalankan pipeline enkripsi hibrida dari plaintext sampai bundle akhir.

    Melempar HybridCryptoError (atau ValueError) dengan pesan ramah bila
    ada input yang tidak valid.
    """
    if not plaintext:
        raise HybridCryptoError("Plaintext tidak boleh kosong.")
    if not vigenere_key or not vigenere_key.strip():
        raise HybridCryptoError("Kunci Vigenere tidak boleh kosong.")
    if not transposition_key or not transposition_key.strip():
        raise HybridCryptoError("Kunci transposition tidak boleh kosong.")

    steps: list[dict] = []

    # 1. Hash integritas atas bentuk kanonik plaintext ASLI. Transposition
    #    menormalkan whitespace & membuang karakter kontrol, jadi bentuk
    #    inilah yang akan dipulihkan saat dekripsi.
    plain_hash = integrity.sha256_hex(transposition.canonical_text(plaintext))
    steps.append(
        {
            "name": "SHA-256 (hash plaintext asli)",
            "output": plain_hash,
        }
    )

    # 2. Layer 1: Vigenere.
    vigenere_out = vigenere.vigenere_encrypt(plaintext, vigenere_key)
    steps.append(
        {
            "name": "Vigenere (substitusi C=(P+K) mod 26)",
            "output": vigenere_out,
        }
    )

    # 3. Layer 2: Modified Transposition.
    transposed_out = transposition.modified_transposition_encrypt(
        vigenere_out, transposition_key
    )
    steps.append(
        {
            "name": "Modified Transposition (permutasi kolom kunci)",
            "output": transposed_out,
        }
    )

    # 4. Layer 3: AES-256-GCM dengan session key dan nonce baru.
    session_key = aes.generate_session_key()
    aes_payload = aes.encrypt(transposed_out, session_key)
    nonce_hex = aes_payload[: aes.NONCE_SIZE_BYTES].hex()

    # 5. Bungkus session key dengan RSA-OAEP.
    public_key = rsa.load_public_key(public_key_pem)
    encrypted_key = rsa.encrypt_session_key(session_key, public_key)

    steps.append(
        {
            "name": "AES-256-GCM (kunci session acak + nonce unik)",
            "output": b64_encode(aes_payload),
        }
    )
    steps.append(
        {
            "name": "RSA-OAEP (bungkus session key)",
            "output": b64_encode(encrypted_key),
        }
    )

    return EncryptResult(
        ciphertext_b64=b64_encode(aes_payload),
        encrypted_key_b64=b64_encode(encrypted_key),
        nonce_hex=nonce_hex,
        integrity_hash=plain_hash,
        steps=steps,
        aes_key_b64=b64_encode(session_key),
    )


def decrypt_message(
    ciphertext_b64: str,
    encrypted_key_b64: str,
    nonce_hex: str,
    vigenere_key: str,
    transposition_key: str,
    private_key_pem: str,
    expected_hash: str,
) -> DecryptResult:
    """Jalankan pipeline dekripsi dan verifikasi integritas.

    Urutan pembukaan harus kebalikan persis enkripsi. Setiap kegagalan
    (Base64 rusak, RSA gagal, tag GCM tidak cocok, format transposition
    salah) dilempar sebagai HybridCryptoError dengan pesan spesifik.
    """
    steps: list[dict] = []

    encrypted_key = b64_decode(encrypted_key_b64)
    aes_payload = b64_decode(ciphertext_b64)
    try:
        nonce = bytes.fromhex(nonce_hex)
    except ValueError as exc:
        raise HybridCryptoError(
            "Nonce harus heksadesimal; salin ulang nilai dari hasil enkripsi."
        ) from exc

    private_key = rsa.load_private_key(private_key_pem)

    # 1. Buka session key dengan RSA-OAEP.
    session_key = rsa.decrypt_session_key(encrypted_key, private_key)
    steps.append(
        {
            "name": "RSA-OAEP (buka session key)",
            "output": "Session key 32 byte dipulihkan.",
        }
    )

    # 2. Validasi nonce terhadap payload (nonce tersimpan di 12 byte pertama).
    stored_nonce = aes_payload[: aes.NONCE_SIZE_BYTES]
    steps.append(
        {
            "name": "Validasi nonce (pencocokan 12 byte pertama payload)",
            "output": f"Nonce {'cocok' if stored_nonce == nonce else 'TIDAK COCOK'} dengan payload.",
        }
    )
    if stored_nonce != nonce:
        raise HybridCryptoError(
            "Nonce tidak cocok dengan payload ciphertext; data kemungkinan "
            "dimodifikasi atau tertukar."
        )
    if len(session_key) != aes.KEY_SIZE_BYTES:
        raise HybridCryptoError(
            "Panjang session key hasil RSA tidak sesuai; kunci RSA mungkin "
            "bukan pasangan yang benar."
        )

    # 3. AES-256-GCM decrypt (autentikasi tag termasuk nonce di payload).
    transposed_out = aes.decrypt(aes_payload, session_key)
    steps.append(
        {
            "name": "AES-256-GCM (dekripsi + verifikasi tag)",
            "output": transposed_out,
        }
    )

    # 4. Kebalikan Modified Transposition.
    vigenere_out = transposition.modified_transposition_decrypt(
        transposed_out, transposition_key
    )
    steps.append(
        {
            "name": "Modified Transposition (susun ulang kolom)",
            "output": vigenere_out,
        }
    )

    # 5. Kebalikan Vigenere.
    plaintext = vigenere.vigenere_decrypt(vigenere_out, vigenere_key)
    steps.append(
        {
            "name": "Vigenere (substitusi balik P=(C-K) mod 26)",
            "output": plaintext,
        }
    )

    # 6. Verifikasi integritas SHA-256.
    integrity_valid = integrity.verify_integrity(expected_hash, plaintext)
    steps.append(
        {
            "name": "SHA-256 (verifikasi integritas)",
            "output": (
                f"Hash asli   : {expected_hash}\n"
                f"Hash dekrip : {integrity.sha256_hex(plaintext)}"
            ),
        }
    )

    return DecryptResult(
        plaintext=plaintext, integrity_valid=integrity_valid, steps=steps
    )
