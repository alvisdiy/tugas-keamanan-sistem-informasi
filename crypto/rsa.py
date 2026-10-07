"""RSA-OAEP: melindungi AES session key, bukan plaintext utama.

- RSA-2048 dengan OAEP(SHA-256, MGF1-SHA-256), padding aman standar.
- Session key 32 byte selalu muat dalam satu blok RSA-2048
  (kapasitas OAEP-SHA256 = 256 - 2*32 - 2 = 190 byte plaintext).
- Kunci disimpan/dikirim sebagai PEM PKCS#8 (SPKI untuk publik).
- Fungsi encrypt/decrypt_private_key_pem menghasilkan JSON {iv, salt,
  ciphertext, tag} ala envelope Fernet, dibangun di atas AES-256-CBC +
  HMAC-SHA256 sehingga penyimpanan private key juga terautentikasi.
"""

import hashlib
import hmac
import json
import os

from base64 import b64decode, b64encode

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.bindings._rust import openssl as rust_openssl
rust_rsa = rust_openssl.rsa
RSAPublicKey = rust_rsa.RSAPublicKey
RSAPrivateKey = rust_rsa.RSAPrivateKey
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from crypto.exceptions import KeyManagementError

_KEY_SIZE = 2048
_PBKDF2_ITERS = 200_000


def generate_key_pair() -> tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    """Bangkitkan pasangan kunci RSA-2048 baru."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=_KEY_SIZE)
    return private_key, private_key.public_key()


def public_key_to_pem(public_key: rsa.RSAPublicKey) -> str:
    """Serialisasi public key ke PEM SubjectPublicKeyInfo."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")


def private_key_to_pem(private_key: rsa.RSAPrivateKey) -> str:
    """Serialisasi private key ke PEM PKCS#8 tanpa enkripsi passphrase."""
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")


def load_public_key(pem_text: str) -> rsa.RSAPublicKey:
    """Muat public key PEM; lempar KeyManagementError bila tidak valid."""
    if not pem_text or not pem_text.strip():
        raise KeyManagementError("RSA public key tidak boleh kosong.")
    try:
        key = serialization.load_pem_public_key(pem_text.strip().encode("ascii"))
    except Exception as exc:
        raise KeyManagementError(
            "RSA public key tidak valid. Gunakan kunci dari tab Key Management."
        ) from exc
    if not isinstance(key, rust_rsa.RSAPublicKey):
        raise KeyManagementError("Kunci yang diberikan bukan RSA public key.")
    return key


def load_private_key(pem_text: str) -> rsa.RSAPrivateKey:
    """Muat private key PEM; lempar KeyManagementError bila tidak valid."""
    if not pem_text or not pem_text.strip():
        raise KeyManagementError("RSA private key tidak boleh kosong.")
    try:
        key = serialization.load_pem_private_key(pem_text.strip().encode(), password=None)
    except Exception as exc:
        raise KeyManagementError(
            "RSA private key tidak valid atau terhapus sebagian. "
            "Tempel ulang PEM lengkap mulai dari baris -----BEGIN."
        ) from exc
    if not isinstance(key, rust_rsa.RSAPrivateKey):
        raise KeyManagementError("Kunci yang diberikan bukan RSA private key.")
    return key


def encrypt_session_key(session_key: bytes, public_key: rsa.RSAPublicKey) -> bytes:
    """Bungkus AES session key dengan RSA-OAEP(SHA-256)."""
    if not session_key:
        raise KeyManagementError("Session key kosong; tidak ada yang dibungkus.")
    try:
        return public_key.encrypt(
            session_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
    except ValueError as exc:
        raise KeyManagementError(
            "Gagal membungkus session key dengan RSA (kunci terlalu kecil?)."
        ) from exc


def decrypt_session_key(encrypted_key: bytes, private_key: rsa.RSAPrivateKey) -> bytes:
    """Buka bungkusan RSA-OAEP untuk memulihkan AES session key."""
    try:
        return private_key.decrypt(
            encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
    except ValueError as exc:
        raise KeyManagementError(
            "RSA gagal membuka session key: encrypted AES key termodifikasi, "
            "terpotong, atau private key tidak pasangan dengan public key."
        ) from exc


def _derive_wrap_key(passphrase: str, salt: bytes) -> bytes:
    """Turunkan kunci wrap 32 byte dari passphrase via PBKDF2-HMAC-SHA256."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(), length=32, salt=salt, iterations=_PBKDF2_ITERS
    )
    return kdf.derive(passphrase.encode("utf-8"))


def _wrap_with_passphrase(data: bytes, passphrase: str) -> str:
    """Enkripsi data dengan AES-256-CBC + HMAC-SHA256 terkunci passphrase."""
    salt = os.urandom(16)
    iv = os.urandom(16)
    key = _derive_wrap_key(passphrase, salt)
    enc_key, mac_key = key[:16], key[16:]
    encryptor = Cipher(algorithms.AES(enc_key), modes.CBC(iv)).encryptor()
    pad_len = 16 - (len(data) % 16)
    padded = data + bytes([pad_len]) * pad_len
    ct = encryptor.update(padded) + encryptor.finalize()
    tag = hmac.new(mac_key, salt + iv + ct, hashlib.sha256).digest()
    envelope = {
        "iv": b64encode(iv).decode(),
        "salt": b64encode(salt).decode(),
        "ciphertext": b64encode(ct).decode(),
        "tag": b64encode(tag).decode(),
    }
    return json.dumps(envelope, separators=(",", ":"))


def _unwrap_with_passphrase(envelope_json: str, passphrase: str) -> bytes:
    """Kembalikan data dari envelope AES-CBC+HMAC terkunci passphrase."""
    try:
        env = json.loads(envelope_json)
        iv = b64decode(env["iv"])
        salt = b64decode(env["salt"])
        ct = b64decode(env["ciphertext"])
        tag = b64decode(env["tag"])
    except Exception as exc:
        raise KeyManagementError(
            "Format JSON private key terenkripsi tidak valid."
        ) from exc
    key = _derive_wrap_key(passphrase, salt)
    enc_key, mac_key = key[:16], key[16:]
    expect = hmac.new(mac_key, salt + iv + ct, hashlib.sha256).digest()
    if not hmac.compare_digest(expect, tag):
        raise KeyManagementError("Passphrase salah atau file kunci rusak.")
    decryptor = Cipher(algorithms.AES(enc_key), modes.CBC(iv)).decryptor()
    padded = decryptor.update(ct) + decryptor.finalize()
    pad_len = padded[-1]
    if not 1 <= pad_len <= 16 or padded[-pad_len:] != bytes([pad_len]) * pad_len:
        raise KeyManagementError("Padding tidak valid; file kunci mungkin rusak.")
    return padded[:-pad_len]


def encrypt_private_key_pem(pem_text: str, passphrase: str) -> str:
    """Kunci private key PEM dengan passphrase menjadi JSON terenkripsi."""
    return _wrap_with_passphrase(pem_text.encode("utf-8"), passphrase)


def decrypt_private_key_pem(envelope_json: str, passphrase: str) -> str:
    """Buka JSON private key terenkripsi menjadi PEM siap pakai."""
    return _unwrap_with_passphrase(envelope_json, passphrase).decode("utf-8")
