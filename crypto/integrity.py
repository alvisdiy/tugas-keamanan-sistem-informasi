"""SHA-256: pembanding integritas, BUKAN algoritma enkripsi.

SHA-256 adalah fungsi hash satu arah: tidak ada kunci, tidak bisa
"didekripsi". Di pipeline ini hash hanya dipakai untuk memverifikasi
bahwa plaintext yang berhasil didekripsi identik dengan plaintext asli
yang di-hash pengirim. Kerahasiaan tetap ditangani AES-256-GCM.
"""

import hashlib
import hmac

from crypto.exceptions import IntegrityError


def sha256_hex(text: str) -> str:
    """Kembalikan hash SHA-256 (heksadesimal) dari string UTF-8."""
    if text is None:
        raise IntegrityError("Teks yang akan di-hash tidak boleh None.")
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def verify_integrity(original_hash: str, decrypted_plaintext: str) -> bool:
    """Bandingkan hash plaintext asli dengan hash hasil dekripsi."""
    if not original_hash or not original_hash.strip():
        raise IntegrityError("Hash integritas asli tidak boleh kosong.")
    return hmac.compare_digest(
        original_hash.strip().lower(), sha256_hex(decrypted_plaintext)
    )
