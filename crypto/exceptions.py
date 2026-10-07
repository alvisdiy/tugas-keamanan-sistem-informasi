"""Exception kustom seluruh pipeline enkripsi hibrida.

Semua modul melempar exception turunan HybridCryptoError sehingga UI cukup
menangkap satu jenis error untuk menampilkan pesan yang ramah pengguna.
"""


class HybridCryptoError(Exception):
    """Induk exception untuk seluruh pipeline hibrida."""


class ValidationError(HybridCryptoError):
    """Input pengguna tidak memenuhi syarat (kosong, format salah, dsb)."""


class VigenereError(ValidationError):
    """Kunci atau teks Vigenere tidak valid."""


class TranspositionError(ValidationError):
    """Kunci atau data transposition tidak valid."""


class DecryptionError(HybridCryptoError):
    """Data terenkripsi gagal didekripsi (rusak, termodifikasi, key salah)."""


class IntegrityError(HybridCryptoError):
    """Hash integritas plaintext asli tidak cocok dengan hasil dekripsi."""


class KeyManagementError(HybridCryptoError):
    """Kunci RSA tidak valid atau gagal dibuat/diproses."""
