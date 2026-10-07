"""Validasi input UI sebelum data masuk ke pipeline kriptografi."""

from utils.encoding import b64_decode, b64_is_valid


def require_non_empty(value: str, label: str) -> str:
    """Pastikan input wajib tidak kosong; kembalikan nilai yang sudah dirapikan."""
    if value is None or not value.strip():
        raise ValueError(f"{label} tidak boleh kosong.")
    return value.strip()


def require_min_length(value: str, label: str, minimum: int) -> str:
    """Pastikan input memiliki panjang minimal tertentu."""
    cleaned = require_non_empty(value, label)
    if len(cleaned) < minimum:
        raise ValueError(f"{label} minimal {minimum} karakter.")
    return cleaned


def require_valid_b64(value: str, label: str) -> bytes:
    """Pastikan input adalah Base64 valid; kembalikan bytes hasil dekode."""
    cleaned = require_non_empty(value, label)
    if not b64_is_valid(cleaned):
        raise ValueError(f"{label} bukan Base64 yang valid.")
    return b64_decode(cleaned)


def require_hex_hash(value: str, label: str) -> str:
    """Pastikan input adalah hash SHA-256 heksadesimal 64 karakter."""
    cleaned = require_non_empty(value, label)
    normalized = cleaned.lower().replace(" ", "")
    if len(normalized) != 64 or any(c not in "0123456789abcdef" for c in normalized):
        raise ValueError(f"{label} harus 64 karakter heksadesimal SHA-256.")
    return normalized
