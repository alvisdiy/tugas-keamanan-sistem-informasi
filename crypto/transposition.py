"""Layer 2: Modified Transposition Cipher (permutasi posisi karakter).

Modifikasi dibanding columnar transposition standar:
1. Whitespace dinormalisasi lebih dulu: semua rangkaian spasi/baris baru
   dipadatkan menjadi satu spasi, lalu spasi tepi dibuang. Panjang data
   menjadi deterministik dan susunan matriks tidak bergantung pada
   jumlah baris baru yang membingungkan.
2. Jumlah kolom ditentukan panjang kunci, dan urutan pembacaan kolom
   ditentukan urutan karakter kunci (urutan stabil: kunci "BACA" dan
   "BAAC" menghasilkan urutan berbeda karena indeks ikut disortir).
3. Enkripsi menambahkan padding sentinel (chr(1)) sampai panjang data
   kelipatan jumlah kolom, sehingga matriks dekripsi selalu penuh dan
   proses dapat dibalik secara pasti tanpa kebocoran panjang berlebih.
4. Setiap kolom hasil bacaan dipisahkan sentinel \\x1F, sehingga dekripsi
   tahu batas kolom meski panjang kolom tidak seragam. Data asli yang
   sudah dinormalisasi tidak mungkin mengandung karakter kontrol ini
   karena karakter kontrol dibuang saat normalisasi.

Enkripsi : isi matriks baris-per-baris, baca kolom mengikuti urutan kunci.
Dekripsi : hitung ulang panjang tiap kolom, pecah ciphertext pada
           pemisah, kosongkan matriks kolom-per-kolom sesuai urutan kunci,
           baca baris-per-baris, buang padding sentinel di ekor.
"""

import unicodedata

from crypto.exceptions import TranspositionError

_UNIT_SEPARATOR = "\x1f"
_PADDING_CHAR = "\x01"


def normalize_text(text: str) -> str:
    """Padatkan whitespace (spasi, tab, baris baru) menjadi satu spasi."""
    return " ".join(text.split())


def canonical_text(text: str) -> str:
    """Bentuk kanonik plaintext sebelum masuk matriks.

    Whitespace dipadatkan menjadi satu spasi dan karakter kontrol dibuang,
    persis seperti yang dilakukan enkripsi. Pipeline memakai fungsi ini
    untuk menghitung hash integritas atas teks yang memang akan dipulihkan
    saat dekripsi, sehingga roundtrip sah selalu VALID.
    """
    return _clean_for_matrix(normalize_text(text))


def _column_order(key: str) -> list[int]:
    """Urutan indeks kolom berdasarkan sorting stabil karakter kunci.

    Karakter diubah huruf kecil agar "Baca" dan "BACA" dianggap sama,
    tetapi indeks asli tetap dipakai sehingga kunci dengan karakter
    duplikat ("BAAC") tetap menghasilkan urutan yang deterministik.
    """
    if key is None:
        raise TranspositionError("Kunci transposition tidak boleh kosong.")
    cleaned = key.strip()
    if not cleaned:
        raise TranspositionError("Kunci transposition tidak boleh kosong.")
    if not cleaned.isprintable():
        raise TranspositionError(
            "Kunci transposition hanya boleh karakter yang dapat dicetak."
        )
    keyed = [(ch.lower(), idx) for idx, ch in enumerate(cleaned)]
    keyed.sort()
    return [idx for _, idx in keyed]


def _clean_for_matrix(text: str) -> str:
    """Buang karakter kontrol yang akan mengganggu matriks/pemisah."""
    return "".join(ch for ch in text if not unicodedata.category(ch).startswith("C"))


def modified_transposition_encrypt(plaintext: str, key: str) -> str:
    """Enkripsi modified transposition: kembalikan kolom hasil bacaan.

    Setiap kolom dipisahkan karakter \\x1f sehingga formatnya:
        kolomPertama\\x1fkolomKedua\\x1f...
    """
    if plaintext is None or not plaintext.strip():
        raise TranspositionError("Plaintext transposition tidak boleh kosong.")

    order = _column_order(key)
    num_cols = len(order)
    data = canonical_text(plaintext)

    # Padding sentinel agar jumlah baris matriks selalu bulat.
    remainder = len(data) % num_cols
    if remainder:
        data += _PADDING_CHAR * (num_cols - remainder)

    num_rows = len(data) // num_cols
    columns: list[list[str]] = [[] for _ in range(num_cols)]
    for row in range(num_rows):
        for col in range(num_cols):
            columns[col].append(data[row * num_cols + col])

    # Baca kolom mengikuti urutan kunci; sisipkan pemisah antar kolom.
    parts = ["".join(columns[col_idx]) for col_idx in order]
    return _UNIT_SEPARATOR.join(parts)


def modified_transposition_decrypt(ciphertext: str, key: str) -> str:
    """Dekripsi modified transposition: kebalikan persis dari enkripsi."""
    if ciphertext is None or not ciphertext.strip():
        raise TranspositionError("Ciphertext transposition tidak boleh kosong.")

    order = _column_order(key)
    num_cols = len(order)
    raw_parts = ciphertext.split(_UNIT_SEPARATOR)
    if len(raw_parts) != num_cols:
        raise TranspositionError(
            "Format ciphertext transposition tidak valid: jumlah segmen "
            f"{len(raw_parts)} tidak sama dengan jumlah kolom {num_cols}. "
            "Kemungkinan ciphertext terpotong atau kunci salah."
        )

    first_len = len(raw_parts[0])
    for i, part in enumerate(raw_parts[1:], start=2):
        if not (len(part) == first_len or len(part) == first_len - 1):
            raise TranspositionError(
                "Format ciphertext transposition tidak valid: panjang segmen "
                f"ke-{i} ({len(part)}) tidak wajar untuk matriks "
                f"{first_len}+ baris. Ciphertext mungkin rusak atau kunci salah."
            )
    if first_len == 0:
        raise TranspositionError(
            "Ciphertext transposition tidak valid: segmen kosong."
        )

    # Bentuk ulang matriks: kolom_posisi[i] adalah isi kolom posisi i,
    # dibaca dari segmen ciphertext sesuai urutan kunci.
    columns: list[list[str]] = [[] for _ in range(num_cols)]
    for read_pos, col_idx in enumerate(order):
        columns[col_idx] = list(raw_parts[read_pos])

    num_rows = first_len
    chars: list[str] = []
    for row in range(num_rows):
        for col in range(num_cols):
            if row < len(columns[col]):
                chars.append(columns[col][row])

    # Buang padding sentinel di ekor, lalu trim spasi tepi hasil normalisasi.
    data = "".join(chars).rstrip(_PADDING_CHAR)
    return data.strip()
