# 🔐 Hybrid Encryption & Decryption

Aplikasi enkripsi-dekripsi pesan berlapis, dibuat dengan **Python + Streamlit** untuk tugas Mata Kuliah **Keamanan Informasi**. Satu pesan dienkripsi lewat **5 lapisan algoritma** yang tugasnya berbeda-beda, bukan hanya satu algoritma.

```
PESAN → Vigenère → Transposition → AES-256-GCM → CIPHERTEXT
```

---

## Daftar Isi

1. [Cara Menjalankan](#1-cara-menjalankan)
2. [Cara Pakai (3 Langkah)](#2-cara-pakai-3-langkah)
3. [Cara Kerja Enkripsi](#3-cara-kerja-enkripsi)
4. [Cara Kerja Dekripsi](#4-cara-kerja-dekripsi)
5. [Penjelasan Tiap Lapisan](#5-penjelasan-tiap-lapisan)
6. [Modifikasi Transposition (Keunikan Project)](#6-modifikasi-transposition-keunikan-project)
7. [Manajemen Kunci AES Session](#7-manajemen-kunci-aes-session)
8. [Penggunaan RSA dan SHA-256](#8-penggunaan-rsa-dan-sha-256)
9. [Testing](#9-testing)
10. [Struktur Project](#10-struktur-project)
11. [Keterbatasan](#11-keterbatasan)
12. [Ringkasan untuk Presentasi](#12-ringkasan-untuk-presentasi)

---

## 1. Cara Menjalankan

Syarat: Python 3.10 atau lebih baru.

```bash
# 1. Masuk ke folder project
cd C:\data\AINGMAUNGG\hash

# 2. Install dependency
pip install -r requirements.txt

# 3. Jalankan aplikasi
streamlit run app.py
```

Browser akan terbuka otomatis di `http://localhost:8501`. Kalau tidak terbuka, akses alamat itu secara manual.

---

## 2. Cara Pakai (3 Langkah)

UI sudah dipandu berurutan. Ada 4 tab, tapi yang perlu diisi hanya 3:

### Langkah 1: Tab "1. Key Management" (dilakukan sekali di awal)

Klik tombol **🔑 Buat Pasangan Kunci RSA**. Aplikasi membuat dua kunci:

| Kunci | Peran | Analogi |
|---|---|---|
| **Public Key** | Dipakai saat mengunci pesan (tab 2) | Gemboknya, boleh dibagikan |
| **Private Key** | Dipakai saat membuka pesan (tab 3) | Kuncinya, JANGAN dibagikan |

Dua kunci ini tersimpan di sesi aplikasi dan **otomatis terisi** di tab berikutnya. Opsi lanjutan: private key bisa diunduh sebagai file biasa, atau sebagai file terproteksi password (AES-256-CBC + HMAC-SHA256 dengan PBKDF2 200 ribu iterasi).

### Langkah 2: Tab "2. Encrypt"

Isi 3 kolom lalu klik **🔒 ENCRYPT**:

1. **Pesan yang mau dirahasiakan** (plaintext, bebas)
2. **Kunci Vigenère** (huruf saja, contoh: `KunciVigenere`)
3. **Kunci Transposition** (huruf saja, contoh: `KunciKolom`)

Public key tidak perlu disentuh karena sudah terisi dari Langkah 1. Hasil enkripsi berupa **4 nilai**:

| Hasil | Artinya |
|---|---|
| **Ciphertext** | Pesan yang sudah terkunci |
| **Encrypted AES Key** | Kunci sesi AES yang sudah dibungkus RSA |
| **Nonce** | Angka acak sekali pakai |
| **Integrity Hash** | Sidik jari SHA-256 dari pesan asli |

### Langkah 3: Tab "3. Decrypt"

Semua 4 nilai di atas **sudah terisi otomatis**, begitu juga private key. Kamu hanya perlu mengisi **kedua kunci klasik yang sama persis** dengan saat mengenkripsi, lalu klik **🔓 DECRYPT**.

Hasil yang muncul:

- **Pesan asli** (plaintext yang pulih)
- **INTEGRITY: VALID** (hijau): pesan sampai utuh, tidak ada yang berubah
- **INTEGRITY: INVALID** (merah): isi pesan berbeda dari aslinya

> Kalau kunci yang diisi beda sedikit saja, dekripsi gagal dengan pesan ramah (bukan crash). Itu perilaku yang benar: kunci harus pasangan.

### Tab "Cara Kerja"

Tidak perlu diisi apa-apa. Berisi tabel lapisan dan diagram alur, siap dipakai untuk presentasi.

---

## 3. Cara Kerja Enkripsi

Masuk dari `pipeline.encrypt_message()` di `crypto/pipeline.py`. Pesan melewati 5 tahap berurutan:

```text
PESAN ASLI
   │
   ▼
[1] SHA-256       hash pesan asli (bentuk kanonik) → integrity hash
   │
   ▼
[2] Vigenère      tiap huruf digeser: C = (P + K) mod 26
   │
   ▼
[3] Transposition  huruf disusun matriks, kolom dibaca sesuai urutan kunci
   │
   ▼
[4] AES-256-GCM   enkripsi dengan kunci sesi acak 32 byte + nonce acak 12 byte
   │
   ▼
[5] RSA-OAEP      kunci sesi dibungkus public key
   │
   ▼
CIPHERTEXT + Encrypted AES Key + Nonce + Integrity Hash
```

Poin penting:

- **Hash dihitung dulu** sebelum pesan disentuh lapisan apa pun, jadi hasil dekripsi bisa dibandingkan dengan aslinya.
- **Kunci sesi AES dibuat acak setiap kali** mengenkripsi (`os.urandom`, bukan random biasa, dan bukan kunci tetap).
- **Nonce baru setiap kali** enkripsi, jadi pesan yang sama dikirim dua kali menghasilkan ciphertext berbeda.
- **RSA hanya membungkus kunci sesi**, bukan mengenkripsi seluruh pesan.

---

## 4. Cara Kerja Dekripsi

Masuk dari `pipeline.decrypt_message()`. Urutannya kebalikan persis:

```text
4 NILAI DITERIMA
   │
   ▼
[1] RSA-OAEP        private key membuka bungkusan → kunci sesi AES pulih
   │
   ▼
[2] Validasi nonce  nonce yang dikirim dicocokkan dengan di dalam payload
   │
   ▼
[3] AES-256-GCM     buka ciphertext, tag autentikasi diverifikasi otomatis
   │
   ▼
[4] Transposition balik  posisi huruf disusun ulang
   │
   ▼
[5] Vigenère balik   huruf digeser balik: P = (C - K) mod 26
   │
   ▼
[6] Cek SHA-256      hash hasil dekripsi dibandingkan dengan hash asli
```

Hasil akhir berupa plaintext dan status integritas. Setiap kegagalan (Base64 rusak, kunci salah, tag tidak cocok) ditampilkan sebagai pesan error ramah, bukan traceback.

---

## 5. Penjelasan Tiap Lapisan

| Lapisan | Tugas | Kuncinya | Kenapa dipakai |
|---|---|---|---|
| **Vigenère** | Substitusi huruf, C = (P + K) mod 26 | Kunci huruf 1 | Mudah dijelaskan; mengubah isi huruf sebelum lapisan berikutnya |
| **Modified Transposition** | Permutasi posisi huruf berdasarkan urutan kolom kunci | Kunci huruf 2 | Mengacak posisi; kekuatannya ada di modifikasinya (lihat bagian 6) |
| **AES-256-GCM** | Enkripsi utama sekaligus autentikasi | Kunci sesi acak | Lapisan yang benar-benar menjaga kerahasiaan + deteksi perubahan data |
| **RSA-OAEP** | Membungkus kunci sesi AES | Pasangan public/private | Menyelesaikan masalah "cara mengirim kunci AES dengan aman" |
| **SHA-256** | Sidik jari pesan untuk verifikasi keutuhan | Tidak pakai kunci | Membuktikan hasil dekripsi identik dengan pesan asli |

Detail penting per lapisan:

**Vigenère (implementasi mandiri, tanpa library)**

- Formula klasik: enkripsi `C = (P + K) mod 26`, dekripsi `P = (C - K) mod 26`.
- Hanya huruf A-Z yang diproses. Spasi, angka, tanda baca, dan emoji disalin apa adanya, dan indeks kunci tidak maju saat melewati karakter non-alfabet.
- Huruf kunci besar/kecil dianggap sama (`RAHASIA` = `rahasia`), huruf pesan mempertahankan bentuknya.

**Modified Transposition (implementasi mandiri)**

- Lengkap di bagian 6.

**AES-256-GCM (library `cryptography` yang terpercaya)**

- Kunci sesi 32 byte (256-bit) dari CSPRNG, baru setiap enkripsi.
- Nonce 12 byte dari `os.urandom`, baru setiap enkripsi, tidak pernah statis.
- Tidak memakai ECB. Mode GCM memberi kerahasiaan sekaligus autentikasi.
- Format payload: `nonce(12) || ciphertext+tag(16)`. Library menggabungkan tag di akhir ciphertext, dan dokumentasinya ditaruh di `crypto/aes.py`.
- Perubahan satu bit pun pada ciphertext, nonce, atau kunci membuat dekripsi gagal (`InvalidTag`).

**RSA-OAEP**

- RSA-2048 dengan padding OAEP (MGF1 + SHA-256). Bukan textbook RSA.
- Kunci sesi 32 byte selalu muat satu blok (kapasitas OAEP-SHA256 pada RSA-2048 = 190 byte).
- Public key disimpan sebagai PEM SubjectPublicKeyInfo, private key sebagai PEM PKCS#8.

**SHA-256**

- Fungsi hash satu arah. Bukan enkripsi: tidak ada kunci dan tidak bisa "didekripsi".
- Perbandingan hash memakai `hmac.compare_digest` agar bebas serangan timing.

---

## 6. Modifikasi Transposition (Keunikan Project)

Ini kontribusi desain utama project, bukan transposition standar dari buku:

| Aspek | Transposition Standar | Modifikasi Project |
|---|---|---|
| Whitespace | Dibiarkan apa adanya | Dipadatkan jadi satu spasi, panjang jadi deterministik |
| Jumlah kolom | Bergantung faktor panjang teks | Ditentukan panjang kunci |
| Urutan baca kolom | Kolom dari kiri ke kanan | Diurutkan dari sortir karakter kunci (indeks asli ikut disortir, jadi kunci berhuruf duplikat seperti `BAAC` tetap deterministik) |
| Padding | Tidak ada | Sentinel `\x01` ditambahkan sampai panjang kelipatan jumlah kolom, agar matriks selalu penuh dan dekripsi pasti bisa dibalik |
| Pemisah kolom | Tidak ada | Karakter kontrol `\x1F` (Unit Separator) antar kolom, agar batas kolom jelas meski panjang kolom beda |
| Kunci salah | Sering "berhasil" tapi hasil kacau | Jumlah segmen atau panjang segmen tidak wajar langsung ditolak (`TranspositionError`) |

Konsekuensinya, enkripsi-dekripsi **benar-benar reversibel** untuk semua bentuk input, dan kunci berbeda menghasilkan ciphertext berbeda yang pasti ditolak saat didekripsi salah.

---

## 7. Manajemen Kunci AES Session

- Setiap proses enkripsi membuat kunci sesi baru 32 byte dari CSPRNG.
- Kunci sesi tidak pernah ditampilkan di UI dan tidak pernah dikirim polos. Ia langsung dibungkus RSA-OAEP setelah dibuat.
- Saat dekripsi, kunci sesi hanya hidup di memori sesaat antara dibuka dari RSA sampai dipakai AES.
- Konstanta `aes_key_b64` ada di hasil pipeline hanya untuk keperluan pengujian; UI tidak menampilkannya.

---

## 8. Penggunaan RSA dan SHA-256

**RSA (RSA-2048 + OAEP-SHA256):**

- Public key membungkus kunci sesi AES saat enkripsi.
- Private key membukanya saat dekripsi.
- Private key hasil generate bisa diunduh sebagai file `.pem`, atau sebagai file `.json` terproteksi password (AES-256-CBC + HMAC-SHA256, turunan kunci via PBKDF2 200 ribu iterasi). Password salah ditolak.

**SHA-256:**

- Dipakai sebagai **verifikasi integritas**, bukan enkripsi.
- Enkripsi: hash pesan asli (bentuk kanonik, lihat catatan di bawah) disimpan bersama hasil.
- Dekripsi: hash dari hasil dekripsi dibandingkan dengan hash asli, `VALID` bila sama.
- Bentuk kanonik artinya whitespace dipadatkan seperti yang dilakukan lapisan transposition, sehingga pesan dengan spasi berlebih tetap VALID setelah roundtrip yang sah.

---

## 9. Testing

```bash
pytest -q
```

Hasil: **48 test, semuanya pass.** Terdiri dari 10 skenario wajib spesifikasi plus pengujian tiap lapisan:

10 skenario wajib (di `tests/test_pipeline.py`):

1. Plaintext pendek
2. Plaintext panjang
3. Plaintext dengan spasi tak beraturan
4. Plaintext dengan angka
5. Plaintext dengan karakter khusus
6. Kunci berbeda
7. Ciphertext dimodifikasi
8. Encrypted AES key dimodifikasi
9. Nonce dimodifikasi
10. Integrity hash tidak cocok

Pengujian lain:

- `test_aes.py`: roundtrip, kunci/nonce selalu acak, tampering satu byte ditolak, payload terpotong ditolak.
- `test_rsa.py`: bungkus/buka kunci sesi, kunci tak berpasangan ditolak, PEM rusak ditolak, wrapper password benar/salah.
- `test_vigenere.py`: vektor klasik (`HELLO`+`KEY`=`RIJVS`), karakter non-alfabet, kunci tanpa huruf ditolak.
- `test_transposition.py`: roundtrip berbagai bentuk teks, kunci duplikat, whitespace, ciphertext rusak ditolak.

Dua skrip verifikasi tambahan:

```bash
python smoke_test.py   # 10 skenario end-to-end lewat pipeline
python ui_test.py      # simulasi klik semua tombol di UI via Streamlit AppTest
```

> Catatan lingkungan: `conftest.py` mengarahkan `sys.path` ke site-packages Python 3.13 karena di mesin pengembang package `cryptography` terinstal di sana. Di mesin lain dengan `cryptography` terinstal normal, file ini tidak masalah karena hanya menambah path yang tersedia.

---

## 10. Struktur Project

```text
hash/
├── app.py                  # UI Streamlit (4 tab, alur 3 langkah terpandu)
├── requirements.txt        # streamlit, cryptography, pytest
├── README.md
├── pytest.ini              # konfigurasi pytest
├── conftest.py             # setup path import untuk pytest
├── smoke_test.py           # verifikasi end-to-end 10 skenario
├── ui_test.py              # verifikasi klik semua elemen UI
│
├── crypto/                 # seluruh algoritma
│   ├── __init__.py
│   ├── vigenere.py         # Layer 1: substitusi (implementasi mandiri)
│   ├── transposition.py    # Layer 2: permutasi posisi (implementasi mandiri)
│   ├── aes.py              # Layer 3: AES-256-GCM (library cryptography)
│   ├── rsa.py              # RSA-OAEP pembungkus kunci sesi
│   ├── integrity.py        # SHA-256 verifikasi integritas
│   ├── pipeline.py         # orkestrator enkripsi & dekripsi
│   └── exceptions.py       # exception kustom seluruh pipeline
│
├── utils/
│   ├── __init__.py
│   ├── encoding.py         # Base64 encode/decode (encoding, bukan enkripsi)
│   └── validation.py       # validasi input UI
│
└── tests/
    ├── test_vigenere.py
    ├── test_transposition.py
    ├── test_aes.py
    ├── test_rsa.py
    └── test_pipeline.py    # 10 skenario wajib + validasi input
```

Prinsip pemisahan: **tidak ada satu file besar**. UI (`app.py`) tidak berisi logika kriptografi; semua logika ada di modul `crypto/` yang bisa diuji terpisah.

---

## 11. Keterbatasan

- Kunci tersimpan di memori sesi browser. Menutup tab berarti kunci hilang dan harus generate ulang; ini disengaja agar kunci tidak pernah ditulis ke disk tanpa sengaja.
- UI tidak menampilkan kunci sesi AES. Nilai `aes_key_b64` di pipeline hanya untuk pengujian otomatis.
- Pipeline klasik (Vigenère + Transposition) tidak menambah kekuatan kriptografis berarti dibanding AES saja; nilainya ada di sisi edukasi dan demonstrasi bertingkat.
- Aplikasi ini tool edukasi untuk tugas kuliah, bukan produk untuk pengiriman pesan produksi.
- Verifikasi integritas memakai hash tanpa kunci (bukan MAC). Untuk jaminan keutuhan yang sebenarnya, tag autentikasi GCM yang sudah memenuhi itu.

---

## 12. Ringkasan untuk Presentasi

Jangan berhenti di "kita menggabungkan 5 algoritma". Poin teknis yang menjawab "kenapa dan apa bedanya":

```text
Vigenère       → substitusi karakter: mengubah ISI huruf (C = (P+K) mod 26)
Modified       → permutasi posisi: mengubah POSISI huruf, urutan kolom
Transposition    ditentukan sortir karakter kunci + padding sentinel
AES-256-GCM    → enkripsi utama sekaligus authenticated encryption,
                 kunci sesi acak per pesan + nonce unik
RSA-OAEP       → melindungi kunci sesi AES, bukan plaintext
SHA-256        → verifikasi integritas hasil dekripsi, bukan enkripsi
```

Demo yang menjawab skeptis dosen:

1. Ubah 1 huruf di ciphertext → dekripsi gagal (bukti authenticated encryption bekerja).
2. Kunci klasik salah → dekripsi gagal (bukti kunci harus pasangan).
3. Integrity hash dipalsukan → plaintext terbaca tapi status INVALID (bukti SHA-256 mendeteksi pemalsuan).
