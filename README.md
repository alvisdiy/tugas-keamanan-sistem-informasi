# 🔐 Hybrid Encryption & Decryption

Aplikasi **Encryption & Decryption Hybrid** berbasis **Python + Streamlit** untuk tugas Mata Kuliah **Keamanan Informasi**. Aplikasi ini melakukan **hybrid encryption** dengan mengombinasikan 5 algoritma/komponen kriptografi, sehingga desainnya jauh berbeda dari implementasi sederhana yang hanya mengandalkan satu algoritma.

> Project berada di: `C:\data\AINGMAUNGG\hash`

---

## 1. Deskripsi Project

Aplikasi ini mengenkripsi plaintext menggunakan **pipeline bertingkat**:

```text
PLAINTEXT
    │
    ▼
[Vigenère Cipher]
    │
    ▼
[Modified Transposition Cipher]
    │
    ▼
[AES-256-GCM]
    │
    ▼
CIPHERTEXT
```

Selanjutnya, **AES session key** yang dihasilkan percuma dibungkus dengan **RSA-OAEP**, dan **SHA-256** digunakan untuk verifikasi integritas. Seluruh proses divisualisasikan sebagai *steps* (langkah) sehingga mudah didemonstrasikan saat presentasi.

---

## 2. Tujuan Project

- Melakukan enkripsi plaintext → ciphertext.
- Melakukan dekripsi ciphertext → plaintext.
- Mengombinasikan **banyak** algoritma kriptografi (Vigenère, Modified Transposition, AES-256, RSA, SHA-256), bukan hanya satu.
- Menampilkan proses setiap layer secara jelas agar mudah didemonstrasikan di presentasi.
- Menjaga desain algoritma yang berbeda dari kelompok lain (tidak sekadar “menggabungkan fungsi bawaan”).

---

## 3. Arsitektur Algoritma

```text
PLAINTEXT
    │
    ▼
SHA-256 (hash plaintext asli)
    ▼
Vigenère (substitusi, C = (P + K) mod 26)
    ▼
Modified Transposition (permutasi posisi)
    ▼
AES-256-GCM (session key acak + nonce unik + tag autentikasi)
    ▼
Encryption Bundle:
  - ciphertext            (Base64)
  - encrypted AES key     (Base64)
  - nonce                 (hex)
  - integrity hash        (hex SHA-256)
    ▲
    │
Dekripsi mengikuti urutan kebalikan (RSA → AES → Transposition → Vigenere → hash)
```

**Pengamanan AES session key:**

```text
AES Session Key ──► RSA-OAEP (encrypted) ──► Encrypted AES Key
```

**Verifikasi integritas:**

```text
SHA256(plaintext asli) =Integrity Hash
SHA256(decrypted plaintext)  = hash yang dihitung ulang
Bandikan → INTEGRITY: VALID / INVALID
```

---

## 4. Algoritma yang Digunakan

### A. Vigenère Cipher (Layer 1)

- Implementasi **mandiri** (tidak menggunakan library yang langsung menyediakan Vigenère).
- Formula klasik:

  ```text
  Enkripsi : C = (P + K) mod 26
  Dekripsi : P = (C - K) mod 26
  ```

- Merujuk hanya pada huruf A–Z.
- Karakter non-alfabet (spasi, angka, tanda baca, emoji) **dilewati dan disalin apa adanya**, sehingga pesan asli tetap terlihat.
- Bukan enkripsi yang kuat sendiri, tetapi berfungsi sebagai lapisan pertimbangan awal agar statistik frekuensi ciphertext sedikit berubah sehingga pola teks sederhana lebih sulit dibaca.

### B. Modified Transposition Cipher (Layer 2)

Ini adalah **kontribusi utama** dalam hal desain algoritma. Transposition standar yang disederhanakan hanya mengurutkan kolom; di sini terdapat beberapa modifikasi:

1. **Normalisasi whitespace**  
   Spasi, tab, dan baris baru dipadatkan menjadi satu spasi. Panjang data menjadi deterministik dan tidak bergantung jumlah baris baru yang membingungkan.

2. **Jumlah kolom = panjang kunci**  
   Semakin panjang kunci, semakin banyak kolom. Ini membuat ruang hasil enkripsi bergantung pada pilihan kunci.

3. **Urutan kolom ditentukan oleh sortir karakter kunci**  
   Setiap karakter kunci mendapat indeks aslinya; karakter diubah ke huruf kecil (agar `BACA` dan `BAAC` konsisten), lalu di-sort. Urutan indeks asli tetap dipakai, sehingga kunci dengan karakter duplikat (`BAAC`) tetap menghasilkan urutan yang deterministik.

4. **Padding sentinel (`\x01`)**  
   Data ditambahkan `padding` sehingga panjangnya kelipatan jumlah kolom, sehingga matriks dekripsi selalu penuh dan proses bisa dibalik tanpa kebocoran panjang berlebih.

5. **Pemisah kolom `\x1F` (unit separator)**  
   Setiap kolom hasil bacaan dipisahkan `Unit Separator`. Dekripsi tahu batas kolom meskipun panjang kolom tidak seragam. Karakter kontrol tidak mungkin muncul di data asli karena dibuang saat normalisasi.

**Format output ciphertext transposition:**

```text
kolom1\x1Fkolom2\x1F...kolomN
```

Dengan modifikasi ini, enkripsi dan dekripsi **benar-benar reversibel** dan kunci berbeda menghasilkan ciphertext berbeda (juga memperlihatkan ketidakcocokan saat kunci salah).

### C. AES-256-GCM (Layer 3)

- **AES-256-GCM** digunakan sebagai lapisan enkripsi utama.
- **TIDAKMenggunakan ECB.**
- **AES session key** dihasilkan dari `os.urandom(32)` (CSPRNG), **bukan** yang di-hardcode.
- **Nonce** dihasilkan `os.urandom(12)` baru setiap proses enkripsi, **tidak statis**.
- Format payload: `nonce(12) || ciphertext + tag(16)`. Library `cryptography` mengeluarkan ciphertext yang sudah disertai tag autentikasi pada bagian akhir; dengan demikian payload tunggal ini cukup untuk dekripsi.
- **Authenticated encryption**: perubahan satu bit pada ciphertext atau nonce akan membuat dekripsi gagal (InvalidTag).
- Kunci AES selalu 32 byte.

### D. RSA (RSA-OAEP): mengamankan AES session key saja

- **Tidak mengenkripsi seluruh plaintext.**
- Menggunakan **RSA-2048** dengan **OAEP padding (MGF1 + SHA-256)**, padding yang aman dan standar, bukan textbook RSA.
- Session key 32 byte selalu muat dalam satu blok RSA-2048 (kapasitas plaintext OAEP-SHA256 = 190 byte).
- Serialisasi PEM PKCS#8 untuk private key, SubjectPublicKeyInfo untuk public key.
- Ada juga enkapsulasi private key dengan passphrase: `AES-256-CBC + HMAC-SHA256` yang terkunci passphrase lewat PBKDF2-HMAC-SHA256 200.000 iterasi, misalnya saat ingin mendownload kunci yang lebih terlindungi.

### E. SHA-256 Integrity Verification

- Menghasilkan hash `SHA-256(original plaintext)`.
- Saat dekripsi, hash dari hasil dekripsi dibandingkan dengan hash asli menggunakan `hmac.compare_digest` (kontradiktif, kebocoran timing reduksi).
- **SHA-256 hanyalah fungsi hash, bukan algoritma enkripsi.**

---

## 5. Modifikasi pada Transposition Cipher

| Aspek | Implementasi Standar | Modifikasi yang Dipilih |
|---|---|---|
| Whitespace | Tidak selalu dinormalisasi | Dipadatkan ke satu spasi, sehingga panjang deterministik |
| Jumlah kolom | Biasanya dari faktor plaintext | Ditentukan panjang kunci |
| Urutan baca | Kolom naik biasa | Urutan dari sortir kunci + indeks asli |
| Padding | Tidak selalu ada | Sentinel `\x01` dipakai agar matriks pasti bulat |
| Pemisah kolom | Bersifat teks biasa | `\x1F` (Unit Separator) dipakai sebagai delimiter |
| Perilaku saat kunci salah | Sering “berhasil” tetapi menghasilkan teks tetap | Format segment tidak cocok / panjang tidak wajar → `TranspositionError` |

Dengan demikian, modifikasi ini memberikan **keunikan** yang justru cocok untuk presentasi: lebih dari sekadar menggeser baris, algoritma ini mengubah susunan berdasarkan urutan sortir kunci, ada padding & pemisah yang eksplisit, dan memiliki mekanisme konfirmasi format yang jelas.

---

## 6. Alur Enkripsi

1. User mengirim plaintext, kunci Vigenère, kunci transposition, dan *public key* RSA.
2. `pipeline.encrypt_message()`:
   - Hitung `SHA-256(plaintext)` → `integrity_hash`.
   - Enkripsi Vigenère.
   - Enkripsi Modified Transposition.
   - Bangkitkan AES session key acak (`32 byte`) dan nonce acak (`12 byte`).
   - Lakukan AES-256-GCM encrypt.
   - Bungkus session key dengan RSA-OAEP menggunakan public key.
3. Mengembalikan `EncryptResult` berisi:
   - `ciphertext_b64`
   - `encrypted_key_b64`
   - `nonce_hex`
   - `integrity_hash`
   - `steps`
   - `aes_key_b64` (hanya untuk demonstrasi pembelajaran; **tidak dikirim** saat proses nyata).

---

## 7. Alur Dekripsi

1. User mengirim ciphertext, encrypted AES key, nonce, kunci Vigenère, kunci transposition, *private key* RSA, dan `expected hash`.
2. `pipeline.decrypt_message()`:
   - Decode Base64 ciphertext + encrypted key.
   - Konversi nonce hex → bytes.
   - Muat private key RSA.
   - Buka session key dengan RSA-OAEP.
   - Validasi nonce terhadap payload (panjang 12 byte pertama payload).
   - AES-256-GCM decrypt (otomatis cek tag autentikasi; gagal → `DecryptionError`).
   - Susun ulang Modified Transposition.
   - Dekripsi Vigenère.
   - Bandingkan `SHA-256(decrypted plaintext)` dengan hash asli.
3. Mengembalikan `DecryptResult` berisi plaintext + `integrity_valid` + `steps`.

---

## 8. Manajemen AES Session Key

- Setiap proses enkripsi membuat **session key baru** 32 byte dari CSPRNG.
- Session key **tidak pernah** disimpan secara permanen, melainkan:
  - Dikirim bersama ciphertext sebagai bagian dari bundle, lalu dibungkus RSA oleh penerima.
  - Dijaga raghy beberapa saat hanya di memori selama proses enkripsi/dekripsi UI.

> Di UI, `aes_key_b64` ditampilkan agar pengguna memahami bahwa AES session key bersifat sesaat; dalam implementasi nyata, lebih disarankan tidak menyimpannya sama sekali.

---

## 9. Penggunaan RSA

- **Public key** digunakan untuk membungkus AES session key.
- **Private key** digunakan untuk membuka bungkusan tersebut.
- Ukuran kunci: **RSA-2048**, padding **OAEP(SHA-256)**.
- Tidak ada penggunaan textbook RSA.
- Private key dapat dilindungi dengan password menggunakan wrapper AES-256-CBC+HMAC-SHA256 sebelum diunduh.

---

## 10. Penggunaan SHA-256

- Hash digunakan untuk memverifikasi bahwa hasil dekripsi **tepat sama** dengan plaintext yang dikirim.
- Hash **bukan** enkripsi: tidak ada kunci, tidak bisa “didekripsi”, berguna hanya untuk perbandingan nilai.
- Saat integrity mismatch, aplikasi menampilkan `INTEGRITY: INVALID`.

---

## 11. Cara Menjalankan Aplikasi

### 11.1 Pastikan Python tersedia

Gunakan Python 3.10+. 

### 11.2 Install dependency

Buka terminal di folder project lalu jalankan:

```bash
pip install -r requirements.txt
```

File `requirements.txt`:

```text
# Core aplikasi
streamlit>=1.30
cryptography>=41.0

# Pengujian
pytest>=7.4
```

### 11.3 Jalankan Streamlit

```bash
streamlit run app.py
```

Setelah itu, silakan buka alamat yang muncul di terminal, biasanya:

```text
http://localhost:8501
```

---

## 12. Cara Melakukan Enkripsi

1. Buka **Tab Encrypt**.
2. Ketik plaintext.
3. Buat kunci Vigenère, misalnya `KunciVigenere`.
4. Buat kunci transposition, misalnya `KunciKolom`.
5. Daftar **Public Key**:
   - Buka tab **Key Management**.
   - Klik **Generate RSA Key Pair**.
   - Salin *Public Key*.
6. Klik **ENCRYPT**.
7. Hasil ditampilkan:
   - `Ciphertext`
   - `Encrypted AES Key`
   - `Nonce`
   - `Integrity Hash`
   - detail 5 step enkripsi.

---

## 13. Cara Melakukan Dekripsi

1. Buka **Tab Decrypt**.
2. Salin nilai dari hasil enkripsi:
   - `Ciphertext`
   - `Encrypted AES Key`
   - `Nonce`
   - `Vigenère Key`
   - `Transposition Key`
   - `RSA Private Key`
   - `Integrity Hash`
3. Klik **DECRYPT**.
4. Aplikasi akan tampil:
   - *Decrypted Plaintext*
   - *INTEGRITY: VALID* (pasti) atau *INTEGRITY: INVALID*

---

## 14. Testing

Jalankan test otomatis dengan:

```bash
pytest -q
```

Test menyertakan 10 skenario wajib spesifikasi:

1. Plaintext pendek
2. Plaintext panjang
3. Plaintext dengan spasi
4. Plaintext dengan angka
5. Plaintext dengan karakter khusus
6. Key berbeda
7. Ciphertext dimodifikasi
8. Encrypted AES key dimodifikasi
9. Nonce dimodifikasi
10. Integrity hash tidak cocok

Selain itu, test juga mencakup:

- AES-GCM roundtrip, nonce acak, kegagalan authenticasi untuk ciphertext/nonce/kunci berbeda.
- RSA-OAEP key wrap/unwrapping, serialisasi PEM, kegagalan saat kunci tidak cocok, dan wrapper private key bersandi password.
- Vigenere roundtrip, non-alfabet, kunci kosong/angka, dan plaintext kosong.
- Transposition roundtrip, kunci duplikat, whitespace normalization, dan modifikasi ciphertext.

Hasil yang diharapkan:

```text
77 passed
```

---

## 15. Keterbatasan Project

- Key management UI masih sederhana: private key disimpan di memori saat generate, dan *download* kunci dilakukan di perangkat yang sama.
- Vigenère/Tansposition **tidak** menggantikan AES; keduanya hanya komponen pipeline.
- `aes_key_b64` ditampilkan di UI untuk keperluan pembelajaran; dalam implementasi produksi, jangan pernah menampilkannya sebagai output yang dapat dicopy.
- SHA-256 bukan enkripsi; integritas hanyalah *one-way* verifikasi.

---

## 16. Hal Penting untuk Presentasi (Novelty/Modifikasi)

Jangan hanya bilang “menggabungkan Vigenère, Transposition, AES, RSA, SHA-256”. Jelaskan teknisnya:

```text
Vigenère      → substitusi karakter, formula C = (P + K) mod 26.
Modified Transposition → permutasi posisi dengan kolom berdasarkan sortir kunci, padding + pemisah kontrol.
AES-256-GCM   → enkripsi utama + authenticated encryption, nonce acak.
RSA-OAEP      → melindungi AES session key saja, bukan plaintext utama.
SHA-256       → verifikasi integritas, bukan enkripsi.
```

**Alasan setiap layer digunakan:**

| Layer | Fungsi |
|---|---|
| Vigenère |Pengganti lapisan substitusi awal yang mudah dijelaskan; berperan mengurangi pola frekuensi awal. |
| Modified Transposition |Mengubah posisi karakter sesuai urutan sortir kunci; lebih kompleks daripada columnar standar. |
| AES-256-GCM |Inti kerahasiaan + autentikasi: satu blok enkripsi kuat. |
| RSA-OAEP |Melindungi kunci sesi agar tanpa kunci publik tidak tahu session key. |
| SHA-256 |Membuktikan bahwa hasil dekripsi tidak dimodifikasi; satu arah saja, bukan enkripsi. |

---

## 17. Requirement Summary

`requirements.txt` minimal:

```text
streamlit
cryptography
```

Tambahan (opsional jika ingin melakukan test):

```text
pytest
```

Dalam repositori ini terdapat juga:

```text
requirements.txt
pytest.ini
conftest.py
.crypto/  # implementasi
utils/    # encoding & validation helper
tests/    # otomatized test
app.py    # Streamlit UI
README.md
```

---

## 18. Security Checklist

- ❌ **Tidak** menggunakan AES-ECB.
- ❌ **Tidak** hardcode AES session key.
- ❌ **Tidak** hardcode RSA private key.
- ❌ **Tidak** menggunakan random biasa untuk cryptographic key.
- ❌ **Tidak** menggunakan textbook RSA.
- ✅ Base64 hanya dibaca sebagai **encoding**, bukan enkripsi.
- ✅ SHA-256 **bukan** klaim enkripsi.
- ✅ Key generation menggunakan `os.urandom` / `AESGCM.generate_key`.
- ✅ Private key disimpan/diunduh hanya dengan mekanisme yang eksplisit, bukan dump tanpa hak.
