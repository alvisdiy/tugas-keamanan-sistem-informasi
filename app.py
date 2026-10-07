"""App Streamlit: Encryption & Decryption Hybrid (Keamanan Informasi).

Alur pakai 3 langkah, diurutkan agar pemula tidak bingung:
  Langkah 1 (Key Management): generate pasangan kunci RSA sekali di awal.
  Langkah 2 (Encrypt): isi pesan + 2 kunci, klik ENCRYPT, salin 4 hasil.
  Langkah 3 (Decrypt): tempel hasil enkripsi, klik DECRYPT, lihat pesan asli.
Tab keempat (Algorithm Explanation) berisi diagram untuk presentasi.

Hasil enkripsi otomatis terbawa ke tab Decrypt sehingga tidak perlu
salin-tempel manual kecuali ingin memindahkan antar perangkat.
"""
from __future__ import annotations

import json
from io import BytesIO
import zipfile

import streamlit as st

from crypto import pipeline, rsa

st.set_page_config(
    page_title="Hybrid Encryption & Decryption",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# Palet inti (3 warna) + 1 aksen: biru tua untuk teks penegas, hijau untuk
# status sukses, kuning untuk peringatan. Sisanya netral Streamlit.
COLOR_INK = "#1E3A5F"  # biru tua, warna identitas aplikasi
COLOR_WARN_BG = "#FFF8E1"
COLOR_WARN_BORDER = "#F5C518"

CUSTOM_CSS = f"""
<style>
    h1 {{ color: {COLOR_INK}; }}
    .step-badge {{
        display: inline-block;
        background: {COLOR_INK};
        color: #fff;
        font-weight: 700;
        padding: 4px 14px;
        border-radius: 6px;
        margin-bottom: 8px;
        font-size: 0.9rem;
    }}
    .hint {{
        background: {COLOR_WARN_BG};
        border-left: 4px solid {COLOR_WARN_BORDER};
        padding: 10px 14px;
        border-radius: 6px;
        font-size: 0.92rem;
    }}
    .pipeline-flow {{
        font-family: "Source Sans Pro", sans-serif;
        font-size: 1.05rem;
        font-weight: 600;
        color: {COLOR_INK};
        text-align: center;
        padding: 10px 0;
        letter-spacing: 0.02em;
    }}
</style>
"""


def badge(text: str) -> None:
    """Label langkah bernomor agar urutan pemakaian terlihat jelas."""
    st.markdown(f'<span class="step-badge">{text}</span>', unsafe_allow_html=True)


def hint(text: str) -> None:
    """Kotak petunjuk singkat, dipakai untuk menjelaskan 'apa yang harus dilakukan'."""
    st.markdown(f'<div class="hint">{text}</div>', unsafe_allow_html=True)


def flow_line(text: str) -> None:
    st.markdown(f'<div class="pipeline-flow">{text}</div>', unsafe_allow_html=True)


def init_session() -> None:
    """Nilai awal session_state supaya semua input punya sumber kebenaran."""
    defaults = {
        "pub_key_pem": "",
        "priv_key_pem": "",
        "keys_generated": False,
        "last_result_enc": None,
        "last_result_dec": None,
    }
    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value


# ---------------------------------------------------------------- Langkah 1
def render_key_management_tab() -> None:
    """Langkah 1: buat pasangan kunci RSA. Dilakukan sekali di awal."""
    st.header("Langkah 1. Buat Pasangan Kunci")
    st.markdown(
        "Kunci ini seperti **kunci pintu digital**. Yang dipakai untuk mengunci "
        "pesan (encrypt) berbeda dengan yang membuka (decrypt), jadi keduanya "
        "harus dibuat berpasangan. **Cukup dilakukan sekali** di awal sesi."
    )

    if st.button("🔑 Buat Pasangan Kunci RSA", type="primary", key="gen_key"):
        with st.spinner("Membuat kunci..."):
            private_key, public_key = rsa.generate_key_pair()
            st.session_state["priv_key_pem"] = rsa.private_key_to_pem(private_key)
            st.session_state["pub_key_pem"] = rsa.public_key_to_pem(public_key)
            st.session_state["keys_generated"] = True

    if not st.session_state["keys_generated"]:
        # Empty state: belum ada kunci, jelaskan apa yang akan muncul.
        st.info(
            "Belum ada kunci. Klik tombol biru di atas, lalu dua kotak teks "
            "akan muncul di bawah: satu untuk **mengunci** pesan, satu untuk "
            "**membuka** pesan."
        )
        return

    pub_pem = st.session_state["pub_key_pem"]
    priv_pem = st.session_state["priv_key_pem"]

    st.success("Kunci berhasil dibuat. Lanjut ke tab **2. Encrypt** di atas.")

    st.subheader("Public Key (untuk mengunci pesan)")
    st.caption("Boleh dibagikan ke siapa pun yang mau mengirim pesan ke kamu.")
    st.code(pub_pem, language="text")
    st.download_button(
        "⬇️ Simpan Public Key sebagai file",
        data=pub_pem,
        file_name="public_key.pem",
        mime="application/x-pem-file",
        key="dl_pub",
    )

    st.subheader("Private Key (untuk membuka pesan)")
    hint(
        "⚠️ JANGAN dibagikan. Siapa pun yang memegang kunci ini bisa membuka "
        "semua pesan terenkripsi kamu. Simpan di tempat aman."
    )
    st.code(priv_pem, language="text")
    st.download_button(
        "⬇️ Simpan Private Key sebagai file",
        data=priv_pem,
        file_name="private_key.pem",
        mime="application/x-pem-file",
        key="dl_priv",
    )

    with st.expander("Opsi lanjutan: kunci private terproteksi password"):
        passphrase = st.text_input(
            "Password untuk mengunci file private key",
            type="password",
            key="key_pass",
        )
        if st.button("Buat file terproteksi", key="protect_key"):
            if not passphrase:
                st.warning("Isi password dulu.")
            else:
                wrapped = rsa.encrypt_private_key_pem(priv_pem, passphrase)
                envelope = json.dumps(
                    {"private_key_pem": wrapped, "algorithm": "AES256-CBC-HMAC-SHA256 (PBKDF2 200k)"}
                )
                st.download_button(
                    "⬇️ Unduh private key terproteksi (.json)",
                    data=envelope,
                    file_name="private_key_protected.json",
                    mime="application/json",
                    key="dl_protect",
                )


# ---------------------------------------------------------------- Langkah 2
def render_encrypt_tab(public_pem: str) -> None:
    """Langkah 2: isi pesan + 2 kunci klasik, jalankan pipeline, salin hasil."""
    st.header("Langkah 2. Enkripsi Pesan")
    if not public_pem:
        st.warning(
            "Kamu belum punya kunci. Buka tab **1. Key Management** dulu dan "
            "klik **Buat Pasangan Kunci RSA**."
        )
        return

    st.markdown("Isi 3 kolom di bawah, lalu klik **ENCRYPT**.")

    plaintext = st.text_area(
        "1. Pesan yang mau dirahasiakan (plaintext)",
        height=140,
        key="enc_plaintext",
        placeholder="Contoh: Rapat dimulai jam 8 malam di ruang 301",
    )

    col_a, col_b = st.columns(2)
    with col_a:
        vigenere_key = st.text_input(
            "2. Kunci Vigenère (huruf saja)",
            key="enc_vigenere",
            placeholder="Contoh: KunciVigenere",
            help="Harus huruf A-Z. Kunci ini menggeser huruf pesan satu per satu.",
        )
    with col_b:
        transposition_key = st.text_input(
            "3. Kunci Transposition (huruf saja)",
            key="enc_transposition",
            placeholder="Contoh: KunciKolom",
            help="Panjang kunci menentukan jumlah kolom; urutan hurufnya menentukan urutan baca.",
        )

    with st.expander("RSA Public Key (otomatis terisi dari Langkah 1)"):
        public_key_pem = st.text_area(
            "Public Key",
            value=public_pem,
            height=140,
            key="enc_pubkey",
            help="Sudah terisi otomatis. Ubah hanya jika mau memakai kunci milik orang lain.",
        )

    if st.button("🔒 ENCRYPT", type="primary", key="enc_button"):
        if not plaintext.strip():
            st.error("Pesan masih kosong. Isi dulu kolom nomor 1.")
        elif not vigenere_key.strip() or not transposition_key.strip():
            st.error("Dua kunci belum lengkap. Isi kunci Vigenère dan Transposition.")
        else:
            with st.spinner("Mengenkripsi melalui 5 lapisan..."):
                try:
                    result = pipeline.encrypt_message(
                        plaintext, vigenere_key, transposition_key, public_key_pem
                    )
                    st.session_state["last_result_enc"] = result
                    st.success("Selesai! Pesan sudah dienkripsi.")
                except Exception as exc:
                    st.error(f"Enkripsi gagal: {exc}")

    result = st.session_state["last_result_enc"]
    if result is None:
        return

    st.divider()
    st.subheader("Hasil Enkripsi")
    hint(
        "Empat nilai di bawah adalah **paket terkirim**. Untuk membuka pesan, "
        "semua nilai ini ditempel di tab **3. Decrypt** bersama kunci yang sama "
        "dan private key. Mereka juga otomatis terbawa ke tab itu."
    )

    st.markdown("**Ciphertext** (pesan yang sudah terkunci)")
    st.code(result.ciphertext_b64, language="text")

    st.markdown("**Encrypted AES Key** (kunci sesi yang dibungkus RSA)")
    st.code(result.encrypted_key_b64, language="text")

    st.markdown("**Nonce** (angka acak sekali pakai)")
    st.code(result.nonce_hex, language="text")

    st.markdown("**Integrity Hash** (sidik jari pesan asli, untuk cek keutuhan)")
    st.code(result.integrity_hash, language="text")

    with st.expander("Lihat langkah demi langkah apa yang terjadi (untuk demo)"):
        flow_line("Pesan → Vigenère → Transposition → AES-256-GCM → Ciphertext")
        for i, step in enumerate(result.steps, start=1):
            st.markdown(f"**Langkah {i}: {step['name']}**")
            st.code(step["output"], language="text")


# ---------------------------------------------------------------- Langkah 3
def render_decrypt_tab() -> None:
    """Langkah 3: tempel hasil enkripsi, buka pesan, cek integritas."""
    st.header("Langkah 3. Dekripsi Pesan")
    enc_result = st.session_state["last_result_enc"]

    if enc_result is not None:
        st.markdown(
            "Nilai dari hasil enkripsi **sudah terisi otomatis**. Pastikan kunci "
            "Vigenère dan Transposition sama persis dengan saat mengenkripsi, "
            "lalu klik **DECRYPT**."
        )
    else:
        st.markdown(
            "Tempel nilai dari hasil enkripsi (ciphertext, encrypted AES key, "
            "nonce, integrity hash), isi kedua kunci yang sama, tempel private "
            "key, lalu klik **DECRYPT**."
        )

    col_l, col_r = st.columns(2)
    with col_l:
        ciphertext_b64 = st.text_area(
            "Ciphertext",
            value=enc_result.ciphertext_b64 if enc_result else "",
            height=110,
            key="dec_ct",
            placeholder="Tempel ciphertext di sini",
        )
        encrypted_key_b64 = st.text_area(
            "Encrypted AES Key",
            value=enc_result.encrypted_key_b64 if enc_result else "",
            height=90,
            key="dec_ek",
            placeholder="Tempel encrypted AES key di sini",
        )
        nonce_hex = st.text_input(
            "Nonce",
            value=enc_result.nonce_hex if enc_result else "",
            key="dec_nonce",
            placeholder="Contoh: d615c62105d3def227f2",
        )
    with col_r:
        vigenere_key = st.text_input(
            "Kunci Vigenère (sama dengan saat encrypt)",
            key="dec_vigenere",
            placeholder="Contoh: KunciVigenere",
        )
        transposition_key = st.text_input(
            "Kunci Transposition (sama dengan saat encrypt)",
            key="dec_transposition",
            placeholder="Contoh: KunciKolom",
        )
        private_key_pem = st.text_area(
            "RSA Private Key",
            value=st.session_state["priv_key_pem"],
            height=90,
            key="dec_priv",
            placeholder="Tempel private key (dimulai dengan -----BEGIN PRIVATE KEY-----)",
        )
        expected_hash = st.text_input(
            "Integrity Hash",
            value=enc_result.integrity_hash if enc_result else "",
            key="dec_hash",
            placeholder="Tempel integrity hash (64 karakter)",
        )

    if st.button("🔓 DECRYPT", type="primary", key="dec_button"):
        missing = [
            label
            for label, value in [
                ("Ciphertext", ciphertext_b64),
                ("Encrypted AES Key", encrypted_key_b64),
                ("Nonce", nonce_hex),
                ("Kunci Vigenère", vigenere_key),
                ("Kunci Transposition", transposition_key),
                ("RSA Private Key", private_key_pem),
                ("Integrity Hash", expected_hash),
            ]
            if not value.strip()
        ]
        if missing:
            st.error("Masih ada yang kosong: " + ", ".join(missing))
        else:
            with st.spinner("Membuka lapisan enkripsi..."):
                try:
                    decrypted = pipeline.decrypt_message(
                        ciphertext_b64,
                        encrypted_key_b64,
                        nonce_hex,
                        vigenere_key,
                        transposition_key,
                        private_key_pem,
                        expected_hash,
                    )
                    st.session_state["last_result_dec"] = decrypted
                    st.session_state["last_result_enc"] = None
                except Exception as exc:
                    st.error(f"Dekripsi gagal: {exc}")

    dec_result = st.session_state["last_result_dec"]
    if dec_result is None:
        return

    st.divider()
    st.subheader("Hasil Dekripsi")
    if dec_result.integrity_valid:
        st.success("✅ INTEGRITY: VALID. Pesan sampai utuh, tidak ada yang berubah.")
    else:
        st.error("❌ INTEGRITY: INVALID. Isi pesan berbeda dari pesan asli yang di-hash.")

    st.markdown("**Pesan asli (plaintext):**")
    st.code(dec_result.plaintext, language="text")

    with st.expander("Lihat langkah pembukaan (untuk demo)"):
        flow_line("Ciphertext → RSA → AES → Transposition balik → Vigenère balik → Pesan")
        for i, step in enumerate(dec_result.steps, start=1):
            st.markdown(f"**Langkah {i}: {step['name']}**")
            st.code(step["output"], language="text")


# ---------------------------------------------------------------- Penjelasan
def render_explanation_tab() -> None:
    """Diagram + alasan tiap lapisan, siap dipakai untuk presentasi."""
    st.header("Cara Kerja Aplikasi")
    st.markdown(
        "Aplikasi ini mengunci pesan berlapis-lapis. Setiap lapisan punya tugas "
        "berbeda, dan kuncinya juga berbeda."
    )

    flow_line("Pesan → Vigenère → Transposition → AES-256-GCM → Ciphertext")

    st.markdown(
        """
| Lapisan | Tugasnya | Kuncinya |
|---|---|---|
| **Vigenère** | Menggeser setiap huruf pesan sesuai kunci, formula C = (P + K) mod 26 | Kunci huruf (mis. KunciVigenere) |
| **Modified Transposition** | Menyusun huruf ke matriks lalu membaca kolom sesuai urutan kunci, posisi huruf jadi acak | Kunci huruf kedua (mis. KunciKolom) |
| **AES-256-GCM** | Enkripsi utama modern, sekaligus mendeteksi jika data diubah (authenticated) | Kunci sesi acak, otomatis dibuat setiap encrypt |
| **RSA-OAEP** | Membungkus kunci sesi AES agar hanya pemilik private key yang bisa membukanya | Pasangan public/private key |
| **SHA-256** | Membuat sidik jari pesan asli, dibandingkan saat decrypt untuk memastikan pesan tidak diubah | Tidak pakai kunci (fungsi hash) |
"""
    )

    st.subheader("Alur kunci AES")
    flow_line("AES Session Key → dibungkus RSA → Encrypted AES Key")
    st.caption(
        "Kunci sesi AES baru dibuat acak setiap kali mengenkripsi dan hanya "
        "dikirim dalam bentuk terbungkus RSA, jadi tidak pernah dikirim polos."
    )

    st.subheader("Alur dekripsi (kebalikannya)")
    flow_line("Ciphertext → AES dibuka → Transposition dibalik → Vigenère dibalik → Pesan asli")

    st.subheader("Kenapa perlu bertingkat?")
    st.markdown(
        """
- Vigenère dan Transposition mudah dijelaskan tapi lemah sendiri-sendiri;
  dipakai berlapis untuk mengubah isi dan posisi huruf sebelum masuk AES.
- AES-256-GCM adalah lapisan yang benar-benar menjaga kerahasiaan,
  plus otomatis mendeteksi perubahan data (authentication tag).
- RSA-OAEP menyelesaikan masalah "bagaimana mengirim kunci AES dengan aman",
  tanpa pernah memakai RSA untuk mengenkripsi seluruh pesan.
- SHA-256 bukan enkripsi. Ia hanya memverifikasi bahwa hasil dekripsi
  identik dengan pesan asli.
"""
    )


# ---------------------------------------------------------------- Layout
def main() -> None:
    st.markdown(CUSTOM_CSS, unsafe_allow_html=True)
    init_session()

    with st.sidebar:
        st.header("🔐 Hybrid Encryption")
        st.caption("Tugas Keamanan Informasi")
        st.divider()
        st.markdown(
            "**Urutan pakai:**\n"
            "1. Buat kunci (sekali)\n"
            "2. Encrypt pesan\n"
            "3. Decrypt pesan\n\n"
            "Tab **Cara Kerja** berisi diagram untuk presentasi."
        )
        st.divider()
        if st.session_state["keys_generated"]:
            st.success("✅ Kunci sudah dibuat")
        else:
            st.warning("⚠️ Kunci belum dibuat. Mulai dari tab 1.")

    tab_key, tab_enc, tab_dec, tab_explain = st.tabs(
        [
            "1. Key Management",
            "2. Encrypt",
            "3. Decrypt",
            "Cara Kerja",
        ]
    )

    with tab_key:
        render_key_management_tab()
    with tab_enc:
        render_encrypt_tab(st.session_state["pub_key_pem"])
    with tab_dec:
        render_decrypt_tab()
    with tab_explain:
        render_explanation_tab()


if __name__ == "__main__":
    main()
