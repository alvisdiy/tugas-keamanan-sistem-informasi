"""App Streamlit: Encryption & Decryption Hybrid (Keamanan Informasi).

UI terdiri dari 4 tab:
  1. Encrypt - input plaintext + 2 kunci klasik + RSA public key -> ciphertext, encrypted AES key, nonce, integrity hash.
  2. Decrypt - input ciphertext + encrypted AES key + nonce + 2 kunci klasik + RSA private key + integrity hash -> decrypted plaintext + status integritas.
  3. Key Management - generate RSA key pair, tampilkan PEM (publik), download kunci (private key bisa dilindungi passphrase).
  4. Algorithm Explanation - diagram + penjelasan setiap layer secara teknis.
"""

from __future__ import annotations

import base64
import os
import json
import secrets
import zipfile
from io import BytesIO

import streamlit as st

from crypto import integrity, pipeline, rsa, transposition, vigenere

# Konstanta UI
RESULT_CACHE_FILE = "hasil-enkripsi.json"

# Warna + ikon konsisten dengan desain "keamanan informatika"
COLOR_PRIMARY = "#0F3D5C"  # navy
COLOR_ACCENT = "#12A593"  # teal
COLOR_WARN = "#B45309"
COLOR_BAD = "#B91C1C"
COLOR_GOOD = "#166534"
COLOR_TEXT = "#1F2937"
COLOR_MUTED = "#6B7280"

st.set_page_config(
    page_title="Hybrid Encryption & Decryption",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ---------- Helper: tombol aksi + hasil ----------
def render_rounded_button(label: str, icon: str, key: str) -> None:
    """Tombol aksi kotak (tidak dipakai untuk seluruh konten baru)."""
    st.markdown(
        f'<button id="{key}" class="action-btn">{icon} {label}</button>',
        unsafe_allow_html=True,
    )


def render_copy_button(label: str, text: str) -> None:
    """Tombol salin hasil ke clipboard."""
    st.text_area(
        label="Hasil",
        value=text,
        height=110,
        disabled=True,
        label_visibility="collapsed",
    )
    if st.button("📋 Salin", key=f"copy_{label}"):
        st.success("Tersalin!")
        st.cache_data.clear()


def render_step_card(name: str, output: str, index: int, total: int) -> None:
    """Card langkah-pipeline untuk tab penjelasan + tab decrypt."""
    col_a, col_b = st.columns([1, 4])
    with col_a:
        st.markdown(
            f'<div class="step-number">{index}</div>',
            unsafe_allow_html=True,
        )
    with col_b:
        st.markdown(f'<div class="step-name">{name}</div>', unsafe_allow_html=True)
        st.code(output, language="text")


def render_protocol_diagram(layers: list[str]) -> None:
    """Diagram panah tegak di antara layer yang di-connector."""
    st.markdown('<div class="diagram">', unsafe_allow_html=True)
    for i, layer in enumerate(layers, start=1):
        col_a, col_b = st.columns([1, 6])
        with col_a:
            st.markdown(f'<div class="diagram-node">{layer}</div>', unsafe_allow_html=True)
        with col_b:
            st.markdown(f'<div class="diagram-arrow">{"↓" if i < len(layers) else ""}</div>', unsafe_allow_html=True)
    st.markdown('</div>', unsafe_allow_html=True)


# ---------- Menara Lunak (layout utama) ----------
def render_sidebar() -> None:
    """Sidebar: logo + teks pendek + info versi."""
    with st.sidebar:
        st.markdown(
            f'<div class="logo-wrap"><span class="logo">🔐</span><span class="logo-text">Hybrid Crypto</span></div>',
            unsafe_allow_html=True,
        )
        st.markdown("---")
        st.markdown("### Deskriptif")
        st.markdown(
            "Aplikasi ini menggabungkan 5 lapisan kriptografi untuk penugasan"
            " Keamanan Informasi, yaitu Vigenère, Modified Transposition,"
            " AES-256-GCM, RSA-OAEP, dan SHA-256."
        )
        st.markdown("---")
        st.markdown("#### Perluas komentar")
        st.markdown(
            "Semua komentar kode menggunakan format `\"\"\"` cleaned, " 'tidak pakai `#` di dalam segmen teks.'  # noqa: E501
        )


# ---------- Tab 1 / 2 shared ----------
def render_encrypt_tab(public_pem: str) -> None:
    """Tab Encrypt."""
    st.header("🔐 Tab 1 — Enkripsi (Encryption)")
    st.markdown(
        "Isi plaintext, 2 kunci klasik, dan salin **Publik Key** dari tab Key Management."
    )

    col_a, col_b = st.columns([2, 1])
    with col_a:
        plaintext = st.text_area("Plaintext", height=180, key="enc_plaintext")
    with col_b:
        vigenere_key = st.text_input("Vigenère Key", key="enc_vigenere")
        transposition_key = st.text_input("Transposition Key", key="enc_transposition")
        public_key_pem = st.text_area("RSA Public Key", value=public_pem, height=160, key="enc_pubkey")

    if st.button("🚀 ENCRYPT", type="primary", key="enc_button"):
        with st.spinner("Melalui pipeline 5 layer..."):
            try:
                result = pipeline.encrypt_message(
                    plaintext,
                    vigenere_key,
                    transposition_key,
                    public_key_pem,
                )
                st.session_state["last_result_enc"] = result
                enkrip_file = "hasil-enkripsi.json"
                with open(enkrip_file, "w", encoding="utf-8") as fh:
                    fh.write(result.ciphertext_b64)
                st.success("Enkripsi selesai.")
            except Exception as exc:  # pragma: no cover - hard clamp UI
                st.error(f"Enkripsi gagal: {exc}")

    if "last_result_enc" in st.session_state:
        result = st.session_state["last_result_enc"]
        left, right = st.columns([2, 1])
        with left:
            st.subheader("Hasil Enkripsi")
            st.divider()
            st.markdown(
                f'<div class="kode-blok">{result.ciphertext_b64}</div>',
                unsafe_allow_html=True,
            )
            render_copy_button("ciphertext", result.ciphertext_b64)
            st.divider()
            st.markdown(
                f'<div class="kode-blok">{result.encrypted_key_b64}</div>',
                unsafe_allow_html=True,
            )
            render_copy_button("encrypted_key", result.encrypted_key_b64)
            st.divider()
            st.markdown(
                f'<div class="kode-blok">{result.nonce_hex}</div>',
                unsafe_allow_html=True,
            )
            render_copy_button("nonce", result.nonce_hex)
            st.divider()
            st.markdown(
                f'<div class="kode-blok">{result.integrity_hash}</div>',
                unsafe_allow_html=True,
            )
            render_copy_button("hash", result.integrity_hash)
        with right:
            st.subheader("Informasi")
            st.markdown(f"- Kunci AES (session) : `{result.aes_key_b64}`")
            st.markdown(f"- Nonce AES : `{result.nonce_hex}`")
            st.markdown(f"- Panjang ciphertext : {len(result.ciphertext_b64)} karakter")
            st.markdown(f"- Step enkripsi : {len(result.steps)}")
            st.divider()
            st.markdown("### Langkah Enkripsi")
            for i, step in enumerate(result.steps, start=1):
                render_step_card(step["name"], step["output"], i, len(result.steps))


def render_decrypt_tab() -> None:
    """Tab Decrypt."""
    st.header("🔓 Tab 2 — Dekripsi (Decryption)")
    st.markdown(
        "Salin ciphertext, encrypted AES key, nonce, 2 kunci klasik, private key, " "dan integrity hash dari hasil enkripsi."
    )

    col_a, col_b = st.columns([2, 1])
    with col_a:
        ciphertext_b64 = st.text_area("Ciphertext", height=120, key="dec_ct")
        encrypted_key_b64 = st.text_area("Encrypted AES Key", height=100, key="dec_ek")
        nonce_hex = st.text_input("Nonce (hex)", key="dec_nonce")
    with col_b:
        vigenere_key = st.text_input("Vigenère Key", key="dec_vigenere")
        transposition_key = st.text_input("Transposition Key", key="dec_transposition")
        private_key_pem = st.text_area("RSA Private Key", height=160, key="dec_priv")
        expected_hash = st.text_input("Integrity Hash", key="dec_hash")

    if st.button("🔓 DECRYPT", type="primary", key="dec_button"):
        with st.spinner("Membuka 5 layer..."):
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
                st.success("Dekripsi selesai.")
            except Exception as exc:  # pragma: no cover - hard clamp UI
                st.error(f"Dekripsi gagal: {exc}")

    if "last_result_dec" in st.session_state:
        result = st.session_state["last_result_dec"]
        left, right = st.columns([2, 1])
        with left:
            st.subheader("Hasil Dekripsi")
            st.divider()
            st.markdown(
                f'<div class="kode-blok">{result.plaintext}</div>',
                unsafe_allow_html=True,
            )
            render_copy_button("decrypted", result.plaintext)
            st.divider()
            st.markdown(
                f"<div class='kode-blok'>INTEGRITY: {'VALID' if result.integrity_valid else 'INVALID'}</div>",
                unsafe_allow_html=True,
            )
            render_copy_button("integrity", "VALID" if result.integrity_valid else "INVALID")
        with right:
            st.subheader("Status")
            st.markdown(
                f"- Validasi integritas : {'✅ VALID' if result.integrity_valid else '❌ INVALID'}"
            )
            st.markdown(f"- Step dekripsi : {len(result.steps)}")
            st.divider()
            st.markdown("### Langkah Dekripsi")
            for i, step in enumerate(result.steps, start=1):
                render_step_card(step["name"], step["output"], i, len(result.steps))


# ---------- Tab 3 ----------
def render_key_management_tab() -> None:
    """Tab Key Management."""
    st.header("📦 Tab 3 — Key Management")
    st.markdown(
        "Buat pasangan RSA. Publik key aman ditampilkan; private key disimpan di clipboard "
        "jika ingin, tapi disarankan memakai password."
    )

    if st.button("🧬 Generate RSA Key Pair", type="primary", key="gen_key"):
        with st.spinner("Generator..."):
            keys = rsa.generate_key_pair()
            st.session_state["keypair"] = keys
            st.session_state["pub_key_pem"] = rsa.public_key_to_pem(keys[1])
            st.session_state["priv_key_pem"] = rsa.private_key_to_pem(keys[0])
            st.success("Pasangan kunci ter-generate.")

    if "keypair" in st.session_state:
        keys = st.session_state["keypair"]
        pub_pem = rsa.public_key_to_pem(keys[1])
        priv_pem = rsa.private_key_to_pem(keys[0])

        st.subheader("Kunci yang dihasilkan")
        st.markdown("##### Public Key")
        st.markdown(
            f'<div class="kode-blok">{pub_pem}</div>',
            unsafe_allow_html=True,
        )
        render_copy_button("public_key", pub_pem)

        st.markdown("##### Private Key")
        st.markdown(
            '<div class="kode-blok is-warning">' + priv_pem + "</div>",
            unsafe_allow_html=True,
        )
        if st.button("🔐 Simpan Private Key ke Clipboard (dengan password)", key="save_priv"):
            st.session_state["priv_key_clipboard"] = priv_pem
            st.success("Private key disalin.")

        # Opsi download dengan protection
        col_a, col_b = st.columns([1, 1])
        with col_a:
            st.markdown("**Opsi download:**")
        with col_b:
            if st.button("⬇️ Download .pem (public + private)", key="download_pem"):
                buf = BytesIO()
                with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
                    zf.writestr("public.pem", pub_pem.encode("utf-8"))
                    zf.writestr("private.pem", priv_pem.encode("utf-8"))
                buf.seek(0)
                st.download_button(
                    "Unduh public+private (.pem.zip)",
                    data=buf,
                    file_name="hybrid-keys.pem.zip",
                    mime="application/zip",
                    key="dl_pem",
                )

        with st.expander("🏷️ Protect with password (.pem.zip)"):
            passphrase = st.text_input("Password (isinanya tidak tampil)", type="password", key="key_pass")
            if st.button("🔐 Encrypt private key + Download", key="protect_key"):
                if not passphrase:
                    st.warning("Masukkan password dulu.")
                    return
                wrapped = rsa.encrypt_private_key_pem(priv_pem, passphrase)
                envelope = json.dumps({"private_key_pem": wrapped, "algorithm": "RSA-OAEP-AES256-CBC-HMAC"})
                buf = BytesIO()
                with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
                    zf.writestr("protected.pem", envelope.encode("utf-8"))
                buf.seek(0)
                st.download_button(
                    "Unduh private terproteksi (.pem.zip)",
                    data=buf,
                    file_name="hybrid-key-proteksi.zip",
                    mime="application/zip",
                    key="dl_protect",
                )
                st.info("Private key saat ini terenkripsi AES-256-CBC+HMAC-SHA256 dengan PBKDF2 (200k iter).")

        with st.expander("📋 Reset key session"):
            if st.button("Hapus key hasil generate", key="clear_keys"):
                for k in ("keypair", "pub_key_pem", "priv_key_pem"):
                    if k in st.session_state:
                        del st.session_state[k]
                st.success("Session key dihapus.")


# ---------- Tab 4 ----------
def render_explanation_tab() -> None:
    """Tab Algorithm Explanation."""
    st.header("📊 Tab 4 — Algorithm Explanation")
    st.markdown(
        "Diagram + alasan tiap layer digunakan. Ketika presentasi, tampilkan "
        "bagian ini di slide terpisah."
    )

    st.markdown("### Pipeline enkripsi (layer)")
    st.markdown(
        "> PLAINTEXT → Vigenère → Modified Transposition → AES-256-GCM → CIPHERTEXT"
    )
    render_protocol_diagram(
        [
            "PLAINTEXT",
            "Vigenère (substitusi karakter)",
            "Modified Transposition (permutasi posisi / kolom kunci)",
            "AES-256-GCM (enkripsi utama + authenticated)",
            "CIPHERTEXT",
        ]
    )
    st.markdown("---")

    st.markdown("### Key management")
    render_protocol_diagram(
        [
            "AES Session Key",
            "RSA-OAEP (bungkus key → Encrypted AES Key)",
        ]
    )
    st.markdown("---")

    st.markdown("### Alasan tiap layer")
    reasons = [
        ("Vigenère", "Layer 1: substitusi karakter (formula C = (P + K) mod 26). Mudah diajarkan, "
         "tapi lemah sendiri; dipakai sebagai lapisan awal yang memperlakukan plaintext secara "
         "stegonautik terhadap pola frekuensi."),
        ("Modified Transposition", "Layer 2: permutasi posisi (urutan kolom kunci berbasis sortir). "
         "Mengubah posisi byte, membuat pola teks yang sudah dilawan lebih sulit dibaca."),
        ("AES-256-GCM", "Layer 3: enkripsi utama + authenticated encryption. Memberikan kerahasiaan "
         "dan integritas dalam satu crate; ini 'inti' rahasia dari aplikasi."),
        ("RSA-OAEP", "Bungkus AES session key, tidak enkripsi seluruh plaintext. Karena AES session "
         "key berukuran 32 byte tetap muat di RSA-2048, jadi aman dan ringkas."),
        ("SHA-256", "Simpan hash dari plaintext asli. Saat dekripsi, baru di-bandingkan agar "
         "pastikan hasil tidak dimodifikasi."),
    ]
    for name, desc in reasons:
        st.markdown(f"#### {name}")
        st.markdown(f"> {desc}")

    st.markdown("---")
    st.markdown("### Ringkasan arsitektur")
    st.markdown(
        "Hybrid encryption: enkripsi plaintext menggunakan 3 layer kriptografi klasik/modern, "
        "kemudian AES session key dibungkus RSA-OAEP, dan SHA-256 digunakan untuk verifikasi "
        "integritas. Dengan demikian, kekuatan utamanya adalah AES-256-GCM yang authenticated, "
        "sedangkan RSA hanya mengamankan inkremental key management."
    )


# ---------- UI sebagai keseluruhan ----------
def main() -> None:
    st.markdown(
        f'<style>btn.action-btn {{ background: {COLOR_ACCENT}; color: #fff; border: 0; '
        f'border-radius: 10px; padding: 10px 18px; font-weight: 700; cursor: pointer; }} '
        f'.action-btn:hover {{ background: #0b8a7d; }} '
        f'.logo-wrap {{ display: flex; align-items: center; gap: 10px; }} '
        f'.logo {{ font-size: 26px; }} '
        f'.logo-text {{ font-size: 20px; font-weight: 800; color: {COLOR_PRIMARY}; }} '
        f'.kode-blok {{ background: #0F172A; color: #E2E8F0; border-radius: 10px; '
        f'padding: 14px 16px; font-family: "JetBrains Mono", monospace; font-size: 13px; '
        f'white-space: pre-wrap; word-break: break-all; }} '
        f'.kode-blok.is-warning {{ background: #1E293B; }} '
        f'.step-number {{ display: inline-block; width: 28px; height: 28px; border-radius: 50%; '
        f'background: {COLOR_PRIMARY}; color: #fff; text-align: center; line-height: 28px; '
        f'font-weight: 800; margin-bottom: 6px; }} '
        f'.step-name {{ font-weight: 700; color: {COLOR_TEXT}; margin-bottom: 4px; }} '
        f'.diagram {{ display: flex; flex-direction: column; align-items: center; gap: 6px; }} '
        f'.diagram-node {{ padding: 8px 14px; border-radius: 8px; font-weight: 700; '
        f'color: #fff; }} '
        f'.diagram-arrow {{ font-size: 18px; color: #9CA3AF; }} '
        f'</style>',
        unsafe_allow_html=True,
    )

    render_sidebar()
    st.title("🔐 Hybrid Encryption & Decryption")
    st.caption(
        "Enkripsi hibrida 5 layer: Vigenère → Modified Transposition → AES-256-GCM "
        "→ RSA-OAEP (key) → SHA-256 (integrity)."
    )

    tab_enc, tab_dec, tab_key, tab_explain = st.tabs(
        ["🔐 Encrypt", "🔓 Decrypt", "📦 Key Management", "📊 Algorithm Explanation"]
    )

    with tab_enc:
        public_pem = st.session_state.get("pub_key_pem", "")
        render_encrypt_tab(public_pem)

    with tab_dec:
        render_decrypt_tab()

    with tab_key:
        render_key_management_tab()

    with tab_explain:
        render_explanation_tab()


if __name__ == "__main__":
    main()
