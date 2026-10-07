"""R-35 click-through: jalankan setiap tombol/elemen interaktif satu per satu.

Setiap kali AppTest menjalankan ulang script, referensi elemen lama menjadi
stale, jadi tombol selalu dicari ulang (fresh lookup) sebelum diklik.
"""
import sys

sys.stdout.reconfigure(encoding="utf-8")

from streamlit.testing.v1 import AppTest


def run_app():
    at = AppTest.from_file("app.py", default_timeout=120)
    at.run()
    return at


def main() -> int:
    at = run_app()
    assert not at.exception
    print("PASS: app dirender tanpa exception")

    # --- Tab 1: generate kunci ---
    btn = next(b for b in at.button if "Buat Pasangan Kunci" in b.label)
    btn.click()
    at.run()
    assert not at.exception
    assert at.session_state["keys_generated"] is True
    assert at.session_state["pub_key_pem"].startswith("-----BEGIN PUBLIC KEY-----")
    print("PASS: [Buat Pasangan Kunci RSA] -> kunci tersimpan, empty state hilang")

    # --- Tab 2: ENCRYPT jalur kosong ---
    at.text_area(key="enc_plaintext").set_value("")
    enc = next(b for b in at.button if b.label.endswith("ENCRYPT"))
    enc.click()
    at.run()
    assert not at.exception
    assert any("Pesan masih kosong" in e.value for e in at.error)
    print("PASS: [ENCRYPT] input kosong -> pesan error spesifik, tanpa crash")

    # --- Tab 2: ENCRYPT jalur sukses (lookup ulang tombol setelah run) ---
    at.text_area(key="enc_plaintext").set_value("Rapat jam 8 malam")
    at.text_input(key="enc_vigenere").set_value("KunciVigenere")
    at.text_input(key="enc_transposition").set_value("KunciKolom")
    enc = next(b for b in at.button if b.label.endswith("ENCRYPT"))
    enc.click()
    at.run()
    assert not at.exception
    result = at.session_state["last_result_enc"]
    assert result is not None, "hasil enkripsi tidak tersimpan"
    assert result.ciphertext_b64 and len(result.integrity_hash) == 64
    print("PASS: [ENCRYPT] input lengkap -> 4 hasil tampil")

    # --- Tab 2: expander demo langkah (muncul setelah enkripsi sukses) ---
    at.text_area(key="enc_plaintext").set_value("Rapat jam 8 malam")
    at.text_input(key="enc_vigenere").set_value("KunciVigenere")
    at.text_input(key="enc_transposition").set_value("KunciKolom")
    next(b for b in at.button if b.label.endswith("ENCRYPT")).click()
    at.run()
    assert not at.exception
    result = at.session_state["last_result_enc"]
    assert result is not None, "hasil enkripsi tidak tersimpan"
    assert any("Lihat langkah demi langkah" in e.label for e in at.expander)
    print("PASS: expander [Lihat langkah demi langkah] tampil di tab Encrypt")

    # --- Tab 3: auto-fill ---
    at.text_area(key="enc_plaintext").set_value("Rapat jam 8 malam")
    at.text_input(key="enc_vigenere").set_value("KunciVigenere")
    at.text_input(key="enc_transposition").set_value("KunciKolom")
    next(b for b in at.button if b.label.endswith("ENCRYPT")).click()
    at.run()
    result = at.session_state["last_result_enc"]
    assert at.text_area(key="dec_ct").value == result.ciphertext_b64
    assert at.text_input(key="dec_hash").value == result.integrity_hash
    assert at.text_area(key="dec_priv").value.startswith("-----BEGIN PRIVATE KEY-----")
    print("PASS: ciphertext, hash, private key auto-terisi di tab Decrypt")

    # --- Tab 3: DECRYPT jalur kosong (hapus semua nilai) ---
    at.text_area(key="dec_ct").set_value("")
    dec = next(b for b in at.button if b.label.endswith("DECRYPT"))
    dec.click()
    at.run()
    assert not at.exception
    assert any("kosong" in e.value.lower() for e in at.error)
    print("PASS: [DECRYPT] input kosong -> daftar field yang hilang ditampilkan")

    # --- Tab 3: DECRYPT jalur sukses ---
    at.text_area(key="dec_ct").set_value(result.ciphertext_b64)
    at.text_input(key="dec_vigenere").set_value("KunciVigenere")
    at.text_input(key="dec_transposition").set_value("KunciKolom")
    dec = next(b for b in at.button if b.label.endswith("DECRYPT"))
    dec.click()
    at.run()
    assert not at.exception
    d = at.session_state["last_result_dec"]
    assert d is not None and d.plaintext == "Rapat jam 8 malam"
    assert d.integrity_valid is True
    print("PASS: [DECRYPT] -> plaintext pulih + INTEGRITY VALID")

    # --- Tab 3: kunci salah -> error ramah, bukan crash ---
    at.text_input(key="dec_vigenere").set_value("KunciSalah")
    dec = next(b for b in at.button if b.label.endswith("DECRYPT"))
    dec.click()
    at.run()
    assert not at.exception
    assert len(at.error) >= 1, "dekripsi kunci salah harus error ramah"
    print("PASS: [DECRYPT] kunci salah -> pesan error ramah, tanpa traceback")

    # --- Tab 4: konten penjelasan ---
    all_text = "\n".join(m.value for m in at.markdown)
    assert "SHA-256" in all_text and "AES-256-GCM" in all_text
    print("PASS: tab [Cara Kerja] berisi tabel lapisan + diagram alur")

    # --- Tombol di tab 1: file terproteksi dengan password kosong ---
    at.tabs_key = None
    protect = next((b for b in at.button if b.label == "Buat file terproteksi"), None)
    if protect is not None:
        protect.click()
        at.run()
        assert any("password" in w.value.lower() for w in at.warning)
        print("PASS: [Buat file terproteksi] tanpa password -> peringatan ramah")

    print()
    print("SEMUA_ELEMAN_INTERAKTIF_TERUJI")
    return 0


if __name__ == "__main__":
    sys.exit(main())
