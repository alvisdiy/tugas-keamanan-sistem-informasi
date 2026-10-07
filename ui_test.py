"""Uji UI end-to-end dengan Streamlit AppTest.

Mensimulasikan alur pengguna nyata:
  1. Buka tab Key Management, klik Generate RSA Key Pair.
  2. Pindah ke tab Encrypt, isi plaintext + kunci, klik ENCRYPT.
  3. Pindah ke tab Decrypt, isi hasil enkripsi, klik DECRYPT.
  4. Pastikan plaintext pulih dan INTEGRITY VALID.
"""
import sys

sys.stdout.reconfigure(encoding="utf-8")

from streamlit.testing.v1 import AppTest

VIG = "KunciVigenere"
TRA = "KunciKolom"


def main() -> int:
    at = AppTest.from_file("app.py", default_timeout=120)
    at.run()

    assert not at.exception, f"App crash saat render: {at.exception}"
    print("[render] 4 tab dirender tanpa exception -> OK")

    # 1. Tab Key Management: generate key pair
    at.tabs[2].run()
    gen_btn = next(b for b in at.button if "Generate RSA" in b.label)
    gen_btn.click()
    at.run()
    assert not at.exception, f"App crash saat generate key: {at.exception}"
    pub_pem = at.session_state["pub_key_pem"]
    priv_pem = at.session_state["priv_key_pem"]
    assert pub_pem.startswith("-----BEGIN PUBLIC KEY-----")
    assert priv_pem.startswith("-----BEGIN PRIVATE KEY-----")
    print("[keymgmt] RSA key pair ter-generate -> OK")

    # 2. Tab Encrypt: isi input lalu klik ENCRYPT
    at.tabs[0].run()
    at.text_area(key="enc_plaintext").set_value("Pesan rahasia uji UI 123 !@#")
    at.text_input(key="enc_vigenere").set_value(VIG)
    at.text_input(key="enc_transposition").set_value(TRA)
    at.text_area(key="enc_pubkey").set_value(pub_pem)
    enc_btn = next(b for b in at.button if b.label.endswith("ENCRYPT"))
    enc_btn.click()
    at.run()
    assert not at.exception, f"App crash saat enkripsi: {at.exception}"
    result = at.session_state["last_result_enc"]
    assert result.ciphertext_b64 and result.encrypted_key_b64 and result.nonce_hex
    assert len(result.integrity_hash) == 64
    print("[encrypt] ciphertext + encrypted key + nonce + hash dihasilkan -> OK")

    # 3. Tab Decrypt: isi input dari hasil enkripsi lalu klik DECRYPT
    at.tabs[1].run()
    at.text_area(key="dec_ct").set_value(result.ciphertext_b64)
    at.text_area(key="dec_ek").set_value(result.encrypted_key_b64)
    at.text_input(key="dec_nonce").set_value(result.nonce_hex)
    at.text_input(key="dec_vigenere").set_value(VIG)
    at.text_input(key="dec_transposition").set_value(TRA)
    at.text_area(key="dec_priv").set_value(priv_pem)
    at.text_input(key="dec_hash").set_value(result.integrity_hash)
    dec_btn = next(b for b in at.button if b.label.endswith("DECRYPT"))
    dec_btn.click()
    at.run()
    assert not at.exception, f"App crash saat dekripsi: {at.exception}"
    decrypted = at.session_state["last_result_dec"]
    assert decrypted.plaintext == "Pesan rahasia uji UI 123 !@#"
    assert decrypted.integrity_valid is True
    print("[decrypt] plaintext pulih + INTEGRITY VALID -> OK")

    print("\nUI_E2E_OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
