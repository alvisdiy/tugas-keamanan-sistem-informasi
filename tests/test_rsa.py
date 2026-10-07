"""Test RSA-OAEP untuk pembungkusan AES session key."""

import json

import pytest

from crypto import rsa
from crypto.exceptions import KeyManagementError


@pytest.fixture(scope="module")
def keypair():
    return rsa.generate_key_pair()


def test_bungkus_dan_buka_session_key(keypair):
    session_key = b"\x01" * 32
    wrapped = rsa.encrypt_session_key(session_key, keypair[1])
    assert rsa.decrypt_session_key(wrapped, keypair[0]) == session_key


def test_encrypted_key_berubah_setiap_waktu(keypair):
    session_key = b"\x02" * 32
    a = rsa.encrypt_session_key(session_key, keypair[1])
    b = rsa.encrypt_session_key(session_key, keypair[1])
    assert a != b, "OAEP harus menambahkan randomisasi"


def test_key_tidak_pasangan_ditolak():
    k1 = rsa.generate_key_pair()
    k2 = rsa.generate_key_pair()
    wrapped = rsa.encrypt_session_key(b"\x03" * 32, k1[1])
    with pytest.raises(KeyManagementError):
        rsa.decrypt_session_key(wrapped, k2[0])


def test_encrypted_key_dimodifikasi_ditolak(keypair):
    wrapped = bytearray(rsa.encrypt_session_key(b"\x04" * 32, keypair[1]))
    wrapped[10] ^= 0xFF
    with pytest.raises(KeyManagementError):
        rsa.decrypt_session_key(bytes(wrapped), keypair[0])


def test_serialisasi_pem_roundtrip(keypair):
    priv_pem = rsa.private_key_to_pem(keypair[0])
    pub_pem = rsa.public_key_to_pem(keypair[1])
    assert priv_pem.startswith("-----BEGIN PRIVATE KEY-----")
    assert pub_pem.startswith("-----BEGIN PUBLIC KEY-----")
    assert rsa.load_private_key(priv_pem).public_key().public_numbers() == (
        rsa.load_public_key(pub_pem).public_numbers()
    )


def test_pem_rusak_ditolak():
    with pytest.raises(KeyManagementError):
        rsa.load_private_key("bukan pem")
    with pytest.raises(KeyManagementError):
        rsa.load_public_key("-----BEGIN PUBLIC KEY-----\nzzz\n-----END PUBLIC KEY-----")


def test_private_key_wrapper_passphrase(keypair):
    priv_pem = rsa.private_key_to_pem(keypair[0])
    envelope = rsa.encrypt_private_key_pem(priv_pem, "passphrase-ku")
    assert json.loads(envelope)["ciphertext"]
    assert rsa.decrypt_private_key_pem(envelope, "passphrase-ku") == priv_pem
    with pytest.raises(KeyManagementError):
        rsa.decrypt_private_key_pem(envelope, "passphrase-salah")
