"""Paket crypto: algoritma pipeline enkripsi hibrida.

Isi:
- vigenere:       Layer 1, substitusi karakter klasik (implementasi mandiri).
- transposition:  Layer 2, modified transposition (permutasi posisi).
- aes:            Layer 3, AES-256-GCM (enkripsi utama terautentikasi).
- rsa:            RSA-OAEP untuk membungkus AES session key.
- integrity:      SHA-256 untuk verifikasi integritas.
- pipeline:       Orkestrator enkripsi/dekripsi hibrida.
- exceptions:     Exception kustom seluruh pipeline.
"""
