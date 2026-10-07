"""Konfigurasi pytest: pastikan paket crypto dan utils dapat diimpor.

Catatan lingkungan: cryptography diinstal di Python 3.13, sedangkan
interpreter utama di lingkungan ini adalah Python 3.12. Agar modul kimia
berjalan, path site-packages Python 3.13 dimasukkan ke sys.path dan DLL
directory pembungkus Rust (_rust.pyd) didaftarkan lewat os.add_dll_directory.
"""
import os
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# cryptography diinstal di Python 3.13; daftarkan sebagai sumber import.
PYTHON313_SITE = Path(
    "C:/Users/alvis/AppData/Local/Programs/Python/Python313/Lib/site-packages"
)
if str(PYTHON313_SITE) not in sys.path:
    sys.path.insert(0, str(PYTHON313_SITE))

# Daftarkan DLL directory agar pembungkus _rust.pyd dapat dimuat.
try:
    os.add_dll_directory(
        str(Path("C:/Users/alvis/AppData/Local/Programs/Python/Python313/DLLs"))
    )
except Exception:
    pass
