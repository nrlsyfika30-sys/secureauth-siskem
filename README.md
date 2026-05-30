# SecureAuth
**Sistem Autentikasi Pengguna dengan Implementasi Manual Bcrypt dan SHA-256**

Mata Kuliah: Sistem Keamanan  
Program Studi: Teknik Informatika — UMRAH 2026

## Anggota Kelompok
| NIM | Nama | Tugas |
|-----|------|-------|
| 2401020007 | Alfa Julyana | Implementasi SHA-256 manual & pengujian keamanan |
| 2401020025 | Nurul Syafika | Implementasi Bcrypt manual & penyusunan laporan |
| 2401020026 | Pitria | UI/UX, database, flowchart, dokumentasi |

---

## Cara Menjalankan

### 1. Install dependensi
```bash
pip install flask
```

### 2. Jalankan server
```bash
python app.py
```

### 3. Buka browser
```
http://localhost:5000
```

---

## Struktur File

```
secureauth/
├── app.py              # Flask backend (routing, auth logic)
├── bcrypt_manual.py    # Implementasi Bcrypt dari scratch (tanpa library)
├── sha256_manual.py    # Implementasi SHA-256 dari scratch (tanpa library)
├── requirements.txt
├── secureauth.db       # Database SQLite (dibuat otomatis saat run)
└── templates/
    ├── login.html      # Halaman login
    ├── register.html   # Halaman registrasi
    └── dashboard.html  # Dashboard pengguna + visualisasi hashing
```

---

## Fitur Utama

- ✅ Registrasi pengguna
- ✅ Login pengguna
- ✅ Hashing password dengan **Bcrypt manual** (from scratch, tanpa library)
- ✅ Session token dengan **SHA-256 manual** (from scratch, tanpa library)
- ✅ Proteksi brute force (max 5 percobaan, lockout 5 menit)
- ✅ Dashboard + visualisasi edukasi proses hashing
- ✅ Demo interaktif SHA-256 dan Bcrypt

---

## Catatan Implementasi

### SHA-256 (sha256_manual.py)
Diimplementasi berdasarkan standar **FIPS PUB 180-4** (NIST).  
Tahapan: Padding → Message Schedule → Compression Function (64 round) → Digest

### Bcrypt (bcrypt_manual.py)
Diimplementasi berdasarkan paper **Provos & Mazieres (1999)**.  
Menggunakan cipher Blowfish (EksBlowfish key setup) dengan adaptive cost factor.  
Tahapan: Generate Salt → EksBlowfish Setup → 2^cost Iterasi → Enkripsi Magic String → Format Output

---

## Pengujian Keamanan
- Brute force protection: dicek via endpoint `/api/login` dengan percobaan berulang
- Validasi password: minimal 8 karakter, huruf besar, huruf kecil, angka
- Verifikasi token: session_token di-clear saat logout
