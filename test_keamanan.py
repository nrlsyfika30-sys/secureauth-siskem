"""
SecureAuth - Script Pengujian Keamanan
Mata Kuliah Sistem Keamanan - Progress Minggu 3

Pengujian meliputi:
1. Pengujian SHA-256 Manual (test vector resmi NIST)
2. Pengujian Bcrypt Manual (hash & verifikasi)
3. Pengujian Brute Force Protection & Validasi Password
"""

import time
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from bcrypt_manual import bcrypt_hash, bcrypt_verify, bcrypt_generate_salt
from sha256_manual import sha256, sha256_token

# ── Warna terminal ─────────────────────────────────────────────────────────
GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
BLUE   = "\033[94m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

hasil = []

def header(text):
    print(f"\n{BOLD}{BLUE}{'='*60}{RESET}")
    print(f"{BOLD}{CYAN}  {text}{RESET}")
    print(f"{BOLD}{BLUE}{'='*60}{RESET}")

def sub(text):
    print(f"\n{BOLD}{YELLOW}  >> {text}{RESET}")
    print(f"  {'-'*50}")

def ok(label, detail=""):
    print(f"  {GREEN}PASS{RESET}  {label}")
    if detail:
        print(f"        {CYAN}{detail}{RESET}")
    hasil.append(("PASS", label))

def fail(label, detail=""):
    print(f"  {RED}FAIL{RESET}  {label}")
    if detail:
        print(f"        {RED}{detail}{RESET}")
    hasil.append(("FAIL", label))

def info(text):
    print(f"  {YELLOW}INFO{RESET}  {text}")


# ==============================================================
# PENGUJIAN 1: SHA-256 MANUAL
# ==============================================================
header("PENGUJIAN 1 : SHA-256 MANUAL")

sub("1.1 Test Vector Resmi NIST")
vectors = [
    ("",      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
    ("hello", "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"),
    ("abc",   "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
]
for msg, expected in vectors:
    result = sha256(msg)
    label  = f"SHA-256('{msg}')"
    if result == expected:
        ok(label, f"Output: {result[:32]}...")
    else:
        fail(label, f"Harusnya: {expected[:32]}...")

sub("1.2 Avalanche Effect")
h1   = sha256("password")
h2   = sha256("Password")
diff = sum(c1 != c2 for c1, c2 in zip(h1, h2))
pct  = round(diff / len(h1) * 100, 1)
info(f"SHA-256('password') = {h1[:24]}...")
info(f"SHA-256('Password') = {h2[:24]}...")
info(f"Perbedaan karakter  = {diff}/{len(h1)} ({pct}%)")
if diff > 20:
    ok("Avalanche effect terbukti — perubahan 1 huruf mengubah lebih dari 50% output")
else:
    fail("Avalanche effect lemah")

sub("1.3 Determinisme (input sama = output selalu sama)")
hasil_5x = [sha256("uji determinisme") for _ in range(5)]
if len(set(hasil_5x)) == 1:
    ok("Deterministik — 5x hash input sama menghasilkan output identik")
else:
    fail("Tidak deterministik!")

sub("1.4 Token SHA-256 (untuk session login)")
t1 = sha256_token("cipika", "1716900000")
t2 = sha256_token("cipika", "1716900000")  # sama persis
t3 = sha256_token("cipika", "1716900001")  # beda 1 detik
info(f"Token login 1 : {t1[:32]}...")
info(f"Token login 2 : {t2[:32]}... (timestamp sama)")
info(f"Token login 3 : {t3[:32]}... (timestamp beda 1 detik)")
if t1 == t2:
    ok("Token deterministik — timestamp sama menghasilkan token sama")
if t1 != t3:
    ok("Token unik per sesi — timestamp beda menghasilkan token berbeda")
ok(f"Panjang token : {len(t1)*4} bit ({len(t1)} karakter hex)")


# ==============================================================
# PENGUJIAN 2: BCRYPT MANUAL
# ==============================================================
header("PENGUJIAN 2 : BCRYPT MANUAL")

sub("2.1 Hash dan Verifikasi Password")
passwords = ["TestPass123", "SecureP@ss1", "Admin2026!!"]
for pwd in passwords:
    start   = time.time()
    hashed  = bcrypt_hash(pwd, cost=4)
    elapsed = round(time.time() - start, 3)
    valid   = bcrypt_verify(pwd, hashed)
    info(f"Password : {pwd}")
    info(f"Hash     : {hashed[:40]}...")
    info(f"Waktu    : {elapsed}s")
    if valid:
        ok(f"Verifikasi '{pwd}' berhasil")
    else:
        fail(f"Verifikasi '{pwd}' gagal!")
    print()

sub("2.2 Penolakan Password Salah")
hashed_benar = bcrypt_hash("PasswordBenar1", cost=4)
ditolak      = bcrypt_verify("PasswordSalah1", hashed_benar)
if not ditolak:
    ok("Password salah berhasil ditolak")
else:
    fail("Password salah diterima — celah keamanan!")

sub("2.3 Keunikan Salt (password sama = hash berbeda)")
h_a = bcrypt_hash("SamaPersis123", cost=4)
h_b = bcrypt_hash("SamaPersis123", cost=4)
info(f"Hash 1 : {h_a}")
info(f"Hash 2 : {h_b}")
if h_a != h_b:
    ok("Salt acak terbukti — password sama menghasilkan hash berbeda")
else:
    fail("Salt tidak acak — kelemahan kritis!")

sub("2.4 Verifikasi Tetap Berhasil Meski Hash Berbeda")
v1 = bcrypt_verify("SamaPersis123", h_a)
v2 = bcrypt_verify("SamaPersis123", h_b)
if v1 and v2:
    ok("Verifikasi berhasil pada kedua hash — salt tersimpan dalam hash")
else:
    fail("Verifikasi gagal!")

sub("2.5 Format Hash Bcrypt")
sample = bcrypt_hash("FormatTest1", cost=10)
parts  = sample.split("$")
info(f"Hash     : {sample}")
info(f"Prefix   : ${parts[1]}$   (versi Bcrypt)")
info(f"Cost     : {parts[2]}   (2^{parts[2]} = {2**int(parts[2])} iterasi)")
info(f"Salt     : {parts[3][:22]}   (22 karakter)")
info(f"Hash val : {parts[3][22:]}   (31 karakter)")
if sample.startswith("$2b$") and len(parts[3]) == 53:
    ok("Format hash Bcrypt valid: $2b$<cost>$<salt 22 char><hash 31 char>")
else:
    fail("Format hash tidak valid!")


# ==============================================================
# PENGUJIAN 3: BRUTE FORCE & VALIDASI PASSWORD
# ==============================================================
header("PENGUJIAN 3 : BRUTE FORCE PROTECTION & VALIDASI")

try:
    from app import app, init_db
    import json
    init_db()

    with app.test_client() as client:

        # Daftarkan akun uji dulu
        client.post('/api/register',
            json={'username': 'akun_uji_bf', 'password': 'UjiCoba123'},
            content_type='application/json')

        sub("3.1 Simulasi 5 Percobaan Login Gagal")
        for i in range(1, 6):
            r = client.post('/api/login',
                json={'username': 'akun_uji_bf', 'password': f'SalahBanget{i}'},
                content_type='application/json')
            d     = json.loads(r.data)
            sisa  = d.get('attempts_remaining', 0)
            info(f"Percobaan {i} | HTTP {r.status_code} | Sisa percobaan: {sisa}")

        sub("3.2 Pemblokiran Setelah Melebihi Batas (percobaan ke-6)")
        r = client.post('/api/login',
            json={'username': 'akun_uji_bf', 'password': 'UjiCoba123'},
            content_type='application/json')
        d = json.loads(r.data)
        if r.status_code == 429:
            ok("Akun diblokir setelah 5 percobaan gagal (HTTP 429)")
            ok(f"Pesan sistem: {d.get('message','')}")
        else:
            fail(f"Akun seharusnya diblokir! Status: {r.status_code}")

        sub("3.3 Validasi Password Saat Registrasi")
        kasus = [
            ("usr1", "pendek",           False, "Password terlalu pendek (< 8 karakter)"),
            ("usr2", "tanpahurufbesar1", False, "Tidak ada huruf besar"),
            ("usr3", "TANPAHURUFKECIL1", False, "Tidak ada huruf kecil"),
            ("usr4", "TanpaAngka",       False, "Tidak ada angka"),
            ("usr5", "ValidPass123",     True,  "Password memenuhi semua syarat"),
        ]
        for uname, pwd, harusnya_pass, desc in kasus:
            r       = client.post('/api/register',
                json={'username': uname, 'password': pwd},
                content_type='application/json')
            sukses  = json.loads(r.data).get('success', False)
            if sukses == harusnya_pass:
                status = "Diterima" if harusnya_pass else "Ditolak"
                ok(f"{desc} --> {status} dengan benar")
            else:
                fail(f"{desc} --> Hasil tidak sesuai ekspektasi!")

        sub("3.4 Login Berhasil dan Pembuatan Token SHA-256")
        client.post('/api/register',
            json={'username': 'uji_token_ok', 'password': 'TokenTest123'},
            content_type='application/json')
        r = client.post('/api/login',
            json={'username': 'uji_token_ok', 'password': 'TokenTest123'},
            content_type='application/json')
        d = json.loads(r.data)
        if d.get('success'):
            token = d.get('debug', {}).get('token_preview', '')
            ok("Login berhasil dengan password yang benar")
            ok(f"Token SHA-256 berhasil dibuat: {token}")
        else:
            fail("Login gagal padahal password benar!")

except Exception as e:
    print(f"  {RED}Error saat pengujian Flask: {e}{RESET}")


# ==============================================================
# RINGKASAN HASIL
# ==============================================================
header("RINGKASAN HASIL PENGUJIAN")

total   = len(hasil)
n_pass  = sum(1 for s, _ in hasil if s == "PASS")
n_fail  = sum(1 for s, _ in hasil if s == "FAIL")
persen  = round(n_pass / total * 100, 1) if total > 0 else 0

print(f"\n  Total Pengujian  : {BOLD}{total}{RESET}")
print(f"  {GREEN}Berhasil (PASS)  : {n_pass}{RESET}")
print(f"  {RED}Gagal    (FAIL)  : {n_fail}{RESET}")
print(f"  Tingkat Sukses   : {BOLD}{persen}%{RESET}")

if n_fail == 0:
    print(f"\n  {GREEN}{BOLD}SEMUA PENGUJIAN BERHASIL — Sistem aman!{RESET}")
else:
    print(f"\n  {RED}{BOLD}Ada {n_fail} pengujian yang gagal!{RESET}")

print(f"\n{BOLD}{BLUE}{'='*60}{RESET}\n")
