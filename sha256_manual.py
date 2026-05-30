"""
SHA-256 Manual Implementation
Implementasi SHA-256 dari nol tanpa menggunakan library kriptografi.
Berdasarkan standar FIPS PUB 180-4 (NIST).

Digunakan untuk: pembuatan session token dan validasi integritas data
"""

import struct


# ─── Konstanta SHA-256 ────────────────────────────────────────────────────────
# 64 konstanta K: 32-bit pertama dari bagian pecahan akar kubik dari 64 bilangan prima pertama
K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]

# Nilai hash awal H0–H7: 32-bit pertama dari bagian pecahan akar kuadrat dari 8 bilangan prima pertama
H0_INIT = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
]


# ─── Fungsi Operasi Bit ───────────────────────────────────────────────────────

def rotr(x, n):
    """Rotate Right: geser bit ke kanan sebanyak n posisi secara circular (32-bit)."""
    return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF

def shr(x, n):
    """Shift Right: geser bit ke kanan sebanyak n posisi."""
    return x >> n

def ch(x, y, z):
    """Choose: pilih bit dari y jika bit x=1, pilih dari z jika bit x=0."""
    return (x & y) ^ (~x & z)

def maj(x, y, z):
    """Majority: pilih bit yang paling banyak muncul di antara x, y, z."""
    return (x & y) ^ (x & z) ^ (y & z)

def sigma0(x):
    """Fungsi sigma kecil 0: digunakan dalam message schedule."""
    return rotr(x, 7) ^ rotr(x, 18) ^ shr(x, 3)

def sigma1(x):
    """Fungsi sigma kecil 1: digunakan dalam message schedule."""
    return rotr(x, 17) ^ rotr(x, 19) ^ shr(x, 10)

def SIGMA0(x):
    """Fungsi Sigma besar 0: digunakan dalam compression function."""
    return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22)

def SIGMA1(x):
    """Fungsi Sigma besar 1: digunakan dalam compression function."""
    return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25)


# ─── Fungsi Utama SHA-256 ─────────────────────────────────────────────────────

def sha256_padding(message_bytes):
    """
    Tahap 1: Padding pesan agar panjangnya kongruen 448 mod 512 bit.
    Tambahkan bit '1', lalu bit '0', lalu panjang pesan asli (64-bit big-endian).
    """
    msg = bytearray(message_bytes)
    original_length_bits = len(message_bytes) * 8

    # Tambahkan byte 0x80 (bit '1' diikuti nol)
    msg.append(0x80)

    # Tambahkan byte 0x00 sampai panjang ≡ 56 (mod 64) byte
    while len(msg) % 64 != 56:
        msg.append(0x00)

    # Tambahkan panjang pesan asli sebagai 64-bit big-endian
    msg += struct.pack('>Q', original_length_bits)

    return bytes(msg)


def sha256_process_block(block, H):
    """
    Tahap 2 & 3: Proses satu blok 512-bit (64 byte).
    - Buat message schedule W[0..63]
    - Jalankan 64 putaran compression
    - Tambahkan hasil ke nilai hash H
    """
    # Parse blok menjadi 16 word 32-bit (big-endian)
    W = list(struct.unpack('>16I', block))

    # Perluas W dari 16 menjadi 64 word
    for i in range(16, 64):
        w = (sigma1(W[i-2]) + W[i-7] + sigma0(W[i-15]) + W[i-16]) & 0xFFFFFFFF
        W.append(w)

    # Inisialisasi variabel kerja dari nilai hash saat ini
    a, b, c, d, e, f, g, h = H

    # 64 putaran compression
    for i in range(64):
        T1 = (h + SIGMA1(e) + ch(e, f, g) + K[i] + W[i]) & 0xFFFFFFFF
        T2 = (SIGMA0(a) + maj(a, b, c)) & 0xFFFFFFFF
        h = g
        g = f
        f = e
        e = (d + T1) & 0xFFFFFFFF
        d = c
        c = b
        b = a
        a = (T1 + T2) & 0xFFFFFFFF

    # Tambahkan hasil ke nilai hash sebelumnya
    H[0] = (H[0] + a) & 0xFFFFFFFF
    H[1] = (H[1] + b) & 0xFFFFFFFF
    H[2] = (H[2] + c) & 0xFFFFFFFF
    H[3] = (H[3] + d) & 0xFFFFFFFF
    H[4] = (H[4] + e) & 0xFFFFFFFF
    H[5] = (H[5] + f) & 0xFFFFFFFF
    H[6] = (H[6] + g) & 0xFFFFFFFF
    H[7] = (H[7] + h) & 0xFFFFFFFF

    return H


def sha256(data):
    """
    Fungsi utama SHA-256.
    Input: string atau bytes
    Output: string hexadecimal 64 karakter (256-bit)
    """
    if isinstance(data, str):
        data = data.encode('utf-8')

    # Tahap 1: Padding
    padded = sha256_padding(data)

    # Tahap 2: Inisialisasi nilai hash
    H = list(H0_INIT)

    # Tahap 3: Proses setiap blok 512-bit
    for i in range(0, len(padded), 64):
        block = padded[i:i+64]
        H = sha256_process_block(block, H)

    # Tahap 4: Hasilkan digest (gabungkan 8 word → hexadecimal)
    digest = ''.join(f'{h:08x}' for h in H)
    return digest


def sha256_token(username, timestamp, secret="secureauth_2026"):
    """
    Buat session token dari kombinasi username + timestamp + secret.
    Digunakan untuk autentikasi sesi pengguna.
    """
    raw = f"{username}:{timestamp}:{secret}"
    return sha256(raw)


# ─── Test / Verifikasi ────────────────────────────────────────────────────────
if __name__ == "__main__":
    # Test vector resmi (NIST)
    test_cases = [
        ("abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
        ("", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
        ("hello", "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"),
    ]

    print("=" * 60)
    print("SHA-256 Manual Implementation - Test Vectors")
    print("=" * 60)
    for msg, expected in test_cases:
        result = sha256(msg)
        status = "✓ PASS" if result == expected else "✗ FAIL"
        print(f"Input   : '{msg}'")
        print(f"Expected: {expected}")
        print(f"Got     : {result}")
        print(f"Status  : {status}")
        print("-" * 60)
