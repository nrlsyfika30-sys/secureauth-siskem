from flask import Flask, request, jsonify, session, render_template, redirect, url_for
import sqlite3
import time
import os
from bcrypt_manual import bcrypt_hash, bcrypt_verify, bcrypt_generate_salt
from sha256_manual import sha256, sha256_token

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', os.urandom(32))

BCRYPT_COST = int(os.environ.get('BCRYPT_COST', 4))
DB_PATH = "secureauth.db"
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_TIME = 300

login_attempts = {}

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username VARCHAR(100) UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            session_token TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    cur.execute('''
        CREATE TABLE IF NOT EXISTS activity_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            action TEXT,
            status TEXT,
            ip_address TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def log_activity(username, action, status, ip_address):
    conn = get_db()
    conn.execute(
        'INSERT INTO activity_log (username, action, status, ip_address) VALUES (?, ?, ?, ?)',
        (username, action, status, ip_address)
    )
    conn.commit()
    conn.close()

def check_brute_force(ip, username):
    key = f"{ip}:{username}"
    now = time.time()
    if key not in login_attempts:
        return False, 0
    attempts, first_attempt = login_attempts[key]
    if now - first_attempt > LOCKOUT_TIME:
        del login_attempts[key]
        return False, 0
    if attempts >= MAX_LOGIN_ATTEMPTS:
        remaining = int(LOCKOUT_TIME - (now - first_attempt))
        return True, remaining
    return False, 0

def record_failed_attempt(ip, username):
    key = f"{ip}:{username}"
    now = time.time()
    if key not in login_attempts:
        login_attempts[key] = [1, now]
    else:
        login_attempts[key][0] += 1

def reset_attempts(ip, username):
    key = f"{ip}:{username}"
    if key in login_attempts:
        del login_attempts[key]

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login_page'))

@app.route('/register')
def register_page():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('register.html')

@app.route('/login')
def login_page():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login_page'))
    return render_template('dashboard.html',
                           username=session.get('username'),
                           session_token=session.get('token', '')[:32] + '...')

@app.route('/api/register', methods=['POST'])
def api_register():
    data = request.get_json()
    username = (data.get('username') or '').strip()
    password = data.get('password') or ''

    if not username or not password:
        return jsonify({'success': False, 'message': 'Username dan password wajib diisi'}), 400
    if len(username) < 3:
        return jsonify({'success': False, 'message': 'Username minimal 3 karakter'}), 400
    if len(password) < 8:
        return jsonify({'success': False, 'message': 'Password minimal 8 karakter'}), 400

    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    if not (has_upper and has_lower and has_digit):
        return jsonify({'success': False, 'message': 'Password harus mengandung huruf besar, huruf kecil, dan angka'}), 400

    conn = get_db()
    existing = conn.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone()
    if existing:
        conn.close()
        return jsonify({'success': False, 'message': 'Username sudah terdaftar'}), 409

    start_time = time.time()
    password_hash = bcrypt_hash(password, cost=BCRYPT_COST)
    hash_time = round(time.time() - start_time, 3)

    conn.execute('INSERT INTO users (username, password_hash) VALUES (?, ?)', (username, password_hash))
    conn.commit()
    conn.close()

    log_activity(username, 'REGISTER', 'SUCCESS', request.remote_addr)

    return jsonify({
        'success': True,
        'message': 'Registrasi berhasil! Silakan login.',
        'debug': {
            'hash_algorithm': 'Bcrypt Manual',
            'cost_factor': BCRYPT_COST,
            'hash_time_seconds': hash_time,
            'hash_preview': password_hash[:20] + '...',
            'hash_format': '$2b$<cost>$<22-char-salt><31-char-hash>'
        }
    })

@app.route('/api/login', methods=['POST'])
def api_login():
    data = request.get_json()
    username = (data.get('username') or '').strip()
    password = data.get('password') or ''
    ip = request.remote_addr

    if not username or not password:
        return jsonify({'success': False, 'message': 'Username dan password wajib diisi'}), 400

    is_locked, remaining = check_brute_force(ip, username)
    if is_locked:
        log_activity(username, 'LOGIN', 'BLOCKED_BRUTE_FORCE', ip)
        return jsonify({
            'success': False,
            'message': f'Terlalu banyak percobaan login. Coba lagi dalam {remaining} detik.',
            'locked': True,
            'remaining_seconds': remaining
        }), 429

    conn = get_db()
    user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()

    if not user:
        record_failed_attempt(ip, username)
        conn.close()
        log_activity(username, 'LOGIN', 'FAIL_USER_NOT_FOUND', ip)
        return jsonify({'success': False, 'message': 'Username tidak ditemukan'}), 401

    start_time = time.time()
    is_valid = bcrypt_verify(password, user['password_hash'])
    verify_time = round(time.time() - start_time, 3)

    if not is_valid:
        record_failed_attempt(ip, username)
        attempts_left = MAX_LOGIN_ATTEMPTS - login_attempts.get(f"{ip}:{username}", [0])[0]
        conn.close()
        log_activity(username, 'LOGIN', 'FAIL_WRONG_PASSWORD', ip)
        return jsonify({
            'success': False,
            'message': f'Password salah. Sisa percobaan: {max(0, attempts_left)}',
            'attempts_remaining': max(0, attempts_left)
        }), 401

    timestamp = str(int(time.time()))
    token = sha256_token(username, timestamp)

    # Token disimpan ke database dan TIDAK dihapus saat logout
    conn.execute('UPDATE users SET session_token = ? WHERE id = ?', (token, user['id']))
    conn.commit()
    conn.close()

    session['user_id'] = user['id']
    session['username'] = username
    session['token'] = token

    reset_attempts(ip, username)
    log_activity(username, 'LOGIN', 'SUCCESS', ip)

    return jsonify({
        'success': True,
        'message': 'Login berhasil!',
        'redirect': '/dashboard',
        'debug': {
            'verify_algorithm': 'Bcrypt Manual',
            'token_algorithm': 'SHA-256 Manual',
            'verify_time_seconds': verify_time,
            'token_preview': token[:32] + '...',
            'token_length': f'{len(token)*4} bit'
        }
    })

@app.route('/api/logout', methods=['POST'])
def api_logout():
    username = session.get('username', 'unknown')
    # Session flask dibersihkan, tapi token di database tetap tersimpan
    session.clear()
    log_activity(username, 'LOGOUT', 'SUCCESS', request.remote_addr)
    return jsonify({'success': True, 'message': 'Logout berhasil'})

@app.route('/api/user-info', methods=['GET'])
def api_user_info():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Tidak terautentikasi'}), 401
    conn = get_db()
    user = conn.execute(
        'SELECT username, created_at, session_token FROM users WHERE id = ?',
        (session['user_id'],)
    ).fetchone()
    conn.close()
    if not user:
        session.clear()
        return jsonify({'success': False, 'message': 'User tidak ditemukan'}), 404
    return jsonify({
        'success': True,
        'user': {
            'username': user['username'],
            'created_at': user['created_at'],
            'session_token_preview': (user['session_token'] or '')[:32] + '...'
        }
    })

@app.route('/api/demo/sha256', methods=['POST'])
def demo_sha256():
    data = request.get_json()
    text = data.get('text', '')[:200]
    result = sha256(text)
    return jsonify({
        'input': text,
        'hash': result,
        'length_bits': len(result) * 4,
        'algorithm': 'SHA-256 Manual',
        'steps': {
            '1_padding': 'Pesan dipadding ke kelipatan 512 bit',
            '2_schedule': '64 word message schedule dibuat dari 16 word pertama',
            '3_compression': '64 putaran fungsi kompresi dengan konstanta K',
            '4_digest': 'Output 256-bit dihasilkan'
        }
    })

@app.route('/api/demo/bcrypt', methods=['POST'])
def demo_bcrypt():
    data = request.get_json()
    password = data.get('password', '')[:50]
    cost = min(int(data.get('cost', 4)), 6)
    start = time.time()
    hashed = bcrypt_hash(password, cost=cost)
    elapsed = round(time.time() - start, 3)
    parts = hashed.split('$')
    return jsonify({
        'input': password,
        'hash': hashed,
        'elapsed_seconds': elapsed,
        'algorithm': 'Bcrypt Manual',
        'components': {
            'prefix': f'${parts[1]}$',
            'cost_factor': parts[2],
            'salt': parts[3][:22],
            'hash_value': parts[3][22:] if len(parts[3]) > 22 else ''
        },
        'steps': {
            '1_salt': 'Salt 16 byte acak di-encode ke Base64 Bcrypt',
            '2_eksblowfish': 'EksBlowfish key setup dengan password + salt',
            '3_iteration': f'Iterasi 2^{cost} = {2**cost} kali',
            '4_encrypt': 'Magic string dienkripsi 64 kali dengan cipher Blowfish',
            '5_format': 'Output diformat: $2b$<cost>$<salt><hash>'
        }
    })

# Inisialisasi database saat startup
init_db()

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    print("=" * 60)
    print("SecureAuth - Bcrypt & SHA-256 Manual")
    print("=" * 60)
    app.run(debug=False, host='0.0.0.0', port=port)
