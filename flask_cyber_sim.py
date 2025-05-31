from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash
from werkzeug.security import check_password_hash, generate_password_hash
import sqlite3
import datetime
from functools import wraps
import secrets
import pyotp
import qrcode
import io
import base64

app = Flask(__name__)
app.secret_key = 'your-secret-key-change-this'

# 데이터베이스 초기화
def init_db():
    conn = sqlite3.connect('yooncar.db')
    c = conn.cursor()
    
    # 사용자 테이블
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        access_level INTEGER DEFAULT 1,
        department TEXT DEFAULT '일반',
        totp_secret TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    
    # 로그인 기록 테이블
    c.execute('''CREATE TABLE IF NOT EXISTS login_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        ip_address TEXT NOT NULL,
        success BOOLEAN NOT NULL,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    
    # 기본 사용자 생성 (실제 환경에서는 더 안전한 방법 사용)
    try:
        c.execute("INSERT INTO users (username, password_hash, access_level, department) VALUES (?, ?, ?, ?)",
                 ('admin', generate_password_hash('admin123'), 9, '보안팀'))
        c.execute("INSERT INTO users (username, password_hash, access_level, department) VALUES (?, ?, ?, ?)",
                 ('user', generate_password_hash('user123'), 3, 'IT팀'))
    except sqlite3.IntegrityError:
        pass  # 이미 존재하는 사용자
    
    conn.commit()
    conn.close()

# 로그인 필요 데코레이터
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# 관리자 권한 필요 데코레이터
def admin_required(access_level=9):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'username' not in session:
                return redirect(url_for('login'))
            
            conn = sqlite3.connect('yooncar.db')
            c = conn.cursor()
            c.execute("SELECT access_level FROM users WHERE username = ?", (session['username'],))
            user_level = c.fetchone()
            conn.close()
            
            if not user_level or user_level[0] < access_level:
                flash('접근 권한이 없습니다.', 'error')
                return redirect(url_for('dashboard'))
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# 사용자 정보 가져오기 헬퍼 함수
def get_user_info(username):
    conn = sqlite3.connect('yooncar.db')
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE username = ?", (username,))
    user = c.fetchone()
    conn.close()
    return dict(user) if user else None

# 최근 로그인 기록 가져오기
def get_recent_logins(username, limit=5):
    conn = sqlite3.connect('yooncar.db')
    c = conn.cursor()
    c.execute("""SELECT timestamp, ip_address, success 
                 FROM login_logs 
                 WHERE username = ? 
                 ORDER BY timestamp DESC 
                 LIMIT ?""", (username, limit))
    logs = c.fetchall()
    conn.close()
    return logs

# 로그인 기록 저장
def log_login_attempt(username, ip_address, success):
    conn = sqlite3.connect('yooncar.db')
    c = conn.cursor()
    c.execute("INSERT INTO login_logs (username, ip_address, success) VALUES (?, ?, ?)",
             (username, ip_address, success))
    conn.commit()
    conn.close()

@app.route('/')
def index():
    if 'username' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        ip_address = request.environ.get('HTTP_X_FORWARDED_FOR', request.environ['REMOTE_ADDR'])
        
        conn = sqlite3.connect('yooncar.db')
        c = conn.cursor()
        c.execute("SELECT password_hash FROM users WHERE username = ?", (username,))
        user = c.fetchone()
        conn.close()
        
        if user and check_password_hash(user[0], password):
            session['username'] = username
            log_login_attempt(username, ip_address, True)
            flash('로그인 성공!', 'success')
            return redirect(url_for('dashboard'))
        else:
            log_login_attempt(username, ip_address, False)
            flash('잘못된 사용자명 또는 비밀번호입니다.', 'error')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    session.clear()
    flash('로그아웃되었습니다.', 'info')
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    user = get_user_info(session['username'])
    recent_logins = get_recent_logins(session['username'])
    
    return render_template('dashboard.html', 
                         user=user, 
                         recent_logins=recent_logins)

@app.route('/admin')
@login_required
@admin_required(9)
def admin():
    user = get_user_info(session['username'])
    
    # 모든 사용자 목록
    conn = sqlite3.connect('yooncar.db')
    c = conn.cursor()
    c.execute("SELECT username, access_level, department, created_at FROM users ORDER BY access_level DESC")
    users = c.fetchall()
    
    # 최근 모든 로그인 기록
    c.execute("""SELECT username, timestamp, ip_address, success 
                 FROM login_logs 
                 ORDER BY timestamp DESC 
                 LIMIT 20""")
    all_logs = c.fetchall()
    conn.close()
    
    return render_template('admin.html', 
                         user=user, 
                         users=users, 
                         all_logs=all_logs)

@app.route('/dark_admin')
@login_required
def dark_admin():
    """
    사이버 감염 시뮬레이션 페이지
    관리자가 실수로 접근하는 것을 시뮬레이션
    """
    user = get_user_info(session['username'])
    
    # 접근 로그 기록 (의심스러운 접근으로 표시)
    ip_address = request.environ.get('HTTP_X_FORWARDED_FOR', request.environ['REMOTE_ADDR'])
    conn = sqlite3.connect('yooncar.db')
    c = conn.cursor()
    c.execute("INSERT INTO login_logs (username, ip_address, success) VALUES (?, ?, ?)",
             (session['username'], f"SUSPICIOUS:{ip_address}", False))
    conn.commit()
    conn.close()
    
    return render_template('cyber_infection_sim.html', user=user)

@app.route('/recovery_success')
@login_required
def recovery_success():
    """
    시뮬레이션 복구 성공 후 리다이렉트 페이지
    """
    flash('🛡️ 시스템이 성공적으로 복구되었습니다! (시뮬레이션)', 'success')
    return redirect(url_for('dashboard'))

@app.route('/api/verify_recovery', methods=['POST'])
@login_required
def verify_recovery():
    """
    복구 코드 검증 API
    """
    data = request.get_json()
    recovery_code = data.get('code', '')
    
    # 정답 복구 코드
    correct_code = "19721121"
    
    if recovery_code == correct_code:
        return jsonify({
            'success': True,
            'message': '복구 성공',
            'redirect': url_for('recovery_success')
        })
    else:
        return jsonify({
            'success': False,
            'message': '잘못된 복구 코드입니다.'
        })

@app.route('/setup-2fa')
@login_required
def setup_2fa():
    user = get_user_info(session['username'])
    
    if user['totp_secret']:
        flash('2단계 인증이 이미 설정되어 있습니다.', 'info')
        return redirect(url_for('dashboard'))
    
    # TOTP 시크릿 생성
    secret = pyotp.random_base32()
    session['temp_totp_secret'] = secret
    
    # QR 코드 생성
    totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
        name=user['username'],
        issuer_name="YoonCar Security"
    )
    
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(totp_uri)
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    img_io = io.BytesIO()
    img.save(img_io, 'PNG')
    img_io.seek(0)
    
    qr_code_data = base64.b64encode(img_io.getvalue()).decode()
    
    return render_template('setup_2fa.html', 
                         user=user, 
                         secret=secret,
                         qr_code=qr_code_data)

if __name__ == '__main__':
    init_db()
    app.run(debug=True, host='0.0.0.0', port=5000)