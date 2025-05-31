import os
import json
import hashlib
import secrets
import logging
from datetime import datetime, timedelta
from functools import wraps
import sqlite3
from flask import Flask, render_template, redirect, request, session, jsonify, flash
from flask_login import LoginManager, login_user, logout_user, UserMixin, login_required, current_user
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import bcrypt
import pyotp
import qrcode
from io import BytesIO
import base64

# 보안 로깅 설정
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - [%(remote_addr)s] - %(message)s',
    handlers=[
        logging.FileHandler('security.log'),
        logging.StreamHandler()
    ]
)

app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', secrets.token_hex(32))

# Rate Limiting 설정
limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

# Flask-Login 설정
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.session_protection = "strong"

# 데이터베이스 초기화
def init_db():
    conn = sqlite3.connect('yooncar_security.db')
    c = conn.cursor()
    
    # 사용자 테이블
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        department TEXT NOT NULL,
        access_level INTEGER NOT NULL DEFAULT 1,
        totp_secret TEXT,
        failed_attempts INTEGER DEFAULT 0,
        locked_until TIMESTAMP,
        last_login TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        is_active BOOLEAN DEFAULT 1
    )''')
    
    # 로그인 시도 기록 테이블
    c.execute('''CREATE TABLE IF NOT EXISTS login_attempts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        ip_address TEXT,
        user_agent TEXT,
        success BOOLEAN,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        failure_reason TEXT
    )''')
    
    # 세션 테이블
    c.execute('''CREATE TABLE IF NOT EXISTS active_sessions (
        session_id TEXT PRIMARY KEY,
        user_id INTEGER,
        ip_address TEXT,
        user_agent TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )''')
    
    # 기본 관리자 계정 생성
    admin_password = bcrypt.hashpw('YC2050@SecureAdmin'.encode('utf-8'), bcrypt.gensalt())
    c.execute('''INSERT OR IGNORE INTO users 
                 (username, password_hash, email, department, access_level) 
                 VALUES (?, ?, ?, ?, ?)''',
              ('admin', admin_password.decode('utf-8'), 'admin@yooncar.com', 'IT Security', 9))
    
    # 일반 사용자 계정들
    users_data = [
        ('j.kim', 'Finance', 'j.kim@yooncar.com', 3),
        ('s.park', 'Engineering', 's.park@yooncar.com', 5),
        ('m.lee', 'HR', 'm.lee@yooncar.com', 2),
        ('d.choi', 'Sales', 'd.choi@yooncar.com', 1)
    ]
    
    for username, dept, email, level in users_data:
        temp_password = bcrypt.hashpw(f'{username}@YoonCar2050'.encode('utf-8'), bcrypt.gensalt())
        c.execute('''INSERT OR IGNORE INTO users 
                     (username, password_hash, email, department, access_level) 
                     VALUES (?, ?, ?, ?, ?)''',
                  (username, temp_password.decode('utf-8'), email, dept, level))
    
    conn.commit()
    conn.close()

# 사용자 모델
class User(UserMixin):
    def __init__(self, id, username, email, department, access_level, totp_secret=None):
        self.id = id
        self.username = username
        self.email = email
        self.department = department
        self.access_level = access_level
        self.totp_secret = totp_secret

@login_manager.user_loader
def load_user(user_id):
    conn = sqlite3.connect('yooncar_security.db')
    c = conn.cursor()
    c.execute('SELECT * FROM users WHERE id = ? AND is_active = 1', (user_id,))
    user_data = c.fetchone()
    conn.close()
    
    if user_data:
        return User(user_data[0], user_data[1], user_data[3], user_data[4], user_data[5], user_data[6])
    return None

def log_security_event(event_type, details, ip_address=None):
    """보안 이벤트 로깅"""
    if not ip_address:
        ip_address = request.remote_addr if request else 'system'
    
    logging.info(f"SECURITY_EVENT: {event_type} - {details} - IP: {ip_address}")

def check_account_lockout(username):
    """계정 잠금 상태 확인"""
    conn = sqlite3.connect('yooncar_security.db')
    c = conn.cursor()
    c.execute('SELECT failed_attempts, locked_until FROM users WHERE username = ?', (username,))
    result = c.fetchone()
    conn.close()
    
    if result:
        failed_attempts, locked_until = result
        if locked_until:
            lock_time = datetime.fromisoformat(locked_until)
            if datetime.now() < lock_time:
                return True, lock_time
        return failed_attempts >= 5, None
    return False, None

def record_login_attempt(username, success, failure_reason=None):
    """로그인 시도 기록"""
    conn = sqlite3.connect('yooncar_security.db')
    c = conn.cursor()
    
    # 로그인 시도 기록
    c.execute('''INSERT INTO login_attempts 
                 (username, ip_address, user_agent, success, failure_reason) 
                 VALUES (?, ?, ?, ?, ?)''',
              (username, request.remote_addr, request.headers.get('User-Agent'), success, failure_reason))
    
    if not success:
        # 실패 횟수 증가
        c.execute('UPDATE users SET failed_attempts = failed_attempts + 1 WHERE username = ?', (username,))
        
        # 5회 실패 시 30분 잠금
        c.execute('SELECT failed_attempts FROM users WHERE username = ?', (username,))
        attempts = c.fetchone()
        if attempts and attempts[0] >= 5:
            lock_until = datetime.now() + timedelta(minutes=30)
            c.execute('UPDATE users SET locked_until = ? WHERE username = ?', 
                     (lock_until.isoformat(), username))
            log_security_event("ACCOUNT_LOCKED", f"Account {username} locked due to multiple failed attempts")
    else:
        # 성공 시 실패 횟수 리셋
        c.execute('UPDATE users SET failed_attempts = 0, locked_until = NULL, last_login = ? WHERE username = ?',
                 (datetime.now().isoformat(), username))
    
    conn.commit()
    conn.close()

def require_access_level(min_level):
    """접근 권한 레벨 확인 데코레이터"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                return redirect('/login')
            if current_user.access_level < min_level:
                log_security_event("UNAUTHORIZED_ACCESS_ATTEMPT", 
                                 f"User {current_user.username} attempted to access restricted area")
                flash('접근 권한이 부족합니다.', 'error')
                return redirect('/dashboard')
            return f(*args, **kwargs)
        return decorated_function
    return decorator

@app.route('/', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def login():
    if current_user.is_authenticated:
        return redirect('/dashboard')
    
    error_message = None
    
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        totp_code = request.form.get('totp_code', '').strip()
        
        # 입력 검증
        if not username or not password:
            error_message = "사용자명과 비밀번호를 입력해주세요."
            record_login_attempt(username, False, "Empty credentials")
            return render_template('login.html', error=error_message)
        
        # 계정 잠금 확인
        is_locked, lock_until = check_account_lockout(username)
        if is_locked:
            if lock_until:
                error_message = f"계정이 잠겨있습니다. {lock_until.strftime('%H:%M')}까지 대기해주세요."
            else:
                error_message = "계정이 잠겨있습니다. 관리자에게 문의하세요."
            record_login_attempt(username, False, "Account locked")
            return render_template('login.html', error=error_message)
        
        # 사용자 인증
        conn = sqlite3.connect('yooncar_security.db')
        c = conn.cursor()
        c.execute('SELECT * FROM users WHERE username = ? AND is_active = 1', (username,))
        user_data = c.fetchone()
        conn.close()
        
        if user_data and bcrypt.checkpw(password.encode('utf-8'), user_data[2].encode('utf-8')):
            user = User(user_data[0], user_data[1], user_data[3], user_data[4], user_data[5], user_data[6])
            
            # 2FA 확인 (TOTP가 설정된 경우)
            if user.totp_secret:
                if not totp_code:
                    return render_template('login.html', show_totp=True, username=username, 
                                         error="2단계 인증 코드를 입력해주세요.")
                
                totp = pyotp.TOTP(user.totp_secret)
                if not totp.verify(totp_code):
                    record_login_attempt(username, False, "Invalid TOTP")
                    return render_template('login.html', show_totp=True, username=username,
                                         error="잘못된 인증 코드입니다.")
            
            # 로그인 성공
            login_user(user, remember=False)
            session.permanent = True
            app.permanent_session_lifetime = timedelta(hours=8)
            
            record_login_attempt(username, True)
            log_security_event("LOGIN_SUCCESS", f"User {username} logged in successfully")
            
            return redirect('/dashboard')
        else:
            record_login_attempt(username, False, "Invalid credentials")
            error_message = "잘못된 사용자명 또는 비밀번호입니다."
    
    return render_template('login.html', error=error_message)

@app.route('/dashboard')
@login_required
def dashboard():
    # 최근 로그인 기록 조회
    conn = sqlite3.connect('yooncar_security.db')
    c = conn.cursor()
    c.execute('''SELECT timestamp, ip_address, success FROM login_attempts 
                 WHERE username = ? ORDER BY timestamp DESC LIMIT 5''', 
              (current_user.username,))
    recent_logins = c.fetchall()
    conn.close()
    
    return render_template('dashboard.html', 
                         user=current_user, 
                         recent_logins=recent_logins)

@app.route('/admin')
@login_required
@require_access_level(9)
def admin_panel():
    conn = sqlite3.connect('yooncar_security.db')
    c = conn.cursor()
    
    # 전체 사용자 조회
    c.execute('SELECT id, username, email, department, access_level, last_login, is_active FROM users')
    users = c.fetchall()
    
    # 최근 보안 이벤트
    c.execute('''SELECT username, ip_address, success, timestamp, failure_reason 
                 FROM login_attempts ORDER BY timestamp DESC LIMIT 20''')
    security_events = c.fetchall()
    
    conn.close()
    
    return render_template('admin.html', users=users, security_events=security_events)

@app.route('/setup-2fa')
@login_required
def setup_2fa():
    if current_user.totp_secret:
        flash('2단계 인증이 이미 설정되어 있습니다.', 'info')
        return redirect('/dashboard')
    
    # TOTP 시크릿 생성
    secret = pyotp.random_base32()
    
    # QR 코드 생성
    totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
        name=current_user.username,
        issuer_name="YoonCar Security System"
    )
    
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(totp_uri)
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    buffer = BytesIO()
    img.save(buffer, format='PNG')
    qr_code_data = base64.b64encode(buffer.getvalue()).decode()
    
    session['temp_totp_secret'] = secret
    
    return render_template('setup_2fa.html', 
                         qr_code=qr_code_data, 
                         secret=secret)

@app.route('/verify-2fa', methods=['POST'])
@login_required
def verify_2fa():
    secret = session.get('temp_totp_secret')
    code = request.form.get('totp_code', '').strip()
    
    if not secret or not code:
        flash('잘못된 요청입니다.', 'error')
        return redirect('/setup-2fa')
    
    totp = pyotp.TOTP(secret)
    if totp.verify(code):
        # 2FA 설정 저장
        conn = sqlite3.connect('yooncar_security.db')
        c = conn.cursor()
        c.execute('UPDATE users SET totp_secret = ? WHERE id = ?', 
                 (secret, current_user.id))
        conn.commit()
        conn.close()
        
        session.pop('temp_totp_secret', None)
        flash('2단계 인증이 성공적으로 설정되었습니다.', 'success')
        log_security_event("2FA_ENABLED", f"User {current_user.username} enabled 2FA")
        return redirect('/dashboard')
    else:
        flash('잘못된 인증 코드입니다. 다시 시도해주세요.', 'error')
        return redirect('/setup-2fa')

@app.route('/logout')
@login_required
def logout():
    log_security_event("LOGOUT", f"User {current_user.username} logged out")
    logout_user()
    session.clear()
    return redirect('/')

@app.errorhandler(429)
def ratelimit_handler(e):
    log_security_event("RATE_LIMIT_EXCEEDED", f"Rate limit exceeded: {e.description}")
    return render_template('error.html', 
                         error="너무 많은 요청입니다. 잠시 후 다시 시도해주세요."), 429

@app.errorhandler(404)
def not_found(e):
    return render_template('error.html', error="페이지를 찾을 수 없습니다."), 404

@app.errorhandler(500)
def internal_error(e):
    log_security_event("INTERNAL_ERROR", f"Internal server error: {str(e)}")
    return render_template('error.html', error="서버 오류가 발생했습니다."), 500

if __name__ == '__main__':
    init_db()
    
    # HTTPS 설정 (운영환경에서는 적절한 SSL 인증서 사용)
    context = None
    if os.path.exists('cert.pem') and os.path.exists('key.pem'):
        context = ('cert.pem', 'key.pem')
    else:
        context = 'adhoc'  # 개발용
    
    app.run(
        host='0.0.0.0',
        port=5000,
        ssl_context=context,
        debug=False  # 운영환경에서는 반드시 False
    )