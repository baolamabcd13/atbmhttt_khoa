from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from database import db, User, LoginAttempt, BlockedIP, SecurityEvent
import pyotp
import qrcode
from io import BytesIO
import base64
from captcha.image import ImageCaptcha
import random
import string
from werkzeug.security import generate_password_hash, check_password_hash
import re
from functools import wraps
import time
from datetime import datetime, timedelta
from sqlalchemy import func, distinct

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'  # Thay đổi thành một key bảo mật
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['PERMANENT_SESSION_LIFETIME'] = 1800  # Session hết hạn sau 30 phút
db.init_app(app)

# Tạo database
with app.app_context():
    db.create_all()

# Decorator để kiểm tra đăng nhập
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login to access this page.')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Hàm kiểm tra mật khẩu mạnh
def is_strong_password(password):
    if len(password) < 8:
        return False
    if not re.search(r"[A-Z]", password):  # Ít nhất 1 chữ hoa
        return False
    if not re.search(r"[a-z]", password):  # Ít nhất 1 chữ thường
        return False
    if not re.search(r"\d", password):     # Ít nhất 1 số
        return False
    if not re.search(r"[ !@#$%&'()*+,-./[\\\]^_`{|}~"+r'"]', password):  # Ít nhất 1 ký tự đặc biệt
        return False
    return True

def generate_captcha():
    # Tạo mã captcha phức tạp hơn
    captcha_text = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
    image = ImageCaptcha(width=280, height=90)
    data = image.generate(captcha_text)
    captcha_image = base64.b64encode(data.getvalue()).decode()
    return captcha_text, captcha_image

# Rate limiting
login_attempts = {}
def check_rate_limit(ip):
    current_time = time.time()
    if ip in login_attempts:
        attempts = [t for t in login_attempts[ip] if current_time - t < 3600]  # Giữ lại các lần thử trong 1 giờ
        login_attempts[ip] = attempts
        if len(attempts) >= 5:  # Giới hạn 5 lần thử trong 1 giờ
            return False
    login_attempts[ip] = login_attempts.get(ip, []) + [current_time]
    return True

@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        
        # Kiểm tra username
        if not username or len(username) < 4:
            flash('Username must be at least 4 characters long.')
            return redirect(url_for('register'))
        
        if not username.isalnum():
            flash('Username must contain only letters and numbers.')
            return redirect(url_for('register'))
        
        # Kiểm tra password match
        if password != confirm_password:
            flash('Passwords do not match!')
            return redirect(url_for('register'))
        
        # Kiểm tra mật khẩu mạnh
        if not is_strong_password(password):
            flash('Password must be at least 8 characters long and contain uppercase, lowercase, numbers, and special characters.')
            return redirect(url_for('register'))
        
        # Kiểm tra username đã tồn tại
        if User.query.filter_by(username=username).first():
            flash('Username already exists!')
            return redirect(url_for('register'))
        
        try:
            # Tạo secret key cho 2FA
            totp_secret = pyotp.random_base32()
            totp = pyotp.TOTP(totp_secret)
            
            # Tạo QR code
            qr = qrcode.QRCode(version=1, box_size=10, border=5)
            provisioning_uri = totp.provisioning_uri(username, issuer_name="SecureAuth")
            qr.add_data(provisioning_uri)
            qr.make(fit=True)
            img = qr.make_image(fill_color="black", back_color="white")
            
            # Chuyển QR code thành base64
            buffered = BytesIO()
            img.save(buffered)
            qr_image = base64.b64encode(buffered.getvalue()).decode()
            
            # Lưu user với mật khẩu đã hash
            hashed_password = generate_password_hash(password)
            new_user = User(
                username=username,
                password=hashed_password,
                totp_secret=totp_secret,
                is_2fa_verified=False  # Thêm trường mới
            )
            db.session.add(new_user)
            db.session.commit()
            
            return render_template('register.html', 
                                 qr_image=qr_image, 
                                 registration_complete=True,
                                 username=username)
            
        except Exception as e:
            db.session.rollback()
            flash('An error occurred during registration. Please try again.')
            return redirect(url_for('register'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        captcha = request.form.get('captcha')
        totp_code = request.form.get('totp_code')
        ip_address = request.remote_addr

        user = User.query.filter_by(username=username).first()
        
        try:
            # Log CAPTCHA attempt
            if captcha != session.get('captcha_text'):
                if user:
                    log_login_attempt(
                        user_id=user.id,
                        ip_address=ip_address,
                        success=False,
                        attempt_type='captcha'
                    )
                log_security_event(
                    'warning',
                    'CAPTCHA verification failed',
                    ip_address,
                    user.id if user else None
                )
                flash('Invalid CAPTCHA!')
                return redirect(url_for('login'))

            # Log CAPTCHA success
            if user:
                log_login_attempt(
                    user_id=user.id,
                    ip_address=ip_address,
                    success=True,
                    attempt_type='captcha'
                )

            if user and check_password_hash(user.password, password):
                totp = pyotp.TOTP(user.totp_secret)
                if totp.verify(totp_code):
                    # Log successful login
                    log_login_attempt(
                        user_id=user.id,
                        ip_address=ip_address,
                        success=True
                    )
                    log_security_event(
                        'success',
                        'Successful 2FA verification',
                        ip_address,
                        user.id
                    )
                    
                    session['user_id'] = user.id
                    user.last_login = datetime.utcnow()
                    db.session.commit()
                    
                    return redirect(url_for('dashboard'))
                else:
                    # Log failed 2FA
                    log_login_attempt(
                        user_id=user.id,
                        ip_address=ip_address,
                        success=False,
                        attempt_type='2fa'
                    )
                    log_security_event(
                        'danger',
                        'Failed 2FA verification',
                        ip_address,
                        user.id
                    )
                    flash('Invalid 2FA code!')
            else:
                # Log failed login
                if user:
                    log_login_attempt(
                        user_id=user.id,
                        ip_address=ip_address,
                        success=False,
                        is_suspicious=True
                    )
                log_security_event(
                    'warning',
                    'Failed login attempt from suspicious IP',
                    ip_address
                )
                flash('Invalid username or password!')
            
            return redirect(url_for('login'))
        
        except Exception as e:
            db.session.rollback()
            flash('An error occurred. Please try again.')
            return redirect(url_for('login'))

    # GET request
    captcha_text, captcha_image = generate_captcha()
    session['captcha_text'] = captcha_text
    return render_template('login.html', captcha_image=captcha_image)

@app.route('/dashboard')
@login_required
def dashboard():
    user = User.query.get(session['user_id'])
    if not user:
        session.clear()
        flash('Please login again.')
        return redirect(url_for('login'))

    # Tạo dữ liệu cho biểu đồ
    current_time = datetime.utcnow()
    chart_labels = [(current_time - timedelta(hours=x)).strftime('%H:00') 
                   for x in range(23, -1, -1)]
    
    # Lấy dữ liệu login attempts theo giờ
    chart_data = []
    for hour in range(23, -1, -1):
        time_from = current_time - timedelta(hours=hour+1)
        time_to = current_time - timedelta(hours=hour)
        attempts = LoginAttempt.query.filter(
            LoginAttempt.timestamp.between(time_from, time_to)
        ).count()
        chart_data.append(attempts)

    successful, failed, blocked = get_login_stats()
    
    context = {
        'username': user.username,
        'last_login': user.last_login.strftime('%Y-%m-%d %H:%M:%S') if user.last_login else 'First Login',
        'ip_address': request.remote_addr,
        'successful_attempts': successful,
        'failed_attempts': failed,
        'blocked_ips': blocked,
        'security_events': get_recent_security_events(),
        'captcha_success_rate': get_captcha_success_rate(),
        'rate_limit_blocks': get_rate_limit_blocks(),
        'suspicious_ips': get_suspicious_ips_count(),
        'chart_labels': chart_labels,  # Thêm labels cho biểu đồ
        'chart_data': chart_data      # Thêm data cho biểu đồ
    }

    return render_template('dashboard.html', **context)

# Helper functions for dashboard
def generate_demo_data(points):
    """Generate demo data for the chart"""
    return [random.randint(0, 100) for _ in range(points)]

def get_successful_attempts():
    """Get number of successful login attempts"""
    return random.randint(10, 50)

def get_failed_attempts():
    """Get number of failed login attempts"""
    return random.randint(50, 200)

def get_blocked_ips():
    """Get list of blocked IPs"""
    return [f"192.168.1.{x}" for x in range(random.randint(1, 10))]

def get_recent_security_events(limit=5):
    events = SecurityEvent.query.order_by(
        SecurityEvent.timestamp.desc()
    ).limit(limit).all()
    return events or []  # Trả về list rỗng nếu không có events

def calculate_captcha_success_rate():
    """Calculate CAPTCHA success rate"""
    return random.randint(60, 95)

def get_rate_limit_blocks():
    return BlockedIP.query.filter(
        BlockedIP.reason == 'rate_limit'
    ).count() or 0

def get_suspicious_ips():
    """Get list of suspicious IPs"""
    return [f"192.168.1.{x}" for x in range(random.randint(5, 15))]

@app.route('/reset-captcha')
def reset_captcha():
    captcha_text, captcha_image = generate_captcha()
    session['captcha_text'] = captcha_text
    return jsonify({'captcha_image': captcha_image})

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.')
    return redirect(url_for('login'))

@app.route('/verify-2fa', methods=['POST'])
def verify_2fa():
    username = request.form.get('username')
    verification_code = request.form.get('verification_code')
    
    if not username or not verification_code:
        flash('Please provide both username and verification code.')
        return redirect(url_for('register'))
    
    user = User.query.filter_by(username=username).first()
    if not user:
        flash('User not found.')
        return redirect(url_for('register'))
    
    totp = pyotp.TOTP(user.totp_secret)
    
    try:
        if totp.verify(verification_code):
            # Cập nhật trạng thái xác thực 2FA của user
            user.is_2fa_verified = True
            db.session.commit()
            
            flash('2FA verification successful! You can now login.')
            return redirect(url_for('login'))
        else:
            flash('Invalid verification code. Please try again.')
            # Trả về trang register với QR code và trạng thái registration_complete
            qr = qrcode.QRCode(version=1, box_size=10, border=5)
            provisioning_uri = totp.provisioning_uri(username, issuer_name="SecureAuth")
            qr.add_data(provisioning_uri)
            qr.make(fit=True)
            img = qr.make_image(fill_color="black", back_color="white")
            
            buffered = BytesIO()
            img.save(buffered)
            qr_image = base64.b64encode(buffered.getvalue()).decode()
            
            return render_template('register.html', 
                                qr_image=qr_image, 
                                registration_complete=True,
                                username=username)
    except Exception as e:
        flash('An error occurred during verification. Please try again.')
        return redirect(url_for('register'))

# Error handlers
@app.errorhandler(404)
def not_found_error(error):
    return render_template('error.html', error='404 - Page Not Found'), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('error.html', error='500 - Internal Server Error'), 500

def log_login_attempt(user_id, ip_address, success, attempt_type='login', is_suspicious=False):
    attempt = LoginAttempt(
        user_id=user_id,
        ip_address=ip_address,
        success=success,
        attempt_type=attempt_type,
        is_suspicious=is_suspicious
    )
    db.session.add(attempt)
    db.session.commit()

def log_security_event(event_type, description, ip_address, user_id=None):
    event = SecurityEvent(
        event_type=event_type,
        description=description,
        ip_address=ip_address,
        user_id=user_id
    )
    db.session.add(event)
    db.session.commit()

def get_login_stats(hours=24):
    since = datetime.utcnow() - timedelta(hours=hours)
    
    # Successful attempts
    successful = LoginAttempt.query.filter(
        LoginAttempt.timestamp >= since,
        LoginAttempt.success == True
    ).count() or 0
    
    # Failed attempts
    failed = LoginAttempt.query.filter(
        LoginAttempt.timestamp >= since,
        LoginAttempt.success == False
    ).count() or 0
    
    # Blocked IPs
    blocked = BlockedIP.query.filter(
        BlockedIP.blocked_at >= since
    ).count() or 0
    
    return successful, failed, blocked

def get_captcha_success_rate(hours=24):
    since = datetime.utcnow() - timedelta(hours=hours)
    total = LoginAttempt.query.filter(
        LoginAttempt.timestamp >= since,
        LoginAttempt.attempt_type == 'captcha'
    ).count()
    
    if total == 0:
        return 100
    
    successful = LoginAttempt.query.filter(
        LoginAttempt.timestamp >= since,
        LoginAttempt.attempt_type == 'captcha',
        LoginAttempt.success == True
    ).count()
    
    return int((successful / total) * 100)

def get_suspicious_ips_count():
    return db.session.query(func.count(distinct(LoginAttempt.ip_address))).filter(
        LoginAttempt.is_suspicious == True
    ).scalar() or 0

if __name__ == '__main__':
    app.run(debug=True)