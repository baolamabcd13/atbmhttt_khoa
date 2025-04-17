from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from database import db, User
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
    if request.method == 'GET':
        captcha_text, captcha_image = generate_captcha()
        session['captcha_text'] = captcha_text
        return render_template('login.html', captcha_image=captcha_image)
    
    if request.method == 'POST':
        if not check_rate_limit(request.remote_addr):
            flash('Too many login attempts. Please try again later.')
            return redirect(url_for('login'))
        
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        captcha = request.form.get('captcha', '')
        totp_code = request.form.get('totp_code', '')
        
        # Kiểm tra captcha
        if captcha.upper() != session.get('captcha_text', ''):
            flash('Invalid CAPTCHA!')
            return redirect(url_for('login'))
        
        # Xóa captcha cũ
        session.pop('captcha_text', None)
        
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            # Kiểm tra mã 2FA
            totp = pyotp.TOTP(user.totp_secret)
            if totp.verify(totp_code):
                session.clear()
                session['user_id'] = user.id
                session['username'] = user.username
                session.permanent = True  # Sử dụng permanent session
                return redirect(url_for('dashboard'))
            else:
                flash('Invalid authentication code!')
        else:
            flash('Invalid username or password!')
        
        return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    user = User.query.get(session['user_id'])
    if not user:
        session.clear()
        flash('Please login again.')
        return redirect(url_for('login'))

    # Lấy thông tin cho dashboard
    current_time = datetime.utcnow()
    
    # Demo data cho biểu đồ
    chart_labels = [(current_time - timedelta(hours=x)).strftime('%H:00') 
                   for x in range(24, -1, -1)]
    chart_data = generate_demo_data(24)  # Hàm tạo demo data

    context = {
        'username': user.username,
        'last_login': user.last_login.strftime('%Y-%m-%d %H:%M:%S') if user.last_login else 'First Login',
        'ip_address': request.remote_addr,
        'successful_attempts': get_successful_attempts(),
        'failed_attempts': get_failed_attempts(),
        'blocked_ips': len(get_blocked_ips()),
        'security_events': get_recent_security_events(),
        'captcha_success_rate': calculate_captcha_success_rate(),
        'rate_limit_blocks': get_rate_limit_blocks(),
        'suspicious_ips': len(get_suspicious_ips()),
        'chart_labels': chart_labels,
        'chart_data': chart_data
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

def get_recent_security_events():
    """Get recent security events"""
    events = [
        {
            'timestamp': (datetime.utcnow() - timedelta(minutes=random.randint(1, 60))).strftime('%H:%M:%S'),
            'type': random.choice(['warning', 'danger', 'success']),
            'description': random.choice([
                'Failed login attempt from suspicious IP',
                'Successful login from new device',
                'Rate limit exceeded for IP',
                'CAPTCHA verification failed',
                'Successful 2FA verification',
                'Multiple failed attempts detected'
            ])
        } for _ in range(10)
    ]
    return sorted(events, key=lambda x: x['timestamp'], reverse=True)

def calculate_captcha_success_rate():
    """Calculate CAPTCHA success rate"""
    return random.randint(60, 95)

def get_rate_limit_blocks():
    """Get number of rate limit blocks"""
    return random.randint(20, 100)

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

if __name__ == '__main__':
    app.run(debug=True)