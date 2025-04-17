from flask import Flask, render_template, request, redirect, url_for, flash, session
from database import db, User
import pyotp
import qrcode
from io import BytesIO
import base64
from captcha.image import ImageCaptcha
import random
import string

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'  # Thay đổi thành một key bảo mật
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db.init_app(app)

# Tạo database
with app.app_context():
    db.create_all()

def generate_captcha():
    # Tạo mã captcha ngẫu nhiên
    captcha_text = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
    image = ImageCaptcha()
    data = image.generate(captcha_text)
    captcha_image = base64.b64encode(data.getvalue()).decode()
    return captcha_text, captcha_image

@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists!')
            return redirect(url_for('register'))
        
        # Tạo secret key cho 2FA
        totp_secret = pyotp.random_base32()
        totp = pyotp.TOTP(totp_secret)
        
        # Tạo QR code
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        provisioning_uri = totp.provisioning_uri(username, issuer_name="YourApp")
        qr.add_data(provisioning_uri)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        
        # Chuyển QR code thành base64 string
        buffered = BytesIO()
        img.save(buffered)
        qr_image = base64.b64encode(buffered.getvalue()).decode()
        
        # Lưu user vào database
        new_user = User(username=username, password=password, totp_secret=totp_secret)
        db.session.add(new_user)
        db.session.commit()
        
        return render_template('register.html', qr_image=qr_image, registration_complete=True)
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        captcha_text, captcha_image = generate_captcha()
        session['captcha_text'] = captcha_text
        return render_template('login.html', captcha_image=captcha_image)
    
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        captcha = request.form['captcha']
        totp_code = request.form['totp_code']
        
        if captcha != session['captcha_text']:
            flash('Invalid CAPTCHA!')
            return redirect(url_for('login'))
        
        user = User.query.filter_by(username=username).first()
        if user and user.password == password:
            totp = pyotp.TOTP(user.totp_secret)
            if totp.verify(totp_code):
                session['user_id'] = user.id
                return redirect(url_for('dashboard'))
            else:
                flash('Invalid 2FA code!')
        else:
            flash('Invalid username or password!')
        
        return redirect(url_for('login'))

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    return render_template('dashboard.html', username=user.username)

if __name__ == '__main__':
    app.run(debug=True)