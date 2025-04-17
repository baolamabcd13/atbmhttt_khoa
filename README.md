# Demo Brute Force Attack và Phòng Chống

## Giới thiệu

Project demo các kỹ thuật tấn công Brute Force và các biện pháp phòng chống thông qua một web application thực tế. Hệ thống bao gồm hai phần chính:

- Web application với các biện pháp bảo mật
- Script tấn công brute force để kiểm thử

## Tính năng

### Bảo mật

- Đăng ký tài khoản với password policy mạnh
- Xác thực 2 yếu tố (2FA) với TOTP
- CAPTCHA verification
- Rate limiting và IP blocking
- Monitoring và logging các nỗ lực tấn công
- Dashboard theo dõi security metrics

### Tấn công

- Multi-threading brute force
- OCR CAPTCHA bypass
- Wordlist attack
- Logging kết quả

## Cài đặt

### 1. Clone repository

```bash
git clone https://github.com/baolamabcd13/atbmhttt_khoa.git
cd atbmhttt_khoa
```

### 2. Tạo môi trường ảo

```bash
python -m venv venv
venv\Scripts\activate
```

### 3. Cài đặt dependencies

```bash
pip install -r requirements.txt
```

Các thư viện chính được sử dụng:

- Flask: Web framework
- SQLAlchemy: Database ORM
- PyOTP: Tạo và verify mã 2FA
- Pillow: Xử lý ảnh CAPTCHA
- Pytesseract: OCR CAPTCHA
- Requests: HTTP requests cho script tấn công

## Chạy ứng dụng

### 1. Khởi động web application

```bash
python app.py
```

Server sẽ chạy tại http://localhost:5000

### 2. Demo tấn công

```bash
python brute_force_attack.py --url http://localhost:5000 --userlist usernames.txt --passlist passwords.txt --threads 3
```

Các tham số:

- --url: URL của web application
- --userlist: File chứa danh sách username
- --passlist: File chứa danh sách password
- --threads: Số luồng tấn công (mặc định: 3)

## Cách hoạt động

### Web Application (app.py)

1. **Đăng ký tài khoản:**

   - Validate password policy
   - Tạo secret key cho 2FA
   - Generate QR code cho Google Authenticator

2. **Đăng nhập:**

   - Verify username/password
   - Kiểm tra CAPTCHA
   - Verify mã 2FA
   - Check rate limiting

3. **Bảo mật:**
   - Session management
   - IP tracking
   - Security logging
   - Real-time monitoring

### Script tấn công (brute_force_attack.py)

1. **Khởi tạo:**

   - Load wordlists
   - Tạo session
   - Setup multi-threading

2. **Tấn công:**

   - Get CAPTCHA từ trang login
   - OCR để giải mã CAPTCHA
   - Thử tất cả các kết hợp username/password
   - Log kết quả

3. **Kết quả:**
   - Số lần thử
   - Thời gian tấn công
   - Các tài khoản tìm được

## Cấu trúc thư mục

atbmhttt_khoa/
├── app.py # Main application
├── database.py # Database models
├── brute_force_attack.py # Attack simulation
├── requirements.txt # Dependencies
├── static/ # Static files
├── templates/ # HTML templates
├── instance/ # Instance configs
└── tests/ # Test cases
