import os
import joblib
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from config import WORDLISTS_DIR

class PasswordPredictor:
    def __init__(self):
        self.model_path = os.path.join(WORDLISTS_DIR, "password_model.pkl")
        self.vectorizer_path = os.path.join(WORDLISTS_DIR, "tfidf_vectorizer.pkl")
        self.model = None
        self.vectorizer = None
        self.wordlist_map = {
            0: "common_passwords.txt",
            1: "tech_industry.txt",
            2: "finance_passwords.txt",
            3: "government_passwords.txt",
            4: "country_specific.txt"
        }
        
        if os.path.exists(self.model_path) and os.path.exists(self.vectorizer_path):
            self.load_model()
        else:
            self.train_demo_model()
    
    def train_demo_model(self):
        """Huấn luyện mô hình demo với dữ liệu mẫu"""
        # Dữ liệu huấn luyện mẫu
        industries = [
            "technology", "technology", "technology", 
            "finance", "finance", "finance",
            "government", "government", "government",
            "healthcare", "healthcare"
        ]
        countries = [
            "us", "us", "uk", 
            "us", "de", "jp",
            "us", "cn", "ru",
            "fr", "ca"
        ]
        passwords = [
            "admin123", "root@2023", "cisco#123",
            "Bank$2023", "Financ3!", "Yen!2023",
            "Gov@1234", "GreatWall#", "Kremlin2023",
            "Medical#1", "Hospital2023"
        ]
        
        # Tạo features
        features = [f"{ind} {country}" for ind, country in zip(industries, countries)]
        
        # Vector hóa văn bản
        self.vectorizer = TfidfVectorizer()
        X = self.vectorizer.fit_transform(features)
        
        # Nhãn phân loại
        y = [0, 0, 0, 1, 1, 1, 2, 2, 2, 3, 3]
        
        # Huấn luyện mô hình
        self.model = RandomForestClassifier(n_estimators=100)
        self.model.fit(X, y)
        
        # Lưu mô hình
        joblib.dump(self.model, self.model_path)
        joblib.dump(self.vectorizer, self.vectorizer_path)
    
    def load_model(self):
        """Tải mô hình đã huấn luyện"""
        self.model = joblib.load(self.model_path)
        self.vectorizer = joblib.load(self.vectorizer_path)
    
    def predict_wordlist(self, industry, country):
        """Dự đoán wordlist phù hợp dựa trên ngành và quốc gia"""
        if not self.model or not self.vectorizer:
            return os.path.join(WORDLISTS_DIR, "common_passwords.txt")
        
        # Tạo feature vector
        text = f"{industry} {country}"
        X = self.vectorizer.transform([text])
        
        # Dự đoán
        prediction = self.model.predict(X)[0]
        wordlist = self.wordlist_map.get(prediction, "common_passwords.txt")
        
        return os.path.join(WORDLISTS_DIR, wordlist)
    
    def generate_dynamic_wordlist(self, base_wordlist, industry, country):
        """Tạo wordlist động dựa trên ngữ cảnh"""
        # Đọc wordlist cơ sở
        with open(base_wordlist, 'r', encoding='utf-8', errors='ignore') as f:
            passwords = [line.strip() for line in f]
        
        # Quy tắc biến đổi dựa trên ngành/địa lý
        transformations = []
        
        if "tech" in industry.lower():
            transformations.extend(["@", "#", "2023", "admin", "root"])
        if "finance" in industry.lower():
            transformations.extend(["$", "bank", "fin", "2023", "!!"])
        if "jp" in country.lower():
            transformations.extend(["japan", "tokyo", "富士山", "123"])
        
        # Tạo wordlist mới
        new_wordlist = []
        for pwd in passwords:
            new_wordlist.append(pwd)
            for transform in transformations:
                new_wordlist.append(f"{pwd}{transform}")
                new_wordlist.append(f"{transform}{pwd}")
        
        # Lưu wordlist tạm thời
        temp_path = os.path.join(WORDLISTS_DIR, "dynamic_wordlist.txt")
        with open(temp_path, 'w', encoding='utf-8') as f:
            f.write("\n".join(set(new_wordlist)))
        
        return temp_path