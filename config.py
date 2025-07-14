import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
WORDLISTS_DIR = os.path.join(BASE_DIR, "wordlists")
os.makedirs(WORDLISTS_DIR, exist_ok=True)

# Default service ports
SERVICE_PORTS = {
    "SSH": "22",
    "FTP": "21",
    "RDP": "3389",
    "HTTP": "80",
    "HTTPS": "443",
    "SMB": "445",
    "SMTP": "25",
    "POP3": "110",
    "IMAP": "143",
    "MYSQL": "3306",
    "POSTGRESQL": "5432",
    "VNC": "5900"
}