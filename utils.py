import os
import platform
import subprocess
import re

def find_exe_in_dir(directory, name=""):
    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.lower().endswith(".exe") and (not name or name in file.lower()):
                return os.path.join(root, file)
    return ""

def get_creation_flags():
    if platform.system() == "Windows":
        return subprocess.CREATE_NO_WINDOW
    return 0

def is_valid_ip(ip):
    pattern = r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$'
    match = re.match(pattern, ip)
    if not match:
        return False
    return all(0 <= int(part) <= 255 for part in match.groups())

def parse_ip_range(ip_range):
    """Parse IP range like 192.168.1.1-100"""
    if '-' not in ip_range:
        return [ip_range]
    
    try:
        base, range_part = ip_range.rsplit('.', 1)
        if '-' in range_part:
            start, end = range_part.split('-')
            try:
                return [f"{base}.{i}" for i in range(int(start), int(end) + 1)]
            except ValueError:
                return [ip_range]
        return [ip_range]
    except (ValueError, IndexError):
        return [ip_range]

def validate_ports(port_str):
    """Validate port range format"""
    pattern = r'^(\d+(-\d+)?)(,(\d+(-\d+)?))*$'
    return bool(re.match(pattern, port_str.strip()))

def check_impacket_installed():
    try:
        result = subprocess.run(
            ["python", "-m", "impacket", "--version"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            creationflags=get_creation_flags(),
            timeout=5
        )
        return result.returncode == 0
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
        return False