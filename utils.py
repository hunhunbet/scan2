import os
import platform
import subprocess
import re
import sys

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
            [sys.executable, "-c", "import impacket; print(impacket.__version__)"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            creationflags=get_creation_flags(),
            timeout=5
        )
        return result.returncode == 0
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
        return False



def get_default_interface():
    """Return the default network interface on Linux/Unix systems."""
    if platform.system() == "Windows":
        return None
    try:
        result = subprocess.run(
            ["ip", "route", "show", "default"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            encoding="utf-8",
            errors="ignore",
            creationflags=get_creation_flags(),
            timeout=5,
        )
        for line in result.stdout.splitlines():
            if " dev " in line:
                parts = line.split()
                if "dev" in parts:
                    return parts[parts.index("dev") + 1]
    except Exception:
        pass

    try:
        result = subprocess.run(
            ["ip", "-o", "link", "show"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            encoding="utf-8",
            errors="ignore",
            creationflags=get_creation_flags(),
            timeout=5,
        )
        for line in result.stdout.splitlines():
            if ":" in line:
                iface = line.split(":", 2)[1].strip().split()[0]
                if iface != "lo":
                    return iface
    except Exception:
        pass
    return None
