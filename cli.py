import argparse
import os
from network_scanner import NetworkScanner


def log(level, message):
    print(f"[{level}] {message}")


def find_nmap():
    nmap_exe = "nmap.exe" if os.name == "nt" else "nmap"
    for path in os.environ.get("PATH", "").split(os.pathsep):
        full_path = os.path.join(path, nmap_exe)
        if os.path.isfile(full_path):
            return full_path
    common_paths = [
        "/usr/bin/nmap",
        "/usr/local/bin/nmap",
        "C:\\Program Files (x86)\\Nmap\\nmap.exe",
        "C:\\Program Files\\Nmap\\nmap.exe",
    ]
    for path in common_paths:
        if os.path.isfile(path):
            return path
    return None


def find_masscan():
    if os.name == "nt":
        candidates = [
            "C:\\Program Files\\Masscan\\masscan.exe",
            "C:\\Program Files (x86)\\Masscan\\masscan.exe",
            "C:\\masscan\\masscan.exe",
        ]
        exe_name = "masscan.exe"
    else:
        candidates = ["/usr/bin/masscan", "/usr/local/bin/masscan"]
        exe_name = "masscan"

    for path in os.environ.get("PATH", "").split(os.pathsep):
        full_path = os.path.join(path, exe_name)
        if os.path.isfile(full_path):
            return full_path
    for path in candidates:
        if os.path.isfile(path):
            return path
    return None


def main():
    parser = argparse.ArgumentParser(description="Network Scanner CLI")
    parser.add_argument("target", help="IP, CIDR range, or file path of targets")
    parser.add_argument("-p", "--ports", required=True, help="Ports to scan")
    parser.add_argument("-t", "--tool", choices=["Nmap", "Masscan"], default="Nmap")
    parser.add_argument(
        "-s",
        "--speed",
        choices=["Slow (Stealth)", "Normal", "Fast", "Aggressive"],
        default="Normal",
    )
    args = parser.parse_args()

    nmap_path = find_nmap()
    masscan_path = find_masscan()
    if args.tool == "Nmap" and not nmap_path:
        log("Error", "Nmap not found in PATH")
        return
    if args.tool == "Masscan" and not masscan_path:
        log("Error", "Masscan not found in PATH")
        return

    scanner = NetworkScanner(nmap_path, masscan_path, log)
    results = scanner.scan_network(args.target, args.ports, args.tool, args.speed)
    for ip, port, service in results:
        print(f"{ip}:{port} {service}")


if __name__ == "__main__":
    main()
