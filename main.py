
import os
import sys

try:
    from PyQt5.QtWidgets import QApplication
except Exception as e:  # noqa: PIE786
    print("PyQt5 is required to launch the GUI: {}".format(e))
    sys.exit(1)

from gui import NetworkScannerGUI


from gui import NetworkScannerGUI
from network_scanner import NetworkScanner


def run_cli() -> None:
    """Simple command-line interface for headless usage."""
    parser = argparse.ArgumentParser(description="Network Scanner CLI")
    parser.add_argument("--target", required=True, help="Target IP, CIDR, or file")
    parser.add_argument("--port", required=True, help="Ports to scan")
    parser.add_argument("--scan-tool", choices=["Nmap", "Masscan"], default="Nmap")
    parser.add_argument("--scan-speed", default="Normal", help="Scan speed preset")
    args = parser.parse_args()

    def log(source: str, message: str) -> None:
        print(f"[{source}] {message}")

    nmap_path = shutil.which("nmap")
    masscan_path = shutil.which("masscan")

    scanner = NetworkScanner(nmap_path, masscan_path, log)
    results = scanner.scan_network(args.target, args.port, args.scan_tool, args.scan_speed)
    for r in results:
        print(r)


if __name__ == "__main__":
    if not os.environ.get("DISPLAY") and sys.platform != "win32":
        print("Error: No DISPLAY environment variable; GUI cannot start.")
        sys.exit(1)

    app = QApplication(sys.argv)
    window = NetworkScannerGUI()
    window.show()
    sys.exit(app.exec_())

