import os
import sys

try:
    from PyQt5.QtWidgets import QApplication
except Exception as e:  # noqa: PIE786
    print("PyQt5 is required to launch the GUI: {}".format(e))
    sys.exit(1)

from gui import NetworkScannerGUI

if __name__ == "__main__":
    if not os.environ.get("DISPLAY") and sys.platform != "win32":
        print("Error: No DISPLAY environment variable; GUI cannot start.")
        sys.exit(1)

    app = QApplication(sys.argv)
    window = NetworkScannerGUI()
    window.show()
    sys.exit(app.exec_())