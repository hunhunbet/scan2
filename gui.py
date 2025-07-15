import os
import sys
import threading
import time
import csv
import re
import random
from datetime import datetime
from PyQt5.QtWidgets import (
    QMainWindow, QApplication, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
    QPushButton, QComboBox, QListWidget, QProgressBar, QTabWidget, QFileDialog,
    QMessageBox, QGroupBox, QGridLayout, QCheckBox, QTableWidget, QTableWidgetItem,
    QAbstractItemView, QHeaderView, QAction, QMenu, QStatusBar, QInputDialog, QDialog, 
    QDialogButtonBox
)
from PyQt5.QtCore import Qt, QTimer, pyqtSignal, QSettings, QSize, QMutex, QMutexLocker
from PyQt5.QtGui import QIcon, QFont, QPalette, QColor

from main_window import DashboardTab
from network_scanner import NetworkScanner
from parallel_executor import ParallelExecutor
from progress_manager import ProgressManager
from config import SERVICE_PORTS, WORDLISTS_DIR
from error_handler import ErrorHandler
from utils import find_exe_in_dir, get_creation_flags, is_valid_ip, validate_ports, check_impacket_installed
from brute_file_tab import BruteForceFileTab
from password_predictor import PasswordPredictor
from mfa_bypass import MFABypass
from plugin_system import PluginManager
from session_manager import SessionManager

class NetworkScannerGUI(QMainWindow):
    scan_update_signal = pyqtSignal(list)
    scan_complete_signal = pyqtSignal()
    brute_complete_signal = pyqtSignal()

    def __init__(self):
        super().__init__()
        self.setWindowTitle("Network Scanner & Brute-force Tool")
        self.setGeometry(100, 100, 1200, 800)
        self.is_scanning = False
        self.scan_paused = False
        self.brute_paused = False
        self.scan_results = []
        self.scan_progress_manager = None
        self.brute_executor = None
        self.scan_thread = None
        self.brute_thread = None
        self.error_handler = ErrorHandler(self.log)
        self.log_mutex = QMutex()
        self.settings = QSettings("NetworkScanner", "Config")
        self.init_ui()
        self.scan_update_signal.connect(self.update_result_list)
        self.scan_complete_signal.connect(self.on_scan_complete)
        self.brute_complete_signal.connect(self.on_brute_complete)
        self.apply_theme()  # Apply theme after UI initialization

    def init_ui(self):
        self.tab_widget = QTabWidget()
        self.setCentralWidget(self.tab_widget)

        self.main_tab = QWidget()
        self.setup_main_tab()
        self.tab_widget.addTab(self.main_tab, "Scan & Brute")

        self.dashboard_tab = DashboardTab(self)
        self.tab_widget.addTab(self.dashboard_tab, "Dashboard")

        self.brute_file_tab = BruteForceFileTab(self)
        self.tab_widget.addTab(self.brute_file_tab, "Brute from File")
        
        # Thêm tab quản lý session
        self.session_tab = SessionManager(self)
        self.tab_widget.addTab(self.session_tab, "Sessions")

        from settings_tab import SettingsTab
        self.settings_tab = SettingsTab()
        self.tab_widget.addTab(self.settings_tab, "Settings")

        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.create_menu()
        
        # Tải hệ thống plugin
        self.plugin_manager = PluginManager(self)
        self.plugin_manager.load_plugins()

    def create_menu(self):
        menu_bar = self.menuBar()
        
        # File Menu
        file_menu = menu_bar.addMenu("File")
        exit_action = QAction("Exit", self)
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)

        # View Menu
        view_menu = menu_bar.addMenu("View")
        # Theme submenu
        theme_menu = QMenu("Theme", self)
        dark_action = QAction("Dark", self)
        dark_action.triggered.connect(lambda: self.set_theme("dark"))
        light_action = QAction("Light", self)
        light_action.triggered.connect(lambda: self.set_theme("light"))
        theme_menu.addAction(dark_action)
        theme_menu.addAction(light_action)
        view_menu.addMenu(theme_menu)

        # Tools Menu
        tools_menu = menu_bar.addMenu("Tools")
        
        # Advanced Brute Menu
        advanced_brute_menu = QMenu("Advanced Brute-force", self)
        tools_menu.addMenu(advanced_brute_menu)
        
        # Advanced options
        brute_hydra_action = QAction("Hydra from File", self)
        brute_hydra_action.triggered.connect(lambda: self.brute_force_from_file("Hydra"))
        advanced_brute_menu.addAction(brute_hydra_action)
        
        brute_ncrack_action = QAction("Ncrack from File", self)
        brute_ncrack_action.triggered.connect(lambda: self.brute_force_from_file("Ncrack"))
        advanced_brute_menu.addAction(brute_ncrack_action)
        
        brute_impacket_action = QAction("Impacket from File", self)
        brute_impacket_action.triggered.connect(lambda: self.brute_force_from_file("Impacket"))
        advanced_brute_menu.addAction(brute_impacket_action)
        
        brute_pth_action = QAction("Pass-the-Hash from File", self)
        brute_pth_action.triggered.connect(lambda: self.brute_force_from_file("Impacket", "Normal", True))
        advanced_brute_menu.addAction(brute_pth_action)

        # Help Menu
        help_menu = menu_bar.addMenu("Help")
        about_action = QAction("About", self)
        about_action.triggered.connect(self.show_about)
        help_menu.addAction(about_action)

    def show_about(self):
        QMessageBox.information(self, "About",
            "Network Scanner and Brute-force Tool\nVersion 2.0\n© 2023")

    def set_theme(self, theme_name):
        self.settings.setValue("theme", theme_name)
        self.apply_theme()

    def apply_theme(self):
        theme = self.settings.value("theme", "dark")
        app = QApplication.instance()
        if theme == "dark":
            # Apply dark theme
            app.setStyle("Fusion")
            dark_palette = QPalette()
            dark_palette.setColor(QPalette.Window, QColor(30, 30, 30))
            dark_palette.setColor(QPalette.WindowText, Qt.white)
            dark_palette.setColor(QPalette.Base, QColor(45, 45, 45))
            dark_palette.setColor(QPalette.AlternateBase, QColor(30, 30, 30))
            dark_palette.setColor(QPalette.ToolTipBase, Qt.white)
            dark_palette.setColor(QPalette.ToolTipText, Qt.white)
            dark_palette.setColor(QPalette.Text, Qt.white)
            dark_palette.setColor(QPalette.Button, QColor(45, 45, 45))
            dark_palette.setColor(QPalette.ButtonText, Qt.white)
            dark_palette.setColor(QPalette.BrightText, Qt.red)
            dark_palette.setColor(QPalette.Link, QColor(42, 130, 218))
            dark_palette.setColor(QPalette.Highlight, QColor(42, 130, 218))
            dark_palette.setColor(QPalette.HighlightedText, Qt.black)
            app.setPalette(dark_palette)
            app.setStyleSheet("""
                QToolTip { color: #ffffff; background-color: #2a82da; border: 1px solid white; }
                QGroupBox { border: 1px solid gray; border-radius: 5px; margin-top: 1ex; }
                QGroupBox::title { subcontrol-origin: margin; left: 10px; padding: 0 5px; }
                QTableWidget { gridline-color: #505050; }
                QHeaderView::section { background-color: #353535; }
            """)
        else:
            # Apply light theme
            app.setStyle("Fusion")
            light_palette = QPalette()
            light_palette.setColor(QPalette.Window, QColor(240, 240, 240))
            light_palette.setColor(QPalette.WindowText, Qt.black)
            light_palette.setColor(QPalette.Base, Qt.white)
            light_palette.setColor(QPalette.AlternateBase, QColor(240, 240, 240))
            light_palette.setColor(QPalette.ToolTipBase, Qt.white)
            light_palette.setColor(QPalette.ToolTipText, Qt.black)
            light_palette.setColor(QPalette.Text, Qt.black)
            light_palette.setColor(QPalette.Button, QColor(240, 240, 240))
            light_palette.setColor(QPalette.ButtonText, Qt.black)
            light_palette.setColor(QPalette.BrightText, Qt.red)
            light_palette.setColor(QPalette.Link, QColor(42, 130, 218))
            light_palette.setColor(QPalette.Highlight, QColor(42, 130, 218))
            light_palette.setColor(QPalette.HighlightedText, Qt.white)
            app.setPalette(light_palette)
            app.setStyleSheet("""
                QToolTip { color: #000000; background-color: #ffffff; border: 1px solid black; }
                QGroupBox { border: 1px solid gray; border-radius: 5px; margin-top: 1ex; }
                QGroupBox::title { subcontrol-origin: margin; left: 10px; padding: 0 5px; }
                QTableWidget { gridline-color: #c0c0c0; }
                QHeaderView::section { background-color: #e0e0e0; }
            """)

    def setup_main_tab(self):
        layout = QVBoxLayout(self.main_tab)
        
        # Target Group
        target_group = QGroupBox("Target")
        target_layout = QHBoxLayout()
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("Enter IP, CIDR range, or file path...")
        target_layout.addWidget(self.target_input, 4)
        self.browse_button = QPushButton("Browse...")
        self.browse_button.clicked.connect(self.browse_target_file)
        target_layout.addWidget(self.browse_button, 1)
        target_group.setLayout(target_layout)
        layout.addWidget(target_group)

        # Scan Configuration Group
        scan_config_group = QGroupBox("Scan Configuration")
        scan_config_layout = QGridLayout()
        
        # Port Input
        scan_config_layout.addWidget(QLabel("Port(s):"), 0, 0)
        self.port_input = QLineEdit()
        self.port_input.setPlaceholderText("e.g., 22,80,443 or 1-1000")
        scan_config_layout.addWidget(self.port_input, 0, 1)
        
        # Scan Tool Selection
        scan_config_layout.addWidget(QLabel("Scan Tool:"), 1, 0)
        self.scan_tool_combo = QComboBox()
        self.scan_tool_combo.addItems(["Nmap", "Masscan"])
        scan_config_layout.addWidget(self.scan_tool_combo, 1, 1)
        
        # Scan Speed
        scan_config_layout.addWidget(QLabel("Scan Speed:"), 2, 0)
        self.scan_speed_combo = QComboBox()
        self.scan_speed_combo.addItems(["Slow (Stealth)", "Normal", "Fast", "Aggressive"])
        scan_config_layout.addWidget(self.scan_speed_combo, 2, 1)
        
        scan_config_group.setLayout(scan_config_layout)
        layout.addWidget(scan_config_group)

        # Scan Controls
        scan_control_layout = QHBoxLayout()
        self.scan_button = QPushButton("Start Scan")
        self.scan_button.clicked.connect(self.toggle_scan)
        scan_control_layout.addWidget(self.scan_button)
        self.pause_button = QPushButton("Pause Scan")
        self.pause_button.clicked.connect(self.toggle_pause_scan)
        self.pause_button.setEnabled(False)
        scan_control_layout.addWidget(self.pause_button)
        self.stop_button = QPushButton("Stop Scan")
        self.stop_button.clicked.connect(self.stop_scan)
        self.stop_button.setEnabled(False)
        scan_control_layout.addWidget(self.stop_button)
        layout.addLayout(scan_control_layout)

        self.scan_progress = QProgressBar()
        self.scan_progress.setRange(0, 100)
        layout.addWidget(self.scan_progress)

        result_group = QGroupBox("Scan Results")
        result_layout = QVBoxLayout()
        self.result_list = QListWidget()
        self.result_list.setSelectionMode(QAbstractItemView.ExtendedSelection)
        result_layout.addWidget(self.result_list)
        brute_control_layout = QHBoxLayout()
        self.brute_button = QPushButton("Brute-force Selected Targets")
        self.brute_button.clicked.connect(self.start_brute_force)
        brute_control_layout.addWidget(self.brute_button)
        self.pause_brute_button = QPushButton("Pause Brute")
        self.pause_brute_button.clicked.connect(self.toggle_pause_brute)
        self.pause_brute_button.setEnabled(False)
        brute_control_layout.addWidget(self.pause_brute_button)
        self.stop_brute_button = QPushButton("Stop Brute")
        self.stop_brute_button.clicked.connect(self.stop_brute_force)
        self.stop_brute_button.setEnabled(False)
        brute_control_layout.addWidget(self.stop_brute_button)
        result_layout.addLayout(brute_control_layout)
        result_group.setLayout(result_layout)
        layout.addWidget(result_group)

        # Brute-force Configuration Group
        brute_config_group = QGroupBox("Brute-force Configuration")
        brute_config_layout = QGridLayout()
        
        # Brute Tool Selection
        brute_config_layout.addWidget(QLabel("Brute Tool:"), 0, 0)
        self.brute_tool_combo = QComboBox()
        self.brute_tool_combo.addItems(["Hydra", "Ncrack", "Impacket"])
        self.brute_tool_combo.currentIndexChanged.connect(self.update_brute_options)
        brute_config_layout.addWidget(self.brute_tool_combo, 0, 1)
        
        # Brute Speed
        brute_config_layout.addWidget(QLabel("Brute Speed:"), 1, 0)
        self.brute_speed_combo = QComboBox()
        self.brute_speed_combo.addItems(["Slow (Stealth)", "Normal", "Fast", "Aggressive"])
        brute_config_layout.addWidget(self.brute_speed_combo, 1, 1)
        
        # PtH/PtT Options
        self.pth_checkbox = QCheckBox("Use Pass-the-Hash (PtH) / Pass-the-Ticket (PtT)")
        self.pth_checkbox.stateChanged.connect(self.update_brute_options)
        brute_config_layout.addWidget(self.pth_checkbox, 2, 0, 1, 2)
        
        # Hash format option
        self.hash_format_label = QLabel("Hash Format:")
        self.hash_format_combo = QComboBox()
        self.hash_format_combo.addItems(["LM:NT", "NT", "Kerberos"])
        brute_config_layout.addWidget(self.hash_format_label, 3, 0)
        brute_config_layout.addWidget(self.hash_format_combo, 3, 1)
        
        # Hide hash options by default
        self.hash_format_label.setVisible(False)
        self.hash_format_combo.setVisible(False)
        
        brute_config_group.setLayout(brute_config_layout)
        layout.addWidget(brute_config_group)

        log_group = QGroupBox("Log")
        log_layout = QVBoxLayout()
        self.log_area = QTableWidget()
        self.log_area.setColumnCount(3)
        self.log_area.setHorizontalHeaderLabels(["Time", "Source", "Message"])
        self.log_area.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.log_area.verticalHeader().setVisible(False)
        self.log_area.setEditTriggers(QTableWidget.NoEditTriggers)
        log_layout.addWidget(self.log_area)
        log_group.setLayout(log_layout)
        layout.addWidget(log_group)

    def update_brute_options(self):
        tool = self.brute_tool_combo.currentText()
        use_pth = self.pth_checkbox.isChecked()
        
        # Show hash option for PtH with Impacket
        is_impacket_pth = (tool == "Impacket" and use_pth)
        self.hash_format_label.setVisible(is_impacket_pth)
        self.hash_format_combo.setVisible(is_impacket_pth)

    def browse_target_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select Target File", "", "Text Files (*.txt);;All Files (*)")
        if file_path:
            self.target_input.setText(file_path)

    def toggle_scan(self):
        if self.is_scanning:
            self.stop_scan()
        else:
            self.start_scan()

    def toggle_pause_scan(self):
        self.scan_paused = not self.scan_paused
        if self.scan_paused:
            self.pause_button.setText("Resume Scan")
            self.log("Info", "Scan paused")
        else:
            self.pause_button.setText("Pause Scan")
            self.log("Info", "Scan resumed")

    def toggle_pause_brute(self):
        self.brute_paused = not self.brute_paused
        if self.brute_paused:
            self.pause_brute_button.setText("Resume Brute")
            self.log("Info", "Brute-force paused")
        else:
            self.pause_brute_button.setText("Pause Brute")
            self.log("Info", "Brute-force resumed")

    def stop_brute_force(self):
        if self.brute_executor:
            self.brute_executor.stop()
            self.brute_button.setEnabled(True)
            self.pause_brute_button.setEnabled(False)
            self.stop_brute_button.setEnabled(False)
            self.log("Info", "Brute-force stopped by user")

    def on_scan_started(self):
        self.dashboard_tab.add_activity("System", 0, "Scan started")
        self.status_bar.showMessage("Scan in progress...")

    def start_scan(self):
        target = self.target_input.text().strip()
        port = self.port_input.text().strip()
        scan_tool = self.scan_tool_combo.currentText()
        scan_speed = self.scan_speed_combo.currentText()
        
        if not target:
            self.log("Error", "Please enter a target")
            return
        if not port:
            self.log("Error", "Please enter port(s) to scan")
            return
        if not validate_ports(port):
            self.log("Error", "Invalid port range format!")
            return
            
        all_targets = []
        if os.path.isfile(target):
            try:
                with open(target, 'r') as f:
                    all_targets = [line.strip() for line in f if line.strip()]
            except Exception as e:
                self.log("Error", f"Cannot read target file: {str(e)}")
                return
        else:
            all_targets = [t.strip() for t in target.split(',') if t.strip()]
        if not all_targets:
            self.log("Error", "No valid targets found")
            return
            
        self.log("Info", f"Starting scan for {len(all_targets)} targets...")
        self.on_scan_started()
        self.is_scanning = True
        self.scan_paused = False
        self.scan_button.setText("Stop Scan")
        self.pause_button.setEnabled(True)
        self.stop_button.setEnabled(True)
        self.result_list.clear()
        self.scan_results = []
        self.scan_progress_manager = ProgressManager(len(all_targets))
        
        nmap_path = self.find_nmap()
        masscan_path = self.find_masscan()
        
        # Check tool paths
        if scan_tool == "Nmap" and not nmap_path:
            self.log("Error", "Nmap not found! Please install Nmap and add it to PATH.")
            self.stop_scan()
            return
        if scan_tool == "Masscan" and not masscan_path:
            self.log("Error", "Masscan not found! Please install Masscan and add it to PATH.")
            self.stop_scan()
            return
            
        scanner = NetworkScanner(nmap_path, masscan_path, self.log)
        self.scan_thread = threading.Thread(
            target=self.run_scan,
            args=(scanner, all_targets, port, scan_tool, scan_speed)
        )
        self.scan_thread.daemon = True
        self.scan_thread.start()
        self.progress_timer = QTimer()
        self.progress_timer.timeout.connect(self.update_scan_progress)
        self.progress_timer.start(1000)

    def run_scan(self, scanner, targets, port, scan_tool, scan_speed):
        for target in targets:
            if not self.is_scanning:
                break
            while self.scan_paused and self.is_scanning:
                time.sleep(0.5)
            try:
                results = scanner.scan_network(target, port, scan_tool, scan_speed)
                if results:
                    self.scan_results.extend(results)
                    self.scan_update_signal.emit(results)
            except Exception as e:
                self.log("Error", f"Error scanning {target}: {str(e)}")
        self.scan_complete_signal.emit()

    def update_scan_progress(self):
        if self.scan_progress_manager:
            progress = self.scan_progress_manager.get_progress()
            if progress["total_targets"] > 0:
                percent = (progress["completed_targets"] / progress["total_targets"]) * 100
            else:
                percent = 0
                
            self.scan_progress.setValue(int(percent))
            dashboard_stats = {
                "total_targets": progress["total_targets"],
                "scanned_targets": progress["completed_targets"],
                "remaining_targets": progress["remaining_targets"],
                "open_services": progress["open_ports"],
                "brute_success": 0,
                "ip_progress": int(percent),
                "scanned_ips": progress["completed_targets"],
                "total_ips": progress["total_targets"],
                "current_target": progress["completed_list"][-1] if progress["completed_list"] else "None"
            }
            self.dashboard_tab.update_stats(dashboard_stats)
            if progress["completed_list"]:
                last_target = progress["completed_list"][-1]
                self.dashboard_tab.add_activity(
                    last_target,
                    self.port_input.text(),
                    f"Scan completed, found {progress['service_distribution']}"
                )

    def update_result_list(self, results):
        for ip, port, service in results:
            item_text = f"{ip}:{port} ({service})"
            item = QListWidgetItem(item_text)
            item.setData(Qt.UserRole, (ip, port, service))
            self.result_list.addItem(item)

    def stop_scan(self):
        self.is_scanning = False
        self.scan_button.setText("Start Scan")
        self.pause_button.setEnabled(False)
        self.stop_button.setEnabled(False)
        self.log("Info", "Scan stopped by user")
        if hasattr(self, 'progress_timer') and self.progress_timer.isActive():
            self.progress_timer.stop()

    def save_scan_results(self):
        results_dir = "results"
        os.makedirs(results_dir, exist_ok=True)
        service_results = {}
        for ip, port, service in self.scan_results:
            if service not in service_results:
                service_results[service] = []
            service_results[service].append((ip, port))
        date_str = datetime.now().strftime("%Y%m%d")
        for service, results in service_results.items():
            filename = f"{service}_{date_str}.csv"
            filepath = os.path.join(results_dir, filename)
            with open(filepath, 'w', newline='') as csvfile:
                writer = csv.writer(csvfile)
                writer.writerow(["IP Address", "Port", "Service"])
                for ip, port in results:
                    writer.writerow([ip, port, service])
            self.log("Info", f"Saved {len(results)} {service} results to {filename}")

    def on_scan_complete(self):
        self.is_scanning = False
        self.scan_button.setText("Start Scan")
        self.pause_button.setEnabled(False)
        self.stop_button.setEnabled(False)
        self.log("Info", "Scan completed successfully")
        self.save_scan_results()
        if hasattr(self, 'progress_timer') and self.progress_timer.isActive():
            self.progress_timer.stop()

    def on_brute_started(self):
        self.dashboard_tab.add_activity("System", 0, "Brute-force started")
        self.status_bar.showMessage("Brute-force in progress...")

    def start_brute_force(self):
        selected_items = self.result_list.selectedItems()
        if not selected_items:
            self.log("Warning", "Please select at least one target from the list")
            return

        selected_items = sorted(selected_items, key=lambda i: i.data(Qt.UserRole)[2])
        
        tool = self.brute_tool_combo.currentText()
        brute_speed = self.brute_speed_combo.currentText()
        use_pth = self.pth_checkbox.isChecked()
        hash_format = self.hash_format_combo.currentText() if use_pth else ""
        
        self.brute_executor = ParallelExecutor(max_threads=5, log_function=self.log)
        
        for item in selected_items:
            ip, port, service = item.data(Qt.UserRole)
            
            # PtH/PtT only supported for RDP and SMB
            if use_pth and service not in ["RDP", "SMB"]:
                self.log("Warning", f"PtH/PtT only supported for RDP and SMB, skipping {service}")
                continue
            
            if tool == "Impacket":
                impacket_path = self.settings.value("impacket_path", "")
                if not impacket_path or not os.path.isdir(impacket_path):
                    self.log("Error", "Impacket path not configured or invalid")
                    return
                
                # Add Impacket path to PATH
                os.environ["PATH"] += os.pathsep + impacket_path
                
                if not check_impacket_installed():
                    self.log("Error", "Impacket not found. Please install and configure path.")
                    return
            
            cmd = None
            if tool == "Hydra":
                cmd = self.build_hydra_command(service, ip, port, brute_speed, use_pth)
            elif tool == "Ncrack":
                cmd = self.build_ncrack_command(service, ip, port, brute_speed, use_pth)
            elif tool == "Impacket":
                cmd = self.build_impacket_command(service, ip, port, brute_speed, use_pth, hash_format)
            else:
                self.log("Error", f"Unknown brute tool: {tool}")
                continue
            
            if cmd:
                target_id = f"{ip}:{port}:{service}"
                self.brute_executor.add_task(target_id, cmd, service)
                self.log("Info", f"Added {target_id} to brute-force queue with {tool}")

        if self.brute_executor.task_queue.empty():
            self.log("Warning", "No valid brute-force tasks created")
            return
            
        self.on_brute_started()
        self.brute_executor.start()
        self.brute_button.setEnabled(False)
        self.pause_brute_button.setEnabled(True)
        self.stop_brute_button.setEnabled(True)
        self.dashboard_tab.update_parallel_status(
            self.brute_executor.active_threads, 
            self.brute_executor.task_queue.qsize()
        )
        self.brute_thread = threading.Thread(target=self.monitor_brute_progress)
        self.brute_thread.daemon = True
        self.brute_thread.start()

    def build_hydra_command(self, service, ip, port, speed, use_pth):
        settings = QSettings("NetworkScanner", "Config")
        hydra_path = settings.value("hydra_path", "hydra")
        cmd = [hydra_path]
        
        # Adjust brute-force speed
        if speed == "Slow (Stealth)":
            cmd.extend(["-t", "1", "-w", "10"])
        elif speed == "Normal":
            cmd.extend(["-t", "4", "-w", "5"])
        elif speed == "Fast":
            cmd.extend(["-t", "8", "-w", "3"])
        elif speed == "Aggressive":
            cmd.extend(["-t", "16", "-w", "1"])
        
        # PtH for SMB and RDP
        if use_pth:
            hash_file = self.get_hash_file()
            if not hash_file:
                return None
                
            if service == "SMB":
                cmd.extend(["-V", "-l", "' '", "-p", f"hash:{hash_file}", f"smb://{ip}"])
                return cmd
            elif service == "RDP":
                cmd.extend(["-V", "-l", "' '", "-p", f"hash:{hash_file}", f"rdp://{ip}"])
                return cmd
        
        # Regular brute-force
        user_file, pass_file = self.get_wordlists(service)
        if not user_file or not pass_file:
            return None
            
        # Sử dụng password predictor
        predictor = PasswordPredictor()
        industry = self.get_target_industry(ip)
        country = self.get_target_country(ip)
        
        # Tạo wordlist động
        base_wordlist = predictor.predict_wordlist(industry, country)
        if not base_wordlist or not os.path.isfile(base_wordlist):
            self.log("Warning", f"Predicted wordlist not found: {base_wordlist}, using default")
            base_wordlist = os.path.join(WORDLISTS_DIR, "common_passwords.txt")
        
        dynamic_wordlist = predictor.generate_dynamic_wordlist(
            base_wordlist, 
            industry, 
            country
        )
        
        cmd.extend(["-L", user_file, "-P", dynamic_wordlist])
        
        if service == "SSH":
            cmd.append(f"ssh://{ip}")
        elif service == "FTP":
            cmd.append(f"ftp://{ip}")
        elif service == "RDP":
            cmd.append(f"rdp://{ip}")
        elif service in ("HTTP", "HTTPS"):
            cmd.append(f"http-get://{ip}")
        elif service == "SMB":
            cmd.append(f"smb://{ip}")
        else:
            self.log("Warning", f"Brute-force with Hydra not supported for {service}")
            return None
        
        return cmd

    def build_ncrack_command(self, service, ip, port, speed, use_pth):
        settings = QSettings("NetworkScanner", "Config")
        ncrack_path = settings.value("ncrack_path", "ncrack")
        cmd = [ncrack_path]
        
        # Adjust brute-force speed
        if speed == "Slow (Stealth)":
            cmd.extend(["-T", "1", "--connection-limit", "1"])
        elif speed == "Normal":
            cmd.extend(["-T", "3", "--connection-limit", "3"])
        elif speed == "Fast":
            cmd.extend(["-T", "4", "--connection-limit", "5"])
        elif speed == "Aggressive":
            cmd.extend(["-T", "5", "--connection-limit", "10"])
        
        # PtH not supported in Ncrack
        if use_pth:
            self.log("Warning", "PtH/PtT not supported with Ncrack, using regular auth")
        
        user_file, pass_file = self.get_wordlists(service)
        if not user_file or not pass_file:
            return None
            
        cmd.extend(["-U", user_file, "-P", pass_file])
        
        if service == "SSH":
            cmd.append(f"ssh://{ip}:{port}")
        elif service == "FTP":
            cmd.append(f"ftp://{ip}:{port}")
        elif service == "RDP":
            cmd.append(f"rdp://{ip}:{port}")
        elif service in ("HTTP", "HTTPS"):
            cmd.append(f"http://{ip}:{port}")
        elif service == "SMB":
            cmd.append(f"smb://{ip}:{port}")
        else:
            self.log("Warning", f"Brute-force with Ncrack not supported for {service}")
            return None
        
        return cmd

    def build_impacket_command(self, service, ip, port, speed, use_pth, hash_format):
        settings = QSettings("NetworkScanner", "Config")
        impacket_path = settings.value("impacket_path", "")
        python_path = settings.value("python_path", "python")
        
        if not impacket_path:
            self.log("Error", "Impacket path not configured")
            return None
            
        cmd = [python_path]
        
        if use_pth:
            # Require hash file instead of password
            hash_file = self.get_hash_file()
            if not hash_file:
                return None
                
            if service == "SMB":
                if hash_format == "Kerberos":
                    cmd.extend(["-m", "impacket.examples.secretsdump", "-k", ip])
                else:
                    cmd.extend(["-m", "impacket.examples.smbexec", 
                               f"{ip}", 
                               "-hashes", hash_file,
                               "-no-pass"])
            elif service == "RDP":
                cmd.extend(["-m", "impacket.examples.rdp_check", 
                           f"{ip}", 
                           "-hashes", hash_file])
            else:
                self.log("Warning", f"PtH with Impacket not supported for {service}")
                return None
        else:
            # Regular brute-force
            user_file, pass_file = self.get_wordlists(service)
            if not user_file or not pass_file:
                return None
                
            if service == "SMB":
                cmd.extend(["-m", "impacket.examples.smbbrute", 
                           f"{ip}", 
                           "-users", user_file,
                           "-passwords", pass_file])
            elif service == "RDP":
                cmd.extend(["-m", "impacket.examples.rdp_brute", 
                           f"{ip}", 
                           "-users", user_file,
                           "-passwords", pass_file])
            else:
                self.log("Warning", f"Brute-force with Impacket not supported for {service}")
                return None
        
        # Add timeout based on speed
        if speed == "Slow (Stealth)":
            cmd.extend(["--timeout", "10"])
        elif speed == "Normal":
            cmd.extend(["--timeout", "5"])
        elif speed == "Fast":
            cmd.extend(["--timeout", "2"])
        elif speed == "Aggressive":
            cmd.extend(["--timeout", "1"])
        
        return cmd

    def get_target_industry(self, ip):
        # TODO: Triển khai thực tế, hiện trả về giá trị mặc định
        return "technology"

    def get_target_country(self, ip):
        # TODO: Triển khai thực tế, hiện trả về giá trị mặc định
        return "us"

    def get_wordlists(self, service):
        settings = QSettings("NetworkScanner", "Config")
        user_file = settings.value(f"{service}_users", "")
        pass_file = settings.value(f"{service}_passwords", "")
        
        if not user_file or not os.path.isfile(user_file):
            user_file, _ = QFileDialog.getOpenFileName(
                self, 
                f"Select Username Wordlist for {service}",
                WORDLISTS_DIR,
                "Text Files (*.txt);;All Files (*)"
            )
            if not user_file:
                self.log("Warning", f"No username wordlist selected for {service}")
                return None, None
            settings.setValue(f"{service}_users", user_file)
            
        if not pass_file or not os.path.isfile(pass_file):
            pass_file, _ = QFileDialog.getOpenFileName(
                self, 
                f"Select Password Wordlist for {service}",
                WORDLISTS_DIR,
                "Text Files (*.txt);;All Files (*)"
            )
            if not pass_file:
                self.log("Warning", f"No password wordlist selected for {service}")
                return None, None
            settings.setValue(f"{service}_passwords", pass_file)
            
        return user_file, pass_file

    def get_hash_file(self):
        hash_file, _ = QFileDialog.getOpenFileName(
            self, 
            "Select Hash File",
            WORDLISTS_DIR,
            "Text Files (*.txt);;All Files (*)"
        )
        return hash_file

    def brute_force_from_file(self, tool="Hydra", speed="Normal", use_pth=False, hash_format="", file_path=None):
        if not file_path:
            file_path, _ = QFileDialog.getOpenFileName(
                self, "Select Brute-force Target File", "", 
                "Text Files (*.txt *.csv);;All Files (*)"
            )
        if not file_path:
            return
            
        targets = []
        import csv as csvmod
        ext = os.path.splitext(file_path)[1].lower()
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                if ext == ".csv":
                    reader = csvmod.reader(f)
                    for row in reader:
                        if len(row) >= 2:
                            ip = row[0].strip()
                            port = row[1].strip()
                            service = row[2].strip() if len(row) >= 3 else None
                            targets.append((ip, port, service))
                else:  # txt file
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        # Try formats: ip:port:service, ip,port,service
                        if ':' in line:
                            parts = line.split(':', 2)
                        elif ',' in line:
                            parts = line.split(',', 2)
                        else:
                            continue
                        if len(parts) < 2:
                            continue
                        ip = parts[0].strip()
                        port = parts[1].strip()
                        service = parts[2].strip() if len(parts) > 2 else None
                        targets.append((ip, port, service))
        except Exception as e:
            self.log("Error", f"Cannot read file: {str(e)}")
            return
        
        if not targets:
            self.log("Warning", "No valid brute-force targets in file.")
            return
            
        seen = set()
        unique_targets = []
        for t in targets:
            key = (t[0], t[1], t[2] or "")
            if key not in seen:
                seen.add(key)
                unique_targets.append(t)
                
        self.log("Info", f"Loaded {len(unique_targets)} unique brute-force targets from file.")
        
        self.brute_executor = ParallelExecutor(max_threads=5, log_function=self.log)
        
        for ip, port, service in unique_targets:
            if not service:
                service = self.deduce_service_from_port(port)
            if not service:
                self.log("Warning", f"Cannot detect service for {ip}:{port}, skipping")
                continue
                
            # PtH/PtT only supported for RDP and SMB
            if use_pth and service not in ["RDP", "SMB"]:
                self.log("Warning", f"PtH/PtT only supported for RDP and SMB, skipping {service}")
                continue
            
            cmd = None
            if tool == "Hydra":
                cmd = self.build_hydra_command(service, ip, port, speed, use_pth)
            elif tool == "Ncrack":
                cmd = self.build_ncrack_command(service, ip, port, speed, use_pth)
            elif tool == "Impacket":
                cmd = self.build_impacket_command(service, ip, port, speed, use_pth, hash_format)
                
            if cmd:
                target_id = f"{ip}:{port}:{service}"
                self.brute_executor.add_task(target_id, cmd, service)
                self.log("Info", f"Added {target_id} to brute-force queue with {tool}")
                
                # Update results table in brute file tab
                row = self.brute_file_tab.results_table.rowCount()
                self.brute_file_tab.results_table.insertRow(row)
                self.brute_file_tab.results_table.setItem(row, 0, QTableWidgetItem(ip))
                self.brute_file_tab.results_table.setItem(row, 1, QTableWidgetItem(port))
                self.brute_file_tab.results_table.setItem(row, 2, QTableWidgetItem(service))
                self.brute_file_tab.results_table.setItem(row, 3, QTableWidgetItem("Pending"))
                self.brute_file_tab.results_table.setItem(row, 4, QTableWidgetItem(""))
                
        if self.brute_executor.task_queue.empty():
            self.log("Warning", "No valid brute-force tasks created from file")
            return
            
        self.on_brute_started()
        self.brute_executor.start()
        self.dashboard_tab.update_parallel_status(
            self.brute_executor.active_threads, 
            self.brute_executor.task_queue.qsize()
        )
        self.brute_thread = threading.Thread(target=self.monitor_brute_progress)
        self.brute_thread.daemon = True
        self.brute_thread.start()

    def deduce_service_from_port(self, port):
        well_known = {
            "22": "SSH",
            "21": "FTP",
            "3389": "RDP",
            "445": "SMB",
            "80": "HTTP",
            "443": "HTTPS",
            "25": "SMTP",
            "110": "POP3",
            "143": "IMAP",
            "3306": "MYSQL",
            "5432": "POSTGRESQL",
            "5900": "VNC"
        }
        return well_known.get(str(port), "Unknown")

    def is_valid_ip_port(self, ip, port):
        try:
            octets = [int(x) for x in ip.split(".")]
            if len(octets) != 4 or not all(0 <= x < 256 for x in octets):
                return False
            port = int(port)
            return 1 <= port <= 65535
        except Exception:
            return False

    def monitor_brute_progress(self):
        try:
            results = self.brute_executor.wait_completion()
            self.brute_complete_signal.emit()
            success_count = 0
            
            # Update results in brute file tab
            for i in range(self.brute_file_tab.results_table.rowCount()):
                ip = self.brute_file_tab.results_table.item(i, 0).text()
                port = self.brute_file_tab.results_table.item(i, 1).text()
                service = self.brute_file_tab.results_table.item(i, 2).text()
                target_id = f"{ip}:{port}:{service}"
                
                result = results.get(target_id, {})
                if result.get("success", False):
                    credentials = result.get("credentials", [])
                    if credentials:
                        cred_text = ", ".join(credentials)
                        self.brute_file_tab.results_table.setItem(i, 3, QTableWidgetItem("Success"))
                        self.brute_file_tab.results_table.setItem(i, 4, QTableWidgetItem(cred_text))
                        success_count += len(credentials)
                        # Highlight success row
                        for col in range(5):
                            if self.brute_file_tab.results_table.item(i, col):
                                self.brute_file_tab.results_table.item(i, col).setBackground(QColor(50, 120, 50))
                    else:
                        self.brute_file_tab.results_table.setItem(i, 3, QTableWidgetItem("Success (no creds)"))
                else:
                    self.brute_file_tab.results_table.setItem(i, 3, QTableWidgetItem("Failed"))
                    # Highlight failure row
                    for col in range(5):
                        if self.brute_file_tab.results_table.item(i, col):
                            self.brute_file_tab.results_table.item(i, col).setBackground(QColor(120, 50, 50))
            
            # Update progress bar
            self.brute_file_tab.progress_bar.setValue(100)
            
            # Update dashboard
            stats = self.dashboard_tab.stats.copy()
            stats["brute_success"] = stats.get("brute_success", 0) + success_count
            self.dashboard_tab.update_stats(stats)
            self.dashboard_tab.update_parallel_status(0, 0)
        except Exception as e:
            self.log("Error", f"Error monitoring brute-force: {str(e)}")

    def on_brute_complete(self):
        self.brute_button.setEnabled(True)
        self.pause_brute_button.setEnabled(False)
        self.stop_brute_button.setEnabled(False)
        self.status_bar.showMessage("Brute-force completed", 5000)

    def log(self, source, message):
        try:
            with QMutexLocker(self.log_mutex):
                timestamp = time.strftime("%H:%M:%S")
                row_position = self.log_area.rowCount()
                self.log_area.insertRow(row_position)
                self.log_area.setItem(row_position, 0, QTableWidgetItem(timestamp))
                self.log_area.setItem(row_position, 1, QTableWidgetItem(source))
                self.log_area.setItem(row_position, 2, QTableWidgetItem(message))
                self.log_area.scrollToBottom()
                if "success" in message.lower() or "error" in message.lower() or "warning" in message.lower():
                    ip = "System"
                    if "://" in message:
                        parts = message.split("://")
                        if len(parts) > 1:
                            ip = parts[1].split('/')[0].split(':')[0]
                    self.dashboard_tab.add_activity(ip, "N/A", message)
        except Exception as e:
            print(f"Logging error: {str(e)}")

    def find_nmap(self):
        if sys.platform == "win32":
            nmap_exe = "nmap.exe"
        else:
            nmap_exe = "nmap"
        for path in os.environ["PATH"].split(os.pathsep):
            full_path = os.path.join(path, nmap_exe)
            if os.path.isfile(full_path):
                return full_path
        common_paths = [
            "/usr/bin/nmap",
            "/usr/local/bin/nmap",
            "C:\\Program Files (x86)\\Nmap\\nmap.exe",
            "C:\\Program Files\\Nmap\\nmap.exe"
        ]
        for path in common_paths:
            if os.path.isfile(path):
                return path
        return None

    def find_masscan(self):
        base_dir = os.path.dirname(os.path.abspath(__file__))
        if sys.platform == "win32":
            exe_name = "masscan.exe"
            common_paths = [
                os.path.join(base_dir, "masscan", exe_name),
                "C:\\Program Files\\Masscan\\masscan.exe",
                "C:\\Program Files (x86)\\Masscan\\masscan.exe",
                "C:\\masscan\\masscan.exe"
            ]
            for path in os.environ["PATH"].split(os.pathsep):
                full_path = os.path.join(path, exe_name)
                if os.path.isfile(full_path):
                    return full_path
        else:
            exe_name = "masscan"
            common_paths = [
                os.path.join(base_dir, "masscan", exe_name),
                os.path.join(base_dir, "masscan", "masscan.exe"),
                "/usr/bin/masscan",
                "/usr/local/bin/masscan"
            ]
            for path in os.environ.get("PATH", "").split(os.pathsep):
                full_path = os.path.join(path, exe_name)
                if os.path.isfile(full_path):
                    return full_path

        for path in common_paths:
            if os.path.isfile(path):
                return path

        return None

    def closeEvent(self, event):
        if self.is_scanning:
            self.stop_scan()
            reply = QMessageBox.question(self, "Scan in Progress",
                                         "Scan was stopped. Are you sure you want to exit?",
                                         QMessageBox.Yes | QMessageBox.No)
            if reply == QMessageBox.No:
                event.ignore()
                return
        if self.brute_executor and self.brute_executor.active_threads > 0:
            self.brute_executor.stop()
            reply = QMessageBox.question(self, "Brute-force in Progress",
                                         "Brute-force was stopped. Are you sure you want to exit?",
                                         QMessageBox.Yes | QMessageBox.No)
            if reply == QMessageBox.No:
                event.ignore()
                return
        if self.scan_thread and self.scan_thread.is_alive():
            self.scan_thread.join(1.0)
        if self.brute_thread and self.brute_thread.is_alive():
            self.brute_thread.join(1.0)
        event.accept()
