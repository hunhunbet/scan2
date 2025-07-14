from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGridLayout, QLabel, QLineEdit,
    QPushButton, QTableWidget, QTableWidgetItem, QHeaderView, QGroupBox,
    QProgressBar, QComboBox, QCheckBox, QFileDialog, QMessageBox
)
from PyQt5.QtCore import Qt, QSettings
from PyQt5.QtGui import QColor, QFont
import os
import csv

class BruteForceFileTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent = parent
        self.log = parent.log if parent else print
        self.targets = []
        self.brute_executor = None
        self.brute_thread = None
        self.brute_paused = False
        self.init_ui()
        
    def init_ui(self):
        main_layout = QVBoxLayout()
        main_layout.setSpacing(15)
        
        # File Selection Section
        file_group = QGroupBox("Target File")
        file_layout = QGridLayout()
        
        file_layout.addWidget(QLabel("File Path:"), 0, 0)
        self.file_path_input = QLineEdit()
        self.file_path_input.setPlaceholderText("Select a file containing targets...")
        file_layout.addWidget(self.file_path_input, 0, 1)
        
        self.browse_button = QPushButton("Browse...")
        self.browse_button.clicked.connect(self.browse_target_file)
        file_layout.addWidget(self.browse_button, 0, 2)
        
        file_group.setLayout(file_layout)
        main_layout.addWidget(file_group)
        
        # Preview Section
        preview_group = QGroupBox("File Preview")
        preview_layout = QVBoxLayout()
        
        self.preview_table = QTableWidget()
        self.preview_table.setColumnCount(3)
        self.preview_table.setHorizontalHeaderLabels(["IP Address", "Port", "Service"])
        self.preview_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.preview_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.preview_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.preview_table.verticalHeader().setVisible(False)
        self.preview_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.preview_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.preview_table.setMinimumHeight(200)
        
        preview_layout.addWidget(self.preview_table)
        preview_group.setLayout(preview_layout)
        main_layout.addWidget(preview_group)
        
        # Configuration Section
        config_group = QGroupBox("Brute-force Configuration")
        config_layout = QGridLayout()
        
        # Tool Selection
        config_layout.addWidget(QLabel("Brute Tool:"), 0, 0)
        self.brute_tool_combo = QComboBox()
        self.brute_tool_combo.addItems(["Hydra", "Ncrack", "Impacket"])
        self.brute_tool_combo.currentIndexChanged.connect(self.update_brute_options)
        config_layout.addWidget(self.brute_tool_combo, 0, 1)
        
        # Speed
        config_layout.addWidget(QLabel("Brute Speed:"), 1, 0)
        self.brute_speed_combo = QComboBox()
        self.brute_speed_combo.addItems(["Slow (Stealth)", "Normal", "Fast", "Aggressive"])
        config_layout.addWidget(self.brute_speed_combo, 1, 1)
        
        # PtH Option
        self.pth_checkbox = QCheckBox("Use Pass-the-Hash (PtH) / Pass-the-Ticket (PtT)")
        self.pth_checkbox.stateChanged.connect(self.update_brute_options)
        config_layout.addWidget(self.pth_checkbox, 2, 0, 1, 2)
        
        # Hash format
        self.hash_format_label = QLabel("Hash Format:")
        self.hash_format_combo = QComboBox()
        self.hash_format_combo.addItems(["LM:NT", "NT", "Kerberos"])
        config_layout.addWidget(self.hash_format_label, 3, 0)
        config_layout.addWidget(self.hash_format_combo, 3, 1)
        self.hash_format_label.setVisible(False)
        self.hash_format_combo.setVisible(False)
        
        config_group.setLayout(config_layout)
        main_layout.addWidget(config_group)
        
        # Execution Controls
        control_layout = QHBoxLayout()
        self.execute_button = QPushButton("Start Brute-force")
        self.execute_button.clicked.connect(self.start_brute_force)
        control_layout.addWidget(self.execute_button)
        
        self.pause_button = QPushButton("Pause")
        self.pause_button.clicked.connect(self.toggle_pause_brute)
        self.pause_button.setEnabled(False)
        control_layout.addWidget(self.pause_button)
        
        self.stop_button = QPushButton("Stop")
        self.stop_button.clicked.connect(self.stop_brute_force)
        self.stop_button.setEnabled(False)
        control_layout.addWidget(self.stop_button)
        
        main_layout.addLayout(control_layout)
        
        # Progress Section
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setTextVisible(True)
        main_layout.addWidget(self.progress_bar)
        
        # Results Section
        results_group = QGroupBox("Brute-force Results")
        results_layout = QVBoxLayout()
        
        self.results_table = QTableWidget()
        self.results_table.setColumnCount(5)
        self.results_table.setHorizontalHeaderLabels(["Target", "Port", "Service", "Status", "Credentials"])
        self.results_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.results_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.results_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.results_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.results_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.Stretch)
        self.results_table.verticalHeader().setVisible(False)
        self.results_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.results_table.setMinimumHeight(200)
        
        results_layout.addWidget(self.results_table)
        results_group.setLayout(results_layout)
        main_layout.addWidget(results_group)
        
        self.setLayout(main_layout)
    
    def update_brute_options(self):
        tool = self.brute_tool_combo.currentText()
        use_pth = self.pth_checkbox.isChecked()
        is_impacket_pth = (tool == "Impacket" and use_pth)
        self.hash_format_label.setVisible(is_impacket_pth)
        self.hash_format_combo.setVisible(is_impacket_pth)
    
    def browse_target_file(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select Brute-force Target File", "", 
            "Text Files (*.txt *.csv);;All Files (*)"
        )
        if file_path:
            self.file_path_input.setText(file_path)
            self.load_file_preview(file_path)
    
    def load_file_preview(self, file_path):
        self.preview_table.setRowCount(0)
        self.targets = []
        
        ext = os.path.splitext(file_path)[1].lower()
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                if ext == ".csv":
                    reader = csv.reader(f)
                    for row in reader:
                        if len(row) >= 2:
                            ip = row[0].strip()
                            port = row[1].strip()
                            service = row[2].strip() if len(row) >= 3 else None
                            self.targets.append((ip, port, service))
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
                        self.targets.append((ip, port, service))
        except Exception as e:
            self.log("Error", f"Cannot read file: {str(e)}")
            return
        
        # Display in preview table
        self.preview_table.setRowCount(len(self.targets))
        for row, (ip, port, service) in enumerate(self.targets):
            self.preview_table.setItem(row, 0, QTableWidgetItem(ip))
            self.preview_table.setItem(row, 1, QTableWidgetItem(port))
            self.preview_table.setItem(row, 2, QTableWidgetItem(service if service else "Unknown"))
    
    def start_brute_force(self):
        if not self.targets:
            QMessageBox.warning(self, "No Targets", "Please load a valid target file first.")
            return
        
        tool = self.brute_tool_combo.currentText()
        speed = self.brute_speed_combo.currentText()
        use_pth = self.pth_checkbox.isChecked()
        hash_format = self.hash_format_combo.currentText() if use_pth else ""
        
        # Call parent's brute_force_from_file method
        self.parent.brute_force_from_file(tool, speed, use_pth, hash_format, self.file_path_input.text())
        
        # Update UI
        self.execute_button.setEnabled(False)
        self.pause_button.setEnabled(True)
        self.stop_button.setEnabled(True)
        self.progress_bar.setValue(0)
        self.results_table.setRowCount(0)
    
    def toggle_pause_brute(self):
        self.brute_paused = not self.brute_paused
        if self.brute_paused:
            self.pause_button.setText("Resume")
            self.log("Info", "Brute-force paused")
        else:
            self.pause_button.setText("Pause")
            self.log("Info", "Brute-force resumed")
    
    def stop_brute_force(self):
        if self.parent.brute_executor:
            self.parent.brute_executor.stop()
            self.execute_button.setEnabled(True)
            self.pause_button.setEnabled(False)
            self.stop_button.setEnabled(False)
            self.log("Info", "Brute-force stopped by user")