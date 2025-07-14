from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QGridLayout, QLabel, QLineEdit, 
    QPushButton, QGroupBox
)
from PyQt5.QtCore import QSettings
import os

class SettingsTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.settings = QSettings("NetworkScanner", "Config")
        self.init_ui()
        self.load_settings()

    def init_ui(self):
        layout = QVBoxLayout()
        
        # Tool Paths
        tool_group = QGroupBox("Tool Paths")
        tool_layout = QGridLayout()
        
        tool_layout.addWidget(QLabel("Nmap Path:"), 0, 0)
        self.nmap_path_edit = QLineEdit()
        tool_layout.addWidget(self.nmap_path_edit, 0, 1)
        
        self.nmap_browse_btn = QPushButton("Browse...")
        self.nmap_browse_btn.clicked.connect(lambda: self.browse_path(self.nmap_path_edit))
        tool_layout.addWidget(self.nmap_browse_btn, 0, 2)
        
        tool_layout.addWidget(QLabel("Hydra Path:"), 1, 0)
        self.hydra_path_edit = QLineEdit()
        tool_layout.addWidget(self.hydra_path_edit, 1, 1)
        
        self.hydra_browse_btn = QPushButton("Browse...")
        self.hydra_browse_btn.clicked.connect(lambda: self.browse_path(self.hydra_path_edit))
        tool_layout.addWidget(self.hydra_browse_btn, 1, 2)
        
        tool_layout.addWidget(QLabel("Ncrack Path:"), 2, 0)
        self.ncrack_path_edit = QLineEdit()
        tool_layout.addWidget(self.ncrack_path_edit, 2, 1)
        
        self.ncrack_browse_btn = QPushButton("Browse...")
        self.ncrack_browse_btn.clicked.connect(lambda: self.browse_path(self.ncrack_path_edit))
        tool_layout.addWidget(self.ncrack_browse_btn, 2, 2)
        
        tool_layout.addWidget(QLabel("Masscan Path:"), 3, 0)
        self.masscan_path_edit = QLineEdit()
        tool_layout.addWidget(self.masscan_path_edit, 3, 1)
        
        self.masscan_browse_btn = QPushButton("Browse...")
        self.masscan_browse_btn.clicked.connect(lambda: self.browse_path(self.masscan_path_edit))
        tool_layout.addWidget(self.masscan_browse_btn, 3, 2)
        
        tool_layout.addWidget(QLabel("Impacket Path:"), 4, 0)
        self.impacket_path_edit = QLineEdit()
        tool_layout.addWidget(self.impacket_path_edit, 4, 1)
        
        self.impacket_browse_btn = QPushButton("Browse...")
        self.impacket_browse_btn.clicked.connect(lambda: self.browse_path(self.impacket_path_edit))
        tool_layout.addWidget(self.impacket_browse_btn, 4, 2)
        
        tool_layout.addWidget(QLabel("Python Path:"), 5, 0)
        self.python_path_edit = QLineEdit()
        self.python_path_edit.setText("python")  # Default value
        tool_layout.addWidget(self.python_path_edit, 5, 1)
        
        self.python_browse_btn = QPushButton("Browse...")
        self.python_browse_btn.clicked.connect(lambda: self.browse_path(self.python_path_edit))
        tool_layout.addWidget(self.python_browse_btn, 5, 2)
        
        tool_group.setLayout(tool_layout)
        layout.addWidget(tool_group)
        
        # Wordlist Paths
        wordlist_group = QGroupBox("Wordlist Paths")
        wordlist_layout = QGridLayout()
        
        services = ["SSH", "FTP", "RDP", "HTTP", "HTTPS", "SMB", "SMTP", "POP3", "IMAP", "MYSQL", "POSTGRESQL", "VNC"]
        self.wordlist_edits = {}
        
        for i, service in enumerate(services):
            wordlist_layout.addWidget(QLabel(f"{service} Users:"), i, 0)
            user_edit = QLineEdit()
            wordlist_layout.addWidget(user_edit, i, 1)
            
            user_browse = QPushButton("Browse...")
            user_browse.clicked.connect(lambda _, e=user_edit: self.browse_path(e))
            wordlist_layout.addWidget(user_browse, i, 2)
            
            wordlist_layout.addWidget(QLabel(f"{service} Passwords:"), i, 3)
            pass_edit = QLineEdit()
            wordlist_layout.addWidget(pass_edit, i, 4)
            
            pass_browse = QPushButton("Browse...")
            pass_browse.clicked.connect(lambda _, e=pass_edit: self.browse_path(e))
            wordlist_layout.addWidget(pass_browse, i, 5)
            
            self.wordlist_edits[service] = (user_edit, pass_edit)
        
        wordlist_group.setLayout(wordlist_layout)
        layout.addWidget(wordlist_group)
        
        # Save Button
        save_btn = QPushButton("Save Settings")
        save_btn.clicked.connect(self.save_settings)
        layout.addWidget(save_btn)
        
        self.setLayout(layout)

    def browse_path(self, edit_widget):
        path, _ = QFileDialog.getOpenFileName(self, "Select File")
        if path:
            edit_widget.setText(path)

    def load_settings(self):
        self.nmap_path_edit.setText(self.settings.value("nmap_path", ""))
        self.hydra_path_edit.setText(self.settings.value("hydra_path", ""))
        self.ncrack_path_edit.setText(self.settings.value("ncrack_path", ""))
        self.masscan_path_edit.setText(self.settings.value("masscan_path", ""))
        self.impacket_path_edit.setText(self.settings.value("impacket_path", ""))
        self.python_path_edit.setText(self.settings.value("python_path", "python"))
        
        for service, (user_edit, pass_edit) in self.wordlist_edits.items():
            user_edit.setText(self.settings.value(f"{service}_users", ""))
            pass_edit.setText(self.settings.value(f"{service}_passwords", ""))

    def save_settings(self):
        self.settings.setValue("nmap_path", self.nmap_path_edit.text())
        self.settings.setValue("hydra_path", self.hydra_path_edit.text())
        self.settings.setValue("ncrack_path", self.ncrack_path_edit.text())
        self.settings.setValue("masscan_path", self.masscan_path_edit.text())
        self.settings.setValue("impacket_path", self.impacket_path_edit.text())
        self.settings.setValue("python_path", self.python_path_edit.text())
        
        for service, (user_edit, pass_edit) in self.wordlist_edits.items():
            self.settings.setValue(f"{service}_users", user_edit.text())
            self.settings.setValue(f"{service}_passwords", pass_edit.text())