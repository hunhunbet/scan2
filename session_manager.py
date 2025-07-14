from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QTableWidget, QTableWidgetItem, 
    QHeaderView, QPushButton, QHBoxLayout, QMenu, QAction
)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QColor

class SessionManager(QWidget):
    def __init__(self, main_window):
        super().__init__()
        self.main_window = main_window
        self.sessions = {}
        self.init_ui()
    
    def init_ui(self):
        layout = QVBoxLayout()
        
        # Bảng session
        self.session_table = QTableWidget()
        self.session_table.setColumnCount(7)
        self.session_table.setHorizontalHeaderLabels([
            "ID", "Target", "Service", "Tool", "Status", 
            "Credentials", "Actions"
        ])
        self.session_table.horizontalHeader().setSectionResizeMode(6, QHeaderView.Stretch)
        self.session_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.session_table.customContextMenuRequested.connect(self.show_context_menu)
        layout.addWidget(self.session_table)
        
        # Nút điều khiển
        control_layout = QHBoxLayout()
        self.kill_btn = QPushButton("Kill Session")
        self.kill_btn.clicked.connect(self.kill_selected_session)
        self.refresh_btn = QPushButton("Refresh")
        self.refresh_btn.clicked.connect(self.refresh_sessions)
        control_layout.addWidget(self.kill_btn)
        control_layout.addWidget(self.refresh_btn)
        layout.addLayout(control_layout)
        
        self.setLayout(layout)
    
    def add_session(self, session_id, target, service, tool, status="Running", credentials=""):
        """Thêm một session mới vào bảng"""
        self.sessions[session_id] = {
            "target": target,
            "service": service,
            "tool": tool,
            "status": status,
            "credentials": credentials
        }
        
        row = self.session_table.rowCount()
        self.session_table.insertRow(row)
        
        self.session_table.setItem(row, 0, QTableWidgetItem(session_id))
        self.session_table.setItem(row, 1, QTableWidgetItem(target))
        self.session_table.setItem(row, 2, QTableWidgetItem(service))
        self.session_table.setItem(row, 3, QTableWidgetItem(tool))
        self.session_table.setItem(row, 4, QTableWidgetItem(status))
        self.session_table.setItem(row, 5, QTableWidgetItem(credentials))
        
        action_btn = QPushButton("Manage")
        action_btn.clicked.connect(lambda: self.manage_session(session_id))
        self.session_table.setCellWidget(row, 6, action_btn)
        
        # Tô màu dựa trên trạng thái
        self.update_row_color(row, status)
    
    def update_row_color(self, row, status):
        """Cập nhật màu dòng dựa trên trạng thái session"""
        if status == "Success":
            color = QColor(220, 255, 220)  # Xanh nhạt
        elif status == "Failed":
            color = QColor(255, 220, 220)  # Đỏ nhạt
        elif status == "Running":
            color = QColor(255, 255, 200)  # Vàng nhạt
        else:
            color = QColor(255, 255, 255)  # Trắng
        
        for col in range(self.session_table.columnCount()):
            if self.session_table.item(row, col):
                self.session_table.item(row, col).setBackground(color)
    
    def manage_session(self, session_id):
        """Quản lý session cụ thể"""
        session = self.sessions.get(session_id)
        if session:
            # Hiển thị dialog quản lý chi tiết
            from session_dialog import SessionDialog
            dialog = SessionDialog(session, self.main_window)
            dialog.exec_()
    
    def show_context_menu(self, position):
        """Hiển thị menu ngữ cảnh cho session"""
        menu = QMenu()
        
        # Lấy session được chọn
        selected_row = self.session_table.currentRow()
        if selected_row >= 0:
            session_id = self.session_table.item(selected_row, 0).text()
            
            # Tạo actions
            view_action = QAction("View Details", self)
            view_action.triggered.connect(lambda: self.manage_session(session_id))
            
            kill_action = QAction("Kill Session", self)
            kill_action.triggered.connect(lambda: self.kill_session(session_id))
            
            export_action = QAction("Export Results", self)
            export_action.triggered.connect(lambda: self.export_session(session_id))
            
            menu.addAction(view_action)
            menu.addAction(kill_action)
            menu.addAction(export_action)
        
        menu.exec_(self.session_table.viewport().mapToGlobal(position))
    
    def kill_session(self, session_id):
        """Dừng session đang chạy"""
        if session_id in self.sessions:
            # Gửi tín hiệu dừng session
            self.main_window.log("Info", f"Killing session: {session_id}")
            self.sessions[session_id]["status"] = "Terminated"
            
            # Cập nhật UI
            for row in range(self.session_table.rowCount()):
                if self.session_table.item(row, 0).text() == session_id:
                    self.session_table.item(row, 4).setText("Terminated")
                    self.update_row_color(row, "Terminated")
                    break
    
    def export_session(self, session_id):
        """Xuất kết quả session"""
        session = self.sessions.get(session_id)
        if session:
            # Logic xuất kết quả
            self.main_window.log("Info", f"Exporting session: {session_id}")
    
    def refresh_sessions(self):
        """Làm mới danh sách session"""
        self.session_table.setRowCount(0)
        for session_id, data in self.sessions.items():
            self.add_session(
                session_id,
                data["target"],
                data["service"],
                data["tool"],
                data["status"],
                data["credentials"]
            )
    
    def kill_selected_session(self):
        """Dừng session được chọn"""
        selected_row = self.session_table.currentRow()
        if selected_row >= 0:
            session_id = self.session_table.item(selected_row, 0).text()
            self.kill_session(session_id)