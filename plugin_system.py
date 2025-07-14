import os
import importlib.util
import inspect
from PyQt5.QtWidgets import QAction

class PluginManager:
    def __init__(self, main_window):
        self.main_window = main_window
        self.plugins = {}
        self.plugins_dir = "plugins"
        os.makedirs(self.plugins_dir, exist_ok=True)
    
    def load_plugins(self):
        """Tải tất cả plugin trong thư mục plugins"""
        for filename in os.listdir(self.plugins_dir):
            if filename.endswith(".py"):
                plugin_path = os.path.join(self.plugins_dir, filename)
                self.load_plugin(plugin_path)
    
    def load_plugin(self, plugin_path):
        """Tải một plugin cụ thể"""
        try:
            plugin_name = os.path.basename(plugin_path)[:-3]
            spec = importlib.util.spec_from_file_location(plugin_name, plugin_path)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            
            # Tìm class plugin
            for name, obj in inspect.getmembers(module):
                if inspect.isclass(obj) and name.endswith("Plugin"):
                    plugin_class = obj
                    plugin_instance = plugin_class(self.main_window)
                    self.plugins[plugin_name] = plugin_instance
                    self._integrate_plugin(plugin_instance)
                    self.main_window.log("Info", f"Loaded plugin: {plugin_name}")
                    break
        except Exception as e:
            self.main_window.log("Error", f"Failed to load plugin {plugin_path}: {str(e)}")
    
    def _integrate_plugin(self, plugin):
        """Tích hợp plugin vào giao diện chính"""
        # Thêm action vào menu
        if hasattr(plugin, "get_menu_action"):
            action = plugin.get_menu_action()
            if action:
                plugin_menu = self.main_window.menuBar().addMenu(plugin.name)
                plugin_menu.addAction(action)
        
        # Thêm tab nếu có
        if hasattr(plugin, "get_ui_tab"):
            tab_widget = plugin.get_ui_tab()
            if tab_widget:
                self.main_window.tab_widget.addTab(tab_widget, plugin.name)
        
        # Đăng ký hook
        if hasattr(plugin, "register_hooks"):
            plugin.register_hooks()

class BasePlugin:
    def __init__(self, main_window):
        self.main_window = main_window
        self.name = "Base Plugin"
        self.version = "1.0"
    
    def get_menu_action(self):
        """Trả về action để thêm vào menu"""
        action = QAction(self.name, self.main_window)
        action.triggered.connect(self.show_ui)
        return action
    
    def get_ui_tab(self):
        """Trả về tab UI nếu có"""
        return None
    
    def show_ui(self):
        """Hiển thị giao diện plugin"""
        pass
    
    def register_hooks(self):
        """Đăng ký hook với hệ thống chính"""
        pass

# Ví dụ plugin
class VulnerabilityScannerPlugin(BasePlugin):
    def __init__(self, main_window):
        super().__init__(main_window)
        self.name = "Vulnerability Scanner"
    
    def get_ui_tab(self):
        from PyQt5.QtWidgets import QWidget, QVBoxLayout, QPushButton
        tab = QWidget()
        layout = QVBoxLayout()
        scan_btn = QPushButton("Scan Vulnerabilities")
        scan_btn.clicked.connect(self.run_scan)
        layout.addWidget(scan_btn)
        tab.setLayout(layout)
        return tab
    
    def run_scan(self):
        self.main_window.log("Info", "Running vulnerability scan...")
        # Logic quét lỗ hổng tại đây