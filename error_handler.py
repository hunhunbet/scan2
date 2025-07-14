import traceback
import subprocess

try:
    from PyQt5.QtWidgets import QMessageBox
except Exception:
    QMessageBox = None

class ErrorHandler:
    def __init__(self, log_function):
        self.log = log_function
    
    def handle(self, exception, context=""):
        try:
            error_type = type(exception).__name__
            error_msg = str(exception)
            stack_trace = traceback.format_exc()
            
            self.log("Error", f"{error_type}: {error_msg}")
            self.log("Debug", f"Context: {context}")
            self.log("Debug", f"Stack trace:\n{stack_trace}")
            
            # User-friendly messages
            if isinstance(exception, subprocess.TimeoutExpired):
                self.show_warning("Timeout", "Operation took too long to complete.")
            elif isinstance(exception, subprocess.CalledProcessError):
                self.show_warning("Execution Error", f"Command failed with code {exception.returncode}")
            elif "network" in error_msg.lower() or "connection" in error_msg.lower():
                self.show_warning("Network Error", "Cannot connect to target. Check network and firewall settings.")
            elif "permission" in error_msg.lower() or "access" in error_msg.lower():
                self.show_warning("Permission Error", "Insufficient permissions. Try running as administrator.")
            elif "file" in error_msg.lower() or "directory" in error_msg.lower():
                self.show_warning("File Error", "File or directory not found. Please check the path.")
            elif "port" in error_msg.lower() or "service" in error_msg.lower():
                self.show_warning("Service Error", "Service unavailable or port blocked.")
            elif "timed out" in error_msg.lower() or "timeout" in error_msg.lower():
                self.show_warning("Timeout", "Operation timed out. Target may be offline or blocking requests.")
            elif "KRB_AP_ERR_SKEW" in error_msg:
                self.show_warning("Time Sync Error", "Kerberos error: Clock skew too large. Sync time with domain controller.")
            elif "impacket" in context or "Impacket" in str(exception):
                if "STATUS_LOGON_FAILURE" in str(exception):
                    self.show_warning("Authentication Failed", "Invalid credentials or insufficient privileges.")
                elif "Connection refused" in str(exception):
                    self.show_warning("Connection Error", "Target refused connection. Service may not be running.")
                else:
                    self.show_warning("Impacket Error", f"Impacket execution failed: {str(exception)}")
            else:
                self.show_warning("System Error", f"An unexpected error occurred: {error_msg[:200]}")
        except Exception as e:
            print(f"Error handling failed: {str(e)}")
    
    def show_warning(self, title, message):
        if QMessageBox is not None:
            try:
                QMessageBox.warning(None, title, message)
            except Exception:
                print(f"{title}: {message}")
        else:
            print(f"{title}: {message}")