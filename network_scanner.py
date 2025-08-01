import ipaddress
import os
import subprocess
import re
import time
import sys
import json
import xml.etree.ElementTree as ET
from progress_manager import ProgressManager
from error_handler import ErrorHandler
from utils import (
    get_creation_flags,
    is_valid_ip,
    parse_ip_range,
    get_default_interface,
)

RESUME_FILE = os.path.join(os.path.dirname(__file__), "results", "resume.json")
MAX_TARGETS = 1024

class NetworkScanner:
    def __init__(self, nmap_path, masscan_path, log_function):
        self.nmap_path = nmap_path
        self.masscan_path = masscan_path
        self.log = log_function
        self.error_handler = ErrorHandler(log_function)

    def load_resume_data(self):
        if not os.path.isfile(RESUME_FILE):
            return []
        try:
            with open(RESUME_FILE, "r") as f:
                data = json.load(f)
            return data.get("completed_targets", [])
        except Exception:
            return []

    def save_resume_data(self, completed_targets):
        try:
            os.makedirs(os.path.dirname(RESUME_FILE), exist_ok=True)
            with open(RESUME_FILE, "w") as f:
                json.dump({"completed_targets": completed_targets}, f)
        except Exception as e:
            self.log("Error", f"Failed to save resume data: {str(e)}")
    
    def scan_network(self, target, port, scan_tool="Nmap", scan_speed="Normal", resume=False):
        try:
            # Parse target specification
            targets = self.parse_targets(target)
            if not targets:
                self.log("Warning", "No valid targets to scan")
                return []

            completed = self.load_resume_data() if resume else []
            targets = [t for t in targets if t not in completed]
            total_targets = len(targets)
            progress = ProgressManager(total_targets)

            scan_results = []
            for target_spec in targets:
                # Handle CIDR ranges
                if '/' in target_spec:
                    scan_results += self.scan_cidr(target_spec, port, scan_tool, scan_speed, progress)
                else:
                    scan_results += self.scan_single(target_spec, port, scan_tool, scan_speed, progress)
                completed.append(target_spec)
                if resume:
                    self.save_resume_data(completed)

            if resume and os.path.isfile(RESUME_FILE):
                os.remove(RESUME_FILE)
            return scan_results
        except Exception as e:
            self.error_handler.handle(e, "Network scanning")
            return []
    
    def parse_targets(self, target):
        """Parse target into list of network specifications, validate and fix if needed"""
        targets = []
        # If it's a file
        if os.path.isfile(target):
            try:
                with open(target, 'r') as f:
                    lines = [line.strip() for line in f.readlines() if line.strip()]
            except Exception as e:
                self.log("Error", f"Cannot read target file: {str(e)}")
                return []
        else:
            lines = [t.strip() for t in target.split(',') if t.strip()]
        for t in lines:
            # Accept IP, IP/CIDR, IP range
            if is_valid_ip(t) or '/' in t or '-' in t:
                targets.append(t)
            else:
                self.log("Warning", f"Invalid target format skipped: {t}")
        if not targets:
            self.log("Error", "No valid targets found after parsing input.")
        if len(targets) > MAX_TARGETS:
            self.log("Warning", f"Target list truncated to {MAX_TARGETS} items")
            targets = targets[:MAX_TARGETS]
        return targets
    
    def scan_cidr(self, cidr, port, scan_tool, scan_speed, progress):
        """Scan CIDR range by splitting into /24 subnets"""
        try:
            network = ipaddress.ip_network(cidr, strict=False)
            
            # For large networks, split into smaller /24 subnets
            if network.prefixlen < 24 and network.num_addresses > 256:
                subnets = list(network.subnets(new_prefix=24))
                self.log("Info", f"Splitting {cidr} into {len(subnets)} /24 subnets")
                
                results = []
                for subnet in subnets:
                    results += self.scan_single(str(subnet), port, scan_tool, scan_speed, progress)
                return results
            else:
                return self.scan_single(cidr, port, scan_tool, scan_speed, progress)
        except Exception as e:
            self.error_handler.handle(e, f"Scanning CIDR {cidr}")
            return []
    
    def scan_single(self, target, port, scan_tool, scan_speed, progress):
        """Scan a single target or subnet"""
        try:
            self.log("Info", f"Scanning: {target} on port(s): {port} using {scan_tool}")
            
            if scan_tool == "Masscan" and self.masscan_path:
                cmd = self.build_masscan_command(target, port, scan_speed)
            elif scan_tool == "Nmap" and self.nmap_path:
                cmd = self.build_nmap_command(target, port, scan_speed)
            else:
                self.log("Error", f"Unsupported scan tool: {scan_tool}")
                return []
            
            # Execute command with timeout
            creation_flags = get_creation_flags()
            timeout = 300 if '/' in target else 120  # Longer timeout for subnets
            
            try:
                result = subprocess.run(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    encoding="utf-8",
                    errors="ignore",
                    timeout=timeout,
                    creationflags=creation_flags
                )
                stdout = result.stdout
                stderr = result.stderr
            except subprocess.TimeoutExpired:
                self.log("Warning", f"Scan timeout for {target}")
                return []
            except Exception as e:
                self.log("Error", f"Error executing {scan_tool}: {str(e)}")
                return []
            
            if stderr:
                self.log("Warning", f"{scan_tool} stderr: {stderr.strip()}")
            
            return self.parse_scan_output(stdout, target, progress, scan_tool)
        except Exception as e:
            self.error_handler.handle(e, f"Scanning target {target}")
            return []
    
    def build_nmap_command(self, target, port, scan_speed):
        cmd = [self.nmap_path, "-n", "-p", port, "--open", "-oX", "-"]
        
        # Adjust scan speed
        if scan_speed == "Slow (Stealth)":
            cmd.extend(["-T2", "-sS"])
        elif scan_speed == "Normal":
            cmd.extend(["-T3", "-sS"])
        elif scan_speed == "Fast":
            cmd.extend(["-T4", "-sS"])
        elif scan_speed == "Aggressive":
            cmd.extend(["-T5", "-sS", "-A"])
        
        cmd.append(target)
        return cmd
    
    def build_masscan_command(self, target, port, scan_speed):
        cmd = [self.masscan_path]

        # Detect network adapter
        if sys.platform == "win32" and os.path.exists(self.masscan_path):
            try:
                result = subprocess.run(
                    [self.masscan_path, "--list"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    encoding="utf-8",
                    errors="ignore",
                    creationflags=get_creation_flags(),
                    timeout=5,
                )
                for line in result.stdout.splitlines():
                    if "adapter" in line.lower():
                        parts = line.split()
                        if parts:
                            adapter = parts[0]
                            cmd.extend(["-e", adapter])
                            break
            except Exception as e:
                self.log(
                    "Warning",
                    f"Failed to detect network adapter: {str(e)}. Using default adapter.",
                )
        else:
            interface = get_default_interface()
            if interface:
                cmd.extend(["-e", interface])
        

        cmd.extend([target, "-p", port, "--open", "-oJ", "-"])


        
        # Adjust scan speed
        if scan_speed == "Slow (Stealth)":
            cmd.extend(["--max-rate", "100"])
        elif scan_speed == "Normal":
            cmd.extend(["--max-rate", "1000"])
        elif scan_speed == "Fast":
            cmd.extend(["--max-rate", "5000"])
        elif scan_speed == "Aggressive":
            cmd.extend(["--max-rate", "10000"])
        
        return cmd
    
    def parse_scan_output(self, output, target, progress, scan_tool):
        if not output:
            self.log("Warning", f"No output from scanner for {target}")
            return []
            
        results = []
        service_counts = {}
        
        if scan_tool == "Nmap":
            if output.strip().startswith("<"):
                return self.parse_nmap_xml_output(output, target, progress)
            blocks = re.split(r"Nmap scan report for ", output)
            for block in blocks[1:]:
                lines = block.splitlines()
                if not lines:
                    continue

                ip_line = lines[0].strip()
                ip_match = re.search(r"((?:\d{1,3}\.){3}\d{1,3}|[a-fA-F0-9:]+)", ip_line)
                if not ip_match:
                    continue

                ip = ip_match.group(1)
                for line in lines:
                    # Find open ports and detect service
                    m = re.search(r"(\d+)/tcp\s+open\s+(\S+)(\s+([\w-]+))?", line)
                    if m:
                        port_found = m.group(1)
                        detected_service = m.group(2) + (f" {m.group(4)}" if m.group(4) else "")
                        results.append((ip, port_found, detected_service))
                        service_counts[detected_service] = service_counts.get(detected_service, 0) + 1
        
        elif scan_tool == "Masscan":
            if output.strip().startswith("["):
                return self.parse_masscan_json_output(output, target, progress)
            for line in output.splitlines():
                m = re.search(r"Discovered open port (\d+)/tcp on (\d+\.\d+\.\d+\.\d+)", line)

                # Typical formats:
                # Discovered open port 80/tcp on 192.168.1.1
                # open tcp 80 192.168.1.1 1623412342
                m = re.search(r"Discovered open port (\d+)/tcp on ([\d.:a-fA-F]+)", line)
                if not m:
                    m = re.search(r"open tcp (\d+) ([\d.:a-fA-F]+)", line)

                if m:
                    port_found = m.group(1)
                    ip = m.group(2)
                    service = self.get_service_from_port(port_found)
                    results.append((ip, port_found, service))
                    service_counts[service] = service_counts.get(service, 0) + 1
        
        # Update progress
        progress.target_completed(target, len(results), service_counts)
        self.log("Info", f"{target}: Found {len(results)} open services {service_counts}")

        return results

    def parse_nmap_xml_output(self, xml_output, target, progress):
        results = []
        service_counts = {}
        try:
            root = ET.fromstring(xml_output)
            for host in root.findall("host"):
                addr = host.find("address").get("addr")
                for port in host.findall("ports/port"):
                    state = port.find("state").get("state")
                    if state != "open":
                        continue
                    portid = port.get("portid")
                    service_elem = port.find("service")
                    service = service_elem.get("name") if service_elem is not None else self.get_service_from_port(portid)
                    results.append((addr, portid, service))
                    service_counts[service] = service_counts.get(service, 0) + 1
        except Exception as e:
            self.log("Error", f"XML parse error: {str(e)}")
        progress.target_completed(target, len(results), service_counts)
        self.log("Info", f"{target}: Found {len(results)} open services {service_counts}")
        return results

    def parse_masscan_json_output(self, json_output, target, progress):
        results = []
        service_counts = {}
        try:
            data = json.loads(json_output)
            for entry in data:
                ip = entry.get("ip")
                portid = str(entry.get("port"))
                service = self.get_service_from_port(portid)
                results.append((ip, portid, service))
                service_counts[service] = service_counts.get(service, 0) + 1
        except Exception as e:
            self.log("Error", f"JSON parse error: {str(e)}")
        progress.target_completed(target, len(results), service_counts)
        self.log("Info", f"{target}: Found {len(results)} open services {service_counts}")
        return results
    
    def get_service_from_port(self, port):
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
        return well_known.get(port, "Unknown")
