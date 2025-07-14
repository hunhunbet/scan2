import time
from collections import deque

class ProgressManager:
    def __init__(self, total_targets):
        self.start_time = time.time()
        self.total_targets = total_targets
        self.completed_targets = 0
        self.completed_ports = 0
        self.open_ports = 0
        self.target_queue = deque()
        self.completed_targets_list = []
        self.service_distribution = {}
    
    def add_target(self, target):
        self.target_queue.append(target)
    
    def target_completed(self, target, open_ports, service_counts):
        self.completed_targets += 1
        self.open_ports += open_ports
        self.completed_targets_list.append(target)
        
        # Update service distribution
        for service, count in service_counts.items():
            self.service_distribution[service] = self.service_distribution.get(service, 0) + count
    
    def get_progress(self):
        elapsed = time.time() - self.start_time
        remaining_targets = self.total_targets - self.completed_targets
        
        # Estimate time remaining
        if self.completed_targets > 0 and self.total_targets > 0:
            time_per_target = elapsed / self.completed_targets
            time_remaining = time_per_target * remaining_targets
            time_remaining_str = self.format_time(time_remaining)
        else:
            time_remaining_str = "Calculating..."
        
        return {
            "total_targets": self.total_targets,
            "completed_targets": self.completed_targets,
            "remaining_targets": remaining_targets,
            "open_ports": self.open_ports,
            "elapsed_time": self.format_time(elapsed),
            "estimated_remaining": time_remaining_str,
            "completed_list": self.completed_targets_list.copy(),
            "service_distribution": self.service_distribution.copy()
        }
    
    def format_time(self, seconds):
        if seconds < 0:
            seconds = 0
            
        hours = int(seconds // 3600)
        minutes = int((seconds % 3600) // 60)
        seconds = int(seconds % 60)
        return f"{hours:02d}:{minutes:02d}:{seconds:02d}"