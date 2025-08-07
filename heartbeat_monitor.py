import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import threading
import time
import json
import os
import re
from datetime import datetime, timedelta
from ping3 import ping
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure
import matplotlib.dates as mdates
from collections import deque
import paramiko
import pystray
import requests
from abc import ABC, abstractmethod

# Simple lock file for single instance
LOCK_FILE = ".heartbeat_monitor.lock"

def is_window_already_open():
    """Check if Heartbeat Monitor window is already open"""
    if not os.path.exists(LOCK_FILE):
        return False
    
    try:
        # Read the PID from the lock file
        with open(LOCK_FILE, 'r') as f:
            pid_str = f.read().strip()
            if not pid_str.isdigit():
                # Invalid PID, remove stale lock file
                remove_lock_file()
                return False
            
            pid = int(pid_str)
            
            # Check if the process is actually running
            try:
                import psutil
                if psutil.pid_exists(pid):
                    # Process exists, check if it's our application
                    try:
                        process = psutil.Process(pid)
                        if "python" in process.name().lower() and any("heartbeat_monitor" in cmd.lower() for cmd in process.cmdline()):
                            return True
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
            except ImportError:
                # psutil not available, fallback to basic check
                try:
                    os.kill(pid, 0)  # Check if process exists (doesn't actually kill)
                    return True
                except OSError:
                    pass
            
            # Process not running, remove stale lock file
            remove_lock_file()
            return False
            
    except (IOError, ValueError):
        # Lock file is corrupted or unreadable, remove it
        remove_lock_file()
        return False
    
    return False

def create_lock_file():
    """Create lock file to indicate instance is running"""
    try:
        # Use exclusive file creation to prevent race conditions
        with open(LOCK_FILE, 'x') as f:
            f.write(str(os.getpid()))
        
        # Make the file hidden on Windows
        try:
            import subprocess
            subprocess.run(['attrib', '+h', LOCK_FILE], capture_output=True, check=False)
        except:
            pass  # Ignore if attrib command fails
        return True
    except FileExistsError:
        # Another instance is already running
        return False
    except Exception:
        return False

def remove_lock_file():
    """Remove lock file when instance closes"""
    try:
        if os.path.exists(LOCK_FILE):
            os.remove(LOCK_FILE)
    except:
        pass


class BaseMetric(ABC):
    """Base class for all metrics"""
    
    def __init__(self, name, display_name, color, marker_style, enabled=True):
        self.name = name
        self.display_name = display_name
        self.color = color
        self.marker_style = marker_style
        self.enabled = enabled
        self.data_history = deque(maxlen=1000)
        self.config = {}
    
    @abstractmethod
    def collect_data(self):
        """Collect data for this metric. Must return (success, value) tuple"""
        pass
    
    @abstractmethod
    def validate_value(self, value):
        """Validate if the collected value is reasonable"""
        pass
    
    def get_config_fields(self):
        """Return list of config fields needed for this metric"""
        return []
    
    def get_display_range(self):
        """Return (min, max) for display range"""
        return (0, 100)
    
    def format_value(self, value):
        """Format value for display"""
        return f"{value:.2f}"


class PingMetric(BaseMetric):
    """Ping status metric (existing functionality)"""
    
    def __init__(self):
        super().__init__("ping", "Ping Status", "blue", "o", True)
    
    def collect_data(self):
        """Collect ping data using existing ping logic"""
        try:
            for attempt in range(self.config.get("retry_count", 4) + 1):
                try:
                    result = ping(self.config.get("target_ip", "8.8.8.8"), timeout=2)
                    if result is not None:
                        return True, "UP"
                except:
                    pass
                
                if attempt < self.config.get("retry_count", 4):
                    time.sleep(self.config.get("retry_delay", 2))
            
            return True, "DOWN"
        except Exception:
            return False, None
    
    def validate_value(self, value):
        """Validate ping value"""
        return value in ["UP", "DOWN"]
    
    def get_config_fields(self):
        return [
            {"name": "target_ip", "type": "text", "label": "Target IP", "default": "8.8.8.8"},
            {"name": "retry_count", "type": "int", "label": "Retry Count", "default": 4},
            {"name": "retry_delay", "type": "int", "label": "Retry Delay (s)", "default": 2}
        ]
    
    def get_display_range(self):
        return (0, 20)  # Special range for ping status


class SSHVoltageMetric(BaseMetric):
    """SSH voltage metric (existing functionality)"""
    
    def __init__(self):
        super().__init__("ssh_voltage", "Voltage (V)", "green", "s", True)
    
    def collect_data(self):
        """Collect SSH voltage data using existing SSH logic"""
        if not self.config.get("ssh_enabled", False):
            return False, None
            
        try:
            for attempt in range(self.config.get("retry_count", 4) + 1):
                try:
                    ssh = paramiko.SSHClient()
                    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    
                    ssh.connect(
                        self.config.get("ssh_host", self.config.get("target_ip", "")),  # Use ssh_host or fallback to target_ip
                        username=self.config.get("ssh_username", ""),
                        password=self.config.get("ssh_password", ""),
                        timeout=self.config.get("ssh_timeout", 10)
                    )
                    
                    stdin, stdout, stderr = ssh.exec_command(self.config.get("ssh_command", "python3 voltage.py"))
                    output = stdout.read().decode().strip()
                    ssh.close()
                    
                    # Parse voltage from output
                    voltage = float(output)
                    if self.validate_value(voltage):
                        return True, voltage
                    else:
                        return False, None
                        
                except Exception as e:
                    if attempt < self.config.get("retry_count", 4):
                        time.sleep(self.config.get("retry_delay", 2))
            
            return False, None
        except Exception:
            return False, None
    
    def validate_value(self, value):
        """Validate voltage value"""
        return isinstance(value, (int, float)) and 11.0 <= value <= 15.0
    
    def get_config_fields(self):
        return [
            {"name": "ssh_host", "type": "text", "label": "SSH Host", "default": ""},
            {"name": "ssh_username", "type": "text", "label": "SSH Username", "default": ""},
            {"name": "ssh_password", "type": "password", "label": "SSH Password", "default": ""},
            {"name": "ssh_command", "type": "text", "label": "SSH Command", "default": "python3 voltage.py"},
            {"name": "ssh_timeout", "type": "int", "label": "SSH Timeout (s)", "default": 10}
        ]
    
    def get_display_range(self):
        return (11.0, 15.0)


class APIMetric(BaseMetric):
    """Base class for API-based metrics"""
    
    def __init__(self, name, display_name, color, marker_style, endpoint, value_path):
        super().__init__(name, display_name, color, marker_style, True)
        self.endpoint = endpoint
        self.value_path = value_path  # JSON path to extract value (e.g., "temperature.current")
    
    def collect_data(self):
        """Collect data from API using socket communication"""
        try:
            import socket
            import json
            
            # Use custom command from config if available
            command_key = f"{self.name.replace('_', '')}_endpoint"
            path_key = f"{self.name.replace('_', '')}_path"
            
            # Map metric names to config keys
            if self.name == "temperature":
                command_key = "temp_endpoint"
                path_key = "temp_path"
            elif self.name == "terahash":
                command_key = "th_endpoint"
                path_key = "th_path"
            elif self.name == "frequency":
                command_key = "freq_endpoint"
                path_key = "freq_path"
            elif self.name == "fan_speed":
                command_key = "fan_endpoint"
                path_key = "fan_path"
            elif self.name == "power":
                command_key = "power_endpoint"
                path_key = "power_path"
            
            command = self.config.get(command_key, self.endpoint)
            value_path = self.config.get(path_key, self.value_path)
            
            # Skip if command is empty (disabled)
            if not command or not command.strip():
                return False, None
            
            # Get miner IP (separate from monitoring Pi IP)
            host = self.config.get("miner_ip", "192.168.168.226")
            port = self.config.get("api_port", 4028)
            
            # Create socket and send command
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.config.get("api_timeout", 10))
                s.connect((host, int(port)))
                s.sendall(command.encode())
                
                # Receive response (miner API doesn't use newlines)
                response = s.recv(8192)
            
            # Parse JSON response
            response_str = response.decode('utf-8', errors='ignore')
            # Clean up response
            response_str = response_str.replace('\x00', '')
            # Find JSON start if needed
            if '{' in response_str:
                json_start = response_str.index('{')
                response_str = response_str[json_start:]
            
            data = json.loads(response_str)
            
            # Extract value using path
            value = self._extract_value(data, value_path)
            if value is not None and self.validate_value(value):
                return True, value
            else:
                return False, None
                
        except Exception as e:
            return False, None
    
    def _extract_value(self, data, path):
        """Extract value from nested JSON using dot notation"""
        try:
            keys = path.split('.')
            current = data
            for key in keys:
                # Handle numeric indices
                if key.isdigit():
                    current = current[int(key)]
                else:
                    # Handle keys that might have spaces (like "GHS 5s")
                    current = current[key]
            return current
        except (KeyError, TypeError, IndexError):
            return None
    
    def get_config_fields(self):
        return [
            {"name": "api_url", "type": "text", "label": "API Base URL", "default": "http://localhost:8080"},
            {"name": "api_token", "type": "text", "label": "API Token (optional)", "default": ""},
            {"name": "api_timeout", "type": "int", "label": "API Timeout (s)", "default": 10}
        ]


class TemperatureMetric(APIMetric):
    """Temperature metric via API - uses temps command to get board temperature"""
    
    def __init__(self):
        super().__init__("temperature", "Temperature (°C)", "red", "^", '{"command":"temps"}', "TEMPS.0.TopLeft")
    
    def validate_value(self, value):
        if isinstance(value, (int, float)) and -40 <= value <= 150:
            return True
        return False
    
    def collect_data(self):
        """Override to handle temperature value"""
        success, value = super().collect_data()
        if success and value is not None:
            # Value is already extracted from the path, just use it directly
            if isinstance(value, (int, float)):
                return True, float(value)
        return False, None
    
    def get_display_range(self):
        return (0, 100)
    
    def format_value(self, value):
        return f"{value:.1f}°C"


class TerahashMetric(APIMetric):
    """Terahash metric via API - uses GHS 5s from stats command"""
    
    def __init__(self):
        super().__init__("terahash", "TH/s", "cyan", "D", '{"command":"stats"}', "STATS.1.GHS 5s")
    
    def validate_value(self, value):
        # Handle both numeric and string values
        if isinstance(value, (int, float)) and value >= 0:
            return True
        if isinstance(value, str):
            try:
                # Remove any commas and convert
                float(value.replace(',', ''))
                return True
            except:
                pass
        return False
    
    def collect_data(self):
        """Override to convert GH/s to TH/s"""
        success, value = super().collect_data()
        if success and value is not None:
            # Convert from GH/s to TH/s
            if isinstance(value, str):
                # Remove commas if present and convert
                value = float(value.replace(',', ''))
            else:
                value = float(value)
            value = value / 1000.0  # GH to TH
            return True, value
        return False, None
    
    def get_display_range(self):
        return (0, 200)  # Adjust based on your miner capacity
    
    def format_value(self, value):
        return f"{value:.2f} TH/s"


class FrequencyMetric(APIMetric):
    """Frequency metric via API - uses average frequency from stats"""
    
    def __init__(self):
        super().__init__("frequency", "Freq (MHz)", "purple", "d", '{"command":"stats"}', "STATS.1.frequency")
    
    def validate_value(self, value):
        if isinstance(value, (int, float)) and value > 0:
            return True
        if isinstance(value, str):
            try:
                float(value)
                return True
            except:
                pass
        return False
    
    def collect_data(self):
        """Override to handle string values"""
        success, value = super().collect_data()
        if success and value is not None:
            if isinstance(value, str):
                value = float(value)
            return True, value
        return False, None
    
    def get_display_range(self):
        return (0, 2000)
    
    def format_value(self, value):
        return f"{value:.0f} MHz"


class FanSpeedMetric(APIMetric):
    """Fan Speed metric via API - calculates average of all fan speeds"""
    
    def __init__(self):
        super().__init__("fan_speed", "Fan (%)", "orange", "v", '{"command":"fans"}', "FANS")
    
    def validate_value(self, value):
        # Value will be a list of fan data, we'll average them
        return isinstance(value, list) and len(value) > 0
    
    def collect_data(self):
        """Override to calculate average fan speed"""
        success, value = super().collect_data()
        if success and value is not None:
            try:
                if isinstance(value, list):
                    # Calculate average speed from all fans
                    speeds = []
                    for fan in value:
                        if isinstance(fan, dict) and 'Speed' in fan:
                            speed = fan['Speed']
                            if isinstance(speed, str):
                                speed = float(speed)
                            speeds.append(speed)
                    
                    if speeds:
                        avg_speed = sum(speeds) / len(speeds)
                        return True, avg_speed
            except Exception:
                pass
        return False, None
    
    def get_display_range(self):
        return (0, 100)
    
    def format_value(self, value):
        return f"{value:.0f}%"


class PowerMetric(APIMetric):
    """Power consumption metric via API"""
    
    def __init__(self):
        super().__init__("power", "Power (W)", "red", "H", '{"command":"power"}', "POWER.0.Watts")
    
    def validate_value(self, value):
        if isinstance(value, (int, float)) and value >= 0:
            return True
        if isinstance(value, str):
            try:
                float(value)
                return True
            except:
                pass
        return False
    
    def collect_data(self):
        """Override to handle string values"""
        success, value = super().collect_data()
        if success and value is not None:
            if isinstance(value, str):
                value = float(value)
            return True, value
        return False, None
    
    def get_display_range(self):
        return (0, 5000)  # Watts
    
    def format_value(self, value):
        return f"{value:.0f}W"


class MetricsManager:
    """Manages all metrics and their data collection"""
    
    def __init__(self):
        self.metrics = {}
        self.data_lock = threading.Lock()
        
        # Register default metrics
        self.register_metric(PingMetric())
        self.register_metric(SSHVoltageMetric())
        self.register_metric(TemperatureMetric())
        self.register_metric(TerahashMetric())
        self.register_metric(FrequencyMetric())
        self.register_metric(FanSpeedMetric())
        self.register_metric(PowerMetric())
    
    def register_metric(self, metric):
        """Register a new metric"""
        self.metrics[metric.name] = metric
    
    def get_metric(self, name):
        """Get metric by name"""
        return self.metrics.get(name)
    
    def get_enabled_metrics(self):
        """Get list of enabled metrics"""
        return [metric for metric in self.metrics.values() if metric.enabled]
    
    def collect_all_data(self, config):
        """Collect data for all enabled metrics"""
        results = {}
        for metric in self.get_enabled_metrics():
            # Update metric config
            metric.config = {k: v for k, v in config.items() if k.startswith(f"{metric.name}_") or k in ["api_url", "api_token", "api_timeout", "target_ip", "retry_count", "retry_delay", "ssh_host", "ssh_username", "ssh_password", "ssh_command", "ssh_timeout"]}
            
            success, value = metric.collect_data()
            results[metric.name] = {
                'success': success,
                'value': value,
                'timestamp': datetime.now(),
                'metric': metric
            }
            
            # Store in metric history
            if success:
                with self.data_lock:
                    metric.data_history.append({
                        'timestamp': datetime.now(),
                        'value': value
                    })
        
        return results


class SettingsWindow:
    def __init__(self, parent, config, save_callback):
        self.parent = parent
        self.config = config
        self.save_callback = save_callback
        
        self.window = tk.Toplevel(parent)
        self.window.title("Settings")
        self.window.geometry("600x700")
        self.window.resizable(True, True)
        self.window.minsize(500, 400)
        self.window.transient(parent)
        self.window.grab_set()
        
        self.setup_ui()
        self.load_config_to_ui()
    
    def setup_ui(self):
        # Create canvas and scrollbar for scrolling
        canvas = tk.Canvas(self.window)
        scrollbar = ttk.Scrollbar(self.window, orient="vertical", command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas)
        
        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        # Main frame inside scrollable area
        main_frame = ttk.Frame(scrollable_frame, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Configure grid weights
        self.window.columnconfigure(0, weight=1)
        self.window.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        
        # Pack canvas and scrollbar
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # Host Configuration (at the top)
        host_frame = ttk.LabelFrame(main_frame, text="Host Configuration", padding="10")
        host_frame.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))
        host_frame.columnconfigure(1, weight=1)
        
        # Target Host/IP (used for ping, SSH, and API)
        ttk.Label(host_frame, text="Target Host/IP:").grid(row=0, column=0, sticky=tk.W, padx=(0, 10))
        self.ip_var = tk.StringVar()
        self.ip_entry = ttk.Entry(host_frame, textvariable=self.ip_var, width=30)
        self.ip_entry.grid(row=0, column=1, sticky=(tk.W, tk.E), padx=(0, 10))
        ttk.Label(host_frame, text="(Used for Ping, SSH, and API calls)").grid(row=1, column=1, sticky=tk.W, padx=(0, 10))
        
        # Ping Configuration
        ping_frame = ttk.LabelFrame(main_frame, text="Ping Configuration", padding="10")
        ping_frame.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))
        ping_frame.columnconfigure(1, weight=1)
        
        # Ping interval - Minutes
        ttk.Label(ping_frame, text="Ping Interval (minutes):").grid(row=1, column=0, sticky=tk.W, padx=(0, 10), pady=(10, 0))
        self.interval_minutes_var = tk.StringVar()
        self.interval_minutes_entry = ttk.Entry(ping_frame, textvariable=self.interval_minutes_var, width=10)
        self.interval_minutes_entry.grid(row=1, column=1, sticky=tk.W, padx=(0, 10), pady=(10, 0))
        
        # Ping interval - Seconds
        ttk.Label(ping_frame, text="Ping Interval (seconds):").grid(row=2, column=0, sticky=tk.W, padx=(0, 10), pady=(10, 0))
        self.interval_seconds_var = tk.StringVar()
        self.interval_seconds_entry = ttk.Entry(ping_frame, textvariable=self.interval_seconds_var, width=10)
        self.interval_seconds_entry.grid(row=2, column=1, sticky=tk.W, padx=(0, 10), pady=(10, 0))
        
        # Retry settings
        ttk.Label(ping_frame, text="Retry Count:").grid(row=3, column=0, sticky=tk.W, padx=(0, 10), pady=(10, 0))
        self.retry_count_var = tk.StringVar()
        self.retry_count_entry = ttk.Entry(ping_frame, textvariable=self.retry_count_var, width=10)
        self.retry_count_entry.grid(row=3, column=1, sticky=tk.W, padx=(0, 10), pady=(10, 0))
        
        ttk.Label(ping_frame, text="Retry Delay (seconds):").grid(row=4, column=0, sticky=tk.W, padx=(0, 10), pady=(10, 0))
        self.retry_delay_var = tk.StringVar()
        self.retry_delay_entry = ttk.Entry(ping_frame, textvariable=self.retry_delay_var, width=10)
        self.retry_delay_entry.grid(row=4, column=1, sticky=tk.W, padx=(0, 10), pady=(10, 0))
        
        # SSH Configuration
        ssh_frame = ttk.LabelFrame(main_frame, text="SSH Monitoring (Optional)", padding="10")
        ssh_frame.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))
        ssh_frame.columnconfigure(1, weight=1)
        
        # SSH Enable
        self.ssh_enabled_var = tk.BooleanVar()
        self.ssh_check = ttk.Checkbutton(ssh_frame, text="Enable SSH Monitoring", variable=self.ssh_enabled_var)
        self.ssh_check.grid(row=0, column=0, columnspan=2, sticky=tk.W, pady=(0, 10))
        
        # SSH Username (Host will use the main Target Host/IP)
        ttk.Label(ssh_frame, text="SSH Username:").grid(row=1, column=0, sticky=tk.W, padx=(0, 10), pady=(5, 0))
        self.ssh_username_var = tk.StringVar()
        self.ssh_username_entry = ttk.Entry(ssh_frame, textvariable=self.ssh_username_var, width=20)
        self.ssh_username_entry.grid(row=1, column=1, sticky=(tk.W, tk.E), padx=(0, 10), pady=(5, 0))
        
        # SSH Password
        ttk.Label(ssh_frame, text="SSH Password:").grid(row=2, column=0, sticky=tk.W, padx=(0, 10), pady=(5, 0))
        self.ssh_password_var = tk.StringVar()
        self.ssh_password_entry = ttk.Entry(ssh_frame, textvariable=self.ssh_password_var, width=20, show="*")
        self.ssh_password_entry.grid(row=2, column=1, sticky=(tk.W, tk.E), padx=(0, 10), pady=(5, 0))
        
        # SSH Command
        ttk.Label(ssh_frame, text="SSH Command:").grid(row=3, column=0, sticky=tk.W, padx=(0, 10), pady=(5, 0))
        self.ssh_command_var = tk.StringVar()
        self.ssh_command_entry = ttk.Entry(ssh_frame, textvariable=self.ssh_command_var, width=40)
        self.ssh_command_entry.grid(row=3, column=1, sticky=(tk.W, tk.E), padx=(0, 10), pady=(5, 0))
        
        # SSH Timeout
        ttk.Label(ssh_frame, text="SSH Timeout (seconds):").grid(row=4, column=0, sticky=tk.W, padx=(0, 10), pady=(5, 0))
        self.ssh_timeout_var = tk.StringVar()
        self.ssh_timeout_entry = ttk.Entry(ssh_frame, textvariable=self.ssh_timeout_var, width=10)
        self.ssh_timeout_entry.grid(row=4, column=1, sticky=tk.W, padx=(0, 10), pady=(5, 0))
        
        # API Metrics Configuration
        api_frame = ttk.LabelFrame(main_frame, text="API Metrics (Optional) - Uses Target Host", padding="10")
        api_frame.grid(row=3, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))
        api_frame.columnconfigure(1, weight=1)
        
        # Miner IP
        ttk.Label(api_frame, text="Miner IP:").grid(row=0, column=0, sticky=tk.W, padx=(0, 10))
        self.miner_ip_var = tk.StringVar()
        self.miner_ip_entry = ttk.Entry(api_frame, textvariable=self.miner_ip_var, width=20)
        self.miner_ip_entry.grid(row=0, column=1, sticky=tk.W, padx=(0, 10))
        
        # API Port
        ttk.Label(api_frame, text="API Port:").grid(row=1, column=0, sticky=tk.W, padx=(0, 10), pady=(5, 0))
        self.api_port_var = tk.StringVar()
        self.api_port_entry = ttk.Entry(api_frame, textvariable=self.api_port_var, width=10)
        self.api_port_entry.grid(row=1, column=1, sticky=tk.W, padx=(0, 10), pady=(5, 0))
        
        # API Timeout
        ttk.Label(api_frame, text="API Timeout (seconds):").grid(row=2, column=0, sticky=tk.W, padx=(0, 10), pady=(5, 0))
        self.api_timeout_var = tk.StringVar()
        self.api_timeout_entry = ttk.Entry(api_frame, textvariable=self.api_timeout_var, width=10)
        self.api_timeout_entry.grid(row=2, column=1, sticky=tk.W, padx=(0, 10), pady=(5, 0))
        
        # Custom API Endpoints (all optional)
        ttk.Label(api_frame, text="Leave endpoints blank to disable specific metrics").grid(row=3, column=0, columnspan=2, sticky=tk.W, pady=(5, 10))
        
        # Temperature
        ttk.Label(api_frame, text="Temperature:").grid(row=3, column=0, sticky=tk.W, padx=(0, 10), pady=(5, 0))
        temp_container = ttk.Frame(api_frame)
        temp_container.grid(row=3, column=1, sticky=(tk.W, tk.E), padx=(0, 10), pady=(5, 0))
        self.temp_endpoint_var = tk.StringVar()
        ttk.Label(temp_container, text="Command:").pack(side=tk.LEFT)
        ttk.Entry(temp_container, textvariable=self.temp_endpoint_var, width=25).pack(side=tk.LEFT, padx=(5, 10))
        self.temp_path_var = tk.StringVar()
        ttk.Label(temp_container, text="JSON Path:").pack(side=tk.LEFT)
        ttk.Entry(temp_container, textvariable=self.temp_path_var, width=20).pack(side=tk.LEFT, padx=(5, 0))
        
        # Terahash
        ttk.Label(api_frame, text="Terahash:").grid(row=4, column=0, sticky=tk.W, padx=(0, 10), pady=(5, 0))
        th_container = ttk.Frame(api_frame)
        th_container.grid(row=4, column=1, sticky=(tk.W, tk.E), padx=(0, 10), pady=(5, 0))
        self.th_endpoint_var = tk.StringVar()
        ttk.Label(th_container, text="Command:").pack(side=tk.LEFT)
        ttk.Entry(th_container, textvariable=self.th_endpoint_var, width=25).pack(side=tk.LEFT, padx=(5, 10))
        self.th_path_var = tk.StringVar()
        ttk.Label(th_container, text="JSON Path:").pack(side=tk.LEFT)
        ttk.Entry(th_container, textvariable=self.th_path_var, width=20).pack(side=tk.LEFT, padx=(5, 0))
        
        # Frequency
        ttk.Label(api_frame, text="Frequency:").grid(row=5, column=0, sticky=tk.W, padx=(0, 10), pady=(5, 0))
        freq_container = ttk.Frame(api_frame)
        freq_container.grid(row=5, column=1, sticky=(tk.W, tk.E), padx=(0, 10), pady=(5, 0))
        self.freq_endpoint_var = tk.StringVar()
        ttk.Label(freq_container, text="Command:").pack(side=tk.LEFT)
        ttk.Entry(freq_container, textvariable=self.freq_endpoint_var, width=25).pack(side=tk.LEFT, padx=(5, 10))
        self.freq_path_var = tk.StringVar()
        ttk.Label(freq_container, text="JSON Path:").pack(side=tk.LEFT)
        ttk.Entry(freq_container, textvariable=self.freq_path_var, width=20).pack(side=tk.LEFT, padx=(5, 0))
        
        # Fan Speed
        ttk.Label(api_frame, text="Fan Speed:").grid(row=6, column=0, sticky=tk.W, padx=(0, 10), pady=(5, 0))
        fan_container = ttk.Frame(api_frame)
        fan_container.grid(row=6, column=1, sticky=(tk.W, tk.E), padx=(0, 10), pady=(5, 0))
        self.fan_endpoint_var = tk.StringVar()
        ttk.Label(fan_container, text="Command:").pack(side=tk.LEFT)
        ttk.Entry(fan_container, textvariable=self.fan_endpoint_var, width=25).pack(side=tk.LEFT, padx=(5, 10))
        self.fan_path_var = tk.StringVar()
        ttk.Label(fan_container, text="JSON Path:").pack(side=tk.LEFT)
        ttk.Entry(fan_container, textvariable=self.fan_path_var, width=20).pack(side=tk.LEFT, padx=(5, 0))
        
        # Power
        ttk.Label(api_frame, text="Power:").grid(row=7, column=0, sticky=tk.W, padx=(0, 10), pady=(5, 0))
        power_container = ttk.Frame(api_frame)
        power_container.grid(row=7, column=1, sticky=(tk.W, tk.E), padx=(0, 10), pady=(5, 0))
        self.power_endpoint_var = tk.StringVar()
        ttk.Label(power_container, text="Command:").pack(side=tk.LEFT)
        ttk.Entry(power_container, textvariable=self.power_endpoint_var, width=25).pack(side=tk.LEFT, padx=(5, 10))
        self.power_path_var = tk.StringVar()
        ttk.Label(power_container, text="JSON Path:").pack(side=tk.LEFT)
        ttk.Entry(power_container, textvariable=self.power_path_var, width=20).pack(side=tk.LEFT, padx=(5, 0))
        
        # Application Settings
        app_frame = ttk.LabelFrame(main_frame, text="Application Settings", padding="10")
        app_frame.grid(row=4, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))
        app_frame.columnconfigure(1, weight=1)
        
        # Close to Tray
        self.close_to_tray_var = tk.BooleanVar()
        self.close_to_tray_check = ttk.Checkbutton(app_frame, text="Close to System Tray", variable=self.close_to_tray_var)
        self.close_to_tray_check.grid(row=0, column=0, columnspan=2, sticky=tk.W)
        
        # Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=5, column=0, columnspan=2, pady=(10, 0))
        
        save_button = ttk.Button(button_frame, text="Save Settings", command=self.save_settings)
        save_button.pack(side=tk.LEFT, padx=(0, 10))
        
        cancel_button = ttk.Button(button_frame, text="Cancel", command=self.window.destroy)
        cancel_button.pack(side=tk.LEFT)
    
    def load_config_to_ui(self):
        """Load configuration values into UI elements"""
        self.ip_var.set(self.config["target_ip"])
        self.interval_minutes_var.set(str(self.config["ping_interval_minutes"]))
        self.interval_seconds_var.set(str(self.config["ping_interval_seconds"]))
        self.retry_count_var.set(str(self.config["retry_count"]))
        self.retry_delay_var.set(str(self.config["retry_delay"]))
        self.ssh_enabled_var.set(self.config["ssh_enabled"])
        self.ssh_username_var.set(self.config.get("ssh_username", ""))
        self.ssh_password_var.set(self.config.get("ssh_password", ""))
        self.ssh_command_var.set(self.config.get("ssh_command", "python3 voltage.py"))
        self.ssh_timeout_var.set(str(self.config.get("ssh_timeout", 10)))
        self.close_to_tray_var.set(self.config.get("close_to_tray", True))
        
        # Load API settings
        self.miner_ip_var.set(self.config.get("miner_ip", "192.168.168.226"))
        self.api_port_var.set(str(self.config.get("api_port", 4028)))
        self.api_timeout_var.set(str(self.config.get("api_timeout", 10)))
        self.temp_endpoint_var.set(self.config.get("temp_endpoint", '{"command":"temps"}'))
        self.temp_path_var.set(self.config.get("temp_path", "TEMPS.0.TEMP"))
        self.th_endpoint_var.set(self.config.get("th_endpoint", '{"command":"stats"}'))
        self.th_path_var.set(self.config.get("th_path", "STATS.1.GHS 5s"))
        self.freq_endpoint_var.set(self.config.get("freq_endpoint", '{"command":"stats"}'))
        self.freq_path_var.set(self.config.get("freq_path", "STATS.1.frequency"))
        self.fan_endpoint_var.set(self.config.get("fan_endpoint", '{"command":"fans"}'))
        self.fan_path_var.set(self.config.get("fan_path", "FANS"))
        self.power_endpoint_var.set(self.config.get("power_endpoint", '{"command":"power"}'))
        self.power_path_var.set(self.config.get("power_path", "POWER.0.Watts"))
    
    def save_settings(self):
        """Save settings and update main window"""
        try:
            # Validate inputs
            minutes = int(self.interval_minutes_var.get())
            seconds = int(self.interval_seconds_var.get())
            retry_count = int(self.retry_count_var.get())
            retry_delay = int(self.retry_delay_var.get())
            ssh_timeout = int(self.ssh_timeout_var.get())
            
            if minutes < 0 or seconds < 0:
                messagebox.showerror("Error", "Ping interval values must be non-negative")
                return
            
            if retry_count < 0 or retry_delay < 0:
                messagebox.showerror("Error", "Retry values must be non-negative")
                return
            
            if ssh_timeout < 1:
                messagebox.showerror("Error", "SSH timeout must be at least 1 second")
                return
            
            # Validate SSH settings only if SSH is enabled
            ssh_enabled = self.ssh_enabled_var.get()
            if ssh_enabled:
                if not self.ssh_username_var.get().strip():
                    messagebox.showerror("Error", "SSH username is required when SSH monitoring is enabled")
                    return
                if not self.ssh_command_var.get().strip():
                    messagebox.showerror("Error", "SSH command is required when SSH monitoring is enabled")
                    return
            
            # Update config
            self.config.update({
                "target_ip": self.ip_var.get(),
                "ping_interval_minutes": minutes,
                "ping_interval_seconds": seconds,
                "retry_count": retry_count,
                "retry_delay": retry_delay,
                "ssh_enabled": ssh_enabled,
                "ssh_host": self.ip_var.get(),  # Use same host as ping
                "ssh_username": self.ssh_username_var.get(),
                "ssh_password": self.ssh_password_var.get(),
                "ssh_command": self.ssh_command_var.get(),
                "ssh_timeout": ssh_timeout,
                "close_to_tray": self.close_to_tray_var.get(),
                # API settings
                "miner_ip": self.miner_ip_var.get(),
                "api_port": int(self.api_port_var.get()) if self.api_port_var.get() else 4028,
                "api_timeout": int(self.api_timeout_var.get()),
            "temp_endpoint": self.temp_endpoint_var.get(),
            "temp_path": self.temp_path_var.get(),
            "th_endpoint": self.th_endpoint_var.get(),
            "th_path": self.th_path_var.get(),
            "freq_endpoint": self.freq_endpoint_var.get(),
            "freq_path": self.freq_path_var.get(),
            "fan_endpoint": self.fan_endpoint_var.get(),
            "fan_path": self.fan_path_var.get(),
            "power_endpoint": self.power_endpoint_var.get(),
            "power_path": self.power_path_var.get()
            })
            
            # Call save callback
            self.save_callback(self.config)
            self.window.destroy()
            
        except ValueError:
            messagebox.showerror("Error", "Please enter valid numbers for all numeric fields")

class HeartbeatMonitor:
    def __init__(self, root):
        self.root = root
        self.root.title("Heartbeat Monitor")
        self.root.geometry("1200x800")
        self.root.resizable(True, True)
        self.root.minsize(800, 600)  # Minimum window size
        
        # Configuration
        self.config_file = "heartbeat_config.json"
        self.default_config = {
            "target_ip": "100.125.102.77",
            "ping_interval_minutes": 1,
            "ping_interval_seconds": 0,
            "retry_count": 4,
            "retry_delay": 2,
            "ssh_enabled": True,
            "ssh_host": "100.125.102.77",
            "ssh_username": "",
            "ssh_password": "",
            "ssh_command": "python3 voltage.py",
            "ssh_timeout": 10,
            "close_to_tray": True,
            # API Configuration
            "miner_ip": "192.168.168.226",
            "api_port": 4028,
            "api_timeout": 10,
            # API Endpoints
            "temp_endpoint": '{"command":"temps"}',
            "temp_path": "TEMPS.0.TopLeft",
            "th_endpoint": '{"command":"stats"}',
            "th_path": "STATS.1.GHS 5s",
            "freq_endpoint": '{"command":"stats"}',
            "freq_path": "STATS.1.frequency",
            "fan_endpoint": '{"command":"fans"}',
            "fan_path": "FANS",
            "power_endpoint": '{"command":"power"}',
            "power_path": "POWER.0.Watts",
            # Metric toggles
            "metrics_enabled": {
                "ping": True,
                "ssh_voltage": True,
                "temperature": True,
                "terahash": True,
                "frequency": False,
                "fan_speed": True,
                "power": True
            }
        }
        self.config = self.load_config()
        
        # Initialize metrics manager
        self.metrics_manager = MetricsManager()
        self._update_metrics_from_config()
        
        # Monitoring state
        self.is_monitoring = False
        self.monitor_thread = None
        self.downtime_events = deque(maxlen=100)  # FIXED: Limit to prevent memory leaks
        self.ping_history = deque(maxlen=1000)  # FIXED: Increased from 500 for better history
        self.ssh_history = deque(maxlen=1000)   # FIXED: Increased from 500 for better history
        self.total_pings = 0
        self.successful_pings = 0
        self.total_ssh = 0
        self.successful_ssh = 0
        
        # Time tracking for uptime/downtime
        self.monitoring_start_time = None
        self.total_uptime_seconds = 0
        self.total_downtime_seconds = 0
        self.last_status_update = None
        self.last_status = None
        self.current_state_start = None  # When current UP/DOWN state started
        self.current_state_type = None  # 'UP' or 'DOWN'
        
        # FIXED: Add thread synchronization
        self.data_lock = threading.Lock()
        
        # Simple graph update throttling
        self.last_graph_update = 0
        self.graph_update_interval = 5  # Update graph every 5 seconds
        
        # File I/O optimization - save immediately on each event
        
        self.setup_ui()
        self.load_config_to_ui()
        self.load_existing_data()
        
        # Schedule a delayed graph update to ensure UI is fully initialized
        # This ensures historical data shows in the graph on startup
        # Check both legacy history and metrics system for data
        has_data = bool(self.ping_history)
        for metric in self.metrics_manager.get_enabled_metrics():
            if metric.data_history:
                has_data = True
                break
        
        if has_data:  # Only schedule if there's historical data
            self.root.after(100, lambda: self.optimized_update_graph(force_update=True))
        
        # Bind resize event to update graph
        self.root.bind('<Configure>', self.on_window_resize)
        
        # Setup system tray
        self.setup_tray()
        
        # Bind window closing event
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
    
    def _update_metrics_from_config(self):
        """Update metrics enabled state from config"""
        metrics_config = self.config.get("metrics_enabled", {})
        for metric_name, metric in self.metrics_manager.metrics.items():
            metric.enabled = metrics_config.get(metric_name, metric_name in ["ping", "ssh_voltage"])
    
    def load_config(self):
        """Load configuration from file or use defaults"""
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r') as f:
                    loaded_config = json.load(f)
                            # Legacy migration code removed - all users should have migrated by now
                    return loaded_config
            except:
                return self.default_config.copy()
        return self.default_config.copy()
    
    def save_config(self):
        """Save current configuration to file"""
        try:
            with open(self.config_file, 'w') as f:
                json.dump(self.config, f, indent=2)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save config: {e}")
    
    def save_config_from_settings(self, new_config):
        """Save configuration from settings window"""
        self.config = new_config
        self.save_config()
        self.load_config_to_ui()
    
    def setup_ui(self):
        """Setup the user interface"""
        # Main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        
        # Control buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=0, column=0, columnspan=2, pady=(0, 10))
        
        self.start_button = ttk.Button(button_frame, text="Start Monitoring", command=self.start_monitoring)
        self.start_button.pack(side=tk.LEFT, padx=(0, 10))
        
        self.stop_button = ttk.Button(button_frame, text="Stop Monitoring", command=self.stop_monitoring, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=(0, 10))
        
        settings_button = ttk.Button(button_frame, text="Settings", command=self.open_settings)
        settings_button.pack(side=tk.LEFT, padx=(0, 10))
        
        refresh_button = ttk.Button(button_frame, text="Refresh Data", command=self.refresh_data)
        refresh_button.pack(side=tk.LEFT, padx=(0, 10))
        
        # Status section
        status_frame = ttk.LabelFrame(main_frame, text="Status", padding="10")
        status_frame.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))
        status_frame.columnconfigure(0, weight=1)
        
        # Status row 1 - Current status and current uptime/downtime
        status_row1 = ttk.Frame(status_frame)
        status_row1.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=(0, 5))
        
        self.status_var = tk.StringVar(value="Ready")
        self.status_label = ttk.Label(status_row1, textvariable=self.status_var, font=("Arial", 10, "bold"))
        self.status_label.pack(side=tk.LEFT)
        
        self.current_state_var = tk.StringVar(value="Current: N/A")
        self.current_state_label = ttk.Label(status_row1, textvariable=self.current_state_var, font=("Arial", 10, "bold"))
        self.current_state_label.pack(side=tk.RIGHT)
        
        # Status row 2 - Total uptime and downtime percentages
        status_row2 = ttk.Frame(status_frame)
        status_row2.grid(row=1, column=0, sticky=(tk.W, tk.E), pady=(0, 5))
        
        self.uptime_var = tk.StringVar(value="Total Uptime: 0s (0%)")
        self.uptime_label = ttk.Label(status_row2, textvariable=self.uptime_var, font=("Arial", 10))
        self.uptime_label.pack(side=tk.LEFT)
        
        self.downtime_var = tk.StringVar(value="Total Downtime: 0s (0%)")
        self.downtime_label = ttk.Label(status_row2, textvariable=self.downtime_var, font=("Arial", 10))
        self.downtime_label.pack(side=tk.RIGHT)
        
        # Status row 3 - Window statistics
        status_row3 = ttk.Frame(status_frame)
        status_row3.grid(row=2, column=0, sticky=(tk.W, tk.E), pady=(0, 5))
        
        self.window_stats_var = tk.StringVar(value="Window: 0 UP / 0 DOWN (0%)")
        self.window_stats_label = ttk.Label(status_row3, textvariable=self.window_stats_var)
        self.window_stats_label.pack(side=tk.LEFT)
        
        self.window_th_var = tk.StringVar(value="Avg TH/s: N/A")
        self.window_th_label = ttk.Label(status_row3, textvariable=self.window_th_var, font=("Arial", 10, "bold"))
        self.window_th_label.pack(side=tk.RIGHT)
        
        # Status row 4 - Last readings for metrics
        status_row4 = ttk.Frame(status_frame)
        status_row4.grid(row=3, column=0, sticky=(tk.W, tk.E), pady=(0, 5))
        
        self.last_ping_var = tk.StringVar(value="Ping: Never")
        self.last_ping_label = ttk.Label(status_row4, textvariable=self.last_ping_var)
        self.last_ping_label.pack(side=tk.LEFT, padx=(0, 10))
        
        self.last_voltage_var = tk.StringVar(value="Voltage: N/A")
        self.last_voltage_label = ttk.Label(status_row4, textvariable=self.last_voltage_var)
        self.last_voltage_label.pack(side=tk.LEFT, padx=(0, 10))
        
        self.last_temp_var = tk.StringVar(value="Temp: N/A")
        self.last_temp_label = ttk.Label(status_row4, textvariable=self.last_temp_var)
        self.last_temp_label.pack(side=tk.LEFT, padx=(0, 10))
        
        # Status row 5 - More last readings
        status_row5 = ttk.Frame(status_frame)
        status_row5.grid(row=4, column=0, sticky=(tk.W, tk.E))
        
        self.last_th_var = tk.StringVar(value="TH/s: N/A")
        self.last_th_label = ttk.Label(status_row5, textvariable=self.last_th_var)
        self.last_th_label.pack(side=tk.LEFT, padx=(0, 10))
        
        self.last_freq_var = tk.StringVar(value="Freq: N/A")
        self.last_freq_label = ttk.Label(status_row5, textvariable=self.last_freq_var)
        self.last_freq_label.pack(side=tk.LEFT, padx=(0, 10))
        
        self.last_fan_var = tk.StringVar(value="Fan: N/A")
        self.last_fan_label = ttk.Label(status_row5, textvariable=self.last_fan_var)
        self.last_fan_label.pack(side=tk.LEFT, padx=(0, 10))
        
        self.last_power_var = tk.StringVar(value="Power: N/A")
        self.last_power_label = ttk.Label(status_row5, textvariable=self.last_power_var)
        self.last_power_label.pack(side=tk.LEFT)
        
        # Create notebook for tabs
        notebook = ttk.Notebook(main_frame)
        notebook.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 10))
        main_frame.rowconfigure(2, weight=1)
        
        # Graph tab
        graph_frame = ttk.Frame(notebook)
        notebook.add(graph_frame, text="Live Monitoring Graph")
        
        # Graph controls frame
        graph_controls_frame = ttk.Frame(graph_frame)
        graph_controls_frame.pack(fill=tk.X, padx=10, pady=(10, 5))
        
        # Time range dropdown
        ttk.Label(graph_controls_frame, text="Time Range:").pack(side=tk.LEFT, padx=(0, 5))
        self.time_range_var = tk.StringVar(value="Last Hour")
        time_range_combo = ttk.Combobox(graph_controls_frame, textvariable=self.time_range_var, 
                                       values=["Last 15 Minutes", "Last 30 Minutes", "Last Hour", "Last 2 Hours", "Last 4 Hours", "Last 8 Hours", "Last 12 Hours", "Last 24 Hours", "All Data"],
                                       state="readonly", width=15)
        time_range_combo.pack(side=tk.LEFT, padx=(0, 20))
        time_range_combo.bind('<<ComboboxSelected>>', self.on_time_range_change)
        
        # Metric toggles frame
        toggles_frame = ttk.LabelFrame(graph_controls_frame, text="Show Metrics")
        toggles_frame.pack(side=tk.LEFT, padx=(20, 0))
        
        # Create toggle variables and checkboxes for each metric
        self.metric_toggles = {}
        for i, (metric_name, metric) in enumerate(self.metrics_manager.metrics.items()):
            var = tk.BooleanVar(value=metric.enabled)
            self.metric_toggles[metric_name] = var
            
            checkbox = ttk.Checkbutton(
                toggles_frame, 
                text=metric.display_name, 
                variable=var,
                command=lambda name=metric_name: self.on_metric_toggle(name)
            )
            checkbox.grid(row=i//3, column=i%3, sticky=tk.W, padx=5, pady=2)
        

        
        # Create matplotlib figure with single plot
        self.fig = Figure(figsize=(12, 6), dpi=100)
        self.ax = self.fig.add_subplot(111)  # Single plot
        self.canvas = FigureCanvasTkAgg(self.fig, graph_frame)
        self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))
        
        # Events tab
        events_frame = ttk.Frame(notebook)
        notebook.add(events_frame, text="Events Log")
        
        # Events text area
        self.events_text = scrolledtext.ScrolledText(events_frame, height=20, width=80)
        self.events_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Clear events button
        clear_button = ttk.Button(events_frame, text="Clear Events", command=self.clear_events)
        clear_button.pack(pady=(0, 10))
        
        # Start timer for UI updates
        self.update_ui_timer()
        
        # Initialize graph display settings
        self.current_time_range = self.time_range_var.get()
    
    def open_settings(self):
        """Open settings window"""
        SettingsWindow(self.root, self.config, self.save_config_from_settings)
    
    def load_config_to_ui(self):
        """Load configuration values into UI elements"""
        # Configuration loading is now handled by the settings window
        # This method is kept for compatibility but does nothing
        pass
    
    def update_ui_timer(self):
        """Update UI elements that need regular updates"""
        if self.is_monitoring:
            # Update time-based statistics
            if self.monitoring_start_time:
                current_time = datetime.now()
                total_monitoring_seconds = (current_time - self.monitoring_start_time).total_seconds()
                
                # Format uptime and downtime durations
                uptime_str = self.format_duration(self.total_uptime_seconds)
                downtime_str = self.format_duration(self.total_downtime_seconds)
                
                # Calculate total percentages
                if total_monitoring_seconds > 0:
                    uptime_percentage = (self.total_uptime_seconds / total_monitoring_seconds) * 100
                    downtime_percentage = (self.total_downtime_seconds / total_monitoring_seconds) * 100
                else:
                    uptime_percentage = 100.0 if self.last_status == "UP" else 0.0
                    downtime_percentage = 0.0 if self.last_status == "UP" else 100.0
                
                # Update total statistics display
                self.uptime_var.set(f"Total Uptime: {uptime_str} ({uptime_percentage:.1f}%)")
                self.downtime_var.set(f"Total Downtime: {downtime_str} ({downtime_percentage:.1f}%)")
                
                # Update current state duration
                if self.current_state_start and self.current_state_type:
                    current_duration = (current_time - self.current_state_start).total_seconds()
                    duration_str = self.format_duration(current_duration)
                    if self.current_state_type == "UP":
                        self.current_state_var.set(f"Currently UP for: {duration_str}")
                    else:
                        self.current_state_var.set(f"Currently DOWN for: {duration_str}")
            
            # Calculate window statistics for selected time range
            self.update_window_statistics()
            
            # Update last metric readings
            self.update_last_readings()
            
            # Update graph with throttling
            self.optimized_update_graph()
        
        # Schedule next update
        self.root.after(1000, self.update_ui_timer)
    
    def update_last_readings(self):
        """Update the display of last readings for all metrics"""
        # Get the last reading from each metric
        for metric_name, metric in self.metrics_manager.metrics.items():
            if metric.data_history:
                last_entry = metric.data_history[-1]
                timestamp = last_entry['timestamp']
                value = last_entry.get('value')
                
                if metric_name == 'ping':
                    time_str = timestamp.strftime('%H:%M:%S')
                    self.last_ping_var.set(f"Ping: {value} @ {time_str}")
                elif metric_name == 'ssh_voltage' and value is not None:
                    self.last_voltage_var.set(f"Voltage: {value:.2f}V")
                elif metric_name == 'temperature' and value is not None:
                    self.last_temp_var.set(f"Temp: {value:.1f}°C")
                elif metric_name == 'terahash' and value is not None:
                    self.last_th_var.set(f"TH/s: {value:.2f}")
                elif metric_name == 'frequency' and value is not None:
                    self.last_freq_var.set(f"Freq: {value:.0f} MHz")
                elif metric_name == 'fan_speed' and value is not None:
                    self.last_fan_var.set(f"Fan: {value:.0f}%")
                elif metric_name == 'power' and value is not None:
                    self.last_power_var.set(f"Power: {value:.0f}W")
    
    def format_duration(self, seconds):
        """Format seconds into a readable duration string"""
        if seconds < 60:
            return f"{int(seconds)}s"
        elif seconds < 3600:
            minutes = int(seconds / 60)
            secs = int(seconds % 60)
            return f"{minutes}m {secs}s"
        elif seconds < 86400:
            hours = int(seconds / 3600)
            minutes = int((seconds % 3600) / 60)
            return f"{hours}h {minutes}m"
        else:
            days = int(seconds / 86400)
            hours = int((seconds % 86400) / 3600)
            return f"{days}d {hours}h"
    
    def update_window_statistics(self):
        """Calculate and update statistics for the selected time window"""
        # Get filtered data for current window
        now = datetime.now()
        time_cutoff = self.get_time_cutoff(now)
        
        # Count UP/DOWN in window
        up_count = 0
        down_count = 0
        window_data = []
        
        with self.data_lock:
            for entry in self.ping_history:
                if entry['timestamp'] >= time_cutoff:
                    window_data.append(entry)
                    if entry['status'] == 'UP':
                        up_count += 1
                    else:
                        down_count += 1
        
        total_window_pings = up_count + down_count
        
        # Calculate window average uptime
        if total_window_pings > 0:
            window_avg = (up_count / total_window_pings) * 100
            self.window_stats_var.set(f"Window: {up_count} UP / {down_count} DOWN ({window_avg:.1f}%)")
            
            # Calculate average TH/s for window if available
            th_metric = self.metrics_manager.get_metric('terahash')
            if th_metric and th_metric.enabled:
                th_sum = 0
                th_count = 0
                with self.metrics_manager.data_lock:
                    for data_point in th_metric.data_history:
                        if data_point['timestamp'] >= time_cutoff and data_point.get('value') is not None:
                            th_sum += data_point['value']
                            th_count += 1
                
                if th_count > 0:
                    avg_th = th_sum / th_count
                    self.window_th_var.set(f"Avg TH/s: {avg_th:.2f}")
                else:
                    self.window_th_var.set("Avg TH/s: N/A")
            else:
                self.window_th_var.set("Avg TH/s: N/A")
        else:
            self.window_stats_var.set("Window: No data")
            self.window_th_var.set("Avg TH/s: N/A")
    
    def auto_save_events(self):
        """Auto-save events to file immediately"""
        try:
            filename = "events_log.txt"
            
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(self.events_text.get(1.0, tk.END))
            
            # Auto-save happens silently - no log message
            
        except Exception as e:
            self.log_event(f"Auto-save failed: {e}", "error")
    
    def update_time_since_down(self):
        """Update the time since last down display"""
        if self.last_down_time:
            time_diff = datetime.now() - self.last_down_time
            hours = int(time_diff.total_seconds() // 3600)
            minutes = int((time_diff.total_seconds() % 3600) // 60)
            seconds = int(time_diff.total_seconds() % 60)
            
            if hours > 0:
                time_str = f"{hours}h {minutes}m {seconds}s"
            elif minutes > 0:
                time_str = f"{minutes}m {seconds}s"
            else:
                time_str = f"{seconds}s"
            
            self.time_since_down_var.set(f"Time since last down: {time_str}")
        else:
            self.time_since_down_var.set("Time since last down: Never")
    
    def update_uptime_percentage(self):
        """Update uptime percentage display"""
        if self.total_pings > 0:
            uptime_pct = (self.successful_pings / self.total_pings) * 100
            self.uptime_var.set(f"Uptime: {uptime_pct:.1f}%")
        else:
            self.uptime_var.set("Uptime: 0%")
    
    def update_ping_stats(self):
        """Update ping statistics display"""
        if self.total_pings > 0:
            success_rate = (self.successful_pings / self.total_pings) * 100
            self.ping_stats_var.set(f"Pings: {self.successful_pings}/{self.total_pings} ({success_rate:.1f}%)")
        else:
            self.ping_stats_var.set("Pings: 0/0 (0%)")
    
    def update_ssh_stats(self):
        """Update SSH statistics display"""
        if self.total_ssh > 0:
            success_rate = (self.successful_ssh / self.total_ssh) * 100
            self.ssh_stats_var.set(f"SSH: {self.successful_ssh}/{self.total_ssh} ({success_rate:.1f}%)")
        else:
            self.ssh_stats_var.set("SSH: 0/0 (0%)")
    
    def update_current_streak(self):
        """Update current successful ping streak"""
        if not self.ping_history:
            self.current_streak_var.set("Current streak: 0 pings")
            return
        
        streak = 0
        for ping_result in reversed(self.ping_history):
            if ping_result['status'] == 'UP':
                streak += 1
            else:
                break
        
        self.current_streak_var.set(f"Current streak: {streak} pings")
    
    def optimized_update_graph(self, force_update=False):
        """Update the live monitoring graph with simple throttling"""
        import time
        
        current_time = time.time()
        
        # Simple throttling - only update every 5 seconds (unless forced)
        if not force_update and current_time - self.last_graph_update < self.graph_update_interval:
            return
            
        if len(self.ping_history) < 2 and not any(m.data_history for m in self.metrics_manager.metrics.values()):
            return
        
        # Prevent too frequent updates during time range changes (unless forced)
        if not force_update and hasattr(self, '_last_time_range_change') and current_time - self._last_time_range_change < 0.5:
            return
        
        # Safety check - don't update if too much data (prevents freezing)
        if len(self.ping_history) > 10000:
            self.ax.clear()
            self.ax.set_title(f'Live Monitoring - {self.current_time_range} (Too much data)')
            self.ax.set_xlabel('Time')
            self.ax.set_ylabel('Status / Voltage (V)')
            self.ax.grid(True, alpha=0.3)
            self.fig.tight_layout()
            self.canvas.draw()
            self.last_graph_update = current_time
            return
        
        try:
            # Show loading indicator for time range changes
            if self.current_time_range != getattr(self, '_last_displayed_range', None):
                # Update status to show loading
                self.status_var.set(f"Loading {self.current_time_range}...")
                self.root.update()
                
                self.ax.clear()
                self.ax.set_title(f'Loading {self.current_time_range}...')
                self.ax.set_xlabel('Time')
                self.ax.set_ylabel('Status / Voltage (V)')
                self.ax.grid(True, alpha=0.3)
                self.fig.tight_layout()
                self.canvas.draw()
                self.root.update()  # Force immediate update
            
            # Simple cleanup - just clear the plot
            self.ax.clear()
            
            # Get filtered data for all enabled metrics
            filtered_data = self.get_filtered_metrics_data()
            
            if not any(data['times'] for data in filtered_data.values()):
                # Show no data message
                self.ax.set_title(f'Live Monitoring - {self.current_time_range} (No data)')
                self.ax.set_xlabel('Time')
                self.ax.set_ylabel('Mixed Metrics')
                self.ax.grid(True, alpha=0.3)
                self.fig.tight_layout()
                self.canvas.draw()
                self.last_graph_update = current_time
                self._last_displayed_range = self.current_time_range
                return
            
            # Plot each enabled metric
            total_points = 0
            plotted_metrics = set()  # Track what we've plotted to avoid duplicates
            
            for metric_name, data in filtered_data.items():
                if not data['times']:
                    continue
                    
                metric = self.metrics_manager.get_metric(metric_name)
                if not metric or not metric.enabled or metric_name in plotted_metrics:
                    continue
                
                plotted_metrics.add(metric_name)
                total_points += len(data['times'])
                
                # Handle special case for ping status
                if metric_name == 'ping':
                    # Special handling for ping status (UP/DOWN)
                    # Use 90 for UP and 10 for DOWN on the normalized scale
                    up_times = []
                    up_statuses = []
                    down_times = []
                    down_statuses = []
                    
                    for time, status in zip(data['times'], data['values']):
                        if status == 'UP':
                            up_times.append(time)
                            up_statuses.append(90)  # Show at 90% on normalized scale
                        else:
                            down_times.append(time)
                            down_statuses.append(10)  # Show at 10% on normalized scale
                    
                    if up_times:
                        self.ax.plot(up_times, up_statuses, 'go', markersize=8, label='Ping UP', picker=5)
                    if down_times:
                        self.ax.plot(down_times, down_statuses, 'ro', markersize=8, label='Ping DOWN', picker=5)
                else:
                    # Sort data by time to ensure proper line connections
                    if data['times'] and data['values']:
                        sorted_pairs = sorted(zip(data['times'], data['values']), key=lambda x: x[0])
                        sorted_times, sorted_values = zip(*sorted_pairs)
                        
                        # Normalize values to 0-100 scale based on metric's display range
                        min_val, max_val = metric.get_display_range()
                        normalized_values = []
                        for val in sorted_values:
                            if max_val > min_val:
                                normalized = ((val - min_val) / (max_val - min_val)) * 100
                                normalized = max(0, min(100, normalized))  # Clamp to 0-100
                            else:
                                normalized = 50  # Default to middle if range is invalid
                            normalized_values.append(normalized)
                        
                        # Store original values for tooltips
                        line = self.ax.plot(
                            sorted_times, 
                            normalized_values, 
                            color=metric.color, 
                            marker=metric.marker_style, 
                            linestyle='-',
                            linewidth=2, 
                            markersize=6, 
                            label=f"{metric.display_name} ({metric.format_value(sorted_values[-1]) if sorted_values else 'N/A'})", 
                            picker=5
                        )[0]
                        
                        # Store original values for tooltip display
                        line.original_values = sorted_values
                        line.metric_name = metric.display_name
                        line.metric = metric
            
            # Set up the graph with normalized scale
            self.ax.set_ylim(0, 100)
            self.ax.set_xlabel('Time')
            self.ax.set_ylabel('Normalized Value (%)')
            
            # Simple title
            title = f'Live Monitoring - {self.current_time_range} ({total_points} points)'
            self.ax.set_title(title)
            self.ax.grid(True, alpha=0.3)
            self.ax.legend()
            
            # Simple x-axis formatting using first available metric data
            first_times = next((data['times'] for data in filtered_data.values() if data['times']), [])
            self.setup_x_axis_format(first_times)
            
            # Enable tooltips
            self.canvas.mpl_connect('pick_event', self.on_pick)
            
            # Adjust layout and draw
            self.fig.tight_layout()
            self.canvas.draw()
            
            # Update timestamp and displayed range
            self.last_graph_update = current_time
            self._last_displayed_range = self.current_time_range
            
            # Restore status if we were loading
            if self.status_var.get().startswith("Loading"):
                if self.is_monitoring:
                    self.status_var.set("Monitoring...")
                else:
                    self.status_var.set("Ready")
            
        except Exception as e:
            # If graph update fails, show error message
            self.ax.clear()
            self.ax.set_title(f'Graph Error - {self.current_time_range}')
            self.ax.set_xlabel('Time')
            self.ax.set_ylabel('Status / Voltage (V)')
            self.ax.grid(True, alpha=0.3)
            self.fig.tight_layout()
            self.canvas.draw()
            self.last_graph_update = current_time
    

    
    def get_filtered_data(self):
        """Get data filtered by current time range with thread-safe access (legacy method)"""
        # Calculate time cutoff based on selected range
        now = datetime.now()
        time_cutoff = self.get_time_cutoff(now)
        
        # Use helper methods for thread-safe data access
        filtered_ping_times, filtered_ping_statuses = self._get_filtered_ping_data(time_cutoff)
        filtered_ssh_times, filtered_ssh_voltages = self._get_filtered_ssh_data(time_cutoff)
        
        return {
            'ping': {'times': filtered_ping_times, 'statuses': filtered_ping_statuses},
            'ssh': {'times': filtered_ssh_times, 'voltages': filtered_ssh_voltages}
        }
    
    def get_filtered_metrics_data(self):
        """Get filtered data for all metrics using the new metrics system"""
        # Calculate time cutoff based on selected range
        now = datetime.now()
        time_cutoff = self.get_time_cutoff(now)
        
        filtered_data = {}
        
        for metric_name, metric in self.metrics_manager.metrics.items():
            if not metric.enabled:
                filtered_data[metric_name] = {'times': [], 'values': []}
                continue
            
            with self.metrics_manager.data_lock:
                filtered_times = []
                filtered_values = []
                
                for data_point in metric.data_history:
                    if data_point['timestamp'] >= time_cutoff:
                        filtered_times.append(data_point['timestamp'])
                        filtered_values.append(data_point['value'])
                
                filtered_data[metric_name] = {
                    'times': filtered_times,
                    'values': filtered_values
                }
        
        return filtered_data
    
    def _get_filtered_ping_data(self, time_cutoff):
        """Thread-safe method to get filtered ping data"""
        with self.data_lock:
            filtered_times = []
            filtered_statuses = []
            
            for ping in self.ping_history:
                if ping['timestamp'] >= time_cutoff:
                    filtered_times.append(ping['timestamp'])
                    filtered_statuses.append(ping['status'])
            
            return filtered_times, filtered_statuses
    
    def _get_filtered_ssh_data(self, time_cutoff):
        """Thread-safe method to get filtered SSH data"""
        with self.data_lock:
            filtered_times = []
            filtered_voltages = []
            
            for ssh in self.ssh_history:
                if ssh['timestamp'] >= time_cutoff and ssh['status'] == 'SUCCESS' and ssh['voltage'] is not None:
                    filtered_times.append(ssh['timestamp'])
                    filtered_voltages.append(ssh['voltage'])
            
            return filtered_times, filtered_voltages
    
    def get_time_cutoff(self, now):
        """Calculate time cutoff based on selected time range"""
        range_text = self.time_range_var.get()
        
        if range_text == "All Data":
            return datetime.min  # Show all data
        
        # Extract minutes from range text - check longer ranges first to avoid partial matches
        if "24 Hours" in range_text:
            minutes = 1440
        elif "12 Hours" in range_text:
            minutes = 720
        elif "8 Hours" in range_text:
            minutes = 480
        elif "4 Hours" in range_text:
            minutes = 240
        elif "2 Hours" in range_text:
            minutes = 120
        elif "Last Hour" in range_text:
            minutes = 60
        elif "30 Minutes" in range_text:
            minutes = 30
        elif "15 Minutes" in range_text:
            minutes = 15
        else:
            minutes = 60  # Default to 1 hour
        
        return now - timedelta(minutes=minutes)
    
    def setup_x_axis_format(self, times):
        """Setup x-axis formatting based on actual data times"""
        if not times:
            # No data, use default formatting
            self.ax.xaxis.set_major_formatter(mdates.DateFormatter('%H:%M'))
            self.ax.xaxis.set_major_locator(mdates.MinuteLocator(interval=5))
            plt.setp(self.ax.xaxis.get_majorticklabels(), rotation=45)
            return
        
        # Calculate actual time span of data
        min_time = min(times)
        max_time = max(times)
        time_span = max_time - min_time
        
        # Simple formatting based on time span with reasonable tick limits
        self.ax.xaxis.set_major_formatter(mdates.DateFormatter('%H:%M'))
        
        if time_span.total_seconds() <= 1800:  # 30 minutes or less
            self.ax.xaxis.set_major_locator(mdates.MinuteLocator(interval=5))
        elif time_span.total_seconds() <= 3600:  # 1 hour or less
            self.ax.xaxis.set_major_locator(mdates.MinuteLocator(interval=10))
        elif time_span.total_seconds() <= 14400:  # 4 hours or less
            self.ax.xaxis.set_major_locator(mdates.MinuteLocator(interval=30))
        elif time_span.total_seconds() <= 43200:  # 12 hours or less
            self.ax.xaxis.set_major_locator(mdates.HourLocator(interval=1))
        else:
            self.ax.xaxis.set_major_locator(mdates.HourLocator(interval=2))
        
        plt.setp(self.ax.xaxis.get_majorticklabels(), rotation=45)
    
    def on_time_range_change(self, event=None):
        """Handle time range dropdown change"""
        import time
        
        # Update the current time range variable
        self.current_time_range = self.time_range_var.get()
        
        # Track time range change to prevent too frequent updates
        self._last_time_range_change = time.time()
        
        # Force immediate graph update using after() to prevent UI freezing
        self.last_graph_update = 0
        self.root.after(10, lambda: self.optimized_update_graph(force_update=True))
    
    def on_metric_toggle(self, metric_name):
        """Handle metric toggle change"""
        # Update metric enabled state
        enabled = self.metric_toggles[metric_name].get()
        self.metrics_manager.get_metric(metric_name).enabled = enabled
        
        # Update config
        if "metrics_enabled" not in self.config:
            self.config["metrics_enabled"] = {}
        self.config["metrics_enabled"][metric_name] = enabled
        
        # Save config
        self.save_config()
        
        # Force immediate graph update
        self.last_graph_update = 0
        self.root.after(10, lambda: self.optimized_update_graph(force_update=True))
    

    
    def on_pick(self, event):
        """Handle tooltip display when clicking on graph points"""
        if event.mouseevent.button == 1:  # Left click
            artist = event.artist
            ind = event.ind[0]
            
            # Get the data point
            xdata = artist.get_xdata()
            ydata = artist.get_ydata()
            
            if len(xdata) > ind and len(ydata) > ind:
                x = xdata[ind]
                y = ydata[ind]
                
                # Format the tooltip based on the line type
                if 'Ping UP' in artist.get_label():
                    tooltip_text = f"Ping: UP\nTime: {x.strftime('%H:%M:%S')}\nStatus: Online"
                elif 'Ping DOWN' in artist.get_label():
                    tooltip_text = f"Ping: DOWN\nTime: {x.strftime('%H:%M:%S')}\nStatus: Offline"
                else:
                    # Check if this line has original values stored (for normalized metrics)
                    if hasattr(artist, 'original_values') and hasattr(artist, 'metric'):
                        original_value = artist.original_values[ind]
                        metric = artist.metric
                        formatted_value = metric.format_value(original_value)
                        tooltip_text = f"{metric.display_name}\nTime: {x.strftime('%H:%M:%S')}\nValue: {formatted_value}\nNormalized: {y:.1f}%"
                    elif 'Voltage' in artist.get_label():
                        tooltip_text = f"SSH Voltage Reading\nTime: {x.strftime('%H:%M:%S')}\nVoltage: {y:.2f}V\nStatus: Active"
                    else:
                        tooltip_text = f"Time: {x.strftime('%H:%M:%S')}\nValue: {y}"
                
                # Get current mouse position relative to the main window
                mouse_x = self.root.winfo_pointerx()
                mouse_y = self.root.winfo_pointery()
                
                # Show tooltip
                self.show_tooltip(tooltip_text, mouse_x, mouse_y)
    
    def show_tooltip(self, text, x, y):
        """Show a tooltip at the specified coordinates"""
        # Create tooltip window
        tooltip = tk.Toplevel(self.root)
        tooltip.wm_overrideredirect(True)
        tooltip.wm_geometry(f"+{x+10}+{y+10}")
        
        # Create tooltip content
        label = tk.Label(tooltip, text=text, justify=tk.LEFT,
                        background="#000000", foreground="white",
                        relief=tk.SOLID, borderwidth=1, font=("Arial", 9))
        label.pack()
        
        # Auto-hide tooltip after 3 seconds
        def hide_tooltip():
            tooltip.destroy()
        
        tooltip.after(3000, hide_tooltip)
    
    def start_monitoring(self):
        """Start the monitoring process"""
        try:
            # Validate inputs
            ip = self.config["target_ip"]
            if not ip:
                messagebox.showerror("Error", "Please configure target IP in Settings")
                return
            
            # Validate SSH settings only if SSH monitoring is enabled
            if self.config["ssh_enabled"]:
                if not self.config["ssh_host"]:
                    messagebox.showerror("Error", "Please configure SSH host in Settings")
                    return
                if not self.config["ssh_username"]:
                    messagebox.showerror("Error", "Please configure SSH username in Settings")
                    return
                if not self.config["ssh_command"]:
                    messagebox.showerror("Error", "Please configure SSH command in Settings")
                    return
            
            # Only reset statistics if no existing data (first time starting)
            if len(self.ping_history) == 0:
                self.total_pings = 0
                self.successful_pings = 0
                self.total_ssh = 0
                self.successful_ssh = 0
                self.ping_history.clear()
                self.ssh_history.clear()
                self.downtime_events.clear()
                self.last_down_time = None
            # Otherwise, keep existing data and continue monitoring from where we left off
            # This preserves historical data when restarting monitoring
            
            # Start monitoring thread
            self.is_monitoring = True
            self.monitoring_start_time = datetime.now()
            self.total_uptime_seconds = 0
            self.total_downtime_seconds = 0
            self.last_status_update = datetime.now()
            self.last_status = None
            self.monitor_thread = threading.Thread(target=self.monitor_loop, daemon=True)
            self.monitor_thread.start()
            
            # Update UI
            self.start_button.config(state=tk.DISABLED)
            self.stop_button.config(state=tk.NORMAL)
            self.status_var.set("Monitoring...")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to start monitoring: {e}")
    
    def stop_monitoring(self):
        """Stop the monitoring process"""
        self.is_monitoring = False
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.status_var.set("Stopped")
    
    def monitor_loop(self):
        """Main monitoring loop using the new metrics system"""
        while self.is_monitoring:
            try:
                current_time = datetime.now()
                
                # Use metrics manager to collect all data
                results = self.metrics_manager.collect_all_data(self.config)
                
                # Handle ping metric specifically for legacy compatibility
                ping_result = results.get('ping')
                if ping_result and ping_result['success']:
                    is_up = ping_result['value'] == 'UP'
                self.total_pings += 1
                if is_up:
                    self.successful_pings += 1
                
                    # Update uptime/downtime tracking
                    if self.last_status is not None and self.last_status_update is not None:
                        duration = (current_time - self.last_status_update).total_seconds()
                        if self.last_status == 'UP':
                            self.total_uptime_seconds += duration
                        else:
                            self.total_downtime_seconds += duration
                    
                    # Track current state changes
                    if self.last_status != ping_result['value']:
                        # State has changed
                        self.current_state_start = current_time
                        self.current_state_type = ping_result['value']
                    elif self.current_state_start is None:
                        # First status
                        self.current_state_start = current_time
                        self.current_state_type = ping_result['value']
                    
                    self.last_status = ping_result['value']
                    self.last_status_update = current_time
                    
                    # Add to legacy ping history for compatibility
                with self.data_lock:
                    self.ping_history.append({
                        'timestamp': current_time,
                            'status': ping_result['value']
                    })
                
                    # Update UI
                    self.root.after(0, lambda: self.last_ping_var.set(
                        f"Last ping: {current_time.strftime('%Y-%m-%d %H:%M:%S')} - {ping_result['value']}"
                    ))
                    
                    # Record downtime if down
                    if not is_up:
                        self.record_downtime(current_time)
                    else:
                        self.root.after(0, lambda: self.log_event(f"UP: {current_time.strftime('%Y-%m-%d %H:%M:%S')}", "up"))
                
                # Handle SSH voltage metric specifically
                ssh_result = results.get('ssh_voltage')
                if ssh_result and ssh_result['success']:
                    voltage = ssh_result['value']
                    self.total_ssh += 1
                    self.successful_ssh += 1
                    
                    # Add to legacy SSH history for compatibility
                    with self.data_lock:
                        self.ssh_history.append({
                            'timestamp': current_time,
                            'status': 'SUCCESS',
                            'voltage': voltage
                        })
                    
                    # Update UI
                    self.root.after(0, lambda v=voltage: self.last_ssh_var.set(
                        f"Last SSH: {current_time.strftime('%Y-%m-%d %H:%M:%S')} - {v:.2f}V"
                    ))
                    self.root.after(0, lambda v=voltage: self.log_event(f"SSH: {v:.2f}V", "ssh"))
                elif self.config.get("ssh_enabled", False):
                    # SSH failed
                    self.total_ssh += 1
                    self.root.after(0, lambda: self.last_ssh_var.set(
                        f"Last SSH: {current_time.strftime('%Y-%m-%d %H:%M:%S')} - FAILED"
                    ))
                    self.root.after(0, lambda: self.log_event(f"SSH: FAILED", "ssh_fail"))
                
                # Log other metrics
                for metric_name, result in results.items():
                    if metric_name in ['ping', 'ssh_voltage']:
                        continue  # Already handled above
                    
                    metric = result['metric']
                    if result['success']:
                        formatted_value = metric.format_value(result['value'])
                        self.root.after(0, lambda name=metric.display_name, val=formatted_value: 
                                      self.log_event(f"{name}: {val}", "metric"))
                    else:
                        self.root.after(0, lambda name=metric.display_name: 
                                      self.log_event(f"{name}: FAILED", "metric_fail"))
                
                # Auto-save on every new data point
                self.root.after(0, self.auto_save_events)
                
                # Calculate total interval in seconds
                total_interval = self.config["ping_interval_minutes"] * 60 + self.config["ping_interval_seconds"]
                
                # Wait for next interval
                time.sleep(total_interval)
                
            except Exception as e:
                self.root.after(0, lambda: self.log_event(f"Error: {e}", "error"))
                time.sleep(5)  # Wait before retrying
    
    def ping_with_retries(self):
        """Ping with retry logic"""
        for attempt in range(self.config["retry_count"] + 1):
            try:
                result = ping(self.config["target_ip"], timeout=2)
                if result is not None:
                    return True
            except:
                pass
            
            if attempt < self.config["retry_count"]:
                time.sleep(self.config["retry_delay"])
        
        return False
    
    def ssh_with_retries(self):
        """SSH with retry logic"""
        for attempt in range(self.config["retry_count"] + 1):
            try:
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                
                ssh.connect(
                    self.config.get("target_ip", self.config.get("ssh_host", "")),  # Use target_ip, fallback to ssh_host for backward compatibility
                    username=self.config["ssh_username"],
                    password=self.config["ssh_password"],
                    timeout=self.config["ssh_timeout"]
                )
                
                stdin, stdout, stderr = ssh.exec_command(self.config["ssh_command"])
                output = stdout.read().decode().strip()
                ssh.close()
                
                # Parse voltage from output (expecting a number between 11.5 and 14.2)
                try:
                    voltage = float(output)
                    if 11.5 <= voltage <= 14.2:
                        return 'SUCCESS', voltage
                    else:
                        return 'FAILED', None
                except ValueError:
                    return 'FAILED', None
                
            except Exception as e:
                if attempt < self.config["retry_count"]:
                    time.sleep(self.config["retry_delay"])
        
        return 'FAILED', None
    
    def record_downtime(self, timestamp):
        """Record a downtime event with thread-safe access"""
        event = {
            "timestamp": timestamp,
            "status": "DOWN"
        }
        
        # FIXED: Thread-safe data access to prevent race conditions
        with self.data_lock:
            self.downtime_events.append(event)
            self.last_down_time = timestamp
            
        self.root.after(0, lambda: self.log_event(f"DOWN: {timestamp.strftime('%Y-%m-%d %H:%M:%S')}", "down"))
    
    def log_event(self, message, event_type="normal"):
        """Add event to the log display with color coding"""
        timestamp = datetime.now().strftime('%H:%M:%S')
        full_message = f"[{timestamp}] {message}\n"
        
        # Insert the message
        self.events_text.insert(tk.END, full_message)
        
        # Apply color coding based on event type
        if event_type == "down":
            # Color the entire line red for DOWN events
            start_pos = f"{self.events_text.index(tk.END).split('.')[0]}.0"
            end_pos = self.events_text.index(tk.END)
            self.events_text.tag_add("down_event", start_pos, end_pos)
            self.events_text.tag_config("down_event", foreground="red", font=("Arial", 9, "bold"))
        elif event_type == "up":
            # Color UP events in green
            start_pos = f"{self.events_text.index(tk.END).split('.')[0]}.0"
            end_pos = self.events_text.index(tk.END)
            self.events_text.tag_add("up_event", start_pos, end_pos)
            self.events_text.tag_config("up_event", foreground="green")
        elif event_type == "ssh":
            # Color SSH voltage events in blue
            start_pos = f"{self.events_text.index(tk.END).split('.')[0]}.0"
            end_pos = self.events_text.index(tk.END)
            self.events_text.tag_add("ssh_event", start_pos, end_pos)
            self.events_text.tag_config("ssh_event", foreground="blue", font=("Arial", 9, "bold"))
        elif event_type == "ssh_fail":
            # Color SSH failure events in orange
            start_pos = f"{self.events_text.index(tk.END).split('.')[0]}.0"
            end_pos = self.events_text.index(tk.END)
            self.events_text.tag_add("ssh_fail_event", start_pos, end_pos)
            self.events_text.tag_config("ssh_fail_event", foreground="orange", font=("Arial", 9, "bold"))
        elif event_type == "auto_save":
            # Color auto-save events in purple
            start_pos = f"{self.events_text.index(tk.END).split('.')[0]}.0"
            end_pos = self.events_text.index(tk.END)
            self.events_text.tag_add("auto_save_event", start_pos, end_pos)
            self.events_text.tag_config("auto_save_event", foreground="purple", font=("Arial", 9, "italic"))
        elif event_type == "error":
            # Color error events in orange
            start_pos = f"{self.events_text.index(tk.END).split('.')[0]}.0"
            end_pos = self.events_text.index(tk.END)
            self.events_text.tag_add("error_event", start_pos, end_pos)
            self.events_text.tag_config("error_event", foreground="orange", font=("Arial", 9, "bold"))
        elif event_type == "metric":
            # Color metric events in cyan
            start_pos = f"{self.events_text.index(tk.END).split('.')[0]}.0"
            end_pos = self.events_text.index(tk.END)
            self.events_text.tag_add("metric_event", start_pos, end_pos)
            self.events_text.tag_config("metric_event", foreground="cyan", font=("Arial", 9))
        elif event_type == "metric_fail":
            # Color metric failure events in red
            start_pos = f"{self.events_text.index(tk.END).split('.')[0]}.0"
            end_pos = self.events_text.index(tk.END)
            self.events_text.tag_add("metric_fail_event", start_pos, end_pos)
            self.events_text.tag_config("metric_fail_event", foreground="red", font=("Arial", 9, "bold"))
        
        self.events_text.see(tk.END)
    
    def load_existing_data(self):
        """Load existing event log data from file"""
        try:
            if os.path.exists("events_log.txt"):
                with open("events_log.txt", 'r', encoding='utf-8') as f:
                    content = f.read()
                    if content.strip():
                        self.events_text.delete(1.0, tk.END)
                        self.events_text.insert(1.0, content)
                        
                        # Parse the loaded data to reconstruct history
                        self.parse_existing_events(content)
                        
        except Exception as e:
            pass  # Error logging handled by secure logging system
    
    def parse_existing_events(self, content):
        """Parse existing event log to reconstruct monitoring history"""
        lines = content.strip().split('\n')
        ping_count = 0
        ssh_count = 0
        successful_pings = 0
        successful_ssh = 0
        previous_timestamp = None
        
        # Get metric references
        ping_metric = self.metrics_manager.get_metric('ping')
        ssh_metric = self.metrics_manager.get_metric('ssh_voltage')
        temp_metric = self.metrics_manager.get_metric('temperature')
        th_metric = self.metrics_manager.get_metric('terahash')
        freq_metric = self.metrics_manager.get_metric('frequency')
        fan_metric = self.metrics_manager.get_metric('fan_speed')
        power_metric = self.metrics_manager.get_metric('power')
        
        for line in lines:
            if not line.strip():
                continue
                
            # Parse timestamp and event
            try:
                # Extract timestamp from the beginning of line
                if line.startswith('[') and ']' in line:
                    timestamp_str = line.split('[')[1].split(']')[0].strip()
                    
                    # Try to extract actual date from the event data
                    actual_date = None
                    if 'UP:' in line or 'DOWN:' in line:
                        # Extract date from UP/DOWN events: "UP: 2025-08-04 12:07:07"
                        try:
                            date_part = line.split('UP:')[1].strip() if 'UP:' in line else line.split('DOWN:')[1].strip()
                            actual_date = datetime.strptime(date_part, '%Y-%m-%d %H:%M:%S')
                            previous_timestamp = actual_date  # Store for SSH events
                        except:
                            pass
                    elif 'SSH:' in line:
                        # For SSH events, use the previous timestamp if available
                        if previous_timestamp:
                            actual_date = previous_timestamp
                    
                    # If we found an actual date, use it; otherwise use today's date
                    if actual_date:
                        timestamp = actual_date
                    else:
                        try:
                            # Parse timestamp (HH:MM:SS format) and use today's date
                            timestamp = datetime.strptime(timestamp_str, '%H:%M:%S')
                            today = datetime.now().date()
                            timestamp = timestamp.replace(year=today.year, month=today.month, day=today.day)
                        except ValueError:
                            # Try alternative timestamp format (YYYY-MM-DD HH:MM:SS)
                            try:
                                timestamp = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S')
                            except ValueError:
                                continue
                    
                    # Parse event type
                    if 'UP:' in line:
                        ping_count += 1
                        successful_pings += 1
                        self.ping_history.append({
                            'timestamp': timestamp,
                            'status': 'UP'
                        })
                        # Add to metrics system
                        if ping_metric:
                            with self.metrics_manager.data_lock:
                                ping_metric.data_history.append({
                                    'timestamp': timestamp,
                                    'value': 'UP'
                        })
                        
                    elif 'DOWN:' in line:
                        ping_count += 1
                        self.ping_history.append({
                            'timestamp': timestamp,
                            'status': 'DOWN'
                        })
                        self.last_down_time = timestamp
                        # Add to metrics system
                        if ping_metric:
                            with self.metrics_manager.data_lock:
                                ping_metric.data_history.append({
                                    'timestamp': timestamp,
                                    'value': 'DOWN'
                                })
                        
                    elif 'SSH:' in line and 'V' in line:
                        ssh_count += 1
                        successful_ssh += 1
                        # Extract voltage value
                        try:
                            voltage_str = line.split('SSH:')[1].split('V')[0].strip()
                            voltage = float(voltage_str)
                            self.ssh_history.append({
                                'timestamp': timestamp,
                                'status': 'SUCCESS',
                                'voltage': voltage
                            })
                            # Add to metrics system
                            if ssh_metric:
                                with self.metrics_manager.data_lock:
                                    ssh_metric.data_history.append({
                                        'timestamp': timestamp,
                                        'value': voltage
                                    })
                        except:
                            pass
                    
                    # Parse new metric types
                    elif 'Temperature' in line and '°C' in line:
                        try:
                            # Format: "Temperature (°C): 56.0°C"
                            temp_str = line.split(':')[-1].replace('°C', '').strip()
                            temp_value = float(temp_str)
                            if temp_metric:
                                with self.metrics_manager.data_lock:
                                    temp_metric.data_history.append({
                                        'timestamp': timestamp,
                                        'value': temp_value
                                    })
                        except:
                            pass
                    
                    elif 'TH/s:' in line:
                        try:
                            # Format: "TH/s: 69.06 TH/s" or "TH/s: FAILED"
                            if 'FAILED' not in line:
                                th_str = line.split('TH/s:')[1].replace('TH/s', '').strip()
                                th_value = float(th_str)
                                if th_metric:
                                    with self.metrics_manager.data_lock:
                                        th_metric.data_history.append({
                                            'timestamp': timestamp,
                                            'value': th_value
                                        })
                        except:
                            pass
                    
                    elif 'Freq' in line and 'MHz' in line:
                        try:
                            # Format: "Freq (MHz): 325 MHz" or "Freq (MHz): FAILED"
                            if 'FAILED' not in line:
                                freq_str = line.split(':')[-1].replace('MHz', '').strip()
                                freq_value = float(freq_str)
                                if freq_metric:
                                    with self.metrics_manager.data_lock:
                                        freq_metric.data_history.append({
                                            'timestamp': timestamp,
                                            'value': freq_value
                                        })
                        except:
                            pass
                    
                    elif 'Fan' in line and '%' in line:
                        try:
                            # Format: "Fan (%): 66%" or "Fan (%): FAILED"
                            if 'FAILED' not in line:
                                fan_str = line.split(':')[-1].replace('%', '').strip()
                                fan_value = float(fan_str)
                                if fan_metric:
                                    with self.metrics_manager.data_lock:
                                        fan_metric.data_history.append({
                                            'timestamp': timestamp,
                                            'value': fan_value
                                    })
                        except:
                            pass
                    
                    elif 'Power' in line and 'W' in line:
                        try:
                            # Format: "Power (W): 1902W" or "Power (W): FAILED"
                            if 'FAILED' not in line:
                                power_str = line.split(':')[-1].replace('W', '').strip()
                                power_value = float(power_str)
                                if power_metric:
                                    with self.metrics_manager.data_lock:
                                        power_metric.data_history.append({
                                            'timestamp': timestamp,
                                            'value': power_value
                                        })
                        except:
                            pass
                            
                    elif 'SSH: FAILED' in line:
                        ssh_count += 1
                        self.ssh_history.append({
                            'timestamp': timestamp,
                            'status': 'FAILED',
                            'voltage': None
                        })
                            
            except Exception as e:
                continue
        
        # Update statistics
        self.total_pings = ping_count
        self.successful_pings = successful_pings
        self.total_ssh = ssh_count
        self.successful_ssh = successful_ssh
        
        # Update UI
        self.update_uptime_percentage()
        self.update_ping_stats()
        self.update_ssh_stats()
        self.update_current_streak()
        self.update_time_since_down()
        self.optimized_update_graph()
    
    def clear_events(self):
        """Clear the events display"""
        self.events_text.delete(1.0, tk.END)
        self.downtime_events.clear()

    def refresh_data(self):
        """Refresh data from the events log file"""
        try:
            # Clear existing data first to prevent duplicates
            self.ping_history.clear()
            self.ssh_history.clear()
            
            # Clear metrics data too
            for metric in self.metrics_manager.metrics.values():
                metric.data_history.clear()
            
            self.total_pings = 0
            self.successful_pings = 0
            self.total_ssh = 0
            self.successful_ssh = 0
            self.last_down_time = None
            
            # Now load fresh data
            self.load_existing_data()
            
            # Force immediate graph update
            self.last_graph_update = 0
            self.root.after(10, lambda: self.optimized_update_graph(force_update=True))
            
            # Update status
            self.status_var.set("Data refreshed")
            self.root.after(2000, lambda: self.status_var.set("Ready" if not self.is_monitoring else "Monitoring..."))
        except Exception as e:
            pass  # Error logging handled by secure logging system

    def on_window_resize(self, event):
        """Handle window resize to update graph canvas"""
        if self.is_monitoring:
            self.optimized_update_graph()
    
    def create_tray_icon(self):
        """Create tray icon"""
        try:
            from PIL import Image, ImageDraw
            icon_size = 16
            image = Image.new('RGB', (icon_size, icon_size), color='blue')
            draw = ImageDraw.Draw(image)
            
            # Draw a simple heart shape
            draw.ellipse([2, 4, 6, 8], fill='red')
            draw.ellipse([10, 4, 14, 8], fill='red')
            draw.polygon([(8, 12), (4, 8), (12, 8)], fill='red')
            
            return image
        except ImportError:
            # Fallback: create a simple colored square
            try:
                from PIL import Image
                image = Image.new('RGB', (16, 16), color='red')
                return image
            except ImportError:
                # Last resort: return None (will use default icon)
                return None
    
    def setup_tray(self):
        """Setup system tray icon and menu"""
        try:
            icon_image = self.create_tray_icon()
            
            # Create tray menu
            menu = pystray.Menu(
                pystray.MenuItem("Show Window", self.show_from_tray),
                pystray.MenuItem("Settings", self.open_settings),
                pystray.Menu.SEPARATOR,
                pystray.MenuItem("Exit", self.quit_app)
            )
            
            # Create tray icon
            self.tray_icon = pystray.Icon("heartbeat_monitor", icon_image, "Heartbeat Monitor", menu)
            
            # Start tray icon in separate thread
            self.tray_thread = threading.Thread(target=self.tray_icon.run, daemon=True)
            self.tray_thread.start()
            
        except Exception as e:
            print(f"Failed to setup tray: {e}")
    
    def show_from_tray(self):
        """Show window from system tray"""
        if hasattr(self, 'tray_icon') and self.tray_icon:
            self.root.deiconify()  # Show the window
            self.root.lift()  # Bring to front
            self.root.focus_force()  # Focus the window
    
    def quit_app(self):
        """Quit the application"""
        remove_lock_file()
        self.is_monitoring = False
        if hasattr(self, 'tray_icon') and self.tray_icon:
            self.tray_icon.stop()
        self.root.quit()
    
    def on_closing(self):
        """Handle window closing with resource cleanup"""
        # FIXED: Clean up resources before closing
        try:
            import gc
            if hasattr(self, 'fig') and self.fig:
                import matplotlib.pyplot as plt
                plt.close(self.fig)
            gc.collect()
        except Exception as e:
            print(f"Cleanup error: {e}")
            
        remove_lock_file()
        if self.config.get("close_to_tray", True):
            # Hide to tray instead of closing
            self.root.withdraw()
        else:
            # Ask user if they want to quit
            if messagebox.askokcancel("Quit", "Do you want to quit the application?"):
                self.quit_app()

def main():
    # Check if window is already open
    if is_window_already_open():
        print("Heartbeat Monitor is already running!")
        return

    # Set instance as running
    if not create_lock_file():
        print("Failed to create lock file. Another instance may be running.")
        return
    
    try:
        root = tk.Tk()
        app = HeartbeatMonitor(root)
        root.mainloop()
    finally:
        # Ensure lock file is removed even if app crashes
        remove_lock_file()

if __name__ == "__main__":
    main() 