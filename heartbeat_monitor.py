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

# Simple lock file for single instance
LOCK_FILE = ".heartbeat_monitor.lock"

def is_window_already_open():
    """Check if Heartbeat Monitor window is already open"""
    return os.path.exists(LOCK_FILE)

def create_lock_file():
    """Create lock file to indicate instance is running"""
    try:
        with open(LOCK_FILE, 'w') as f:
            f.write(str(os.getpid()))
        # Make the file hidden on Windows
        try:
            import subprocess
            subprocess.run(['attrib', '+h', LOCK_FILE], capture_output=True, check=False)
        except:
            pass  # Ignore if attrib command fails
        return True
    except:
        return False

def remove_lock_file():
    """Remove lock file when instance closes"""
    try:
        if os.path.exists(LOCK_FILE):
            os.remove(LOCK_FILE)
    except:
        pass


class SettingsWindow:
    def __init__(self, parent, config, save_callback):
        self.parent = parent
        self.config = config
        self.save_callback = save_callback
        
        self.window = tk.Toplevel(parent)
        self.window.title("Settings")
        self.window.geometry("500x600")
        self.window.resizable(False, False)
        self.window.transient(parent)
        self.window.grab_set()
        
        self.setup_ui()
        self.load_config_to_ui()
    
    def setup_ui(self):
        # Main frame
        main_frame = ttk.Frame(self.window, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Configure grid weights
        self.window.columnconfigure(0, weight=1)
        self.window.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        
        # Ping Configuration
        ping_frame = ttk.LabelFrame(main_frame, text="Ping Configuration", padding="10")
        ping_frame.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))
        ping_frame.columnconfigure(1, weight=1)
        
        # Target IP
        ttk.Label(ping_frame, text="Target IP:").grid(row=0, column=0, sticky=tk.W, padx=(0, 10))
        self.ip_var = tk.StringVar()
        self.ip_entry = ttk.Entry(ping_frame, textvariable=self.ip_var, width=20)
        self.ip_entry.grid(row=0, column=1, sticky=(tk.W, tk.E), padx=(0, 10))
        
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
        ssh_frame = ttk.LabelFrame(main_frame, text="SSH Monitoring", padding="10")
        ssh_frame.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))
        ssh_frame.columnconfigure(1, weight=1)
        
        # SSH Enable
        self.ssh_enabled_var = tk.BooleanVar()
        self.ssh_check = ttk.Checkbutton(ssh_frame, text="Enable SSH Monitoring", variable=self.ssh_enabled_var)
        self.ssh_check.grid(row=0, column=0, columnspan=2, sticky=tk.W, pady=(0, 10))
        
        # SSH Host
        ttk.Label(ssh_frame, text="SSH Host:").grid(row=1, column=0, sticky=tk.W, padx=(0, 10))
        self.ssh_host_var = tk.StringVar()
        self.ssh_host_entry = ttk.Entry(ssh_frame, textvariable=self.ssh_host_var, width=20)
        self.ssh_host_entry.grid(row=1, column=1, sticky=(tk.W, tk.E), padx=(0, 10))
        
        # SSH Username
        ttk.Label(ssh_frame, text="SSH Username:").grid(row=2, column=0, sticky=tk.W, padx=(0, 10), pady=(5, 0))
        self.ssh_username_var = tk.StringVar()
        self.ssh_username_entry = ttk.Entry(ssh_frame, textvariable=self.ssh_username_var, width=20)
        self.ssh_username_entry.grid(row=2, column=1, sticky=(tk.W, tk.E), padx=(0, 10), pady=(5, 0))
        
        # SSH Password
        ttk.Label(ssh_frame, text="SSH Password:").grid(row=3, column=0, sticky=tk.W, padx=(0, 10), pady=(5, 0))
        self.ssh_password_var = tk.StringVar()
        self.ssh_password_entry = ttk.Entry(ssh_frame, textvariable=self.ssh_password_var, width=20, show="*")
        self.ssh_password_entry.grid(row=3, column=1, sticky=(tk.W, tk.E), padx=(0, 10), pady=(5, 0))
        
        # SSH Command
        ttk.Label(ssh_frame, text="SSH Command:").grid(row=4, column=0, sticky=tk.W, padx=(0, 10), pady=(5, 0))
        self.ssh_command_var = tk.StringVar()
        self.ssh_command_entry = ttk.Entry(ssh_frame, textvariable=self.ssh_command_var, width=40)
        self.ssh_command_entry.grid(row=4, column=1, sticky=(tk.W, tk.E), padx=(0, 10), pady=(5, 0))
        
        # SSH Timeout
        ttk.Label(ssh_frame, text="SSH Timeout (seconds):").grid(row=5, column=0, sticky=tk.W, padx=(0, 10), pady=(5, 0))
        self.ssh_timeout_var = tk.StringVar()
        self.ssh_timeout_entry = ttk.Entry(ssh_frame, textvariable=self.ssh_timeout_var, width=10)
        self.ssh_timeout_entry.grid(row=5, column=1, sticky=tk.W, padx=(0, 10), pady=(5, 0))
        
        # Application Settings
        app_frame = ttk.LabelFrame(main_frame, text="Application Settings", padding="10")
        app_frame.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))
        app_frame.columnconfigure(1, weight=1)
        
        # Close to Tray
        self.close_to_tray_var = tk.BooleanVar()
        self.close_to_tray_check = ttk.Checkbutton(app_frame, text="Close to System Tray", variable=self.close_to_tray_var)
        self.close_to_tray_check.grid(row=0, column=0, columnspan=2, sticky=tk.W)
        
        # Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=3, column=0, columnspan=2, pady=(10, 0))
        
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
        self.ssh_host_var.set(self.config["ssh_host"])
        self.ssh_username_var.set(self.config["ssh_username"])
        self.ssh_password_var.set(self.config["ssh_password"])
        self.ssh_command_var.set(self.config["ssh_command"])
        self.ssh_timeout_var.set(str(self.config["ssh_timeout"]))
        self.close_to_tray_var.set(self.config.get("close_to_tray", True))
    
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
                if not self.ssh_host_var.get().strip():
                    messagebox.showerror("Error", "SSH host is required when SSH monitoring is enabled")
                    return
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
                "ssh_host": self.ssh_host_var.get(),
                "ssh_username": self.ssh_username_var.get(),
                "ssh_password": self.ssh_password_var.get(),
                "ssh_command": self.ssh_command_var.get(),
                "ssh_timeout": ssh_timeout,
                "close_to_tray": self.close_to_tray_var.get()
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
            "target_ip": "8.8.8.8",
            "ping_interval_minutes": 1,
            "ping_interval_seconds": 0,
            "retry_count": 4,
            "retry_delay": 2,
            "ssh_enabled": False,
            "ssh_host": "",
            "ssh_username": "",
            "ssh_password": "",
            "ssh_command": "python3 voltage.py",
            "ssh_timeout": 10,
            "close_to_tray": True
        }
        self.config = self.load_config()
        
        # Monitoring state
        self.is_monitoring = False
        self.monitor_thread = None
        self.downtime_events = deque(maxlen=100)  # FIXED: Limit to prevent memory leaks
        self.ping_history = deque(maxlen=1000)  # FIXED: Increased from 500 for better history
        self.ssh_history = deque(maxlen=1000)   # FIXED: Increased from 500 for better history
        self.last_down_time = None
        self.total_pings = 0
        self.successful_pings = 0
        self.total_ssh = 0
        self.successful_ssh = 0
        
        # FIXED: Add thread synchronization
        self.data_lock = threading.Lock()
        
        # FIXED: Graph update throttling
        self.last_graph_update = 0
        self.graph_update_interval = 5  # Update graph every 5 seconds instead of every second
        
        # FIXED: File I/O optimization
        self.auto_save_counter = 0
        self.auto_save_interval = 10  # Save every 10 events instead of every event
        
        self.setup_ui()
        self.load_config_to_ui()
        self.load_existing_data()
        
        # Schedule a delayed graph update to ensure UI is fully initialized
        # This ensures historical data shows in the graph on startup
        if self.ping_history: # Only schedule if there's historical data
            self.root.after(100, self.update_graph)
        
        # Bind resize event to update graph
        self.root.bind('<Configure>', self.on_window_resize)
        
        # Setup system tray
        self.setup_tray()
        
        # Bind window closing event
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
    
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
        
        # Status row 1
        status_row1 = ttk.Frame(status_frame)
        status_row1.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=(0, 5))
        
        self.status_var = tk.StringVar(value="Ready")
        self.status_label = ttk.Label(status_row1, textvariable=self.status_var, font=("Arial", 10, "bold"))
        self.status_label.pack(side=tk.LEFT)
        
        self.uptime_var = tk.StringVar(value="Uptime: 0%")
        self.uptime_label = ttk.Label(status_row1, textvariable=self.uptime_var, font=("Arial", 10, "bold"))
        self.uptime_label.pack(side=tk.RIGHT)
        
        # Status row 2
        status_row2 = ttk.Frame(status_frame)
        status_row2.grid(row=1, column=0, sticky=(tk.W, tk.E), pady=(0, 5))
        
        self.last_ping_var = tk.StringVar(value="Last ping: Never")
        self.last_ping_label = ttk.Label(status_row2, textvariable=self.last_ping_var)
        self.last_ping_label.pack(side=tk.LEFT)
        
        self.ping_stats_var = tk.StringVar(value="Pings: 0/0 (0%)")
        self.ping_stats_label = ttk.Label(status_row2, textvariable=self.ping_stats_var)
        self.ping_stats_label.pack(side=tk.RIGHT)
        
        # Status row 3
        status_row3 = ttk.Frame(status_frame)
        status_row3.grid(row=2, column=0, sticky=(tk.W, tk.E), pady=(0, 5))
        
        self.last_ssh_var = tk.StringVar(value="Last SSH: Never")
        self.last_ssh_label = ttk.Label(status_row3, textvariable=self.last_ssh_var)
        self.last_ssh_label.pack(side=tk.LEFT)
        
        self.ssh_stats_var = tk.StringVar(value="SSH: 0/0 (0%)")
        self.ssh_stats_label = ttk.Label(status_row3, textvariable=self.ssh_stats_var)
        self.ssh_stats_label.pack(side=tk.RIGHT)
        
        # Status row 4
        status_row4 = ttk.Frame(status_frame)
        status_row4.grid(row=3, column=0, sticky=(tk.W, tk.E))
        
        self.time_since_down_var = tk.StringVar(value="Time since last down: Never")
        self.time_since_down_label = ttk.Label(status_row4, textvariable=self.time_since_down_var)
        self.time_since_down_label.pack(side=tk.LEFT)
        
        self.current_streak_var = tk.StringVar(value="Current streak: 0 pings")
        self.current_streak_label = ttk.Label(status_row4, textvariable=self.current_streak_var)
        self.current_streak_label.pack(side=tk.RIGHT)
        
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
        self.current_time_range = "Last Hour"
    
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
            self.update_time_since_down()
            self.update_uptime_percentage()
            self.update_ping_stats()
            self.update_ssh_stats()
            self.update_current_streak()
            self.optimized_update_graph()  # FIXED: Use throttled graph updates
        
        # Schedule next update
        self.root.after(1000, self.update_ui_timer)
    
    def auto_save_events(self):
        """Auto-save events to file with batching"""
        self.auto_save_counter += 1
        
        if self.auto_save_counter >= self.auto_save_interval:
            try:
                filename = "events_log.txt"
                
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(self.events_text.get(1.0, tk.END))
                
                self.auto_save_counter = 0
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
    
    def optimized_update_graph(self):
        """Update the live monitoring graph with throttling and cleanup"""
        import time
        import gc
        
        current_time = time.time()
        
        # FIXED: Throttle graph updates to reduce CPU usage
        if current_time - self.last_graph_update < self.graph_update_interval:
            return
            
        if len(self.ping_history) < 2:
            return
        
        # FIXED: Clean up old matplotlib objects to prevent memory leaks
        if hasattr(self, 'fig') and self.fig:
            plt.close(self.fig)
        
        # Clear the plot
        self.ax.clear()
        
        # Get filtered data based on current settings
        data = self.get_filtered_data()
        ping_data = data['ping']
        ssh_data = data['ssh']
        
        if not ping_data['times']:
            return
        
        # Create separate arrays for UP and DOWN points
        up_times = []
        up_statuses = []
        down_times = []
        down_statuses = []
        
        for time, status in zip(ping_data['times'], ping_data['statuses']):
            if status == 'UP':
                up_times.append(time)
                up_statuses.append(15)  # UP goes to top
            else:
                down_times.append(time)
                down_statuses.append(5)   # DOWN goes to bottom
        
        # Plot ping status
        if up_times:
            self.ax.plot(up_times, up_statuses, 'bo', markersize=8, label='Ping UP', picker=5)
        if down_times:
            self.ax.plot(down_times, down_statuses, 'ro', markersize=8, label='Ping DOWN', picker=5)
        
        # Plot SSH voltage if available
        if ssh_data['times']:
            self.ax.plot(ssh_data['times'], ssh_data['voltages'], 'g-', linewidth=2, marker='s', markersize=6, label='Voltage (V)', picker=5)
        
        # Set up the graph
        self.ax.set_ylim(0, 16)
        self.ax.set_xlabel('Time')
        self.ax.set_ylabel('Status / Voltage (V)')
        self.ax.set_title(f'Live Monitoring - {self.current_time_range}')
        self.ax.grid(True, alpha=0.3)
        self.ax.legend()
        
        # Format x-axis based on time range
        self.setup_x_axis_format()
        
        # Adjust layout
        self.fig.tight_layout()
        
        # Enable tooltips
        self.canvas.mpl_connect('pick_event', self.on_pick)
        
        # Redraw the canvas
        self.canvas.draw()
        
        # FIXED: Update last graph update time and force garbage collection
        self.last_graph_update = current_time
        gc.collect()
    
    # Removed redundant update_graph method - use optimized_update_graph directly
    
    def get_filtered_data(self):
        """Get data filtered by current time range with thread-safe access"""
        now = datetime.now()
        
        # Calculate time cutoff based on selected range
        time_cutoff = self.get_time_cutoff(now)
        
        # Use helper methods for thread-safe data access
        filtered_ping_times, filtered_ping_statuses = self._get_filtered_ping_data(time_cutoff)
        filtered_ssh_times, filtered_ssh_voltages = self._get_filtered_ssh_data(time_cutoff)
        
        return {
            'ping': {'times': filtered_ping_times, 'statuses': filtered_ping_statuses},
            'ssh': {'times': filtered_ssh_times, 'voltages': filtered_ssh_voltages}
        }
    
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
        
        # Extract minutes from range text
        if "15 Minutes" in range_text:
            minutes = 15
        elif "30 Minutes" in range_text:
            minutes = 30
        elif "Hour" in range_text:
            if "2 Hours" in range_text:
                minutes = 120
            elif "4 Hours" in range_text:
                minutes = 240
            elif "8 Hours" in range_text:
                minutes = 480
            elif "12 Hours" in range_text:
                minutes = 720
            elif "24 Hours" in range_text:
                minutes = 1440
            else:
                minutes = 60
        else:
            minutes = 60  # Default to 1 hour
        
        return now - timedelta(minutes=minutes)
    
    def setup_x_axis_format(self):
        """Setup x-axis formatting based on time range"""
        range_text = self.time_range_var.get()
        
        if "15 Minutes" in range_text or "30 Minutes" in range_text:
            # Show minute intervals for short ranges
            self.ax.xaxis.set_major_formatter(mdates.DateFormatter('%H:%M'))
            self.ax.xaxis.set_major_locator(mdates.MinuteLocator(interval=1))
        elif "Hour" in range_text:
            # Show 5-minute intervals for hourly ranges
            self.ax.xaxis.set_major_formatter(mdates.DateFormatter('%H:%M'))
            self.ax.xaxis.set_major_locator(mdates.MinuteLocator(interval=5))
        elif "2 Hours" in range_text or "4 Hours" in range_text:
            # Show 15-minute intervals for 2-4 hour ranges
            self.ax.xaxis.set_major_formatter(mdates.DateFormatter('%H:%M'))
            self.ax.xaxis.set_major_locator(mdates.MinuteLocator(interval=15))
        elif "8 Hours" in range_text or "12 Hours" in range_text:
            # Show hourly intervals for 8-12 hour ranges
            self.ax.xaxis.set_major_formatter(mdates.DateFormatter('%H:%M'))
            self.ax.xaxis.set_major_locator(mdates.HourLocator(interval=1))
        elif "24 Hours" in range_text:
            # Show 2-hour intervals for 24-hour range
            self.ax.xaxis.set_major_formatter(mdates.DateFormatter('%H:%M'))
            self.ax.xaxis.set_major_locator(mdates.HourLocator(interval=2))
        else:
            # Default formatting
            self.ax.xaxis.set_major_formatter(mdates.DateFormatter('%H:%M'))
            self.ax.xaxis.set_major_locator(mdates.MinuteLocator(interval=5))
        
        plt.setp(self.ax.xaxis.get_majorticklabels(), rotation=45)
    
    def on_time_range_change(self, event=None):
        """Handle time range dropdown change"""
        # Use time_range_var.get() directly instead of storing in redundant variable
        self.update_graph()
    

    
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
        """Main monitoring loop"""
        while self.is_monitoring:
            try:
                current_time = datetime.now()
                
                # Perform ping test
                is_up = self.ping_with_retries()
                self.total_pings += 1
                if is_up:
                    self.successful_pings += 1
                
                # Add to ping history with thread-safe access
                with self.data_lock:
                    self.ping_history.append({
                        'timestamp': current_time,
                        'status': 'UP' if is_up else 'DOWN'
                    })
                
                # Update last ping info
                self.root.after(0, lambda: self.last_ping_var.set(
                    f"Last ping: {current_time.strftime('%Y-%m-%d %H:%M:%S')} - {'UP' if is_up else 'DOWN'}"
                ))
                
                # Perform SSH test if enabled
                ssh_result = None
                voltage = None
                if self.config["ssh_enabled"]:
                    ssh_result, voltage = self.ssh_with_retries()
                    self.total_ssh += 1
                    if ssh_result == 'SUCCESS':
                        self.successful_ssh += 1
                    
                    # Add to SSH history with thread-safe access
                    with self.data_lock:
                        self.ssh_history.append({
                            'timestamp': current_time,
                            'status': ssh_result,
                            'voltage': voltage
                        })
                    
                    # Update last SSH info
                    if voltage is not None:
                        self.root.after(0, lambda: self.last_ssh_var.set(
                            f"Last SSH: {current_time.strftime('%Y-%m-%d %H:%M:%S')} - {voltage:.2f}V"
                        ))
                    else:
                        self.root.after(0, lambda: self.last_ssh_var.set(
                            f"Last SSH: {current_time.strftime('%Y-%m-%d %H:%M:%S')} - FAILED"
                        ))
                
                # Record downtime if down
                if not is_up:
                    self.record_downtime(current_time)
                else:
                    # Log successful ping
                    self.root.after(0, lambda: self.log_event(f"UP: {current_time.strftime('%Y-%m-%d %H:%M:%S')}", "up"))
                
                # Log SSH result
                if self.config["ssh_enabled"]:
                    if ssh_result == 'SUCCESS' and voltage is not None:
                        self.root.after(0, lambda: self.log_event(f"SSH: {voltage:.2f}V", "ssh"))
                    else:
                        self.root.after(0, lambda: self.log_event(f"SSH: FAILED", "ssh_fail"))
                
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
                    self.config["ssh_host"],
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
                        
                    elif 'DOWN:' in line:
                        ping_count += 1
                        self.ping_history.append({
                            'timestamp': timestamp,
                            'status': 'DOWN'
                        })
                        self.last_down_time = timestamp
                        
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
        self.update_graph()
    
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
            self.total_pings = 0
            self.successful_pings = 0
            self.total_ssh = 0
            self.successful_ssh = 0
            self.last_down_time = None
            
            # Now load fresh data
            self.load_existing_data()
            # Data refresh logging handled by secure logging system
        except Exception as e:
            pass  # Error logging handled by secure logging system

    def on_window_resize(self, event):
        """Handle window resize to update graph canvas"""
        if self.is_monitoring:
            self.update_graph()
    
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
    create_lock_file()
    
    root = tk.Tk()
    app = HeartbeatMonitor(root)
    root.mainloop()

if __name__ == "__main__":
    main() 