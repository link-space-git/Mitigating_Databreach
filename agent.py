#!/usr/bin/env python3
"""
File Monitor Agent Sender
Lightweight agent that monitors local file activities and sends them to a central monitor.

Usage:
    python agent_sender.py [monitor_directory] [server_ip] [server_port]

Configuration:
    - Set COMPUTER_A_IP to Computer A's IP address
    - Set COMPUTER_A_PORT to match Computer A's listener port (default: 9999)
"""

import os
import sys
import json
import socket
import time
import logging
from datetime import datetime
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import getpass
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import hashlib

# === CONFIGURATION - EDIT THESE SETTINGS ===
# Computer A's IP address (the central monitor)
COMPUTER_A_IP = "192.168.0.101"  # CHANGE THIS to Computer A's actual IP
COMPUTER_A_PORT = 9999           # Must match the port in file_monitor.py

# Network settings
USE_UDP = True                   # Use UDP for speed (recommended)
SOCKET_TIMEOUT = 5               # Socket timeout in seconds
RETRY_DELAY = 2                  # Delay between retries on network failure

# Monitoring settings
DEFAULT_MONITOR_DIR = os.path.expanduser("~")  # Default directory to monitor
RECURSIVE_MONITORING = True      # Monitor subdirectories

# Duplicate prevention settings
EVENT_DEBOUNCE_TIME = 1        # Time in seconds to wait before sending duplicate events
# === END CONFIGURATION ===

def get_resource_path(relative_path):
    """Get absolute path to resource, works for dev and for PyInstaller"""
    try:
        if getattr(sys, 'frozen', False):
            # Running as compiled .exe
            base_path = os.path.dirname(sys.executable)
        else:
            # Running as Python script
            base_path = os.path.dirname(os.path.abspath(__file__))
        
        path = os.path.join(base_path, relative_path)
        print(f"🔧 Resource path: {relative_path} -> {path}")
        return path
    except Exception as e:
        print(f"❌ Error getting resource path: {e}")
        return relative_path

def setup_logging():
    """Setup logging with correct paths for .exe"""
    log_dir = get_resource_path('logs')
    log_file = os.path.join(log_dir, 'agent.log')
    
    # Create logs directory if it doesn't exist
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)
        print(f"✅ Created log directory: {log_dir}")
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler(sys.stdout)
        ]
    )
    print(f"✅ Logging to: {log_file}")
    return logging.getLogger(__name__)

class PathSelectorGUI:
    """
    Simple GUI for selecting the directory to monitor.
    """
    
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("File Monitor Agent - Path Selector")
        self.root.geometry("550x360")
        self.root.resizable(False, False)
        
        # Center the window on screen
        self.center_window()
        
        # Variable to store the selected path
        self.selected_path = None
        self.server_ip = tk.StringVar(value=COMPUTER_A_IP)
        self.server_port = tk.StringVar(value=str(COMPUTER_A_PORT))
        self.use_udp = tk.BooleanVar(value=USE_UDP)
        self.recursive_monitoring = tk.BooleanVar(value=RECURSIVE_MONITORING)
        
        # Monitoring control variables
        self.is_monitoring = False
        self.observer = None
        self.event_handler = None
        
        self.setup_ui()
        
    def center_window(self):
        """Center the window on the screen"""
        self.root.update_idletasks()
        width = self.root.winfo_width()
        height = self.root.winfo_height()
        x = (self.root.winfo_screenwidth() // 2) - (width // 2)
        y = (self.root.winfo_screenheight() // 2) - (height // 2)
        self.root.geometry(f'{width}x{height}+{x}+{y}')
        
    def setup_ui(self):
        """Setup the user interface"""
        # Main frame with scrollbar if needed
        main_frame = ttk.Frame(self.root, padding="15")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Title
        title_label = ttk.Label(main_frame, text="File Monitor Agent", 
                               font=("Arial", 16, "bold"))
        title_label.pack(pady=(0, 15))
        
        # Path selection frame
        path_frame = ttk.LabelFrame(main_frame, text="Monitoring Directory", padding="10")
        path_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Current path display with scrollbar
        path_container = ttk.Frame(path_frame)
        path_container.pack(fill=tk.X, pady=(0, 10))
        
        self.path_var = tk.StringVar(value=DEFAULT_MONITOR_DIR)
        path_entry = ttk.Entry(path_container, textvariable=self.path_var, state="readonly")
        path_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        # Browse button
        browse_button = ttk.Button(path_container, text="Browse", 
                                  command=self.browse_directory, width=10)
        browse_button.pack(side=tk.RIGHT, padx=(5, 0))
        
        # Network settings frame
        network_frame = ttk.LabelFrame(main_frame, text="Network Settings", padding="10")
        network_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Server IP
        ip_frame = ttk.Frame(network_frame)
        ip_frame.pack(fill=tk.X, pady=5)
        ttk.Label(ip_frame, text="Server IP:", width=12).pack(side=tk.LEFT)
        ip_entry = ttk.Entry(ip_frame, textvariable=self.server_ip)
        ip_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(5, 0))
        
        # Server Port
        port_frame = ttk.Frame(network_frame)
        port_frame.pack(fill=tk.X, pady=5)
        ttk.Label(port_frame, text="Server Port:", width=12).pack(side=tk.LEFT)
        port_entry = ttk.Entry(port_frame, textvariable=self.server_port, width=10)
        port_entry.pack(side=tk.LEFT, padx=(5, 0))
        
        # Protocol selection
        protocol_frame = ttk.Frame(network_frame)
        protocol_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(protocol_frame, text="Settings:", width=12).pack(side=tk.LEFT)
        
        udp_check = ttk.Checkbutton(protocol_frame, text="Use UDP", variable=self.use_udp)
        udp_check.pack(side=tk.LEFT, padx=(5, 15))
        
        recursive_check = ttk.Checkbutton(protocol_frame, text="Recursive Monitoring", 
                       variable=self.recursive_monitoring)
        recursive_check.pack(side=tk.LEFT)
        
        # Button frame
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=15)
        
        # Status label
        self.status_label = ttk.Label(button_frame, text="Select a directory and click 'Start Monitoring'", 
                                     foreground="blue", font=("Arial", 9))
        self.status_label.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        # Control buttons
        self.start_button = ttk.Button(button_frame, text="Start Monitoring", 
                                      command=self.start_monitoring, width=15)
        self.start_button.pack(side=tk.RIGHT, padx=(5, 0))
        
        self.stop_button = ttk.Button(button_frame, text="Stop Monitoring", 
                                     command=self.stop_monitoring, width=15, state="disabled")
        self.stop_button.pack(side=tk.RIGHT, padx=(5, 0))
        
        ttk.Button(button_frame, text="Exit", 
                  command=self.exit_app, width=12).pack(side=tk.RIGHT, padx=(5, 0))
        
    def browse_directory(self):
        """Open directory browser dialog"""
        directory = filedialog.askdirectory(
            initialdir=self.path_var.get(),
            title="Select Directory to Monitor"
        )
        if directory:
            self.path_var.set(directory)
            self.status_label.config(text=f"Selected: {directory}", foreground="green")
    
    def validate_inputs(self):
        """Validate user inputs"""
        # Check if directory exists
        if not os.path.exists(self.path_var.get()):
            messagebox.showerror("Error", f"Directory does not exist: {self.path_var.get()}")
            return False
        
        # Validate IP address
        ip = self.server_ip.get().strip()
        if not ip:
            messagebox.showerror("Error", "Server IP cannot be empty")
            return False
            
        try:
            socket.inet_aton(ip)
        except socket.error:
            messagebox.showerror("Error", "Invalid IP address format")
            return False
        
        # Validate port number
        try:
            port = int(self.server_port.get())
            if not (1 <= port <= 65535):
                raise ValueError("Port out of range")
        except ValueError:
            messagebox.showerror("Error", "Port must be a number between 1 and 65535")
            return False
        
        return True
    
    def start_monitoring(self):
        """Start monitoring with selected settings"""
        if not self.validate_inputs():
            return
            
        if self.is_monitoring:
            messagebox.showinfo("Info", "Monitoring is already running")
            return
            
        try:
            # Create and start the observer
            self.event_handler = FileEventSender(
                self.server_ip.get().strip(), 
                int(self.server_port.get()), 
                self.use_udp.get()
            )
            self.observer = Observer()
            self.observer.schedule(
                self.event_handler, 
                self.path_var.get(), 
                recursive=self.recursive_monitoring.get()
            )
            
            self.observer.start()
            self.is_monitoring = True
            
            # Update UI
            self.start_button.config(state="disabled")
            self.stop_button.config(state="normal")
            self.status_label.config(
                text=f"✅ Monitoring: {self.path_var.get()}", 
                foreground="green"
            )
            
            # Disable configuration inputs while monitoring
            for widget in self.root.winfo_children():
                if isinstance(widget, (ttk.Entry, ttk.Checkbutton)):
                    widget.config(state="disabled")
            
            messagebox.showinfo("Success", f"Started monitoring: {self.path_var.get()}")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to start monitoring: {e}")
    
    def stop_monitoring(self):
        """Stop monitoring"""
        if not self.is_monitoring:
            return
            
        try:
            if self.observer:
                self.observer.stop()
                self.observer.join()
            if self.event_handler:
                self.event_handler._close_socket()
                
            self.is_monitoring = False
            
            # Update UI
            self.start_button.config(state="normal")
            self.stop_button.config(state="disabled")
            self.status_label.config(
                text="Monitoring stopped. Click 'Start Monitoring' to begin again.", 
                foreground="blue"
            )
            
            # Re-enable configuration inputs
            for widget in self.root.winfo_children():
                if isinstance(widget, (ttk.Entry, ttk.Checkbutton)):
                    widget.config(state="normal")
            
            messagebox.showinfo("Info", "Monitoring stopped")
            
        except Exception as e:
            messagebox.showerror("Error", f"Error stopping monitoring: {e}")
    
    def exit_app(self):
        """Exit the application"""
        if self.is_monitoring:
            self.stop_monitoring()
        self.root.quit()
        self.root.destroy()

class FileEventSender(FileSystemEventHandler):
    def __init__(self, server_ip, server_port, use_udp=True):
        print(f"🔧 Initializing FileEventSender: {server_ip}:{server_port}")
        
        self.server_ip = server_ip
        self.server_port = server_port
        self.use_udp = use_udp
        self.hostname = socket.gethostname()
        self.username = getpass.getuser()
        self.socket = None
        
        # Setup logging with correct paths
        self.logger = setup_logging()
        
        # Enhanced duplicate event prevention
        self.last_events = {}
        self.event_lock = threading.Lock()
        self.debounce_time = EVENT_DEBOUNCE_TIME
        
        print("✅ FileEventSender initialized")
        
    def create_socket(self):
        """Create and configure the socket"""
        try:
            if self.use_udp:
                self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                print("✅ UDP socket created")
            else:
                self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.socket.settimeout(5)
                print("✅ TCP socket created")
            return True
        except Exception as e:
            print(f"❌ Failed to create socket: {e}")
            return False
    
    def should_send_event(self, action, path, dest_path=None):
        """Check if we should send this event (duplicate prevention)"""
        with self.event_lock:
            current_time = time.time()
            event_key = f"{action}_{path}_{dest_path}"
            
            # Check if this is a duplicate event
            if event_key in self.last_events:
                time_diff = current_time - self.last_events[event_key]
                if time_diff < self.debounce_time:
                    print(f"🔇 Duplicate event filtered: {event_key}")
                    return False
            
            # Update last event time
            self.last_events[event_key] = current_time
            
            # Clean up old events (prevent memory leak)
            old_events = [key for key, timestamp in self.last_events.items() 
                         if current_time - timestamp > 60]  # Keep for 60 seconds
            for key in old_events:
                del self.last_events[key]
                
            return True
    
    def send_event(self, action, path, dest_path=None):
        """Send a file event to the central monitor with duplicate prevention"""
        # Check if we should send this event
        if not self.should_send_event(action, path, dest_path):
            return False
            
        print(f"📤 Sending event: {action} {path}")
        
        # Create event data
        event_data = {
            "host": self.hostname,
            "user": self.username,
            "action": action,
            "path": path,
            "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]  # Include milliseconds
        }
        
        if dest_path:
            event_data["dest_path"] = dest_path
        
        try:
            json_data = json.dumps(event_data)
            print(f"📦 JSON data prepared")
        except Exception as e:
            print(f"❌ JSON serialization failed: {e}")
            return False
        
        # Send the data
        success = self._send_data(json_data)
        if success:
            print(f"✅ Event sent successfully: {action} - {path}")
            self.logger.info(f"Sent: {action} - {path}")
        else:
            print(f"❌ Failed to send event: {action} - {path}")
            
        return success
    
    def _send_data(self, data):
        """Send data to the server with retry logic"""
        max_retries = 3
        
        for attempt in range(max_retries):
            try:
                # Create socket if needed
                if not self.socket:
                    if not self.create_socket():
                        time.sleep(2)
                        continue
                
                print(f"🔧 Sending attempt {attempt + 1} to {self.server_ip}:{self.server_port}")
                
                # Send data
                if self.use_udp:
                    bytes_sent = self.socket.sendto(data.encode('utf-8'), (self.server_ip, self.server_port))
                    print(f"📡 UDP bytes sent: {bytes_sent}")
                    return True
                else:
                    # TCP implementation
                    if not hasattr(self, 'connected') or not self.connected:
                        self.socket.connect((self.server_ip, self.server_port))
                        self.connected = True
                    self.socket.sendall(data.encode('utf-8'))
                    print("📡 TCP data sent")
                    return True
                
            except Exception as e:
                print(f"💥 Error (attempt {attempt + 1}): {e}")
                self._close_socket()
                
                if attempt < max_retries - 1:
                    print(f"🔄 Retrying in 2 seconds...")
                    time.sleep(2)
        
        print(f"❌ All {max_retries} attempts failed")
        return False
    
    def _close_socket(self):
        """Close the socket"""
        if self.socket:
            try:
                self.socket.close()
            except:
                pass
            self.socket = None
        if hasattr(self, 'connected'):
            self.connected = False
    
    def on_created(self, event):
        if not event.is_directory:
            self.send_event("CREATED", event.src_path)
    
    def on_deleted(self, event):
        if not event.is_directory:
            self.send_event("DELETED", event.src_path)
    
    def on_modified(self, event):
        if not event.is_directory:
            self.send_event("MODIFIED", event.src_path)
    
    def on_moved(self, event):
        if not event.is_directory:
            self.send_event("RENAME", event.src_path, event.dest_path)

def show_gui():
    """Show the GUI for path selection and monitoring control"""
    gui = PathSelectorGUI()
    gui.root.mainloop()

def main():
    """Main function to start the file monitoring agent"""
    # Parse command line arguments (if provided, skip GUI)
    if len(sys.argv) > 1:
        # Use command line arguments
        monitor_dir = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_MONITOR_DIR
        server_ip = sys.argv[2] if len(sys.argv) > 2 else COMPUTER_A_IP
        server_port = int(sys.argv[3]) if len(sys.argv) > 3 else COMPUTER_A_PORT
        use_udp = USE_UDP
        recursive = RECURSIVE_MONITORING
        
        # Validate directory
        if not os.path.exists(monitor_dir):
            print(f"Error: Directory does not exist: {monitor_dir}")
            sys.exit(1)
        
        print(f"File Monitor Agent Starting...")
        print(f"  Monitoring: {monitor_dir}")
        print(f"  Sending to: {server_ip}:{server_port}")
        print(f"  Protocol: {'UDP' if use_udp else 'TCP'}")
        print(f"  Recursive: {recursive}")
        print(f"  Duplicate prevention: Enabled ({EVENT_DEBOUNCE_TIME}s debounce)")
        print("  Press Ctrl+C to stop\n")
        
        # Create and start the observer
        event_handler = FileEventSender(server_ip, server_port, use_udp)
        observer = Observer()
        observer.schedule(event_handler, monitor_dir, recursive=recursive)
        
        try:
            observer.start()
            print(f"✅ Monitoring started on: {monitor_dir}")
            print("   File events will be sent to the central monitor")
            print("   Duplicate events within 0.5 seconds will be filtered out")
            
            # Keep the script running
            while True:
                time.sleep(1)
                
        except KeyboardInterrupt:
            print("\n🛑 Stopping monitor...")
        except Exception as e:
            print(f"❌ Error: {e}")
        finally:
            observer.stop()
            observer.join()
            event_handler._close_socket()
            print("✅ Agent stopped")
    else:
        # Show GUI for configuration and monitoring control
        print("Starting File Monitor Agent GUI...")
        show_gui()
        print("File Monitor Agent closed")

if __name__ == "__main__":
    main()