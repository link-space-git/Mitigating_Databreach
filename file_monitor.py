import os
import sys
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import json
import time
from datetime import datetime
import pandas as pd
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import getpass
import csv
import re
import socket
import psutil
import threading
import subprocess
import requests

from database_manager import db_manager

# === Socket server imports and configuration ===
import socketserver
import threading
from typing import Dict, Any
# Configuration for the network listener
LISTENER_PORT = 9998  # Port for receiving events from remote agents
LISTENER_HOST = '0.0.0.0'  # Listen on all network interfaces
# === END NEW ===

logging_enabled = True
_logging_lock = threading.Lock()

def set_logging_enabled(state: bool):
    """Enable or disable file activity logging globally (thread-safe)"""
    global logging_enabled
    with _logging_lock:
        logging_enabled = state
        status = "ENABLED" if state else "DISABLED"
        print(f"🔧 [LOGGING CONTROL] File activity logging: {status}")
        
        # Add a small delay to ensure the setting propagates
        import time
        time.sleep(0.1)

def is_logging_enabled():
    """Check if logging is enabled (thread-safe)"""
    with _logging_lock:
        return logging_enabled

# Color scheme
DARK_BG = "#0d1117"  
DARK_CARD = "#161b22"  
DARK_HOVER = "#21262d" 
ACCENT_BLUE = "#58a6ff"  
ACCENT_GREEN = "#3fb950"  
ACCENT_RED = "#f85149"  
TEXT_PRIMARY = "#f0f6fc"  
TEXT_SECONDARY = "#8b949e"  

class ModernButton(ttk.Button):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.configure(style="Modern.TButton")
    
class ModernEntry(ttk.Entry):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.configure(style="Modern.TEntry")

class ModernCombobox(ttk.Combobox):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.configure(style="Modern.TCombobox")

# === FIXED: Network Event Receiver Class ===
class NetworkEventReceiver:
    """
    Listens for file events from remote agents over the network.
    Runs as a background thread and integrates with existing logging system.
    """
    
    def __init__(self, gui, port=LISTENER_PORT, host=LISTENER_HOST):
        self.gui = gui
        self.port = port
        self.host = host
        self.running = False
        self.server = None
        self.thread = None
        
    def start(self):
        """Start the network listener in a background thread"""
        if self.running:
            return
            
        try:
            # Create UDP server - FIXED: Use ThreadingUDPServer for better handling
            self.server = socketserver.ThreadingUDPServer((self.host, self.port), NetworkEventHandler)
            self.server.gui = self.gui  # Pass GUI reference to handler
            
            # Start server in a separate thread
            self.thread = threading.Thread(target=self._run_server, daemon=True)
            self.thread.start()
            self.running = True
            
            print(f"📡 Network listener started on port {self.port}")
            self.gui.log_file_event(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] "
                                  f"Network listener started on port {self.port}", "info")
        except Exception as e:
            print(f"❌ Failed to start network listener: {e}")
            self.gui.log_file_event(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] "
                                  f"Failed to start network listener: {e}", "error")
    
    def _run_server(self):
        """Run the UDP server (called in background thread)"""
        try:
            print(f"🔄 UDP Server listening on {self.host}:{self.port}")
            self.server.serve_forever()
        except Exception as e:
            print(f"Network listener error: {e}")
        finally:
            self.running = False
    
    def stop(self):
        """Stop the network listener"""
        if self.server:
            self.server.shutdown()
            self.server.server_close()
        self.running = False
        print("📡 Network listener stopped")

class NetworkEventHandler(socketserver.BaseRequestHandler):
    """
    Handles incoming UDP messages from remote agents with comprehensive
    error handling, validation, and logging capabilities.
    """
    
    def __init__(self, request, client_address, server):
        """Initialize the network event handler"""
        self.event_count = 0
        self.last_event_time = None
        self.client_ip = client_address[0] if client_address else "unknown"
        super().__init__(request, client_address, server)
    
    def setup(self):
        """Called before handle() method - setup the handler"""
        self.last_event_time = datetime.now()
        print(f"🔧 NetworkEventHandler setup for client: {self.client_ip}")
        
    def handle(self):
        try:
            data, socket = self.request
            message = data.decode('utf-8').strip()
            
            # Debug: Print raw message
            print(f"📥 Raw message received: {message}")
            
            # Parse JSON message
            event_data = json.loads(message)
            
            # Validate required fields
            required_fields = ['host', 'user', 'action', 'path', 'timestamp']
            if all(field in event_data for field in required_fields):
                # Validate and fix timestamp format
                if not self._validate_timestamp(event_data['timestamp']):
                    # Try to fix the timestamp or use current time
                    event_data['timestamp'] = self._fix_timestamp_format(event_data['timestamp'])
                
                # Process the remote event through the GUI's event handler
                if hasattr(self.server, 'gui'):
                    self._process_remote_event(event_data)
            else:
                error_msg = f"Missing required fields. Expected: {required_fields}, Got: {list(event_data.keys())}"
                print(f"❌ {error_msg}")
                self._send_error_response(socket, error_msg)
                
        except json.JSONDecodeError as e:
            error_msg = f"JSON decode error: {e}"
            print(f"❌ {error_msg}")
            self._send_error_response(socket, error_msg)
        except Exception as e:
            error_msg = f"Error handling network event: {e}"
            print(f"❌ {error_msg}")
            self._send_error_response(socket, error_msg)
    
    def finish(self):
        """Called after handle() method completes - cleanup"""
        print(f"🔧 NetworkEventHandler finished for {self.client_ip}, processed {self.event_count} events")
    
    def _validate_timestamp(self, timestamp):
        """Validate timestamp format (YYYY-MM-DD HH:MM:SS)"""
        try:
            # Basic format validation
            if not timestamp or len(timestamp) != 19:
                return False
            
            # Try to parse the timestamp
            datetime.strptime(timestamp, '%Y-%m-%d %H:%M:%S')
            return True
        except:
            return False
    
    def _parse_message(self, message: str) -> Dict[str, Any]:
        """
        Parse JSON message with comprehensive error handling.
        
        Args:
            message: JSON string to parse
            
        Returns:
            Dict: Parsed event data or None if parsing fails
        """
        try:
            event_data = json.loads(message)
            
            # Ensure it's a dictionary
            if not isinstance(event_data, dict):
                print("❌ Parsed JSON is not a dictionary")
                return None
            
            return event_data
            
        except json.JSONDecodeError as e:
            print(f"❌ JSON decode error: {e}")
            return None
        except Exception as e:
            print(f"❌ Unexpected parsing error: {e}")
            return None
    
    def _validate_event_data(self, event_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Validate all required fields in the event data.
        
        Args:
            event_data: Dictionary containing event data
            
        Returns:
            Dict: {'valid': bool, 'error': str} validation result
        """
        required_fields = ['host', 'user', 'action', 'path', 'timestamp']
        
        # Check for missing required fields
        missing_fields = [field for field in required_fields if field not in event_data]
        if missing_fields:
            error_msg = f"Missing required fields: {', '.join(missing_fields)}"
            print(f"❌ {error_msg}")
            return {"valid": False, "error": error_msg}
        
        # Validate field types and content
        validation_checks = [
            self._validate_host_field(event_data['host']),
            self._validate_user_field(event_data['user']),
            self._validate_action_field(event_data['action']),
            self._validate_path_field(event_data['path']),
            self._validate_timestamp_field(event_data['timestamp']),
        ]
        
        for check_result in validation_checks:
            if not check_result["valid"]:
                return check_result
        
        # Validate optional dest_path if present
        if 'dest_path' in event_data and event_data['dest_path'] is not None:
            dest_validation = self._validate_path_field(event_data['dest_path'], field_name="dest_path")
            if not dest_validation["valid"]:
                return dest_validation
        
        return {"valid": True, "error": ""}
    
    def _validate_host_field(self, host: str) -> Dict[str, Any]:
        """Validate the host field"""
        if not isinstance(host, str):
            return {"valid": False, "error": "Host must be a string"}
        
        if not host.strip():
            return {"valid": False, "error": "Host cannot be empty"}
        
        if len(host) > 255:
            return {"valid": False, "error": "Host name too long"}
        
        # Basic hostname validation (can be IP or hostname)
        if not re.match(r'^[a-zA-Z0-9\.\-_]+$', host):
            return {"valid": False, "error": "Invalid host format"}
        
        return {"valid": True, "error": ""}
    
    def _validate_user_field(self, user: str) -> Dict[str, Any]:
        """Validate the user field"""
        if not isinstance(user, str):
            return {"valid": False, "error": "User must be a string"}
        
        if not user.strip():
            return {"valid": False, "error": "User cannot be empty"}
        
        if len(user) > 100:
            return {"valid": False, "error": "User name too long"}
        
        # Basic username validation
        if not re.match(r'^[a-zA-Z0-9\.\-_@]+$', user):
            return {"valid": False, "error": "Invalid user format"}
        
        return {"valid": True, "error": ""}
    
    def _validate_action_field(self, action: str) -> Dict[str, Any]:
        """Validate the action field"""
        valid_actions = ['CREATED', 'MODIFIED', 'DELETED', 'RENAME']
        
        if not isinstance(action, str):
            return {"valid": False, "error": "Action must be a string"}
        
        if action not in valid_actions:
            return {"valid": False, "error": f"Invalid action: {action}. Must be one of: {', '.join(valid_actions)}"}
        
        return {"valid": True, "error": ""}
    
    def _validate_path_field(self, path: str, field_name: str = "path") -> Dict[str, Any]:
        """Validate the path field"""
        if not isinstance(path, str):
            return {"valid": False, "error": f"{field_name} must be a string"}
        
        if not path.strip():
            return {"valid": False, "error": f"{field_name} cannot be empty"}
        
        if len(path) > 4096:  # Reasonable path length limit
            return {"valid": False, "error": f"{field_name} too long"}
        
        # Check for path traversal attempts
        if any(segment in path for segment in ['../', '..\\', '://']):
            return {"valid": False, "error": f"Invalid {field_name} - potential path traversal"}
        
        return {"valid": True, "error": ""}
    
    def _validate_timestamp_field(self, timestamp: str) -> Dict[str, Any]:
        """Validate the timestamp field"""
        if not isinstance(timestamp, str):
            return {"valid": False, "error": "Timestamp must be a string"}
        
        if not timestamp.strip():
            return {"valid": False, "error": "Timestamp cannot be empty"}
        
        # Validate timestamp format (YYYY-MM-DD HH:MM:SS)
        timestamp_pattern = r'^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$'
        if not re.match(timestamp_pattern, timestamp):
            return {"valid": False, "error": "Invalid timestamp format. Use: YYYY-MM-DD HH:MM:SS"}
        
        # Validate it's a reasonable date (not in future, not too far in past)
        try:
            event_time = datetime.strptime(timestamp, '%Y-%m-%d %H:%M:%S')
            current_time = datetime.now()
            
            # Allow some tolerance for clock differences
            if event_time > current_time:
                time_diff = event_time - current_time
                if time_diff.total_seconds() > 300:  # 5 minutes in future
                    return {"valid": False, "error": "Timestamp too far in future"}
            
            # Don't accept events from too far in past (1 year)
            if (current_time - event_time).days > 365:
                return {"valid": False, "error": "Timestamp too far in past"}
                
        except ValueError as e:
            return {"valid": False, "error": f"Invalid timestamp: {e}"}
        
        return {"valid": True, "error": ""}
    
    def _process_remote_event(self, event_data: Dict[str, Any]):
        """Process remote file event and log it to remote log section"""
        try:
            # Extract event data
            host = event_data['host']
            user = event_data['user']
            action = event_data['action']
            path = event_data['path']
            timestamp = event_data['timestamp']
            dest_path = event_data.get('dest_path')  # Optional for rename events
            
            # Debug print
            print(f"[REMOTE {host}] {action} {path}")
            if dest_path:
                print(f"           -> {dest_path}")
            
            # Add host to filter dropdown
            self.server.gui.add_remote_host_to_filter(host)
            
            # Use the GUI's REMOTE logging method
            if dest_path:
                log_message = f"[{timestamp}] User: {user}@{host} | {action}: {path} -> {dest_path}"
            else:
                log_message = f"[{timestamp}] User: {user}@{host} | {action}: {path}"
            
            # Log to REMOTE GUI section with appropriate tag
            self.server.gui.log_remote_event(log_message, action.lower())
            
            # Also write to CSV if event handler exists
            if hasattr(self.server.gui, 'event_handler') and self.server.gui.event_handler:
                self.server.gui.event_handler.log_remote_action(event_data)
                
        except Exception as e:
            print(f"❌ Error processing remote event: {e}")
            # Log error to remote section
            error_msg = f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Error processing remote event: {e}"
            self.server.gui.log_remote_event(error_msg, "error")
    
    def _format_log_message(self, host: str, user: str, action: str, path: str, 
                          timestamp: str, dest_path: str = None) -> str:
        """
        Format the log message for display.
        
        Args:
            host: Remote host name
            user: User who performed the action
            action: File action type
            path: File path
            timestamp: Event timestamp
            dest_path: Destination path (for rename events)
            
        Returns:
            str: Formatted log message
        """
        base_message = f"[{timestamp}] User: {user}@{host} | {action}: {path}"
        
        if dest_path:
            return f"{base_message} -> {dest_path}"
        else:
            return base_message

    def _fix_timestamp_format(self, timestamp):
        """Attempt to fix various timestamp formats or use current time"""
        try:
            # Try common timestamp formats
            formats_to_try = [
                '%Y-%m-%d %H:%M:%S',
                '%Y-%m-%d %H:%M:%S.%f',
                '%Y/%m/%d %H:%M:%S',
                '%Y-%m-%dT%H:%M:%S',
                '%Y-%m-%dT%H:%M:%S.%f',
                '%Y%m%d_%H%M%S',
                '%Y%m%d%H%M%S'
            ]
            
            for fmt in formats_to_try:
                try:
                    dt = datetime.strptime(timestamp, fmt)
                    # Convert to standard format
                    return dt.strftime('%Y-%m-%d %H:%M:%S')
                except:
                    continue
            
            # If all parsing fails, use current time
            print(f"⚠️ Could not parse timestamp: {timestamp}, using current time")
            return datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            
        except Exception as e:
            print(f"⚠️ Error fixing timestamp {timestamp}: {e}, using current time")
            return datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    def _send_success_response(self, socket):
        """
        Send success response back to the client.
        
        Args:
            socket: The socket to send response through
        """
        try:
            response = {
                "status": "success",
                "message": "Event processed successfully",
                "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
            response_json = json.dumps(response)
            socket.sendto(response_json.encode('utf-8'), self.client_address)
            
        except Exception as e:
            print(f"❌ Failed to send success response to {self.client_ip}: {e}")
    
    def _send_error_response(self, socket, error_message):
        """Send error response back to the remote agent"""
        try:
            response = {
                "status": "error",
                "message": error_message,
                "expected_timestamp_format": "YYYY-MM-DD HH:MM:SS"
            }
            response_data = json.dumps(response).encode('utf-8')
            socket.sendto(response_data, self.client_address)
            print(f"❌ Sent error response to {self.client_address[0]}: {error_message}")
        except Exception as e:
            print(f"❌ Failed to send error response: {e}")
    
    def _log_error_to_gui(self, error_message: str):
        """
        Log error message to the GUI's remote log section.
        
        Args:
            error_message: Error message to log
        """
        if hasattr(self.server, 'gui'):
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            formatted_message = f"[{timestamp}] NETWORK ERROR: {error_message}"
            self.server.gui.log_remote_event(formatted_message, "error")
    
    def get_handler_stats(self) -> Dict[str, Any]:
        """
        Get statistics for this handler instance.
        
        Returns:
            Dict: Handler statistics
        """
        return {
            "client_ip": self.client_ip,
            "event_count": self.event_count,
            "last_event_time": self.last_event_time.isoformat() if self.last_event_time else None,
            "handler_start_time": self.last_event_time.isoformat() if self.last_event_time else None
        }

class FastIPResolver:
    """Enhanced Fast IP address resolution - Automatic detection for all access types with real-time updates"""
    
    def __init__(self):
        self.local_ips = self._get_local_ips()
        self.host_cache = {}
        self.primary_lan_ip = self._get_primary_lan_ip()
        self.last_known_ip = self.primary_lan_ip
        self.network_status = "Online" if self._is_network_actually_connected() else "Offline"
        self.ip_tracking_active = True
        self.network_change_callbacks = []
        
        # Start background thread for real-time IP monitoring
        self._start_ip_tracking()
    
    def _is_network_actually_connected(self):
        """Check if network is actually connected (not just has an IP)"""
        try:
            # Method 1: Check if we can reach external resources
            socket.setdefaulttimeout(2)
            
            # Try DNS query
            try:
                socket.gethostbyname("google.com")
                return True
            except:
                pass
            
            # Try connecting to common services
            test_servers = [
                ("8.8.8.8", 53),  # Google DNS
                ("1.1.1.1", 53),  # Cloudflare DNS
                ("8.8.8.8", 80),  # Google HTTP
            ]
            
            for server, port in test_servers:
                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                        s.settimeout(2)
                        s.connect((server, port))
                        return True
                except:
                    continue
            
            # Method 2: Check network interfaces status
            for interface, stats in psutil.net_io_counters(pernic=True).items():
                # If any interface has recent activity, consider it connected
                if stats.bytes_sent > 0 or stats.bytes_recv > 0:
                    # But verify the interface is actually up
                    try:
                        addrs = psutil.net_if_addrs().get(interface, [])
                        for addr in addrs:
                            if addr.family == socket.AF_INET and addr.address != "127.0.0.1":
                                return True
                    except:
                        continue
            
            return False
            
        except Exception:
            return False
    
    def _start_ip_tracking(self):
        """Start background thread for real-time IP monitoring"""
        def ip_tracker():
            check_interval = 2  # Check every 2 seconds for faster response
            consecutive_offline_checks = 0
            required_offline_checks = 2  # Require 2 consecutive offline checks to mark as offline
            
            while self.ip_tracking_active:
                try:
                    # Get current IP
                    new_ip = self._get_primary_lan_ip()
                    
                    # Check if network is actually connected
                    is_actually_connected = self._is_network_actually_connected()
                    
                    # Determine new status and IP
                    old_status = self.network_status
                    old_ip = self.primary_lan_ip
                    
                    if not is_actually_connected:
                        consecutive_offline_checks += 1
                        if consecutive_offline_checks >= required_offline_checks:
                            # Network is actually disconnected
                            self.network_status = "Offline"
                            self.primary_lan_ip = "127.0.0.1"
                            consecutive_offline_checks = required_offline_checks  # Prevent overflow
                    else:
                        # Network is connected
                        consecutive_offline_checks = 0
                        if new_ip != "Unknown" and new_ip != "127.0.0.1":
                            self.network_status = "Online"
                            self.primary_lan_ip = new_ip
                            self.last_known_ip = new_ip
                        else:
                            self.network_status = "Offline"
                            self.primary_lan_ip = "127.0.0.1"
                    
                    # Check if status or IP changed
                    ip_changed = old_ip != self.primary_lan_ip
                    status_changed = old_status != self.network_status
                    
                    # Notify if there was a change
                    if ip_changed or status_changed:
                        self._notify_network_change()
                        print(f"IP Changed: {old_ip} -> {self.primary_lan_ip}, Status: {old_status} -> {self.network_status}")
                        
                except Exception as e:
                    print(f"IP tracking error: {e}")
                    # On error, assume offline
                    old_status = self.network_status
                    self.network_status = "Offline"
                    self.primary_lan_ip = "127.0.0.1"
                    if old_status != "Offline":
                        self._notify_network_change()
                
                # Sleep before next check
                time.sleep(check_interval)
        
        # Start the tracking thread
        self.tracking_thread = threading.Thread(target=ip_tracker, daemon=True)
        self.tracking_thread.start()
    
    def _notify_network_change(self):
        """Notify registered callbacks about network changes"""
        for callback in self.network_change_callbacks:
            try:
                callback(self.primary_lan_ip, self.network_status)
            except Exception as e:
                print(f"Error in network change callback: {e}")
    
    def register_network_change_callback(self, callback):
        """Register a callback function to be notified of network changes"""
        self.network_change_callbacks.append(callback)
    
    def stop_ip_tracking(self):
        """Stop the IP tracking thread"""
        self.ip_tracking_active = False
    
    def _get_local_ips(self):
        """Get all local IP addresses quickly"""
        local_ips = set()
        try:
            local_ips.add('127.0.0.1')
            local_ips.add('localhost')
            local_ips.add('::1')
            
            for interface, addrs in psutil.net_if_addrs().items():
                for addr in addrs:
                    if addr.family == socket.AF_INET:
                        ip = addr.address
                        local_ips.add(ip)
        except Exception:
            pass
        
        return local_ips
    
    def _get_primary_lan_ip(self):
        """Get primary LAN IP quickly with enhanced detection"""
        try:
            # Method 1: Check network interfaces and filter only active ones
            active_interfaces = []
            
            for interface, addrs in psutil.net_if_addrs().items():
                # Skip loopback and virtual interfaces
                if interface.startswith(('lo', 'virbr', 'docker', 'veth')):
                    continue
                
                # Check if interface is up and has carrier
                try:
                    stats = psutil.net_if_stats()[interface]
                    if not stats.isup:
                        continue
                except:
                    continue
                    
                for addr in addrs:
                    if addr.family == socket.AF_INET:
                        ip = addr.address
                        if ip != "127.0.0.1" and not ip.startswith('169.254.'):  # Skip APIPA addresses
                            active_interfaces.append((interface, ip))
            
            # Return the first active interface IP
            if active_interfaces:
                return active_interfaces[0][1]
                
        except:
            pass
        
        try:
            # Method 2: Socket connection to external server
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(2)
                s.connect(("8.8.8.8", 80))
                ip = s.getsockname()[0]
                if ip and ip != "127.0.0.1":
                    return ip
        except:
            pass
        
        # Method 3: Fallback to hostname resolution
        try:
            hostname = socket.gethostname()
            ip = socket.gethostbyname(hostname)
            if ip != "127.0.0.1":
                return ip
        except:
            pass
        
        return "Unknown"
    
    def _is_lan_ip(self, ip):
        """Fast LAN IP check"""
        if not ip or ip == "Unknown":
            return False
        try:
            if ip == '127.0.0.1' or ip == 'localhost':
                return True
                
            octets = ip.split('.')
            if len(octets) != 4:
                return False
                
            first_octet = int(octets[0])
            second_octet = int(octets[1])
            
            return (first_octet == 10 or 
                   (first_octet == 172 and 16 <= second_octet <= 31) or
                   (first_octet == 192 and second_octet == 168))
        except:
            return False
    
    def _is_public_ip(self, ip):
        """Check if IP is public (not in private ranges)"""
        if not ip or ip == "Unknown" or ip == "127.0.0.1":
            return False
            
        try:
            octets = ip.split('.')
            if len(octets) != 4:
                return False
                
            first_octet = int(octets[0])
            second_octet = int(octets[1])
            
            # Private IP ranges
            if first_octet == 10:
                return False
            if first_octet == 172 and 16 <= second_octet <= 31:
                return False
            if first_octet == 192 and second_octet == 168:
                return False
            if first_octet == 169 and second_octet == 254:  # APIPA
                return False
            if first_octet == 100 and 64 <= second_octet <= 127:  # CGNAT
                return False
                
            return True
        except:
            return False
    
    def get_current_ip_info(self):
        """Get current IP address and network status"""
        ip_type = "Local/LAN"
        if self.network_status == "Offline" or self.primary_lan_ip == "127.0.0.1":
            ip_type = "Offline"
        elif self._is_public_ip(self.primary_lan_ip):
            ip_type = "External"
        elif self.primary_lan_ip.startswith('169.254.'):
            ip_type = "Hotspot/Local"
        elif self.primary_lan_ip.startswith('100.'):
            ip_type = "CGNAT/Local"
            
        return {
            "ip": self.primary_lan_ip,
            "status": self.network_status,
            "type": ip_type
        }
    
    def get_ssh_client_ip(self):
        """Detect active SSH client IP addresses"""
        ssh_ips = []
        try:
            if os.name == 'posix':  # Linux/macOS
                # Use 'who' command to find SSH connections
                result = subprocess.run(['who'], capture_output=True, text=True, timeout=2)
                if result.returncode == 0:
                    for line in result.stdout.splitlines():
                        if 'pts/' in line:  # Terminal session
                            ip_match = re.search(r'\(([\d\.]+)\)', line)
                            if ip_match:
                                ip = ip_match.group(1)
                                if ip and ip not in self.local_ips and ip != '0.0.0.0':
                                    ssh_ips.append(ip)
            
            # Remove duplicates
            seen = set()
            unique_ssh_ips = []
            for ip in ssh_ips:
                if ip not in seen:
                    seen.add(ip)
                    unique_ssh_ips.append(ip)
            
            return unique_ssh_ips
            
        except (subprocess.TimeoutExpired, subprocess.SubprocessError, Exception):
            return []
    
    def resolve_unc_path_ip_fast(self, path):
        """Fast UNC path resolution"""
        if not path.startswith('\\\\'):
            return None
            
        try:
            parts = path.split('\\')
            if len(parts) >= 3:
                hostname = parts[2]
                if hostname and hostname not in self.local_ips:
                    # Check cache first
                    if hostname in self.host_cache:
                        return self.host_cache[hostname]
                    
                    # Fast resolution
                    try:
                        ip = socket.gethostbyname(hostname)
                        self.host_cache[hostname] = ip
                        return ip
                    except:
                        return None
        except Exception:
            pass
        return None
    
    def detect_ip_for_file_event_auto(self, file_path, action):
        """
        Automatic IP detection for all access types in priority order:
        1️⃣ SSH client IP (highest priority for remote access)
        2️⃣ UNC/Network share IP 
        3️⃣ Current active IP from real-time tracker (always up-to-date)
        """
        current_ip_info = self.get_current_ip_info()
        detected_ip = current_ip_info["ip"]
        network_status = current_ip_info["status"]
        
        # 1️⃣ SSH Client IP Detection (Highest priority for remote access)
        ssh_ips = self.get_ssh_client_ip()
        if ssh_ips:
            detected_ip = ssh_ips[0]
            return detected_ip
        
        # 2️⃣ UNC/Network Share IP Detection
        unc_ip = self.resolve_unc_path_ip_fast(file_path)
        if unc_ip:
            detected_ip = unc_ip
            return detected_ip
        
        # 3️⃣ Current active IP from real-time tracker (always up-to-date)
        if detected_ip != "Unknown":
            # Determine access type based on IP characteristics
            if network_status == "Offline" or detected_ip == "127.0.0.1":
                detected_ip = "127.0.0.1"
            
            return detected_ip
        
        # Final fallback
        return "127.0.0.1"

class FileMonitorEventHandler(FileSystemEventHandler):
    def __init__(self, gui):
        super().__init__()
        self.gui = gui
        self.log_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "log_data"))
        self.csv_file = os.path.join(self.log_dir, "file_activity.csv")
        self.current_user = getpass.getuser()
        self.ip_resolver = FastIPResolver()  # Use enhanced resolver with real-time tracking
        
        # Register for network change notifications
        self.ip_resolver.register_network_change_callback(self.on_network_change)

        # Get the application root directory
        self.app_root_dir = os.path.dirname(os.path.abspath(__file__))
        
        # Get the parent directory of the app (to catch PyInstaller dist folder)
        self.app_parent_dir = os.path.dirname(self.app_root_dir)
        
        # List of specific application subdirectories to ignore
        self.ignored_app_dirs = [
            self.app_root_dir,  # Main app directory
            os.path.join(self.app_root_dir, "log_data"),  # Log directory
            os.path.join(self.app_root_dir, "product"),  # Product directory
            os.path.join(self.app_root_dir, "train"),  # Training directory
            os.path.join(self.app_root_dir, "tools"),  # Tools directory
        ]
        
        # Add PyInstaller related paths
        # Check if running from PyInstaller bundle
        if hasattr(sys, '_MEIPASS'):
            # PyInstaller temp directory
            self.ignored_app_dirs.append(sys._MEIPASS)
            
            # Also ignore the actual executable location
            exe_dir = os.path.dirname(sys.executable)
            self.ignored_app_dirs.append(exe_dir)
            
            # Add common PyInstaller output paths
            pyinstaller_paths = [
                os.path.join(self.app_parent_dir, "dist"),
                os.path.join(self.app_parent_dir, "build"),
                os.path.join(self.app_parent_dir, "__pycache__"),
            ]
            self.ignored_app_dirs.extend(pyinstaller_paths)
        
        # Also ignore any path that contains these patterns
        self.ignored_patterns = [
            '\\dist\\',
            '\\build\\',
            '\\__pycache__\\',
            '\\product\\',
            '\\log_data\\',
            '\\train\\',
            '\\tools\\',
            '_MEI',  # PyInstaller temp folder pattern
        ]
        
        # Ensure log directory exists
        if not os.path.exists(self.log_dir):
            os.makedirs(self.log_dir)
        
        # Initialize CSV file with headers if it doesn't exist
        if not os.path.exists(self.csv_file):
            self.initialize_csv()
    
    def on_network_change(self, new_ip, status):
        """Callback for network changes - log the change"""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        message = f"[{timestamp}] NETWORK CHANGE: IP={new_ip}, Status={status}"
        self.gui.log_file_event(message, "info")
        # Also update the GUI status display
        self.gui.update_network_status_display()
    
    def initialize_csv(self):
        """Create CSV file with headers including IP address"""
        try:
            with open(self.csv_file, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(['timestamp', 'user', 'ip', 'action', 'path', 'dest_path'])
        except Exception as e:
            print(f"Error creating CSV file: {e}")
    
    def should_ignore(self, path):
        """Check if a path should be ignored for logging"""
        abs_path = os.path.abspath(path)
        
        # Ignore application directories
        for ignored_dir in self.ignored_app_dirs:
            if abs_path.startswith(ignored_dir):
                return True
            
        # Check for ignored patterns in the path
        path_lower = abs_path.lower()
        for pattern in self.ignored_patterns:
            if pattern.lower() in path_lower:
                return True
        
        # Enhanced: Ignore backup directories and operations
        backup_keywords = ['backup', 'restore', '.bak', '_backup_']
        if any(keyword in abs_path.lower() for keyword in backup_keywords):
            return True
        
        # Check if this is a backup operation by checking the process
        try:
            import psutil
            current_process = psutil.Process()
            process_name = current_process.name().lower()
            if any(keyword in process_name for keyword in ['backup', 'restore']):
                return True
        except:
            pass
        
        return False
    
    def log_action(self, action, path, dest_path=None):
        """Log file action with automatic IP detection and database logging"""
        # Check if logging is enabled globally (thread-safe)
        from file_monitor import is_logging_enabled
        if not is_logging_enabled():
            return  # Skip logging during backup/restore operations
        
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        user = self.current_user
        
        # Automatic IP detection (always uses current IP)
        ip_address = self.ip_resolver.detect_ip_for_file_event_auto(path, action)
        
        # Write to CSV file
        try:
            with open(self.csv_file, 'a', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow([timestamp, user, ip_address, action, path, dest_path or ''])
        except Exception as e:
            print(f"Error writing to CSV: {e}")
        
        # NEW: Log to database (non-blocking, catch all errors)
        try:
            from database_manager import db_manager
            if hasattr(db_manager, 'enabled') and db_manager.enabled:
                # Determine file type from extension
                file_type = None
                if os.path.isfile(path):
                    ext = os.path.splitext(path)[1]
                    file_type = ext[1:].upper() if ext else 'FILE'
                
                db_manager.log_file_activity(
                    username=user,
                    action=action,
                    file_path=path,
                    file_type=file_type,
                    anomaly_score=None
                )
        except Exception as e:
            # Don't let database errors affect file monitoring
            print(f"⚠️ Database logging error (non-critical): {e}")
        
        # Format log message
        if dest_path:
            message = f"LOCAL | User: {user} | IP: {ip_address} | {action}: {path} -> {dest_path}"
        else:
            message = f"LOCAL | User: {user} | IP: {ip_address} | {action}: {path}"
        
        # Write to session log
        self.gui.write_to_session_log(message)
        
        # Log to GUI
        if dest_path:
            gui_message = f"[{timestamp}] User: {user} | IP: {ip_address} | {action}: {path} -> {dest_path}"
        else:
            gui_message = f"[{timestamp}] User: {user} | IP: {ip_address} | {action}: {path}"
            
        self.gui.log_file_event(gui_message, action.lower())
    
    def log_remote_action(self, event_data):
        """Log remote file action received from network agent"""
        # Check if logging is enabled globally (thread-safe)
        from file_monitor import is_logging_enabled
        if not is_logging_enabled():
            return  # Skip logging during backup/restore operations
        
        timestamp = event_data['timestamp']
        user = event_data['user']
        host = event_data['host']
        action = event_data['action']
        path = event_data['path']
        dest_path = event_data.get('dest_path')
        
        # Use host as IP for remote events
        ip_address = host
        
        # Write to CSV file
        try:
            with open(self.csv_file, 'a', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow([timestamp, f"{user}@{host}", ip_address, action, path, dest_path or ''])
        except Exception as e:
            print(f"Error writing remote event to CSV: {e}")
        
        # ✅ WRITE REMOTE EVENTS TO SESSION LOG
        if dest_path:
            message = f"REMOTE | Host: {host} | User: {user} | {action}: {path} -> {dest_path}"
        else:
            message = f"REMOTE | Host: {host} | User: {user} | {action}: {path}"
        
        self.gui.write_to_session_log(message)
    
    def on_created(self, event):
        if not self.should_ignore(event.src_path):
            self.log_action("CREATED", event.src_path)
    
    def on_deleted(self, event):
        if not self.should_ignore(event.src_path):
            self.log_action("DELETED", event.src_path)
    
    def on_modified(self, event):
        if not self.should_ignore(event.src_path):
            self.log_action("MODIFIED", event.src_path)
    
    def on_moved(self, event):
        if not self.should_ignore(event.src_path):
            self.log_action("RENAME", event.src_path, event.dest_path)

class FileMonitorTab(ttk.Frame):
    def __init__(self, parent, main_app=None):
        super().__init__(parent, style="Dark.TFrame")
        self.main_app = main_app
        
        # Apply styling
        self.bg_color = DARK_BG
        self.card_color = DARK_CARD
        self.hover_color = DARK_HOVER
        self.primary_color = ACCENT_BLUE
        self.text_primary = TEXT_PRIMARY
        self.text_secondary = TEXT_SECONDARY
        
        # Fonts
        self.mono_font = ("Cascadia Code", 9)
        
        # File monitoring variables
        self.monitoring = False
        self.observer = None
        self.monitor_path = os.path.expanduser("~")
        self.log_file_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "file_monitor_logs")
        
        # === FIXED: Network receiver ===
        self.network_receiver = NetworkEventReceiver(self)
        # === END FIXED ===
        
        if not os.path.exists(self.log_file_path):
            os.makedirs(self.log_file_path)
        
        # ✅ CREATE SESSION LOG FILE
        session_timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        self.session_log_file = os.path.join(
            self.log_file_path,
            f"session_{session_timestamp}.log"
        )
        
        # Write session start header
        self.write_to_session_log(f"=== FILE MONITOR SESSION STARTED ===")
        self.write_to_session_log(f"Session: {session_timestamp}")
        self.write_to_session_log(f"Monitor Path: {self.monitor_path}")
        self.write_to_session_log(f"=" * 50)
        
        # Filter variables
        self.filter_action_var = tk.StringVar(value="ALL")
        self.filter_user_var = tk.StringVar()
        self.filter_ip_var = tk.StringVar()
        
        # Remote log filter variables
        self.remote_filter_host_var = tk.StringVar(value="ALL")
        self.remote_filter_action_var = tk.StringVar(value="ALL")
        
        # Initialize UI
        self.create_widgets()
        
        # Load configuration and start monitoring if previously active
        if self.load_monitor_config():
            self.start_file_monitoring()
        
        # === FIXED: Start network receiver automatically ===
        self.start_network_receiver()
        # === END FIXED ===

    def create_widgets(self):
        """Create all GUI widgets for the file monitor tab"""
        # Main container
        main_frame = ttk.Frame(self, style="Dark.TFrame")
        main_frame.pack(fill=tk.BOTH, expand=True, padx=15, pady=15)
        
        # Left panel - Controls
        left_panel = ttk.Frame(main_frame, style="Dark.TFrame")
        left_panel.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 15))
        
        # Path selection card
        path_card = ttk.LabelFrame(left_panel, text="Monitor Directory", style="Card.TFrame")
        path_card.pack(fill=tk.X, pady=(0, 15))
        
        ttk.Label(path_card, text="Directory:", style="Card.TLabel").pack(anchor=tk.W, padx=10, pady=(10, 5))
        
        path_frame = ttk.Frame(path_card, style="Card.TFrame")
        path_frame.pack(fill=tk.X, padx=10, pady=(0, 10))
        
        self.monitor_path_entry = ModernEntry(path_frame)
        self.monitor_path_entry.insert(0, self.monitor_path)
        self.monitor_path_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        browse_btn = ModernButton(path_frame, text="Browse", command=self.browse_monitor_dir, width=8)
        browse_btn.pack(side=tk.RIGHT, padx=(5, 0))
        
        # === FIXED: Network status card ===
        network_card = ttk.LabelFrame(left_panel, text="Network Status", style="Card.TFrame")
        network_card.pack(fill=tk.X, pady=(0, 15))
        
        # Network receiver status
        network_status_frame = ttk.Frame(network_card, style="Card.TFrame")
        network_status_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Label(network_status_frame, text="Remote Agents:", style="Card.TLabel").pack(anchor=tk.W)
        self.network_status_label = ttk.Label(network_status_frame, text="Listening on port 9999", 
                                            style="Secondary.TLabel")
        self.network_status_label.pack(anchor=tk.W)
        
        # Network controls
        network_btn_frame = ttk.Frame(network_card, style="Card.TFrame")
        network_btn_frame.pack(fill=tk.X, padx=10, pady=(0, 10))
        
        ModernButton(network_btn_frame, text="Restart Listener", 
                   command=self.restart_network_receiver).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        ModernButton(network_btn_frame, text="Stop Listener", 
                   command=self.stop_network_receiver).pack(side=tk.RIGHT, fill=tk.X, expand=True)
        # === END FIXED ===
        
        # Filter controls card
        filter_card = ttk.LabelFrame(left_panel, text="Log Filters", style="Card.TFrame")
        filter_card.pack(fill=tk.X, pady=(0, 15))
        
        ttk.Label(filter_card, text="Filter by action:", style="Card.TLabel").pack(anchor=tk.W, padx=10, pady=(10, 5))
        
        # Action filter dropdown
        filter_dropdown = ModernCombobox(
            filter_card,
            textvariable=self.filter_action_var,
            values=["ALL", "CREATED", "MODIFIED", "DELETED", "RENAME"],
            state="readonly",
            width=20
        )
        filter_dropdown.pack(fill=tk.X, padx=10, pady=(0, 10))
        filter_dropdown.bind("<<ComboboxSelected>>", self.apply_log_filters)
        
        # User filter
        ttk.Label(filter_card, text="Filter by user:", style="Card.TLabel").pack(anchor=tk.W, padx=10, pady=(10, 5))
        user_entry = ModernEntry(filter_card, textvariable=self.filter_user_var)
        user_entry.pack(fill=tk.X, padx=10, pady=(0, 10))
        
        # Button frame
        btn_frame = ttk.Frame(filter_card, style="Card.TFrame")
        btn_frame.pack(fill=tk.X, padx=10, pady=(0, 10))
        
        ModernButton(btn_frame, text="Apply Filters", command=self.apply_log_filters).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        ModernButton(btn_frame, text="Clear Filters", command=self.clear_log_filters).pack(side=tk.RIGHT, fill=tk.X, expand=True)
        
        # Control buttons card
        control_card = ttk.LabelFrame(left_panel, text="Monitoring Controls", style="Card.TFrame")
        control_card.pack(fill=tk.X, pady=(0, 15))
        
        self.start_monitor_btn = ModernButton(control_card, text="▶ Start Monitoring", 
                                          command=self.start_file_monitoring)
        self.start_monitor_btn.pack(fill=tk.X, padx=10, pady=10)
        
        self.stop_monitor_btn = ModernButton(control_card, text="⏹ Stop Monitoring", 
                                         command=self.stop_file_monitoring, state="disabled")
        self.stop_monitor_btn.pack(fill=tk.X, padx=10, pady=(0, 10))
        
        # Right panel - log display
        right_panel = ttk.Frame(main_frame, style="Dark.TFrame")
        right_panel.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)
        
        # Create notebook for local and remote logs
        self.log_notebook = ttk.Notebook(right_panel, style="Dark.TNotebook")
        self.log_notebook.pack(fill=tk.BOTH, expand=True)
        
        # Local monitoring tab
        local_tab = ttk.Frame(self.log_notebook, style="Dark.TFrame")
        self.log_notebook.add(local_tab, text="📁 Local Monitoring")
        
        # Remote monitoring tab
        remote_tab = ttk.Frame(self.log_notebook, style="Dark.TFrame")
        self.log_notebook.add(remote_tab, text="🌐 Remote Monitoring")
        
        # Setup local log display
        self.setup_local_log_display(local_tab)
        
        # Setup remote log display
        self.setup_remote_log_display(remote_tab)

    def write_to_session_log(self, message):
        """Write message to session log file"""
        try:
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            log_entry = f"[{timestamp}] {message}"
            
            with open(self.session_log_file, 'a', encoding='utf-8') as f:
                f.write(log_entry + '\n')
                
            print(f"SESSION LOG: {log_entry}")  # Optional: also print to console
        except Exception as e:
            print(f"Error writing to session log: {e}")
    
    def setup_local_log_display(self, parent):
        """Setup local file monitoring log display"""
        # Log frame
        log_card = ttk.LabelFrame(parent, text="Real-time Local File Monitoring", style="Card.TFrame")
        log_card.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Add log counter
        log_header = ttk.Frame(log_card, style="Card.TFrame")
        log_header.pack(fill=tk.X, padx=10, pady=(10, 0))
        
        self.log_count_label = ttk.Label(log_header, text="0 events", style="Secondary.TLabel")
        self.log_count_label.pack(side=tk.RIGHT)
        
        ttk.Label(log_header, text="Local File Activity", style="Card.TLabel").pack(side=tk.LEFT)
        
        # Log display
        log_frame = ttk.Frame(log_card, style="Card.TFrame")
        log_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        self.monitor_log = scrolledtext.ScrolledText(
            log_frame, 
            wrap=tk.WORD, 
            width=80, 
            height=20,
            bg=self.card_color,
            fg=self.text_primary,
            insertbackground=self.text_primary,
            selectbackground=self.hover_color,
            font=self.mono_font,
            relief=tk.FLAT,
            borderwidth=0
        )
        self.monitor_log.pack(fill=tk.BOTH, expand=True)
        
        # Configure tags for different message types
        self.monitor_log.tag_config("created", foreground=ACCENT_GREEN)
        self.monitor_log.tag_config("deleted", foreground=ACCENT_RED)
        self.monitor_log.tag_config("modified", foreground="#ff9d00") 
        self.monitor_log.tag_config("rename", foreground=ACCENT_BLUE)
        self.monitor_log.tag_config("info", foreground=self.text_secondary)
        
        self.monitor_log.insert(tk.END, "Local file monitoring with real-time IP detection ready...\n", "info")
        self.monitor_log.config(state=tk.DISABLED)
    
    def setup_remote_log_display(self, parent):
        """Setup remote file monitoring log display"""
        # Main frame
        main_frame = ttk.Frame(parent, style="Dark.TFrame")
        main_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Remote filters card
        filter_card = ttk.LabelFrame(main_frame, text="Remote Log Filters", style="Card.TFrame")
        filter_card.pack(fill=tk.X, pady=(0, 10))
        
        filter_frame = ttk.Frame(filter_card, style="Card.TFrame")
        filter_frame.pack(fill=tk.X, padx=10, pady=10)
        
        # Host filter
        ttk.Label(filter_frame, text="Filter by host:", style="Card.TLabel").grid(row=0, column=0, sticky=tk.W, padx=(0, 10))
        self.host_filter_combo = ModernCombobox(
            filter_frame,
            textvariable=self.remote_filter_host_var,
            values=["ALL"],
            state="readonly",
            width=15
        )
        self.host_filter_combo.grid(row=0, column=1, padx=(0, 20))
        self.host_filter_combo.bind("<<ComboboxSelected>>", self.apply_remote_filters)
        
        # Action filter
        ttk.Label(filter_frame, text="Filter by action:", style="Card.TLabel").grid(row=0, column=2, sticky=tk.W, padx=(0, 10))
        self.action_filter_combo = ModernCombobox(
            filter_frame,
            textvariable=self.remote_filter_action_var,
            values=["ALL", "CREATED", "MODIFIED", "DELETED", "RENAME"],
            state="readonly",
            width=15
        )
        self.action_filter_combo.grid(row=0, column=3, padx=(0, 20))
        self.action_filter_combo.bind("<<ComboboxSelected>>", self.apply_remote_filters)
        
        # Control buttons
        btn_frame = ttk.Frame(filter_frame, style="Card.TFrame")
        btn_frame.grid(row=0, column=4, sticky=tk.EW)
        
        ModernButton(btn_frame, text="Apply", command=self.apply_remote_filters, width=8).pack(side=tk.LEFT, padx=(0, 5))
        ModernButton(btn_frame, text="Clear", command=self.clear_remote_filters, width=8).pack(side=tk.LEFT, padx=(0, 5))
        ModernButton(btn_frame, text="Clear Logs", command=self.clear_remote_logs, width=10).pack(side=tk.LEFT)
        
        # Log frame
        log_card = ttk.LabelFrame(main_frame, text="Real-time Remote File Monitoring", style="Card.TFrame")
        log_card.pack(fill=tk.BOTH, expand=True)
        
        # Add log counter
        log_header = ttk.Frame(log_card, style="Card.TFrame")
        log_header.pack(fill=tk.X, padx=10, pady=(10, 0))
        
        self.remote_log_count_label = ttk.Label(log_header, text="0 remote events", style="Secondary.TLabel")
        self.remote_log_count_label.pack(side=tk.RIGHT)
        
        ttk.Label(log_header, text="Remote File Activity from Agents", style="Card.TLabel").pack(side=tk.LEFT)
        
        # Log display
        log_frame = ttk.Frame(log_card, style="Card.TFrame")
        log_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        self.remote_monitor_log = scrolledtext.ScrolledText(
            log_frame, 
            wrap=tk.WORD, 
            width=80, 
            height=20,
            bg=self.card_color,
            fg=self.text_primary,
            insertbackground=self.text_primary,
            selectbackground=self.hover_color,
            font=self.mono_font,
            relief=tk.FLAT,
            borderwidth=0
        )
        self.remote_monitor_log.pack(fill=tk.BOTH, expand=True)
        
        # Configure tags for different message types (same as local)
        self.remote_monitor_log.tag_config("created", foreground=ACCENT_GREEN)
        self.remote_monitor_log.tag_config("deleted", foreground=ACCENT_RED)
        self.remote_monitor_log.tag_config("modified", foreground="#ff9d00") 
        self.remote_monitor_log.tag_config("rename", foreground=ACCENT_BLUE)
        self.remote_monitor_log.tag_config("info", foreground=self.text_secondary)
        
        self.remote_monitor_log.insert(tk.END, "Remote file monitoring ready. Waiting for agent connections...\n", "info")
        self.remote_monitor_log.config(state=tk.DISABLED)
        
        # Track known hosts for filtering
        self.known_remote_hosts = set()
    
    def log_remote_event(self, message, msg_type="info"):
        """Log remote file event to the remote log display"""
        self.remote_monitor_log.config(state=tk.NORMAL)
        
        # Insert message with appropriate tag
        self.remote_monitor_log.insert(tk.END, message + "\n", msg_type)
        
        # Auto-scroll to bottom
        self.remote_monitor_log.see(tk.END)
        self.remote_monitor_log.config(state=tk.DISABLED)
        
        # Update remote log count
        self.update_remote_log_count()
    
    def update_remote_log_count(self):
        """Update the remote log count display"""
        try:
            log_content = self.remote_monitor_log.get(1.0, tk.END)
            line_count = len(log_content.splitlines()) - 1  # Subtract 1 for initial message
            self.remote_log_count_label.config(text=f"{line_count} remote events")
        except:
            pass
    
    def add_remote_host_to_filter(self, host):
        """Add a new host to the remote host filter dropdown"""
        if host and host not in self.known_remote_hosts:
            self.known_remote_hosts.add(host)
            
            # Update the combobox values
            current_values = list(self.known_remote_hosts)
            current_values.sort()
            current_values.insert(0, "ALL")
            
            # Update the host filter combobox
            self.host_filter_combo.configure(values=current_values)
    
    def apply_remote_filters(self, event=None):
        """Apply filters to remote log display"""
        host_filter = self.remote_filter_host_var.get()
        action_filter = self.remote_filter_action_var.get()
        
        # Store current scroll position
        current_scroll = self.remote_monitor_log.yview()
        
        self.remote_monitor_log.config(state=tk.NORMAL)
        
        # Show all lines first
        self.remote_monitor_log.tag_configure("filtered", elide=False)
        
        if host_filter == "ALL" and action_filter == "ALL":
            # No filters applied, show all
            self.remote_monitor_log.tag_configure("hidden", elide=False)
            self.log_remote_event("All filters cleared - showing all remote events", "info")
        else:
            # Apply filters by hiding non-matching lines
            content = self.remote_monitor_log.get(1.0, tk.END)
            lines = content.splitlines()
            
            self.remote_monitor_log.delete(1.0, tk.END)
            
            for line in lines:
                show_line = True
                
                # Apply host filter
                if host_filter != "ALL" and host_filter not in line:
                    show_line = False
                
                # Apply action filter
                if action_filter != "ALL" and action_filter.lower() not in line.lower():
                    show_line = False
                
                # Determine message type for coloring
                msg_type = "info"
                if "CREATED" in line:
                    msg_type = "created"
                elif "DELETED" in line:
                    msg_type = "deleted"
                elif "MODIFIED" in line:
                    msg_type = "modified"
                elif "RENAME" in line:
                    msg_type = "rename"
                
                if show_line:
                    self.remote_monitor_log.insert(tk.END, line + "\n", msg_type)
            
            self.log_remote_event(f"Applied filters - Host: {host_filter}, Action: {action_filter}", "info")
        
        # Restore scroll position
        self.remote_monitor_log.yview_moveto(current_scroll[0])
        self.remote_monitor_log.config(state=tk.DISABLED)
        self.update_remote_log_count()
    
    def clear_remote_filters(self):
        """Clear all remote log filters"""
        self.remote_filter_host_var.set("ALL")
        self.remote_filter_action_var.set("ALL")
        self.apply_remote_filters()
    
    def clear_remote_logs(self):
        """Clear the remote log display"""
        self.remote_monitor_log.config(state=tk.NORMAL)
        self.remote_monitor_log.delete(1.0, tk.END)
        self.remote_monitor_log.insert(tk.END, "Remote logs cleared. Waiting for agent connections...\n", "info")
        self.remote_monitor_log.config(state=tk.DISABLED)
        self.update_remote_log_count()
        self.clear_remote_filters()

    # === NETWORK RECEIVER METHODS ===
    def start_network_receiver(self):
        """Start the network event receiver"""
        try:
            self.network_receiver.start()
            self.network_status_label.config(text="Listening on port 9999")
            self.log_remote_event("Network receiver started - listening for remote agents", "info")
        except Exception as e:
            self.network_status_label.config(text=f"Error: {str(e)}")
            self.log_remote_event(f"Failed to start network receiver: {e}", "error")
    
    def stop_network_receiver(self):
        """Stop the network event receiver"""
        try:
            self.network_receiver.stop()
            self.network_status_label.config(text="Stopped")
            self.log_remote_event("Network receiver stopped", "info")
        except Exception as e:
            self.log_remote_event(f"Error stopping network receiver: {e}", "error")
    
    def restart_network_receiver(self):
        """Restart the network event receiver"""
        self.stop_network_receiver()
        time.sleep(1)  # Brief pause
        self.start_network_receiver()

    # === FILE MONITORING METHODS ===
    def browse_monitor_dir(self):
        """Browse for directory to monitor"""
        directory = filedialog.askdirectory(initialdir=self.monitor_path)
        if directory:
            self.monitor_path = directory
            self.monitor_path_entry.delete(0, tk.END)
            self.monitor_path_entry.insert(0, directory)
            self.save_monitor_config()
            
            # Restart monitoring if active
            if self.monitoring:
                self.stop_file_monitoring()
                self.start_file_monitoring()
    
    def start_file_monitoring(self):
        """Start monitoring file system events"""
        if self.monitoring:
            return
        
        try:
            self.monitor_path = self.monitor_path_entry.get()
            if not os.path.exists(self.monitor_path):
                messagebox.showerror("Error", f"Directory does not exist: {self.monitor_path}")
                return
            
            # Create event handler
            self.event_handler = FileMonitorEventHandler(self)
            
            # Create observer
            self.observer = Observer()
            self.observer.schedule(self.event_handler, self.monitor_path, recursive=True)
            self.observer.start()
            
            self.monitoring = True
            self.start_monitor_btn.config(state="disabled")
            self.stop_monitor_btn.config(state="normal")
            
            # ✅ LOG TO SESSION
            self.write_to_session_log(f"STARTED MONITORING: {self.monitor_path}")
            
            self.log_file_event(f"Started monitoring: {self.monitor_path}", "info")
            self.save_monitor_config()
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to start monitoring: {str(e)}")
            self.write_to_session_log(f"MONITORING ERROR: {str(e)}")

    def stop_file_monitoring(self):
        """Stop monitoring file system events"""
        if not self.monitoring or not self.observer:
            return
        
        try:
            self.observer.stop()
            self.observer.join()
            self.monitoring = False
            self.start_monitor_btn.config(state="normal")
            self.stop_monitor_btn.config(state="disabled")
            
            # ✅ LOG TO SESSION
            self.write_to_session_log("STOPPED MONITORING")
            
            self.log_file_event("Stopped file monitoring", "info")
            
        except Exception as e:
            messagebox.showerror("Error", f"Error stopping monitoring: {str(e)}")
            self.write_to_session_log(f"STOP MONITORING ERROR: {str(e)}")
    
    def log_file_event(self, message, msg_type="info"):
        """Log file event to the GUI display"""
        self.monitor_log.config(state=tk.NORMAL)
        
        # Insert message with appropriate tag
        self.monitor_log.insert(tk.END, message + "\n", msg_type)
        
        # Auto-scroll to bottom
        self.monitor_log.see(tk.END)
        self.monitor_log.config(state=tk.DISABLED)
        
        # Update log count
        self.update_log_count()
    
    def update_log_count(self):
        """Update the log count display"""
        try:
            log_content = self.monitor_log.get(1.0, tk.END)
            line_count = len(log_content.splitlines()) - 1  # Subtract 1 for initial message
            self.log_count_label.config(text=f"{line_count} events")
        except:
            pass
    
    def apply_log_filters(self, event=None):
        """Apply filters to log display"""
        action_filter = self.filter_action_var.get()
        user_filter = self.filter_user_var.get().lower()
        
        # Store current scroll position
        current_scroll = self.monitor_log.yview()
        
        self.monitor_log.config(state=tk.NORMAL)
        
        if action_filter == "ALL" and not user_filter:
            # No filters applied, show all
            self.monitor_log.tag_configure("hidden", elide=False)
            self.log_file_event("All filters cleared - showing all events", "info")
        else:
            # Apply filters by hiding non-matching lines
            content = self.monitor_log.get(1.0, tk.END)
            lines = content.splitlines()
            
            self.monitor_log.delete(1.0, tk.END)
            
            for line in lines:
                show_line = True
                
                # Apply action filter
                if action_filter != "ALL" and action_filter not in line:
                    show_line = False
                
                # Apply user filter
                if user_filter and user_filter not in line.lower():
                    show_line = False
                
                # Determine message type for coloring
                msg_type = "info"
                if "CREATED" in line:
                    msg_type = "created"
                elif "DELETED" in line:
                    msg_type = "deleted"
                elif "MODIFIED" in line:
                    msg_type = "modified"
                elif "RENAME" in line:
                    msg_type = "rename"
                
                if show_line:
                    self.monitor_log.insert(tk.END, line + "\n", msg_type)
            
            self.log_file_event(f"Applied filters - Action: {action_filter}, User: {user_filter or 'ALL'}", "info")
        
        # Restore scroll position
        self.monitor_log.yview_moveto(current_scroll[0])
        self.monitor_log.config(state=tk.DISABLED)
        self.update_log_count()
    
    def clear_log_filters(self):
        """Clear all log filters"""
        self.filter_action_var.set("ALL")
        self.filter_user_var.set("")
        self.apply_log_filters()
    
    def save_monitor_config(self):
        """Save monitoring configuration"""
        config = {
            'monitor_path': self.monitor_path,
            'monitoring': self.monitoring
        }
        config_file = os.path.join(os.path.dirname(__file__), "monitor_config.json")
        try:
            with open(config_file, 'w') as f:
                json.dump(config, f)
        except Exception as e:
            print(f"Error saving config: {e}")
    
    def load_monitor_config(self):
        """Load monitoring configuration"""
        config_file = os.path.join(os.path.dirname(__file__), "monitor_config.json")
        try:
            if os.path.exists(config_file):
                with open(config_file, 'r') as f:
                    config = json.load(f)
                
                self.monitor_path = config.get('monitor_path', self.monitor_path)
                self.monitor_path_entry.delete(0, tk.END)
                self.monitor_path_entry.insert(0, self.monitor_path)
                
                return config.get('monitoring', False)
        except Exception as e:
            print(f"Error loading config: {e}")
        return False
    
    def update_network_status_display(self):
        """Update network status display in the GUI"""
        if hasattr(self, 'event_handler') and self.event_handler:
            ip_info = self.event_handler.ip_resolver.get_current_ip_info()
            status_text = f"IP: {ip_info['ip']} | Status: {ip_info['status']} | Type: {ip_info['type']}"
            
            # Update network status label if it exists
            if hasattr(self, 'network_status_label'):
                current_text = self.network_status_label.cget("text")
                if "Listening" in current_text:
                    self.network_status_label.config(text=f"Listening on port 9999 | {status_text}")
    
    def on_close(self):
        """Clean up resources when closing"""
        try:
            # ✅ LOG SESSION END
            self.write_to_session_log("=" * 50)
            self.write_to_session_log("=== FILE MONITOR SESSION ENDED ===")
            
            if self.monitoring:
                self.stop_file_monitoring()
            if hasattr(self, 'network_receiver'):
                self.stop_network_receiver()
            if hasattr(self, 'event_handler') and self.event_handler:
                self.event_handler.ip_resolver.stop_ip_tracking()
        except Exception as e:
            print(f"Error during cleanup: {e}")

class FileMonitorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("File Monitor with Network Integration")
        self.root.geometry("1200x700")
        self.root.configure(bg=DARK_BG)
        
        # Apply modern styling
        self.setup_styles()
        
        # Create notebook for tabs
        self.notebook = ttk.Notebook(root, style="Dark.TNotebook")
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Create file monitor tab
        self.file_monitor_tab = FileMonitorTab(self.notebook, self)
        self.notebook.add(self.file_monitor_tab, text="📁 File Monitor")
        
        # Start the application
        self.root.after(100, self.on_app_start)
    
    def setup_styles(self):
        """Configure modern dark theme styles"""
        style = ttk.Style()
        
        # Configure dark theme
        style.theme_use('clam')
        
        # Configure colors for different styles
        style.configure("Dark.TFrame", background=DARK_BG)
        style.configure("Card.TFrame", background=DARK_CARD)
        style.configure("Card.TLabel", background=DARK_CARD, foreground=TEXT_PRIMARY)
        style.configure("Secondary.TLabel", background=DARK_CARD, foreground=TEXT_SECONDARY)
        
        # Configure notebook
        style.configure("Dark.TNotebook", background=DARK_BG, borderwidth=0)
        style.configure("Dark.TNotebook.Tab", 
                       background=DARK_CARD,
                       foreground=TEXT_SECONDARY,
                       padding=[15, 5])
        style.map("Dark.TNotebook.Tab",
                 background=[("selected", DARK_HOVER)],
                 foreground=[("selected", TEXT_PRIMARY)])
        
        # Configure buttons
        style.configure("Modern.TButton",
                       background=DARK_CARD,
                       foreground=TEXT_PRIMARY,
                       borderwidth=0,
                       focuscolor="none",
                       padding=[10, 5])
        style.map("Modern.TButton",
                 background=[("active", DARK_HOVER), ("pressed", DARK_HOVER)],
                 foreground=[("active", TEXT_PRIMARY)])
        
        # Configure entries
        style.configure("Modern.TEntry",
                       fieldbackground=DARK_CARD,
                       foreground=TEXT_PRIMARY,
                       borderwidth=1,
                       relief="flat")
        
        # Configure combobox
        style.configure("Modern.TCombobox",
                       fieldbackground=DARK_CARD,
                       foreground=TEXT_PRIMARY,
                       background=DARK_CARD,
                       borderwidth=1,
                       relief="flat")
        
        # Configure labelframe
        style.configure("Card.TLabelframe", background=DARK_CARD, foreground=TEXT_PRIMARY)
        style.configure("Card.TLabelframe.Label", background=DARK_CARD, foreground=TEXT_PRIMARY)
    
    def on_app_start(self):
        """Called when application starts"""
        print("File Monitor Application Started")
        print("Network listener should be running on port 9999")

def main():
    root = tk.Tk()
    app = FileMonitorApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()