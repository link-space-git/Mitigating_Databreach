import os
import re
import pandas as pd
import numpy as np
from river import anomaly, preprocessing, compose
from datetime import datetime, timedelta
import time
from collections import deque, defaultdict
import json
import pickle
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading
from sklearn.model_selection import train_test_split
import warnings
warnings.filterwarnings('ignore')

class AlertPopup:
    """Popup alert notification window with update capabilities and auto-close."""
    
    def __init__(self, parent, alert, detector, mass_activities=None):
        # Store the actual FileExplorer GUI instance for notification panel access
        self.gui_parent = parent.gui_parent if hasattr(parent, 'gui_parent') else parent
        # Store the Tk root for window creation
        self.tk_parent = parent.root if hasattr(parent, 'root') else parent
        
        self.alert = alert
        self.detector = detector
        self.mass_activities = mass_activities or []
        self.popup = None
        self.detail_popup = None
        self.is_ransomware_alert = any(keyword in alert['reason'].lower() for keyword in ['ransomware', 'encryption', '.lock', '.enc', '.crypt'])
        self.is_mass_deletion_alert = "MASS DELETION/SABOTAGE" in alert['reason']
        self.auto_close_timer = None
        
        self.create_popup()
        
        # Start auto-close timer (20 seconds)
        self.auto_close_timer = self.popup.after(20000, self.auto_close)
    
    def auto_close(self):
        """Automatically close the popup and move to notification panel."""
        if self.popup and self.popup.winfo_exists():
            try:
                # Cancel any pending auto-close to prevent multiple calls
                if self.auto_close_timer:
                    self.popup.after_cancel(self.auto_close_timer)
                    self.auto_close_timer = None
                
                # Store alert data for notification panel
                alert_data = self.alert.copy()
                alert_data['files_count'] = len(self.mass_activities) if self.mass_activities else 1
                
                # Add IP address to alert data if available
                if 'ip_address' not in alert_data and hasattr(self, 'alert'):
                    alert_data['ip_address'] = self.alert.get('ip_address', 'Unknown')
                
                # Add mass metadata for proper file details
                if hasattr(self, 'mass_activities') and self.mass_activities:
                    alert_data['mass_metadata'] = {
                        'affected_files': self.mass_activities,
                        'count': len(self.mass_activities)
                    }
                
                # FIX: Use gui_parent to access notification panel methods
                if self.gui_parent and hasattr(self.gui_parent, 'add_to_notification_panel'):
                    self.gui_parent.add_to_notification_panel(alert_data)
                    print(f"✅ Auto-closed alert and moved to notification panel: {self.alert['reason']}")
                else:
                    print(f"❌ No GUI parent available for notification panel")
                
                # Clean up and close
                self._on_close()
                
            except Exception as e:
                print(f"❌ Error in auto_close: {e}")
                # Still close the popup even if notification fails
                self._on_close()
    
    def get_timestamp_string(self, timestamp):
        """Safely convert timestamp to string format."""
        if isinstance(timestamp, str):
            return timestamp
        elif hasattr(timestamp, 'strftime'):
            return timestamp.strftime("%Y-%m-%d %H:%M:%S")
        else:
            # Fallback: try to convert to datetime or use current time
            try:
                if hasattr(timestamp, 'isoformat'):
                    return timestamp.isoformat()
                else:
                    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            except:
                return datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    def parse_timestamp(self, timestamp):
        """Safely parse timestamp to datetime object."""
        if isinstance(timestamp, str):
            try:
                # Handle ISO format with timezone
                if timestamp.endswith('Z'):
                    timestamp = timestamp.replace('Z', '+00:00')
                return datetime.fromisoformat(timestamp)
            except ValueError:
                # Try other common formats
                for fmt in ['%Y-%m-%d %H:%M:%S', '%Y-%m-%dT%H:%M:%S', '%Y-%m-%d %H:%M:%S.%f']:
                    try:
                        return datetime.strptime(timestamp, fmt)
                    except ValueError:
                        continue
                # Final fallback
                return datetime.now()
        elif hasattr(timestamp, 'strftime'):
            return timestamp
        else:
            # Fallback to current time
            return datetime.now()
    
    def create_popup(self):
        """Create the main alert popup."""
        # Use tk_parent for window creation
        self.popup = tk.Toplevel(self.tk_parent)
        self.popup.title("Security Alert")
        self.popup.geometry("500x320")  # Slightly increased for IP address
        self.popup.configure(bg='#2c2c2c')
        self.popup.resizable(False, False)
        self.popup.attributes('-topmost', True)
        
        # Store reference for potential updates
        if self.is_ransomware_alert or self.is_mass_deletion_alert:
            self.popup.alert_ref = self
        
        # Header
        header_frame = tk.Frame(self.popup, bg='#ff6b6b', height=40)
        header_frame.pack(fill=tk.X, padx=10, pady=(10, 0))
        header_frame.pack_propagate(False)
        
        alert_title = self.get_alert_title()
        self.header_label = tk.Label(header_frame, text=f"⚠️  SECURITY ALERT - {alert_title}", 
                font=("Arial", 12, "bold"), fg="white", bg='#ff6b6b')
        self.header_label.pack(expand=True)
        
        # Content frame
        content_frame = tk.Frame(self.popup, bg='#2c2c2c')
        content_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Time - Use safe timestamp parsing
        timestamp = self.alert['original_timestamp']
        dt = self.parse_timestamp(timestamp)
        time_str = dt.strftime("%Y-%m-%d %H:%M:%S")
        tk.Label(content_frame, text=f"🕒  {time_str}", 
                font=("Arial", 9), fg="white", bg='#2c2c2c', justify=tk.LEFT).pack(anchor=tk.W, pady=(0, 5))
        
        # Severity
        severity_color = '#ff4757' if self.alert['alert_level'] == 'CRITICAL' else '#ffa502'
        severity_text = f"🔴  {self.alert['alert_level']}"
        tk.Label(content_frame, text=severity_text, 
                font=("Arial", 10, "bold"), fg=severity_color, bg='#2c2c2c').pack(anchor=tk.W, pady=(0, 10))
        
        # Alert message
        alert_msg = self.get_alert_message()
        self.alert_msg_label = tk.Label(content_frame, text=f"ALERT: {alert_msg}", 
                font=("Arial", 10), fg="white", bg='#2c2c2c', justify=tk.LEFT, wraplength=450)
        self.alert_msg_label.pack(anchor=tk.W, pady=(0, 10))
        
        # User
        tk.Label(content_frame, text=f"User: {self.alert['user']}", 
                font=("Arial", 9), fg="white", bg='#2c2c2c').pack(anchor=tk.W, pady=(0, 5))
        
        # IP Address - NEW
        ip_address = self.alert.get('ip_address', 'Unknown')
        tk.Label(content_frame, text=f"IP Address: {ip_address}", 
                font=("Arial", 9), fg="white", bg='#2c2c2c').pack(anchor=tk.W, pady=(0, 5))
        
        # Files count
        files_count = len(self.mass_activities) if self.mass_activities else 1
        self.files_label = tk.Label(content_frame, text=f"Operations: {files_count} file{'s' if files_count > 1 else ''}", 
                font=("Arial", 9), fg="white", bg='#2c2c2c')
        self.files_label.pack(anchor=tk.W, pady=(0, 5))
        
        # Prediction
        prediction = self.get_prediction()
        self.prediction_label = tk.Label(content_frame, text=f"Prediction: {prediction}", 
                font=("Arial", 9), fg="white", bg='#2c2c2c')
        self.prediction_label.pack(anchor=tk.W, pady=(0, 15))
        
        # Button frame
        button_frame = tk.Frame(content_frame, bg='#2c2c2c')
        button_frame.pack(side=tk.BOTTOM, fill=tk.X, pady=(20, 0))
        
        inner_button_frame = tk.Frame(button_frame, bg='#2c2c2c')
        inner_button_frame.pack(expand=True)
        
        # OK button
        ok_btn = tk.Button(inner_button_frame, text="OK", command=self._on_close, 
                        bg='#4ecdc4', fg="white", font=("Arial", 9, "bold"), width=10)
        ok_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        # Details button
        details_btn = tk.Button(inner_button_frame, text="Details ▶", command=self.show_details, 
                            bg='#45aaf2', fg="white", font=("Arial", 9, "bold"), width=12)
        details_btn.pack(side=tk.LEFT)
    
    def update_alert_data(self, new_alert, new_mass_activities):
        """Update existing popup with new alert data."""
        if not self.popup or not self.popup.winfo_exists():
            return False
            
        try:
            # Update alert data
            old_count = len(self.mass_activities) if self.mass_activities else 0
            self.alert = new_alert
            self.mass_activities = new_mass_activities or self.mass_activities
            new_count = len(self.mass_activities) if self.mass_activities else 0
            
            # Update UI elements if they exist
            if hasattr(self, 'files_label'):
                files_count = len(self.mass_activities) if self.mass_activities else 1
                increment = new_count - old_count
                increment_text = f" (+{increment} new)" if increment > 0 else ""
                self.files_label.config(text=f"Operations: {files_count} file{'s' if files_count > 1 else ''}{increment_text}")
            
            # Update alert message
            if hasattr(self, 'alert_msg_label'):
                alert_msg = self.get_alert_message()
                self.alert_msg_label.config(text=f"ALERT: {alert_msg}")
            
            # Update prediction
            if hasattr(self, 'prediction_label'):
                prediction = self.get_prediction()
                self.prediction_label.config(text=f"Prediction: {prediction}")
            
            # Update detail popup if it's open
            if self.detail_popup and self.detail_popup.winfo_exists():
                self._refresh_detail_popup()
            
            print(f"🔄 Updated alert: {old_count} → {new_count} files (+{new_count - old_count})")
            return True
            
        except Exception as e:
            print(f"❌ Error updating alert popup: {e}")
            return False
    
    def _refresh_detail_popup(self):
        """Refresh the details popup with current data."""
        if not self.detail_popup or not self.detail_popup.winfo_exists():
            return
        
        # Close and reopen the details popup to refresh all data
        self.detail_popup.destroy()
        self.detail_popup = None
        self.show_details()
    
    def _on_close(self):
        """Handle popup close and cleanup for all alert types."""
        # Cancel auto-close timer if it exists
        if self.auto_close_timer:
            self.popup.after_cancel(self.auto_close_timer)
            self.auto_close_timer = None
            
        # Generate the popup key that was used to track this popup
        popup_key = self._get_popup_key()
        
        # Remove from active popups tracking
        if popup_key in self.detector.active_popups:
            del self.detector.active_popups[popup_key]
            print(f"🗑️ Removed popup tracking for {popup_key}")
        
        if self.popup:
            self.popup.destroy()

    def _get_popup_key(self):
        """Get the popup key that was used to track this popup."""
        user = self.alert['user']
        ip_address = self.alert.get('ip_address', 'unknown')
        
        # Check if this is a ransomware or mass deletion alert
        is_ransomware = any(keyword in self.alert['reason'].lower() 
                            for keyword in ['ransomware', 'encryption', '.lock', '.enc', '.crypt'])
        is_mass_deletion = "MASS DELETION/SABOTAGE" in self.alert['reason']
        
        if is_ransomware or is_mass_deletion:
            return f"{user}_{ip_address}"
        else:
            action = self.alert.get('action', 'unknown')
            # Use the same normalization as the GUI
            normalized_action = action.upper()
            action_mapping = {
                'CREATED': 'CREATE',
                'DELETED': 'DELETE', 
                'MODIFIED': 'MODIFY',
                'MOVED': 'MOVE',
                'RENAMED': 'RENAME',
                'MASS DELETE': 'DELETE',
                'MASS CREATE': 'CREATE', 
                'MASS MODIFY': 'MODIFY',
                'MASS MOVE': 'MOVE',
                'MASS RENAME': 'RENAME'
            }
            normalized_action = action_mapping.get(normalized_action, normalized_action)
            return f"{user}_{ip_address}_{normalized_action}"
    
    def get_alert_message(self):
        """Generate appropriate alert message based on the anomaly."""
        reason = self.alert['reason']
        
        if "MASS FILE CREATION / DATA FLOODING" in reason:
            return "Mass File Creation / Data Flooding Detected"
        # Check for MASS DELETION patterns
        if "MASS DELETION/SABOTAGE" in reason:
            return "Mass Deletion / Sabotage Detected"
        # Check for ransomware patterns FIRST
        elif any(keyword in reason.lower() for keyword in ['ransomware', 'encryption', '.lock', '.enc', '.crypt', 'encrypted']):
            return "Potential Ransomware / Mass Encryption Detected"
        elif "ransomware encryption" in reason.lower():
            return "Potential Ransomware / Mass Encryption Detected"
        elif "Mass deletion activity" in reason:
            return "Mass file deletion detected"
        elif "Mass file creation" in reason:
            return "Mass file creation activity detected"
        elif "Mass modification activity" in reason:
            return "Mass file modification detected"
        elif "Mass file movement/exfiltration" in reason:
            return "Mass file movement detected"
        elif "Critical data movement" in reason:
            return "Critical data movement detected"
        elif "Sensitive file access" in reason:
            return "Sensitive file access detected"
        elif "Off-hours activity" in reason:
            return "Suspicious off-hours activity"
        elif "System file modification" in reason:
            return "System file modification detected"
        elif "Suspicious destination" in reason:
            return "Suspicious file destination detected"
        else:
            return "Suspicious activity detected"

    def get_prediction(self):
        """Generate appropriate prediction based on the anomaly."""
        reason = self.alert['reason']
        
        if "MASS FILE CREATION / DATA FLOODING" in reason:
            return "Data Flooding Attack / Suspicious Bulk File Creation"
        # Check for MASS DELETION patterns
        if "MASS DELETION/SABOTAGE" in reason:
            return "Ransomware / Mass Deletion"
        # Check for ransomware patterns FIRST
        elif any(keyword in reason.lower() for keyword in ['ransomware', 'encryption', '.lock', '.enc', '.crypt', 'encrypted']):
            return "Ransomware / Mass Encryption Activity (EDR/XDR Level)"
        elif "ransomware encryption" in reason.lower():
            return "Ransomware / Mass Encryption Activity (EDR/XDR Level)"
        elif "Mass deletion activity" in reason:
            return "Ransomware / Mass Deletion"
        elif "Mass file creation" in reason:
            return "Data Flooding Attack / Suspicious Bulk File Creation"
        elif "Mass modification activity" in reason:
            return "Data Corruption Attack / Mass Encryption Activity"
        elif "Mass file movement/exfiltration" in reason:
            return "Mass File Exfiltration / Bulk Data Relocation"
        elif "Critical data movement" in reason:
            return "Data Theft"
        elif "Sensitive file access" in reason:
            return "Unauthorized Access"
        elif "Off-hours activity" in reason:
            return "Suspicious Behavior"
        elif "System file modification" in reason:
            return "System Compromise"
        elif "Suspicious destination" in reason:
            return "Data Exfiltration Attempt"
        else:
            return "Suspicious Behavior"
    
    def show_details(self):
        """Show detailed alert information."""
        if self.detail_popup and self.detail_popup.winfo_exists():
            self.detail_popup.lift()
            return
            
        self.detail_popup = tk.Toplevel(self.popup)
        self.detail_popup.title("Alert Details")
        self.detail_popup.geometry("1200x600")  # Increased width for additional columns
        self.detail_popup.configure(bg='#2c2c2c')
        self.detail_popup.resizable(True, True)
        self.detail_popup.attributes('-topmost', True)
        
        # Header
        header_frame = tk.Frame(self.detail_popup, bg='#45aaf2', height=40)
        header_frame.pack(fill=tk.X, padx=10, pady=(10, 0))
        header_frame.pack_propagate(False)
        
        alert_title = self.get_alert_title()
        tk.Label(header_frame, text=f"🔍  Alert Details - {alert_title}", 
                font=("Arial", 12, "bold"), fg="white", bg='#45aaf2').pack(expand=True)
        
        # Content frame
        content_frame = tk.Frame(self.detail_popup, bg='#2c2c2c')
        content_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Create notebook for tabs
        notebook = ttk.Notebook(content_frame)
        notebook.pack(fill=tk.BOTH, expand=True)
        
        # Details tab
        details_frame = ttk.Frame(notebook, padding=10)
        notebook.add(details_frame, text="Alert Details")
        
        ttk.Label(details_frame, text="Anomaly Details", font=("Arial", 10, "bold")).grid(row=0, column=0, sticky=tk.W, pady=(0, 10))
        
        details_grid = ttk.Frame(details_frame)
        details_grid.grid(row=1, column=0, sticky=tk.W)
        
        # Use safe timestamp parsing
        timestamp = self.alert['original_timestamp']
        dt = self.parse_timestamp(timestamp)
        time_str = dt.strftime("%Y-%m-%d %H:%M:%S")
        
        # Get files count and duration
        files_count = len(self.mass_activities) if self.mass_activities else 1
        duration_text = ""
        
        if self.mass_activities and len(self.mass_activities) > 0:
            first_activity = self.mass_activities[0]
            if 'mass_duration' in first_activity:
                duration_minutes = first_activity['mass_duration']
                minutes = int(duration_minutes)
                seconds = int((duration_minutes - minutes) * 60)
                
                if minutes > 0:
                    duration_text = f"{minutes} minutes {seconds} seconds"
                else:
                    duration_text = f"{seconds} seconds"
        
        # Get IP address from alert
        ip_address = self.alert.get('ip_address', 'Unknown')
        
        details_data = [
            ("Timestamp:", time_str),
            ("Alert Level:", self.alert['alert_level']),
            ("Anomaly Score:", f"{self.alert['anomaly_score']:.3f}"),
            ("Severity Score:", f"{self.alert.get('severity_score', 0)}"),
            ("User:", self.alert['user']),
            ("IP Address:", ip_address),  # NEW IP address field
            ("Action:", self.alert['action']),
            ("Operations:", f"{files_count} file{'s' if files_count > 1 else ''}" + (f" in {duration_text}" if duration_text else "")),
            ("Reason:", self.alert['reason'])
        ]
        
        for i, (label, value) in enumerate(details_data):
            ttk.Label(details_grid, text=label, font=("Arial", 9, "bold")).grid(row=i, column=0, sticky=tk.W, pady=2)
            ttk.Label(details_grid, text=value, font=("Arial", 9)).grid(row=i, column=1, sticky=tk.W, pady=2, padx=(10, 0))
        
        # Files tab - ALWAYS SHOW, even for single files
        files_frame = ttk.Frame(notebook, padding=10)
        notebook.add(files_frame, text="Affected Files")
        
        # Add duration info at the top for mass operations
        if duration_text:
            duration_label = ttk.Label(files_frame, text=f"Mass operation duration: {duration_text}", 
                                    font=("Arial", 10, "bold"))
            duration_label.pack(anchor=tk.W, pady=(0, 10))
        
        # Updated columns to include IP Address and Destination Path
        columns = ("Time", "User", "IP Address", "Action", "File Path", "Destination Path", "Type")
        tree = ttk.Treeview(files_frame, columns=columns, show="headings", height=15)
        
        tree.heading("Time", text="Time")
        tree.heading("User", text="User")
        tree.heading("IP Address", text="IP Address")  # NEW
        tree.heading("Action", text="Action")
        tree.heading("File Path", text="File Path")
        tree.heading("Destination Path", text="Destination Path")  # NEW
        tree.heading("Type", text="Type")
        
        tree.column("Time", width=150)
        tree.column("User", width=100)
        tree.column("IP Address", width=120)  # NEW
        tree.column("Action", width=80)
        tree.column("File Path", width=300)   # Reduced to accommodate additional columns
        tree.column("Destination Path", width=300)  # NEW
        tree.column("Type", width=80)
        
        v_scrollbar = ttk.Scrollbar(files_frame, orient=tk.VERTICAL, command=tree.yview)
        h_scrollbar = ttk.Scrollbar(files_frame, orient=tk.HORIZONTAL, command=tree.xview)
        tree.configure(yscrollcommand=v_scrollbar.set, xscrollcommand=h_scrollbar.set)
        
        tree.pack(fill=tk.BOTH, expand=True)
        v_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        h_scrollbar.pack(side=tk.BOTTOM, fill=tk.X)
        
        if self.mass_activities:
            # Show all affected files
            for activity in self.mass_activities:
                # Extract timestamp
                if 'timestamp' in activity:
                    if hasattr(activity['timestamp'], 'strftime'):
                        time_str = activity['timestamp'].strftime('%Y-%m-%d %H:%M:%S')
                    else:
                        time_str = str(activity['timestamp'])
                else:
                    # Use the alert timestamp as fallback
                    time_str = self.get_timestamp_string(self.alert['original_timestamp'])
                
                # Extract file information
                file_path = activity.get('file_path', 'Unknown')
                file_type = activity.get('file_type', 'Unknown')
                user = activity.get('user', 'Unknown')
                action = activity.get('action', 'Unknown')
                ip_address = activity.get('ip_address', 'Unknown')  # NEW: Get IP from activity
                dest_path = activity.get('dest_path', '')  # NEW: Get destination path
                
                tree.insert("", tk.END, values=(time_str, user, ip_address, action, file_path, dest_path, file_type))
        else:
            # Single file alert - show the file from alert data
            time_str = self.get_timestamp_string(self.alert['original_timestamp'])
            file_path = self.alert.get('file_path', 'Unknown')
            file_type = self.alert.get('file_type', 'Unknown')
            user = self.alert.get('user', 'Unknown')
            action = self.alert.get('action', 'Unknown')
            ip_address = self.alert.get('ip_address', 'Unknown')  # NEW
            dest_path = self.alert.get('dest_path', '')  # NEW: Get destination path from alert
            
            tree.insert("", tk.END, values=(time_str, user, ip_address, action, file_path, dest_path, file_type))
        
        # REMOVED: Explanation tab and its contents
        
        button_frame = ttk.Frame(content_frame)
        button_frame.pack(fill=tk.X, pady=(10, 0))
        ttk.Button(button_frame, text="Close", command=self.detail_popup.destroy).pack()
    
    def get_anomaly_explanation(self):
        """Generate explanation for the anomaly."""
        explanation = "This alert was triggered because:\n\n"
        
        # Calculate duration for mass activities
        duration_text = ""
        if self.mass_activities and len(self.mass_activities) > 0:
            first_activity = self.mass_activities[0]
            if 'mass_duration' in first_activity:
                duration_minutes = first_activity['mass_duration']
                minutes = int(duration_minutes)
                seconds = int((duration_minutes - minutes) * 60)
                
                if minutes > 0:
                    duration_text = f"{minutes} minutes {seconds} seconds"
                else:
                    duration_text = f"{seconds} seconds"
        
        # Get IP address for explanation
        ip_address = self.alert.get('ip_address', 'Unknown')
        
        # Check for MASS DELETION patterns
        if "MASS DELETION/SABOTAGE" in self.alert['reason']:
            count = len(self.mass_activities) if self.mass_activities else 1
            explanation += f"- User '{self.alert['user']}' (IP: {ip_address}) performed {count} deletion operations"
            if duration_text:
                explanation += f" within {duration_text}"
            explanation += "\n"
            explanation += "- This exceeds the mass deletion threshold (20+ files in 60 seconds)\n"
            explanation += "- Pattern indicates potential data sabotage or destructive attack\n"
            explanation += "- Multiple files were permanently removed in rapid succession\n"
        # Check for ransomware patterns FIRST
        elif any(keyword in self.alert['reason'].lower() for keyword in ['ransomware', 'encryption', '.lock', '.enc', '.crypt']):
            count = len(self.mass_activities) if self.mass_activities else 1
            explanation += f"- User '{self.alert['user']}' (IP: {ip_address}) performed {count} file operations with ransomware patterns\n"
            explanation += "- Files were modified and/or renamed with encrypted extensions (.lock, .enc, .crypt, etc.)\n"
            explanation += "- Multiple file types were affected simultaneously\n"
            explanation += "- High-frequency activity detected in short time window\n"
            explanation += "- This matches known ransomware encryption behavior patterns\n"
        elif "ransomware encryption" in self.alert['reason'].lower():
            count = len(self.mass_activities) if self.mass_activities else 1
            explanation += f"- User '{self.alert['user']}' (IP: {ip_address}) performed {count} file operations with ransomware patterns\n"
            explanation += "- Files were modified and/or renamed with encrypted extensions (.lock, .enc, .crypt, etc.)\n"
            explanation += "- Multiple file types were affected simultaneously\n"
            explanation += "- High-frequency activity detected in short time window\n"
        elif "Mass deletion activity" in self.alert['reason']:
            count = len(self.mass_activities) if self.mass_activities else 1
            explanation += f"- User '{self.alert['user']}' (IP: {ip_address}) performed {count} deletion operations"
            if duration_text:
                explanation += f" within {duration_text}"
            explanation += "\n"
        elif "Mass file movement/exfiltration" in self.alert['reason']:
            count = len(self.mass_activities) if self.mass_activities else 1
            explanation += f"- User '{self.alert['user']}' (IP: {ip_address}) performed {count} move/copy operations"
            if duration_text:
                explanation += f" within {duration_text}"
            explanation += "\n"
            # Add destination path information if available
            if self.mass_activities and any('dest_path' in activity for activity in self.mass_activities):
                dest_paths = set(activity.get('dest_path', '') for activity in self.mass_activities if activity.get('dest_path'))
                if dest_paths:
                    explanation += f"- Files were moved to: {', '.join(dest_paths)}\n"
        elif "Mass file creation" in self.alert['reason']:
            count = len(self.mass_activities) if self.mass_activities else 1
            explanation += f"- User '{self.alert['user']}' (IP: {ip_address}) performed {count} creation operations"
            if duration_text:
                explanation += f" within {duration_text}"
            explanation += "\n"
        elif "Mass modification activity" in self.alert['reason']:
            count = len(self.mass_activities) if self.mass_activities else 1
            explanation += f"- User '{self.alert['user']}' (IP: {ip_address}) performed {count} modification operations"
            if duration_text:
                explanation += f" within {duration_text}"
            explanation += "\n"
        
        if "Critical data movement" in self.alert['reason']:
            explanation += f"- User '{self.alert['user']}' (IP: {ip_address}) moved/copied files with critical extensions\n"
            if self.mass_activities and any('dest_path' in activity for activity in self.mass_activities):
                dest_paths = set(activity.get('dest_path', '') for activity in self.mass_activities if activity.get('dest_path'))
                if dest_paths:
                    explanation += f"- Destination paths: {', '.join(dest_paths)}\n"
        
        if "Sensitive file access" in self.alert['reason']:
            explanation += f"- User '{self.alert['user']}' (IP: {ip_address}) accessed files that may contain sensitive information\n"
            
        if "Off-hours activity" in self.alert['reason']:
            alert_time = datetime.fromisoformat(self.alert['original_timestamp'])
            explanation += f"- Activity occurred during off-hours ({alert_time.strftime('%H:%M')}) from IP: {ip_address}\n"
            
        if "System file modification" in self.alert['reason']:
            explanation += f"- System files were modified from IP: {ip_address}, which could indicate system compromise\n"
            
        if "Suspicious destination" in self.alert['reason']:
            explanation += f"- Files were moved to suspicious locations from IP: {ip_address}\n"
            if self.mass_activities and any('dest_path' in activity for activity in self.mass_activities):
                dest_paths = set(activity.get('dest_path', '') for activity in self.mass_activities if activity.get('dest_path'))
                if dest_paths:
                    explanation += f"- Suspicious destinations: {', '.join(dest_paths)}\n"
            
        if "High anomaly score" in self.alert['reason']:
            explanation += f"- The anomaly detection algorithm scored this activity as highly suspicious ({self.alert['anomaly_score']:.3f})\n"
            
        if "Suspicious pattern" in self.alert['reason']:
            explanation += f"- The activity matched known suspicious patterns in the detection system\n"
            
        if "High severity score" in self.alert['reason']:
            severity_score = self.alert.get('severity_score', 0)
            explanation += f"- Multiple risk factors contributed to high severity score ({severity_score})\n"
        
        explanation += f"\nThe anomaly detection score was: {self.alert['anomaly_score']:.3f}"
        
        return explanation
    
    def get_recommended_actions(self):
        """Generate recommended actions based on the anomaly type."""
        actions = ""
        
        reason = self.alert['reason']
        ip_address = self.alert.get('ip_address', 'Unknown')
        
        # Check for MASS DELETION patterns
        if "MASS DELETION/SABOTAGE" in reason:
            actions += f"- IMMEDIATELY: Isolate the affected system from IP {ip_address}\n"
            actions += "- Check if backups are available and current\n"
            actions += "- Block user account and IP address at firewall\n"
            actions += "- Investigate if this was intentional or malicious\n"
            actions += "- Check for ransomware indicators (may be prelude to encryption)\n"
            actions += "- Preserve system logs for forensic analysis\n"
            actions += "- Contact incident response team immediately\n"
        # Check for ransomware patterns FIRST
        elif any(keyword in reason.lower() for keyword in ['ransomware', 'encryption', '.lock', '.enc', '.crypt']):
            actions += "- IMMEDIATELY: Isolate the affected host from the network\n"
            actions += f"- Block IP address {ip_address} at firewall\n"
            actions += "- Disconnect from all network connections (LAN/WiFi)\n"
            actions += "- Verify and restore from clean backups if available\n"
            actions += "- Scan with anti-malware/EDR tools\n"
            actions += "- Check for ransom notes and encryption indicators\n"
            actions += "- Contact incident response team immediately\n"
            actions += "- Do NOT pay any ransom demands\n"
            actions += "- Preserve system state for forensic analysis\n"
        elif "ransomware encryption" in reason.lower():
            actions += "- IMMEDIATELY: Isolate the affected host from the network\n"
            actions += f"- Block IP address {ip_address} at firewall\n"
            actions += "- Disconnect from all network connections (LAN/WiFi)\n"
            actions += "- Verify and restore from clean backups if available\n"
            actions += "- Scan with anti-malware/EDR tools\n"
            actions += "- Check for ransom notes and encryption indicators\n"
            actions += "- Contact incident response team immediately\n"
        
        if "Mass deletion" in reason:
            actions += f"- Check if IP {ip_address} is authorized for these operations\n"
            actions += "- Immediately check if backups are available and current\n"
            actions += "- Contact the user to verify if this was intentional\n"
            actions += "- Check for ransomware indicators on the system\n"
            actions += "- Consider temporarily suspending user account\n"
        
        if "Mass movement" in reason or "exfiltration" in reason:
            actions += f"- Check network logs for data exfiltration from IP {ip_address}\n"
            actions += "- Verify if user/IP has authorization for these operations\n"
            actions += "- Review accessed files for sensitivity classification\n"
            actions += "- Consider blocking external transfers from this IP\n"
            # Check destination paths for suspicious locations
            if self.mass_activities and any('dest_path' in activity for activity in self.mass_activities):
                dest_paths = set(activity.get('dest_path', '') for activity in self.mass_activities if activity.get('dest_path'))
                suspicious_dests = [path for path in dest_paths if any(susp in path.lower() for susp in ['temp', 'tmp', 'download', 'usb', 'external'])]
                if suspicious_dests:
                    actions += f"- Investigate suspicious destinations: {', '.join(suspicious_dests)}\n"
        
        if "Mass creation" in reason:
            actions += f"- Verify if IP {ip_address} has authorization to create these files\n"
            actions += "- Check for malware or suspicious content in created files\n"
        
        if "Mass modification" in reason:
            actions += f"- Verify if IP {ip_address} has authorization to modify these files\n"
            actions += "- Check file integrity and compare with backups\n"
        
        if "Critical data" in reason:
            actions += f"- Verify if IP {ip_address} has authorization to access these files\n"
            actions += "- Review data classification policies\n"
            actions += "- Consider implementing additional access controls\n"
        
        if "Off-hours" in reason:
            actions += f"- Verify if IP {ip_address} has authorization for off-hours work\n"
            actions += "- Check if this aligns with user's typical work patterns\n"
            
        if "Suspicious destination" in reason:
            actions += f"- Check destination devices for unauthorized data transfers from IP {ip_address}\n"
            actions += "- Review data loss prevention policies\n"
            actions += "- Verify if user has business need for these transfers\n"
        
        if not actions:
            actions = f"- Review activity from IP {ip_address} to determine if it's legitimate\n"
            actions += "- Check if user/IP has appropriate permissions\n"
            actions += "- Monitor for similar activities from this IP address\n"
        
        actions += f"- Document this incident with IP {ip_address} in the security log\n"
        actions += "- Update detection rules if this is a false positive\n"
        
        return actions
    
    def get_alert_title(self):
        """Generate appropriate title for the details popup."""
        # Check for MASS DELETION patterns
        if "MASS FILE CREATION / DATA FLOODING" in self.alert['reason']:
            return "Mass File Creation / Data Flooding Detected"
        elif "MASS DELETION/SABOTAGE" in self.alert['reason']:
            return "Mass Deletion / Sabotage Detected"
        # Check for ransomware patterns FIRST
        elif any(keyword in self.alert['reason'].lower() for keyword in ['ransomware', 'encryption', '.lock', '.enc', '.crypt']):
            return "Ransomware / Mass Encryption Detected"
        elif "ransomware encryption" in self.alert['reason'].lower():
            return "Ransomware / Mass Encryption Detected"
        elif "Mass deletion activity" in self.alert['reason']:
            return "Multiple Files Deleted"
        elif "Mass file creation" in self.alert['reason']:
            return "Multiple Files Created"
        elif "Mass modification activity" in self.alert['reason']:
            return "Multiple Files Modified"
        elif "Mass file movement/exfiltration" in self.alert['reason']:
            return "Multiple Files Moved"
        elif "Critical data movement" in self.alert['reason']:
            return "Critical Data Movement"
        elif "Sensitive file access" in self.alert['reason']:
            return "Sensitive File Access"
        elif "Off-hours activity" in self.alert['reason']:
            return "Off-Hours Activity"
        elif "System file modification" in self.alert['reason']:
            return "System File Modification"
        elif "Suspicious destination" in self.alert['reason']:
            return "Suspicious File Destination"
        else:
            return "Suspicious Activity"

class AutomatedAnomalyDetectorGUI:
    
    def __init__(self, root):
        self.root = root
        self.detector = AnomalyDetector()
        self.gui_parent = None 
        
        # Define model persistence paths
        self.model_path = "product/trained_model.pkl"
        self.training_flag_path = "product/training_completed.flag"
        
        # Load model state automatically on startup
        self.detector.load_state()
        
        self.monitoring = False
        self.monitor_thread = None
        self.recent_anomalies = deque(maxlen=50)
        self.mass_activities = defaultdict(list)
        self.training_in_progress = False
        self.alert_feature_cache = {}
        self.alert_counter = 0
        
        # Track current CSV monitoring state
        self.current_csv_path = None
        self.last_processed_time = self._load_last_processed_time()
        
        # Notification Panel state
        self.notification_panel_visible = False
        self.notification_panel = None
        self.notification_frame = None
        self.notification_alerts = []  # Store alerts that have moved to notification panel
        
        # Fixed file paths for automatic operation
        self.csv_path_var = tk.StringVar(value=r"log_data/file_activity.csv")
        self.training_data_path = r"train/training_baseline_link_only.csv"
        
        self.setup_gui()
        
        # Auto-start monitoring after a short delay to let GUI initialize
        self.root.after(2000, self.auto_start)

    def auto_start(self):
        """Automatically load training data ONLY if no trained model exists."""
        print("🚀 Starting automatic initialization...")
        
        # Check if model is already trained and saved
        if self._is_model_trained():
            print("✅ Trained model detected. Skipping training data load.")
            self.status_var.set("Trained model loaded - Starting monitoring...")
            
            # Start monitoring immediately with existing model
            self.root.after(1000, self.start_monitoring_after_training)
        else:
            print("🧠 No trained model found. Training new model...")
            # First, load training data
            print("📂 Automatically loading training data on startup...")
            self.load_training_data(file_path=self.training_data_path)

    def _is_model_trained(self):
        """Check if a trained model already exists."""
        # Check multiple indicators of trained model
        model_exists = (
            self.detector.baseline_trained or  # Model is already trained in memory
            os.path.exists(self.model_path) or  # Model file exists
            os.path.exists(self.training_flag_path)  # Training completion flag exists
        )
        
        if model_exists and not self.detector.baseline_trained:
            # Model file exists but not loaded in memory - load it
            print("📂 Found saved model file, loading...")
            success = self._load_trained_model()
            if success:
                self.update_model_status_display()
                return True
            else:
                print("❌ Failed to load saved model. Will retrain.")
                return False
        
        return self.detector.baseline_trained

    def _load_trained_model(self):
        """Load a previously trained model from file."""
        try:
            if os.path.exists(self.model_path):
                with open(self.model_path, "rb") as f:
                    saved_state = pickle.load(f)
                
                # Restore the detector state
                self.detector.model = saved_state.get('model')
                self.detector.normal_threshold = saved_state.get('normal_threshold', 0.5)
                self.detector.anomaly_threshold = saved_state.get('anomaly_threshold', 0.8)
                self.detector.baseline_trained = saved_state.get('baseline_trained', False)
                self.detector.training_samples = saved_state.get('training_samples', 0)
                
                print("✅ Loaded existing trained model from file.")
                print(f"   Thresholds: normal={self.detector.normal_threshold:.3f}, anomaly={self.detector.anomaly_threshold:.3f}")
                return True
        except Exception as e:
            print(f"❌ Error loading trained model: {e}")
        
        return False

    def start_monitoring_after_training(self):
        """Start monitoring after training has completed successfully."""
        try:
            csv_path = self.csv_path_var.get()
            if not os.path.exists(csv_path):
                print(f"❌ CSV file not found: {csv_path}")
                return
            
            # Use the interval from the GUI settings
            interval = int(self.interval_var.get())
            
            # Start monitoring using the same logic as the manual start
            if not self.monitoring:
                # RESET monitoring state for fresh start
                self.current_csv_path = csv_path
                self.last_processed_time = None
                
                # Clear only popup tracking, keep ransomware state
                self.detector.active_popups.clear()
                
                self.monitoring = True
                self.status_var.set(f"Auto-monitoring {os.path.basename(csv_path)}...")
                
                # Refresh ransomware popups after starting
                self.root.after(1000, self.refresh_ransomware_popups)
                
                self.monitor_thread = threading.Thread(
                    target=self.monitor_file,
                    args=(csv_path, interval),
                    daemon=True
                )
                self.monitor_thread.start()
                
                print(f"✅ Started monitoring {csv_path}")
                print(f"   Interval: {interval} seconds")
                print(f"   Model trained: {self.detector.baseline_trained}")
                print(f"   Training samples: {self.detector.training_samples}")
                
            else:
                print("⚠️ Monitoring is already running")
                
        except Exception as e:
            print(f"❌ Error starting automatic monitoring: {e}")

    def normalize_action(self, action):
        if not action or action == 'Unknown':
            return 'UNKNOWN'
        
        # Convert to uppercase and strip whitespace
        action_upper = action.upper().strip()
        
        # Action normalization mapping
        action_mapping = {
            'CREATED': 'CREATE',
            'DELETED': 'DELETE', 
            'MODIFIED': 'MODIFY',
            'MOVED': 'MOVE',
            'RENAMED': 'RENAME',
            'MASS DELETE': 'DELETE',
            'MASS CREATE': 'CREATE', 
            'MASS MODIFY': 'MODIFY',
            'MASS MOVE': 'MOVE',
            'MASS RENAME': 'RENAME',
            'READ': 'READ',
            'WRITE': 'WRITE',
            'ACCESSED': 'ACCESS',
            'OPENED': 'OPEN',
            'CLOSED': 'CLOSE',
            'COPIED': 'COPY'
        }
        
        return action_mapping.get(action_upper, action_upper)
    
    def setup_gui(self):
        # Main frames - simplified without buttons
        control_frame = ttk.LabelFrame(self.root, text="Automated Anomaly Detection System", padding=10)
        control_frame.pack(fill=tk.X, padx=10, pady=5)
        
        alerts_frame = ttk.LabelFrame(self.root, text="Security Alerts", padding=10)
        alerts_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Configuration frame only (no buttons)
        config_frame = ttk.Frame(control_frame)
        config_frame.pack(fill=tk.X, pady=5)
        
        # Monitoring configuration (read-only display)
        ttk.Label(config_frame, text="Check Interval (sec):").grid(row=0, column=0, padx=5, sticky=tk.W)
        self.interval_var = tk.StringVar(value="10")
        interval_label = ttk.Label(config_frame, textvariable=self.interval_var, width=10, background="white")
        interval_label.grid(row=0, column=1, padx=5, sticky=tk.W)
        
        ttk.Label(config_frame, text="CSV File:").grid(row=0, column=2, padx=5, sticky=tk.W)
        csv_label = ttk.Label(config_frame, textvariable=self.csv_path_var, width=50, background="white")
        csv_label.grid(row=0, column=3, padx=5, sticky=tk.W+tk.E)
        
        # Model status display
        model_status = "TRAINED" if self.detector.baseline_trained else "UNTRAINED"
        status_color = "green" if self.detector.baseline_trained else "red"
        model_status_text = f"Model Status: {model_status}"
        
        if self.detector.baseline_trained:
            model_status_text += f" ({self.detector.training_samples} samples)"
        
        self.model_status_label = ttk.Label(
            config_frame, 
            text=model_status_text,
            foreground=status_color,
            font=("Arial", 9, "bold")
        )
        self.model_status_label.grid(row=1, column=0, columnspan=3, padx=5, pady=5, sticky=tk.W)
        
        # Thresholds display
        if self.detector.baseline_trained:
            thresholds_text = f"Thresholds: Normal={self.detector.normal_threshold:.3f}, Anomaly={self.detector.anomaly_threshold:.3f}"
            ttk.Label(
                config_frame, 
                text=thresholds_text,
                font=("Arial", 8)
            ).grid(row=1, column=3, columnspan=2, padx=5, pady=5, sticky=tk.W)
        
        # Status bar and progress bar
        self.status_var = tk.StringVar(value="Initializing automated anomaly detection system...")
        status_bar = ttk.Label(self.root, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(self.root, variable=self.progress_var, maximum=100)
        self.progress_bar.pack(side=tk.BOTTOM, fill=tk.X, padx=10, pady=5)
        self.progress_bar.pack_forget()
        
        # Alerts treeview
        columns = ("Time", "Level", "User", "IP", "Action", "Files", "Score", "Reason")
        self.alerts_tree = ttk.Treeview(alerts_frame, columns=columns, show="headings", height=20)
        
        # Configure columns
        column_widths = {
            "Time": 150,
            "Level": 80,
            "User": 100,
            "IP": 120,
            "Action": 80,
            "Files": 120,
            "Score": 80,
            "Reason": 300
        }
        
        for col in columns:
            self.alerts_tree.heading(col, text=col)
            self.alerts_tree.column(col, width=column_widths.get(col, 100))
        
        # Scrollbars for alerts tree
        v_scrollbar = ttk.Scrollbar(alerts_frame, orient=tk.VERTICAL, command=self.alerts_tree.yview)
        h_scrollbar = ttk.Scrollbar(alerts_frame, orient=tk.HORIZONTAL, command=self.alerts_tree.xview)
        self.alerts_tree.configure(yscrollcommand=v_scrollbar.set, xscrollcommand=h_scrollbar.set)
        
        # Pack alerts tree and scrollbars
        self.alerts_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        v_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        h_scrollbar.pack(side=tk.BOTTOM, fill=tk.X)
        
        # Setup context menu for alerts
        self.setup_alerts_context_menu()
        
        # Display initial model status
        self.update_model_status_display()
        
        # Print startup status
        print("🚀 Automated Anomaly Detection System Started")
        print(f"📂 Training data path: {self.training_data_path}")
        print(f"📁 Monitoring path: {self.csv_path_var.get()}")
        if self.detector.baseline_trained:
            print(f"✅ Model loaded: {self.detector.training_samples} training samples")
            print(f"📊 Thresholds - Normal: {self.detector.normal_threshold:.3f}, Anomaly: {self.detector.anomaly_threshold:.3f}")
            print(f"🗑️ Mass Deletion - {self.detector.mass_deletion_threshold} files in {self.detector.mass_deletion_window}s")
        else:
            print("⚠️  Model needs training - will auto-load training data")

    def update_model_status_display(self):
        """Update the model status display in the GUI."""
        model_status = "TRAINED" if self.detector.baseline_trained else "UNTRAINED"
        status_color = "green" if self.detector.baseline_trained else "red"
        
        model_status_text = f"Model Status: {model_status}"
        if self.detector.baseline_trained:
            model_status_text += f" ({self.detector.training_samples} samples)"
        
        if hasattr(self, 'model_status_label'):
            self.model_status_label.config(text=model_status_text, foreground=status_color)
        
        # Update thresholds display if trained
        if self.detector.baseline_trained:
            thresholds_text = f"Thresholds: Normal={self.detector.normal_threshold:.3f}, Anomaly={self.detector.anomaly_threshold:.3f}"
            current_status = self.status_var.get()
            if "Model:" not in current_status:
                self.status_var.set(f"Model: {model_status}{' (' + str(self.detector.training_samples) + ' samples)' if self.detector.baseline_trained else ''}")

    def get_popup_key(self, alert):
        """
        Generate a unique key for popup identification.
        """
        user = alert.get('user', 'unknown')
        ip_address = alert.get('ip_address', 'unknown')
        action = alert.get('action', 'unknown')
        reason = alert.get('reason', '')
        
        # Normalize user and IP for consistent key generation
        user = user.strip().lower()
        ip_address = ip_address.strip().lower()
        
        # Check if this is a ransomware alert
        is_ransomware = (
            alert.get('alert_level') == 'CRITICAL' and 
            any(keyword in reason.lower() for keyword in [
                'ransomware', 'encryption', '.lock', '.enc', '.crypt', 'encrypted'
            ])
        )
        
        # Check if this is a mass deletion alert
        is_mass_deletion = (
            alert.get('alert_level') == 'CRITICAL' and 
            any(keyword in reason for keyword in [
                'MASS DELETION/SABOTAGE', 'Mass deletion activity'
            ])
        )
        
        # Check if this is a mass creation alert
        is_mass_creation = (
            alert.get('alert_level') == 'CRITICAL' and 
            any(keyword in reason for keyword in [
                'MASS FILE CREATION / DATA FLOODING', 'Mass file creation'
            ])
        )
        
        # Check for attack type from metadata
        attack_type = alert.get('attack_type')
        if attack_type:
            if attack_type == 'RANSOMWARE':
                is_ransomware = True
            elif attack_type == 'MASS_DELETION':
                is_mass_deletion = True
            elif attack_type == 'MASS_CREATION':
                is_mass_creation = True
        
        # For critical alerts, use user+ip to track ongoing attacks across different actions
        if is_ransomware or is_mass_deletion or is_mass_creation:
            # Special handling for mass creation to ensure unique tracking
            if is_mass_creation:
                return f"{user}_{ip_address}_CREATION"
            else:
                return f"{user}_{ip_address}"
        
        # For other alerts, use user+ip+action to group similar activities
        normalized_action = self.normalize_action(action)
        
        # Action normalization mapping for consistent grouping
        action_mapping = {
            'CREATED': 'CREATE',
            'DELETED': 'DELETE', 
            'MODIFIED': 'MODIFY',
            'MOVED': 'MOVE',
            'RENAMED': 'RENAME',
            'MASS DELETE': 'DELETE',
            'MASS CREATE': 'CREATE', 
            'MASS MODIFY': 'MODIFY',
            'MASS MOVE': 'MOVE',
            'MASS RENAME': 'RENAME',
            'READ': 'READ',
            'WRITE': 'WRITE',
            'ACCESSED': 'ACCESS'
        }
        
        # Apply normalization
        normalized_action = action_mapping.get(normalized_action, normalized_action)
        
        # Clean up the action string for key generation
        normalized_action = normalized_action.upper().strip()
        
        # Generate the key for non-critical alerts
        popup_key = f"{user}_{ip_address}_{normalized_action}"
        
        # Clean the key to remove any problematic characters
        popup_key = re.sub(r'[^a-zA-Z0-9_]', '_', popup_key)
        
        return popup_key
    
    def _create_or_update_popup(self, alert, mass_activities, is_critical_alert):
        """Unified method to create or update popups for all alert types."""
        popup_key = self.get_popup_key(alert)
        
        # Check if popup already exists and is still active
        existing_popup = self.detector.active_popups.get(popup_key)
        
        if existing_popup and self._is_popup_active(existing_popup):
            # UPDATE EXISTING POPUP
            success = existing_popup.update_alert_data(alert, mass_activities)
            if success:
                current_count = len(mass_activities) if mass_activities else 1
                previous_count = existing_popup.alert.get('previous_count', current_count)
                increment = current_count - previous_count
                
                print(f"🔄 Updated existing popup for {popup_key}: {previous_count} → {current_count} files (+{increment} new)")
                
                # Update the tracking
                existing_popup.alert['previous_count'] = current_count
                return existing_popup
            else:
                print(f"❌ Failed to update existing popup for {popup_key}")
                # Fall through to create new popup
        
        # CREATE NEW POPUP (either no existing popup or update failed)
        # Pass self (which has gui_parent reference) so AlertPopup can access notification methods
        popup = AlertPopup(self, alert, self.detector, mass_activities)
        
        # Track the popup for future updates
        self.detector.active_popups[popup_key] = popup
        popup.alert['previous_count'] = len(mass_activities) if mass_activities else 1
        
        alert_type = "critical"
        if any(keyword in alert['reason'].lower() for keyword in ['ransomware', 'encryption']):
            alert_type = "ransomware"
        elif "MASS DELETION/SABOTAGE" in alert['reason']:
            alert_type = "mass deletion"
            
        print(f"🆕 Created new {alert_type} popup for {popup_key}: {popup.alert['previous_count']} files")
        
        return popup

    def _is_popup_active(self, popup):
        """Check if a popup window is still active and visible."""
        return (popup and 
                hasattr(popup, 'popup') and 
                popup.popup and 
                popup.popup.winfo_exists())

    def cleanup_stale_popups(self):
        """Clean up references to popups that have been closed."""
        stale_keys = []
        for popup_key, popup in self.detector.active_popups.items():
            if not self._is_popup_active(popup):
                stale_keys.append(popup_key)
        
        for stale_key in stale_keys:
            del self.detector.active_popups[stale_key]
            print(f"🧹 Cleaned up stale popup reference for {stale_key}")
        
        return len(stale_keys)

    def _get_timestamp_file_path(self):
        """Get the path for storing the last processed timestamp."""
        return "log_data/last_processed.json"

    def _load_last_processed_time(self):
        """Load the last processed timestamp from file."""
        timestamp_file = self._get_timestamp_file_path()
        try:
            if os.path.exists(timestamp_file):
                with open(timestamp_file, 'r') as f:
                    data = json.load(f)
                timestamp_str = data.get('last_processed_time')
                if timestamp_str:
                    # Convert string back to datetime
                    return pd.to_datetime(timestamp_str)
            print("📂 No previous timestamp found, will process all entries on first run")
        except Exception as e:
            print(f"❌ Error loading last processed time: {e}")
        return None

    def _save_last_processed_time(self, timestamp):
        """Save the last processed timestamp to file."""
        timestamp_file = self._get_timestamp_file_path()
        try:
            os.makedirs(os.path.dirname(timestamp_file), exist_ok=True)
            # Convert timestamp to string for JSON serialization
            if hasattr(timestamp, 'isoformat'):
                timestamp_str = timestamp.isoformat()
            else:
                timestamp_str = str(timestamp)
            
            data = {
                'last_processed_time': timestamp_str,
                'saved_at': datetime.now().isoformat()
            }
            
            with open(timestamp_file, 'w') as f:
                json.dump(data, f, indent=2)
            
            print(f"💾 Saved last processed time: {timestamp_str}")
        except Exception as e:
            print(f"❌ Error saving last processed time: {e}")

    def start_monitoring(self):
        """Start monitoring automatically (no manual trigger)."""
        if self.monitoring:
            print("⚠️ Monitoring is already running")
            return
        
        csv_path = self.csv_path_var.get()
        if not os.path.exists(csv_path):
            error_msg = f"❌ CSV file not found: {csv_path}"
            print(error_msg)
            self.status_var.set(error_msg)
            return
        
        try:
            interval = int(self.interval_var.get())
        except ValueError:
            error_msg = "❌ Invalid interval value"
            print(error_msg)
            self.status_var.set(error_msg)
            return
        
        # CLEANUP: Remove any existing duplicates before starting monitoring
        if hasattr(self.detector, 'active_ransomware_alerts'):
            self.detector.cleanup_duplicate_ransomware_entries()
        
        # Check if model needs training
        if not self.detector.baseline_trained:
            print("⚠️ Model needs training but will continue with basic detection")
            self.status_var.set("Model untrained - using basic detection")
        
        # RESET monitoring state for fresh start
        self.current_csv_path = csv_path
        self.last_processed_time = None  # Reset to process all recent entries
        
        # Clear only popup tracking, keep ransomware state
        self.detector.active_popups.clear()
        
        self.monitoring = True
        self.status_var.set(f"Monitoring {os.path.basename(csv_path)}...")
        
        # Refresh ransomware popups after starting
        self.root.after(1000, self.refresh_ransomware_popups)
        
        self.monitor_thread = threading.Thread(
            target=self.monitor_file,
            args=(csv_path, interval),
            daemon=True
        )
        self.monitor_thread.start()
        
        print(f"✅ Started monitoring: {csv_path}")
        print(f"   Interval: {interval} seconds")
        print(f"   Model trained: {self.detector.baseline_trained}")
        print(f"   Training samples: {self.detector.training_samples}")
        print(f"   Mass Deletion: {self.detector.mass_deletion_threshold} files in {self.detector.mass_deletion_window}s")

    def refresh_ransomware_popups(self):
        """Refresh ransomware popups for active attacks (useful after restarting monitoring)."""
        
        # Clean up duplicate entries first
        self.detector.cleanup_duplicate_ransomware_entries()
        
        # Clean up any stale popup references
        stale_popups = []
        for user_ip_key, popup in self.detector.active_popups.items():
            if (not popup or 
                not hasattr(popup, 'popup') or 
                not popup.popup or 
                not popup.popup.winfo_exists()):
                stale_popups.append(user_ip_key)
        
        for stale_key in stale_popups:
            del self.detector.active_popups[stale_key]
            print(f"🧹 Cleaned up stale popup reference for {stale_key}")
        
        # Use the detector's active_ransomware_alerts directly for most current data
        attack_details = self.detector.active_ransomware_alerts
        
        for user_ip_key, attack_data in attack_details.items():
            # Only process active attacks
            if not attack_data.get('active', False):
                continue
                
            # Check if we need to create a new popup or update an existing one
            existing_popup = self.detector.active_popups.get(user_ip_key)
            
            if existing_popup:
                # UPDATE EXISTING POPUP with current data
                alert_data = attack_data.get('metadata', {})
                
                # Create updated alert with current IP and file count
                current_count = attack_data.get('count', 0)
                previous_count = existing_popup.alert.get('previous_count', current_count)
                file_increase = current_count - previous_count
                
                # Extract user and IP from the key
                user_parts = user_ip_key.split('_')
                user_name = user_parts[0] if len(user_parts) > 0 else 'Unknown'
                ip_address = user_parts[1] if len(user_parts) > 1 else 'Unknown'
                
                alert = {
                    'original_timestamp': alert_data.get('start_time', datetime.now()).isoformat(),
                    'alert_level': 'CRITICAL',
                    'user': user_name,
                    'action': alert_data.get('alert_type', 'RANSOMWARE'),
                    'anomaly_score': alert_data.get('anomaly_score', 0.9),
                    'reason': alert_data.get('ransomware_reason', alert_data.get('mass_deletion_reason', 'Critical activity detected')),
                    'file_path': 'Multiple files',
                    'file_type': 'Various',
                    'ip_address': ip_address,
                    'previous_count': previous_count
                }
                
                mass_activities = alert_data.get('affected_files', [])
                
                # Update the existing popup with current data
                success = existing_popup.update_alert_data(alert, mass_activities)
                if success:
                    print(f"🔄 Updated existing critical popup for {user_ip_key}: {previous_count} → {current_count} files (+{file_increase} new)")
                else:
                    print(f"❌ Failed to update existing popup for {user_ip_key}")
                    
            else:
                # CREATE NEW POPUP for active attack
                alert_data = attack_data.get('metadata', {})
                current_count = attack_data.get('count', 0)
                
                # Create alert with proper IP address from the user_ip_key
                user_parts = user_ip_key.split('_')
                user_name = user_parts[0] if len(user_parts) > 0 else 'Unknown'
                ip_address = user_parts[1] if len(user_parts) > 1 else 'Unknown'
                
                alert = {
                    'original_timestamp': alert_data.get('start_time', datetime.now()).isoformat(),
                    'alert_level': 'CRITICAL',
                    'user': user_name,
                    'action': alert_data.get('alert_type', 'RANSOMWARE'), 
                    'anomaly_score': alert_data.get('anomaly_score', 0.9),
                    'reason': alert_data.get('ransomware_reason', alert_data.get('mass_deletion_reason', 'Critical activity detected')),
                    'file_path': 'Multiple files',
                    'file_type': 'Various',
                    'ip_address': ip_address,
                    'previous_count': current_count
                }
                
                mass_activities = alert_data.get('affected_files', [])
                popup = self._create_or_update_popup(alert, mass_activities, True)
                print(f"🔄 Created new critical popup for {user_ip_key}: {current_count} files")

    def load_training_data(self, file_path=None):
        """Load training data automatically with optional file path."""
        if self.training_in_progress:
            print("⚠️ Training is already in progress")
            return
            
        # Use provided file path or default training path
        if file_path is None:
            file_path = self.training_data_path
        
        if os.path.exists(file_path):
            # Auto-load from provided path
            print(f"📂 Auto-loading training data: {file_path}")
            self.progress_bar.pack(side=tk.BOTTOM, fill=tk.X, padx=10, pady=5)
            self.progress_var.set(0)
            
            self.training_in_progress = True
            self.status_var.set("Auto-training in progress...")
            
            training_thread = threading.Thread(
                target=self.run_training,
                args=(file_path,),
                daemon=True
            )
            training_thread.start()
        else:
            error_msg = f"❌ Training file not found: {file_path}"
            print(error_msg)
            self.status_var.set(error_msg)

    def run_training(self, file_path):
        try:
            self.status_var.set("Loading training data...")
            success = self.detector.train_baseline_model(file_path, progress_callback=self.update_progress)
            self.root.after(0, self.training_completed, success, file_path)
            
        except Exception as e:
            self.root.after(0, self.training_failed, str(e))

    def update_progress(self, progress):
        self.root.after(0, lambda: self.progress_var.set(progress))
        self.root.after(0, lambda: self.status_var.set(f"Training: {progress:.1f}%"))

    def training_completed(self, success, file_path):
        self.progress_bar.pack_forget()
        self.training_in_progress = False
        
        if success:
            # AUTO-SAVE: Save model state immediately after training
            self.detector.save_state()
            
            # ALSO save to our model persistence file
            self._save_trained_model()
            
            success_msg = f"✅ Training completed and model saved: {file_path}"
            print(success_msg)
            self.status_var.set("Training completed - Starting monitoring...")
            
            print(f"🎯 Calibrated thresholds:")
            print(f"   Normal threshold (95th percentile): {self.detector.normal_threshold:.3f}")
            print(f"   Anomaly threshold (99th percentile): {self.detector.anomaly_threshold:.3f}")
            print(f"   Mass Deletion: {self.detector.mass_deletion_threshold} files in {self.detector.mass_deletion_window}s")
            
            # AUTO-START: Begin monitoring after training completes
            print("👀 Automatically starting monitoring after training...")
            self.root.after(1000, self.start_monitoring_after_training)
            
        else:
            error_msg = "❌ Training failed"
            print(error_msg)
            self.status_var.set(error_msg)

    def training_failed(self, error_message):
        self.progress_bar.pack_forget()
        self.training_in_progress = False
        
        error_msg = f"❌ Training error: {error_message}"
        print(error_msg)
        self.status_var.set("Training error")

    def setup_alerts_context_menu(self):
        # Keep only view details for context menu
        self.context_menu = tk.Menu(self.root, tearoff=0)
        self.context_menu.add_command(label="View Details", command=self.view_alert_details)
        
        self.alerts_tree.bind("<Button-3>", self.show_context_menu)

    def show_context_menu(self, event):
        item = self.alerts_tree.identify_row(event.y)
        if item:
            self.alerts_tree.selection_set(item)
            self.context_menu.post(event.x_root, event.y_root)

    def view_alert_details(self):
        selected = self.alerts_tree.selection()
        if selected:
            item = self.alerts_tree.item(selected[0])
            alert_data = {
                'original_timestamp': item['values'][0],
                'alert_level': item['values'][1],
                'user': item['values'][2],
                'ip_address': item['values'][3],
                'action': item['values'][4],
                'files_count': item['values'][5],
                'anomaly_score': float(item['values'][6]),
                'reason': item['values'][7]
            }
            
            mass_activities = []
            # Handle timestamp properly
            timestamp = alert_data['original_timestamp']
            if isinstance(timestamp, (datetime, pd.Timestamp)):
                alert_time = timestamp
            else:
                alert_time = datetime.fromisoformat(timestamp)
                
            # Try to find stored activities for this alert
            user_key_prefix = f"{alert_data['user']}_{alert_data['action']}_{alert_time.strftime('%Y%m%d%H%M')}"
            
            # Look for any matching key (since we added alert_id suffix)
            matching_keys = [key for key in self.mass_activities.keys() if key.startswith(user_key_prefix)]
            if matching_keys:
                # Use the first matching key
                mass_activities = self.mass_activities[matching_keys[0]]
            
            # Pass self (GUI instance) so AlertPopup can access notification methods
            AlertPopup(self, alert_data, self.detector, mass_activities)

    def add_alert(self, alert, anomaly_data, is_mass_activity=False, mass_activities=None):
        """Add alert to GUI with unified popup update behavior for all alert types."""
        
        # **CHECK FOR SUPPRESSED ALERTS**
        if anomaly_data.get('suppressed', False):
            print(f"🔇 Suppressed duplicate alert for file already in ransomware/mass deletion: {alert.get('file_path', 'Unknown')}")
            return  # Don't add to GUI at all
        
        # Check if this user/IP has an active critical alert that should suppress this one
        user = alert.get('user', 'unknown')
        ip_address = alert.get('ip_address', 'unknown')
        user_ip_key = f"{user}_{ip_address}"
        
        # Suppress non-critical alerts if there's an active critical alert for same user/IP
        if (user_ip_key in self.detector.active_popups and 
            alert.get('alert_level') != 'CRITICAL' and
            self._is_popup_active(self.detector.active_popups[user_ip_key])):
            print(f"🔇 Suppressed non-critical alert due to active critical alert for {user_ip_key}")
            return

        # Generate unique alert ID
        alert_id = self.alert_counter
        self.alert_counter += 1
        
        # Store features for potential feedback learning
        if 'features' in anomaly_data:
            self.alert_feature_cache[f"features_{alert_id}"] = anomaly_data['features']
            self.alert_feature_cache[f"event_{alert_id}"] = anomaly_data['event']

        # Determine if this is a critical alert
        is_ransomware_alert = (
            alert['alert_level'] == 'CRITICAL' and 
            any(keyword in alert['reason'].lower() for keyword in ['ransomware', 'encryption', '.lock', '.enc', '.crypt'])
        )
        is_mass_deletion_alert = (
            alert['alert_level'] == 'CRITICAL' and 
            "MASS DELETION/SABOTAGE" in alert['reason']
        )
        is_critical_alert = is_ransomware_alert or is_mass_deletion_alert
        
        # For single alerts, create a single-item mass_activities list
        if not is_mass_activity and 'event' in anomaly_data:
            single_activity = {
                'timestamp': anomaly_data['event'].get('timestamp', datetime.now()),
                'user': alert['user'],
                'action': alert['action'],
                'file_path': alert.get('file_path', 'Unknown'),
                'file_type': alert.get('file_type', 'Unknown'),
                'file_size': anomaly_data['event'].get('file_size', 0),
                'ip_address': alert.get('ip_address', 'Unknown')
            }
            # Add all fields from the original event
            for key, value in anomaly_data['event'].items():
                if key not in single_activity:
                    single_activity[key] = value
            mass_activities = [single_activity]
        elif not mass_activities and 'event' in anomaly_data:
            # Create mass_activities from single event if not provided
            mass_activities = [{
                'timestamp': anomaly_data['event'].get('timestamp', datetime.now()),
                'user': alert['user'],
                'action': alert['action'],
                'file_path': alert.get('file_path', 'Unknown'),
                'file_type': alert.get('file_type', 'Unknown'),
                'file_size': anomaly_data['event'].get('file_size', 0),
                'ip_address': alert.get('ip_address', 'Unknown')
            }]

        # Store mass activities for details view
        if mass_activities:
            timestamp = alert['original_timestamp']
            if isinstance(timestamp, (datetime, pd.Timestamp)):
                alert_time = timestamp
            else:
                alert_time = datetime.fromisoformat(timestamp)
                
            user_key = f"{alert['user']}_{alert['action']}_{alert_time.strftime('%Y%m%d%H%M')}_{alert_id}"
            self.mass_activities[user_key] = mass_activities

        # Add to alerts tree
        tree_item = self._add_to_alerts_tree(alert, mass_activities, is_mass_activity, alert_id)

        # Handle popup creation/update for ALL critical and anomaly alerts
        if alert['alert_level'] in ['ANOMALY', 'CRITICAL']:
            self._create_or_update_popup(alert, mass_activities, is_critical_alert)

    def _add_to_alerts_tree(self, alert, mass_activities, is_mass_activity, alert_id, is_updated=False):
        """Add alert entry to the alerts treeview."""
        # Calculate display values
        files_count = len(mass_activities) if mass_activities else 1
        duration_text = ""
        
        if is_mass_activity and mass_activities and len(mass_activities) > 0:
            first_activity = mass_activities[0]
            if 'mass_duration' in first_activity:
                duration_minutes = first_activity['mass_duration']
                count = first_activity.get('mass_count', files_count)
                
                # Format duration
                minutes = int(duration_minutes)
                seconds = int((duration_minutes - minutes) * 60)
                
                if minutes > 0:
                    duration_text = f"{minutes}m {seconds}s"
                else:
                    duration_text = f"{seconds}s"
                
                # Update alert reason for mass activities
                if not any(keyword in alert['reason'].lower() for keyword in ['ransomware', 'encryption']) and "MASS DELETION/SABOTAGE" not in alert['reason']:
                    alert['reason'] = f"Mass {alert['action'].lower()} activity - {count} operations in {duration_text}"
                
                alert['action'] = f"MASS {alert['action']}"
        
        # Prepare values for treeview
        if is_mass_activity and mass_activities:
            files_display = f"{files_count} files/{duration_text}" if duration_text else f"{files_count} files"
        else:
            files_display = f"{files_count} file{'s' if files_count > 1 else ''}"
        
        # Add "(UPDATED)" suffix for updated critical alerts
        reason_display = alert['reason']
        if is_updated:
            reason_display = f"{alert['reason']} (UPDATED)"

        values = (
            alert['original_timestamp'],
            alert['alert_level'],
            alert['user'],
            alert.get('ip_address', 'Unknown'),
            alert['action'],
            files_display,
            f"{alert['anomaly_score']:.3f}",
            reason_display
        )
        
        # Insert into treeview
        item = self.alerts_tree.insert("", tk.END, values=values)
        self.alerts_tree.see(item)
        
        return item

    def monitor_file(self, csv_path, interval):
        """Monitor CSV file with improved restart handling - processes ONLY new entries after saved timestamp."""
        # Load last processed time on startup
        if not hasattr(self, 'last_processed_time') or self.last_processed_time is None:
            self.last_processed_time = self._load_last_processed_time()
        
        print(f"🔍 Monitoring started: {csv_path}")
        print(f"   Interval: {interval}s")
        print(f"   Last processed time: {self.last_processed_time}")
        print(f"   Mass Deletion: {self.detector.mass_deletion_threshold} files in {self.detector.mass_deletion_window}s")
        
        while self.monitoring:
            try:
                if not os.path.exists(csv_path):
                    self.root.after(0, lambda: self.status_var.set(f"CSV not found: {csv_path}"))
                    time.sleep(interval)
                    continue
                
                df = pd.read_csv(csv_path)
                
                if df.empty:
                    time.sleep(interval)
                    continue
                
                df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
                df = df.dropna(subset=['timestamp'])
                
                # **FIXED: Process ONLY new entries based on saved timestamp**
                if self.last_processed_time is None:
                    # On first run with no saved timestamp, process ALL entries in the CSV file
                    new_rows = df.copy()  # Process entire dataframe
                    if not new_rows.empty:
                        self.last_processed_time = new_rows['timestamp'].max()
                        # Save the timestamp immediately after first processing
                        self._save_last_processed_time(self.last_processed_time)
                        print(f"🔄 Processing ALL entries on first run: {len(new_rows)} total entries")
                else:
                    # Normal operation: process only new entries
                    new_rows = df[df['timestamp'] > self.last_processed_time]
                
                if not new_rows.empty:
                    self.last_processed_time = new_rows['timestamp'].max()
                    # Save the updated timestamp after processing new rows
                    self._save_last_processed_time(self.last_processed_time)
                    
                    self.root.after(0, lambda: self.status_var.set(
                        f"Monitoring: {len(new_rows)} new events at {self.last_processed_time.strftime('%H:%M:%S')}"
                    ))
                    
                    processed_count = 0
                    for _, row in new_rows.iterrows():
                        if not self.monitoring:
                            break
                        
                        # Process event (existing logic)
                        file_path = 'Unknown'
                        file_type = 'Unknown'
                        
                        # Priority 1: Use 'path' field if available
                        if 'path' in row and pd.notna(row['path']) and row['path'] != 'Unknown':
                            file_path = row['path']
                        # Priority 2: Use file_path if 'path' is not available
                        if file_path == 'Unknown' and 'file_path' in row and pd.notna(row['file_path']) and row['file_path'] != 'Unknown':
                            file_path = row['file_path']
                        # Priority 3: Use file_name as last resort
                        if file_path == 'Unknown' and 'file_name' in row and pd.notna(row['file_name']):
                            file_path = row['file_name']
                        
                        if file_path != 'Unknown':
                            if '.' in file_path:
                                file_type = file_path.split('.')[-1].upper() + '_FILE'
                            else:
                                file_type = 'FILE'
                        
                        if 'file_type' in row and pd.notna(row['file_type']) and row['file_type'] != 'Unknown':
                            file_type = row['file_type']
                        
                        ip_address = 'Unknown'
                        if 'ip' in row and pd.notna(row['ip']):
                            ip_address = row['ip']
                        elif 'ip_address' in row and pd.notna(row['ip_address']):
                            ip_address = row['ip_address']
                        
                        event = {
                            'timestamp': row['timestamp'],
                            'user': row.get('user', 'Unknown'),
                            'action': row.get('action', 'Unknown'),
                            'file_path': file_path,
                            'file_type': file_type,
                            'file_size': row.get('file_size', 0),
                            'ip_address': ip_address
                        }
                        
                        for col in row.index:
                            if col not in event and pd.notna(row[col]):
                                event[col] = row[col]
                        
                        if 'dest_path' in row and pd.notna(row['dest_path']):
                            event['dest_path'] = row['dest_path']
                        
                        alert, anomaly_data, is_mass_activity, mass_activities = self.detector.detect_anomalies(event)
                        
                        if alert:
                            if 'ip_address' not in alert and 'ip_address' in event:
                                alert['ip_address'] = event['ip_address']
                            
                            self.root.after(0, lambda a=alert, ad=anomaly_data, ima=is_mass_activity, ma=mass_activities: 
                                        self.add_alert(a, ad, ima, ma))
                        
                        processed_count += 1
                    
                    print(f"📊 Processed {processed_count} new events")
                    
                    # Clean up stale popups every 10 monitoring cycles
                    self.cleanup_counter = getattr(self, 'cleanup_counter', 0) + 1
                    if self.cleanup_counter >= 10:
                        stale_count = self.cleanup_stale_popups()
                        if stale_count > 0:
                            print(f"🧹 Cleaned up {stale_count} stale popup references")
                        self.cleanup_counter = 0
                    
                time.sleep(interval)
                
            except Exception as e:
                error_msg = f"Monitoring error: {str(e)}"
                print(f"❌ {error_msg}")
                self.root.after(0, lambda: self.status_var.set(error_msg))
                time.sleep(interval)
        
        print("🛑 Monitoring stopped")

class AnomalyDetector:
    """Production-ready anomaly detector with River ML - BEHAVIOR-FOCUSED."""

    def __init__(self):
        self.model = None
        self.baseline_trained = False
        self.normal_threshold = 0.5
        self.anomaly_threshold = 0.8
        self.gui_parent = None
        self.unknown_categories = set()
        self.user_score_buffers = defaultdict(lambda: deque(maxlen=10))
        self.normal_buffer = deque(maxlen=1000)
        self.training_samples = 0
        self.state_file = "product/anomaly_detector_state.pkl"
        self.model_file = "product/trained_model.pkl"

        # Enhanced BEHAVIOR-FOCUSED detection components
        self.user_action_counts = defaultdict(lambda: defaultdict(lambda: deque(maxlen=300)))
        self.action_time_windows = {
            'DELETE': 60,   # 1 minute window for deletions
            'CREATE': 120,  # 2 minutes for creations  
            'MODIFY': 180,  # 3 minutes for modifications
            'MOVE': 120,    # 2 minutes for moves
            'RENAME': 120,  # 2 minutes for renames
        }
        
        # BEHAVIOR-FOCUSED tracking (not user-focused)
        self.behavior_pattern_buffers = defaultdict(lambda: deque(maxlen=1000))
        self.action_frequency_tracking = defaultdict(lambda: defaultdict(int))

        # Detection metrics
        self.true_positives = []
        self.false_positives = []
        self.false_negatives = []

        # Action normalization mapping
        self.action_mapping = {
            'CREATED': 'CREATE',
            'DELETED': 'DELETE', 
            'MODIFIED': 'MODIFY',
            'MOVED': 'MOVE',
            'RENAMED': 'RENAME'
        }

        # Ransomware and mass deletion alert aggregation
        self.active_ransomware_alerts = {}  # Format: {user: {start_time, count, files, last_alert_time}}
        self.ransomware_alert_window = 180  # EXTENDED: 180 seconds window to group ransomware alerts
        self.ransomware_min_files = 5      # Minimum files to trigger ransomware alert
        self.ransomware_cooldown_period = 300  # 5 minutes cooldown after alert ends
        
        # Mass Deletion / Sabotage detection settings
        self.mass_deletion_threshold = 20  # 20+ deletions in 60 seconds
        self.mass_deletion_window = 60     # 60 second window for mass deletion detection
        
        # Mass File Creation / Data Flooding detection settings
        self.mass_creation_threshold = 40  # 40+ creations in 30 seconds
        self.mass_creation_window = 30     # 30 second window for mass creation detection
        
        # Sensitive file patterns for prioritization
        self.SENSITIVE_EXTS = {
            '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.csv', '.pdf', '.txt', '.rtf', '.odt', '.ods',
            '.db', '.sql', '.sqlite', '.mdb', '.bak', '.dump', '.json', '.xml', '.yml', '.yaml', '.conf', '.cfg',
            '.ini', '.env', '.pem', '.key', '.pfx', '.zip', '.rar', '.7z', '.tar', '.gz', '.tax', '.qbw', '.qbb',
            '.enc', '.locked', '.crypted', '.encrypted'
        }
        
        self.SENSITIVE_NAMES = {
            'password', 'credential', 'backup', 'config', 'key', 'secret', 'payroll', 'employee', 'client',
            'customer', 'finance', 'budget', 'report', 'invoice', 'tax', 'database', 'userdata', 'contract',
            'nda', 'compliance', 'confidential', 'private'
        }
        
        # Mass activity tracking
        self.mass_deletion_buffers = defaultdict(lambda: deque(maxlen=1000))
        self.mass_creation_buffers = defaultdict(lambda: deque(maxlen=1000))
        self.active_mass_deletion_alerts = {}
        self.active_mass_creation_alerts = {}

        # Track active popups to prevent duplicates
        self.active_popups = {}  # Format: {user_ip_key: popup_reference}

        # Extended detection buffers
        self.extended_activity_buffers = defaultdict(lambda: defaultdict(lambda: deque(maxlen=1000)))
        
        # Mass activity detection buffers
        self.mass_activity_buffers = defaultdict(lambda: defaultdict(lambda: deque(maxlen=200)))
        self.mass_activity_metadata = defaultdict(dict)

        self.initialize_model()

    

    def initialize_model(self):
        """Initialize the HalfSpaceTrees model with optimal parameters."""
        self.model = anomaly.HalfSpaceTrees(
            n_trees=25,
            height=15,
            window_size=250,
            seed=42
        )

    def _categorize_file_size(self, file_size):
        """Categorize file size for behavior pattern analysis."""
        if file_size == 0:
            return 0  # Empty/unknown
        elif file_size < 1024:  # < 1KB
            return 1
        elif file_size < 1024 * 1024:  # < 1MB
            return 2
        elif file_size < 10 * 1024 * 1024:  # < 10MB
            return 3
        else:  # >= 10MB
            return 4

    def _is_sensitive_file(self, file_path):
        """Check if a file is sensitive based on extension or filename patterns."""
        if not file_path or file_path == 'Unknown':
            return False
            
        file_path_lower = file_path.lower()
        filename = file_path_lower.split('/')[-1]  # Get filename without path
        
        # Check for sensitive extensions
        if '.' in filename:
            file_ext = '.' + filename.split('.')[-1]
            if file_ext in self.SENSITIVE_EXTS:
                return True
        
        # Check for sensitive name patterns in filename
        for sensitive_name in self.SENSITIVE_NAMES:
            if sensitive_name in filename:
                return True
                
        return False

    def _detect_mass_deletion_sabotage(self, user, current_time, normalized_action):
        """Enhanced Mass Deletion / Sabotage detection with sensitive file awareness."""
        if normalized_action != 'DELETE':
            return False, None
            
        # Convert current time to timestamp
        if isinstance(current_time, (datetime, pd.Timestamp)):
            current_timestamp = current_time.timestamp()
        else:
            current_timestamp = pd.to_datetime(current_time).timestamp()
        
        # Get DELETE events for this user from buffers
        user_key = f"{user}_deletion_buffer"
        delete_buffer = self.mass_deletion_buffers[user_key]
        
        # Use extended window for mass deletion detection (60 seconds)
        recent_deletions = [e for e in delete_buffer if (current_timestamp - e['timestamp']) <= self.mass_deletion_window]
        
        print(f"🔍 Mass deletion analysis for {user}: {len(recent_deletions)} deletions in {self.mass_deletion_window}s window")
        
        # MASS DELETION THRESHOLD: 20+ deletions in 60 seconds
        if len(recent_deletions) >= self.mass_deletion_threshold:
            # Calculate duration and find the most concentrated window
            if recent_deletions:
                sorted_deletions = sorted(recent_deletions, key=lambda x: x['timestamp'])
                
                # Find the most concentrated sub-window
                max_count = 0
                best_window = []
                
                for i in range(len(sorted_deletions)):
                    window_start = sorted_deletions[i]['timestamp']
                    window_events = []
                    
                    for j in range(i, len(sorted_deletions)):
                        if (sorted_deletions[j]['timestamp'] - window_start) <= self.mass_deletion_window:
                            window_events.append(sorted_deletions[j])
                        else:
                            break
                    
                    if len(window_events) > max_count:
                        max_count = len(window_events)
                        best_window = window_events
                
                if max_count >= self.mass_deletion_threshold:
                    # Calculate duration for the best window
                    start_time = min(e['timestamp'] for e in best_window)
                    end_time = max(e['timestamp'] for e in best_window)
                    duration_seconds = end_time - start_time
                    
                    minutes = int(duration_seconds // 60)
                    seconds = int(duration_seconds % 60)
                    if minutes > 0:
                        duration_text = f"{minutes}m {seconds}s"
                    else:
                        duration_text = f"{seconds}s"
                    
                    # Collect affected files and count sensitive files
                    affected_files = []
                    sensitive_count = 0
                    
                    for entry in best_window:
                        file_event = entry['event']
                        file_path = file_event.get('file_path', 'Unknown')
                        
                        # Check if file is sensitive
                        is_sensitive = self._is_sensitive_file(file_path)
                        if is_sensitive:
                            sensitive_count += 1
                        
                        affected_files.append({
                            'timestamp': entry['original_time'],
                            'user': file_event.get('user', 'Unknown'),
                            'action': file_event.get('action', 'Unknown'),
                            'file_path': file_path,
                            'file_type': file_event.get('file_type', 'Unknown'),
                            'file_size': file_event.get('file_size', 0),
                            'ip_address': file_event.get('ip_address', 'Unknown'),
                            'dest_path': file_event.get('dest_path', ''),
                            'is_sensitive': is_sensitive
                        })
                    
                    # Calculate sensitive ratio and anomaly score
                    sensitive_ratio = sensitive_count / len(affected_files) if affected_files else 0
                    anomaly_score = 1.0 if sensitive_ratio > 0 else 0.85
                    
                    # Build mass deletion metadata
                    mass_deletion_metadata = {
                        'count': len(affected_files),
                        'sensitive_count': sensitive_count,
                        'sensitive_ratio': sensitive_ratio,
                        'duration_seconds': duration_seconds,
                        'duration_text': duration_text,
                        'start_time': datetime.fromtimestamp(start_time),
                        'end_time': datetime.fromtimestamp(end_time),
                        'affected_files': affected_files,
                        'action': 'DELETE',
                        'user': user,
                        'ip_address': affected_files[0]['ip_address'] if affected_files else 'Unknown',
                        'mass_deletion_detected': True,
                        'mass_deletion_reason': f"🚨 MASS DELETION/SABOTAGE: {len(affected_files)} files deleted in {duration_text} ({sensitive_count} sensitive files)",
                        'anomaly_score': anomaly_score,
                        'detection_type': 'MASS_DELETION',
                        'detection_confidence': 'HIGH',
                        'window_seconds': self.mass_deletion_window,
                        'threshold_used': self.mass_deletion_threshold
                    }
                    
                    print(f"🚨 MASS DELETION detected for {user}: {len(affected_files)} files ({sensitive_count} sensitive) in {duration_text}")
                    
                    # Log forensic information
                    self._log_mass_deletion_forensics(mass_deletion_metadata)
                    
                    return True, mass_deletion_metadata
        
        return False, None

    def _log_mass_deletion_forensics(self, metadata):
        """Log mass deletion events for forensic analysis."""
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'event_type': 'MASS_DELETION_DETECTED',
            'user': metadata['user'],
            'ip_address': metadata['ip_address'],
            'total_files': metadata['count'],
            'sensitive_files': metadata['sensitive_count'],
            'sensitive_ratio': metadata['sensitive_ratio'],
            'duration_seconds': metadata['duration_seconds'],
            'anomaly_score': metadata['anomaly_score'],
            'reason': metadata['mass_deletion_reason'],
            'affected_files': [f['file_path'] for f in metadata['affected_files']]
        }
        
        # Save to forensic log file
        log_file = "reports/mass_deletion_forensics.json"
        os.makedirs(os.path.dirname(log_file), exist_ok=True)
        try:
            with open(log_file, 'a') as f:
                f.write(json.dumps(log_entry) + '\n')
        except Exception as e:
            print(f"❌ Error writing mass deletion forensics: {e}")

    def _detect_mass_creation_flooding(self, user, current_time, normalized_action):
        """Detect Mass File Creation / Data Flooding attacks."""
        if normalized_action != 'CREATE':
            return False, None
            
        # Convert current time to timestamp
        if isinstance(current_time, (datetime, pd.Timestamp)):
            current_timestamp = current_time.timestamp()
        else:
            current_timestamp = pd.to_datetime(current_time).timestamp()
        
        # Get CREATE events for this user from buffers
        user_key = f"{user}_creation_buffer"
        creation_buffer = self.mass_creation_buffers[user_key]
        
        # Use creation window for mass creation detection (30 seconds)
        recent_creations = [e for e in creation_buffer if (current_timestamp - e['timestamp']) <= self.mass_creation_window]
        
        print(f"🔍 Mass creation analysis for {user}: {len(recent_creations)} creations in {self.mass_creation_window}s window")
        
        # MASS CREATION THRESHOLD: 40+ creations in 30 seconds
        if len(recent_creations) >= self.mass_creation_threshold:
            # Calculate duration and find the most concentrated window
            if recent_creations:
                sorted_creations = sorted(recent_creations, key=lambda x: x['timestamp'])
                
                # Find the most concentrated sub-window
                max_count = 0
                best_window = []
                
                for i in range(len(sorted_creations)):
                    window_start = sorted_creations[i]['timestamp']
                    window_events = []
                    
                    for j in range(i, len(sorted_creations)):
                        if (sorted_creations[j]['timestamp'] - window_start) <= self.mass_creation_window:
                            window_events.append(sorted_creations[j])
                        else:
                            break
                    
                    if len(window_events) > max_count:
                        max_count = len(window_events)
                        best_window = window_events
                
                if max_count >= self.mass_creation_threshold:
                    # Calculate duration for the best window
                    start_time = min(e['timestamp'] for e in best_window)
                    end_time = max(e['timestamp'] for e in best_window)
                    duration_seconds = end_time - start_time
                    
                    minutes = int(duration_seconds // 60)
                    seconds = int(duration_seconds % 60)
                    if minutes > 0:
                        duration_text = f"{minutes}m {seconds}s"
                    else:
                        duration_text = f"{seconds}s"
                    
                    # Collect affected files
                    affected_files = []
                    
                    for entry in best_window:
                        file_event = entry['event']
                        affected_files.append({
                            'timestamp': entry['original_time'],
                            'user': file_event.get('user', 'Unknown'),
                            'action': file_event.get('action', 'Unknown'),
                            'file_path': file_event.get('file_path', 'Unknown'),
                            'file_type': file_event.get('file_type', 'Unknown'),
                            'file_size': file_event.get('file_size', 0),
                            'ip_address': file_event.get('ip_address', 'Unknown'),
                            'dest_path': file_event.get('dest_path', '')
                        })
                    
                    # Build mass creation metadata
                    mass_creation_metadata = {
                        'count': len(affected_files),
                        'duration_seconds': duration_seconds,
                        'duration_text': duration_text,
                        'start_time': datetime.fromtimestamp(start_time),
                        'end_time': datetime.fromtimestamp(end_time),
                        'affected_files': affected_files,
                        'action': 'CREATE',
                        'user': user,
                        'ip_address': affected_files[0]['ip_address'] if affected_files else 'Unknown',
                        'mass_creation_detected': True,
                        'mass_creation_reason': f"🚨 MASS FILE CREATION / DATA FLOODING: {len(affected_files)} files created in {duration_text}",
                        'anomaly_score': 0.9,
                        'detection_type': 'MASS_CREATION',
                        'detection_confidence': 'HIGH',
                        'window_seconds': self.mass_creation_window,
                        'threshold_used': self.mass_creation_threshold
                    }
                    
                    print(f"🚨 MASS FILE CREATION / DATA FLOODING detected for {user}: {len(affected_files)} files in {duration_text}")
                    
                    # Log forensic information
                    self._log_mass_creation_forensics(mass_creation_metadata)
                    
                    return True, mass_creation_metadata
        
        return False, None

    def _log_mass_creation_forensics(self, metadata):
        """Log mass creation events for forensic analysis."""
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'event_type': 'MASS_CREATION_DETECTED',
            'user': metadata['user'],
            'ip_address': metadata['ip_address'],
            'total_files': metadata['count'],
            'duration_seconds': metadata['duration_seconds'],
            'anomaly_score': metadata['anomaly_score'],
            'reason': metadata['mass_creation_reason'],
            'affected_files': [f['file_path'] for f in metadata['affected_files']]
        }
        
        # Save to forensic log file
        log_file = "product/mass_creation_forensics.json"
        os.makedirs(os.path.dirname(log_file), exist_ok=True)
        try:
            with open(log_file, 'a') as f:
                f.write(json.dumps(log_entry) + '\n')
        except Exception as e:
            print(f"❌ Error writing mass creation forensics: {e}")

    def _should_trigger_mass_deletion_alert(self, user, mass_deletion_metadata):
        """Trigger mass deletion alert with duplicate prevention."""
        current_time = time.time()
        ip_address = mass_deletion_metadata.get('ip_address', 'unknown')
        user_ip_key = f"{user}_{ip_address}"
        
        if user_ip_key in self.active_mass_deletion_alerts:
            alert_data = self.active_mass_deletion_alerts[user_ip_key]
            
            # Update existing alert data
            current_count = mass_deletion_metadata['count']
            previous_count = alert_data['count']
            
            alert_data['count'] = current_count
            alert_data['files'] = mass_deletion_metadata['affected_files']
            alert_data['last_update_time'] = current_time
            alert_data['metadata'] = mass_deletion_metadata
            alert_data['update_count'] = alert_data.get('update_count', 0) + 1
            
            # Mark as incremental update
            mass_deletion_metadata['incremental_update'] = True
            mass_deletion_metadata['previous_count'] = previous_count
            mass_deletion_metadata['update_number'] = alert_data['update_count']
            mass_deletion_metadata['file_increase'] = current_count - previous_count
            
            print(f"🔄 Updated mass deletion alert for {user_ip_key}: {previous_count} → {current_count} files (+{current_count - previous_count} new)")
            
            return False
        else:
            # NEW MASS DELETION ATTACK
            mass_deletion_metadata['new_attack'] = True
            
            # Initialize tracking for this attack
            self.active_mass_deletion_alerts[user_ip_key] = {
                'start_time': current_time,
                'count': mass_deletion_metadata['count'],
                'files': mass_deletion_metadata['affected_files'],
                'last_alert_time': current_time,
                'last_update_time': current_time,
                'metadata': mass_deletion_metadata,
                'update_count': 0,
                'alert_count': 1,
                'active': True,
                'alert_type': 'MASS_DELETION'
            }
            
            print(f"🗑️ NEW Mass Deletion attack detected for {user_ip_key}: {mass_deletion_metadata['count']} files")
            return True

    def _should_trigger_mass_creation_alert(self, user, mass_creation_metadata):
        """Trigger mass creation alert with duplicate prevention."""
        current_time = time.time()
        ip_address = mass_creation_metadata.get('ip_address', 'unknown')
        user_ip_key = f"{user}_{ip_address}_CREATION"
        
        if user_ip_key in self.active_mass_creation_alerts:
            alert_data = self.active_mass_creation_alerts[user_ip_key]
            
            # Update existing alert data
            current_count = mass_creation_metadata['count']
            previous_count = alert_data['count']
            
            alert_data['count'] = current_count
            alert_data['files'] = mass_creation_metadata['affected_files']
            alert_data['last_update_time'] = current_time
            alert_data['metadata'] = mass_creation_metadata
            alert_data['update_count'] = alert_data.get('update_count', 0) + 1
            
            # Mark as incremental update
            mass_creation_metadata['incremental_update'] = True
            mass_creation_metadata['previous_count'] = previous_count
            mass_creation_metadata['update_number'] = alert_data['update_count']
            mass_creation_metadata['file_increase'] = current_count - previous_count
            
            print(f"🔄 Updated mass creation alert for {user_ip_key}: {previous_count} → {current_count} files (+{current_count - previous_count} new)")
            
            return False
        else:
            # NEW MASS CREATION ATTACK
            mass_creation_metadata['new_attack'] = True
            
            # Initialize tracking for this attack
            self.active_mass_creation_alerts[user_ip_key] = {
                'start_time': current_time,
                'count': mass_creation_metadata['count'],
                'files': mass_creation_metadata['affected_files'],
                'last_alert_time': current_time,
                'last_update_time': current_time,
                'metadata': mass_creation_metadata,
                'update_count': 0,
                'alert_count': 1,
                'active': True,
                'alert_type': 'MASS_CREATION'
            }
            
            print(f"📁 NEW Mass File Creation attack detected for {user_ip_key}: {mass_creation_metadata['count']} files")
            return True

    def _update_mass_deletion_buffers(self, event):
        """Update mass deletion detection buffers with new events."""
        user = event.get('user', 'unknown')
        normalized_action = self.normalize_action(event.get('action', ''))
        
        if normalized_action == 'DELETE':
            # Convert timestamp to consistent format
            timestamp = event.get('timestamp', datetime.now())
            if isinstance(timestamp, (datetime, pd.Timestamp)):
                current_time = timestamp.timestamp()
            else:
                current_time = pd.to_datetime(timestamp).timestamp()
            
            # Use user-based buffer for tracking (group by user)
            user_key = f"{user}_deletion_buffer"
            buffer = self.mass_deletion_buffers[user_key]
            
            # Add current event to buffer
            buffer.append({
                'event': event,
                'timestamp': current_time,
                'original_time': timestamp
            })
            
            # Clean old entries (keep 5 minutes max for analysis)
            while buffer and (current_time - buffer[0]['timestamp']) > 300:  # 5 minutes
                buffer.popleft()

    def _update_mass_creation_buffers(self, event):
        """Update mass creation detection buffers with new events."""
        user = event.get('user', 'unknown')
        normalized_action = self.normalize_action(event.get('action', ''))
        
        if normalized_action == 'CREATE':
            # Convert timestamp to consistent format
            timestamp = event.get('timestamp', datetime.now())
            if isinstance(timestamp, (datetime, pd.Timestamp)):
                current_time = timestamp.timestamp()
            else:
                current_time = pd.to_datetime(timestamp).timestamp()
            
            # Use user-based buffer for tracking (group by user)
            user_key = f"{user}_creation_buffer"
            buffer = self.mass_creation_buffers[user_key]
            
            # Add current event to buffer
            buffer.append({
                'event': event,
                'timestamp': current_time,
                'original_time': timestamp
            })
            
            # Clean old entries (keep 5 minutes max for analysis)
            while buffer and (current_time - buffer[0]['timestamp']) > 300:  # 5 minutes
                buffer.popleft()

    def update_extended_buffers(self, user, action, event, timestamp):
        """Update extended buffers for longer-term detection."""
        normalized_action = self.normalize_action(action)
        if normalized_action in ['MODIFY', 'RENAME']:
            user_action_key = f"{user}_{normalized_action}"
            buffer = self.extended_activity_buffers[user][user_action_key]
            
            # Convert timestamp
            if isinstance(timestamp, (datetime, pd.Timestamp)):
                current_time = timestamp.timestamp()
            else:
                current_time = pd.to_datetime(timestamp).timestamp()
            
            # Add to extended buffer
            buffer.append({
                'event': event,
                'timestamp': current_time,
                'original_time': timestamp
            })
            
            # Clean old entries (keep 10 minutes max)
            while buffer and (current_time - buffer[0]['timestamp']) > 600:  # 10 minutes
                buffer.popleft()

    def normalize_action(self, action):
        """
        Normalize action names for consistent grouping in popup keys.
        
        Args:
            action (str): Raw action string from event
            
        Returns:
            str: Normalized action string
        """
        if not action or action == 'Unknown':
            return 'UNKNOWN'
        
        # Convert to uppercase and strip whitespace
        action_upper = action.upper().strip()
        
        # Action normalization mapping
        action_mapping = {
            'CREATED': 'CREATE',
            'DELETED': 'DELETE', 
            'MODIFIED': 'MODIFY',
            'MOVED': 'MOVE',
            'RENAMED': 'RENAME',
            'MASS DELETE': 'DELETE',
            'MASS CREATE': 'CREATE', 
            'MASS MODIFY': 'MODIFY',
            'MASS MOVE': 'MOVE',
            'MASS RENAME': 'RENAME',
            'READ': 'READ',
            'WRITE': 'WRITE',
            'ACCESSED': 'ACCESS',
            'OPENED': 'OPEN',
            'CLOSED': 'CLOSE',
            'COPIED': 'COPY'
        }
        
        return action_mapping.get(action_upper, action_upper)

    def track_action_rate(self, user, action, timestamp):
        """Track action rates per user in rolling time windows - BEHAVIOR-FOCUSED."""
        normalized_action = self.normalize_action(action)
        window_size = self.action_time_windows.get(normalized_action, 60)  # default 1 minute

        # Use BEHAVIOR-based tracking instead of user-based
        action_key = f"BEHAVIOR_{normalized_action}"  # Track by action type, not user
        action_counts = self.user_action_counts[action_key][normalized_action]

        # Convert timestamp to seconds for comparison
        if isinstance(timestamp, (datetime, pd.Timestamp)):
            current_time = timestamp.timestamp()
        else:
            current_time = pd.to_datetime(timestamp).timestamp()

        # Remove old entries outside the window
        while action_counts and (current_time - action_counts[0]) > window_size:
            action_counts.popleft()

        # Add current action
        action_counts.append(current_time)

        return len(action_counts)

    def get_action_rate_score(self, user, action):
        """Calculate action rate severity score - BEHAVIOR-FOCUSED."""
        normalized_action = self.normalize_action(action)
        window_size = self.action_time_windows.get(normalized_action, 60)
        
        # Track by action type across all users (BEHAVIOR-FOCUSED)
        action_key = f"BEHAVIOR_{normalized_action}"
        count = len(self.user_action_counts[action_key][normalized_action])

        # Define thresholds for different actions (BEHAVIOR-BASED)
        thresholds = {
            'DELETE': 8,   # 8+ deletes per window across ALL users = high risk
            'CREATE': 15,  # 15+ creations across ALL users
            'MODIFY': 12,  # 12+ modifications across ALL users  
            'MOVE': 8,     # 8+ moves across ALL users
            'RENAME': 10,  # 10+ renames across ALL users
        }

        threshold = thresholds.get(normalized_action, 10)
        rate_ratio = count / threshold

        if rate_ratio >= 1.5:
            return 3  # High severity
        elif rate_ratio >= 1.0:
            return 2  # Medium severity
        elif rate_ratio >= 0.7:
            return 1  # Low severity
        else:
            return 0  # Normal

    def extract_features(self, event):
        """Extract features for anomaly detection - FOCUS ON BEHAVIOR PATTERNS, NOT USER IDENTITY."""
        features = {}

        # Normalize action first
        normalized_action = self.normalize_action(event.get('action', 'UNKNOWN'))

        # Time-based features (BEHAVIOR PATTERN)
        if 'timestamp' in event:
            try:
                if isinstance(event['timestamp'], str):
                    dt = datetime.fromisoformat(event['timestamp'].replace('Z', '+00:00'))
                else:
                    dt = event['timestamp'] if hasattr(event['timestamp'], 'hour') else pd.Timestamp(event['timestamp'])

                features['hour'] = dt.hour
                features['day_of_week'] = dt.weekday()
                features['minute'] = dt.minute
                features['is_off_hours'] = 1 if dt.hour >= 22 or dt.hour < 6 else 0
            except:
                features['hour'] = 12
                features['day_of_week'] = 0
                features['minute'] = 0
                features['is_off_hours'] = 0

        # Action features (using normalized action) - BEHAVIOR PATTERN
        features['action_READ'] = 1 if normalized_action == 'READ' else 0
        features['action_WRITE'] = 1 if normalized_action == 'WRITE' else 0
        features['action_CREATE'] = 1 if normalized_action == 'CREATE' else 0
        features['action_DELETE'] = 1 if normalized_action == 'DELETE' else 0
        features['action_MOVE'] = 1 if normalized_action == 'MOVE' else 0
        features['action_RENAME'] = 1 if normalized_action == 'RENAME' else 0
        features['action_MODIFY'] = 1 if normalized_action == 'MODIFY' else 0

        # BEHAVIOR-FOCUSED: Use generic user category instead of specific user ID
        user = str(event.get('user', 'unknown'))
        features['user_category'] = hash(user) % 10  # Simple bucketing, not identity-based

        # File path features - BEHAVIOR PATTERN
        file_path = str(event.get('file_path', ''))
        features['path_length'] = len(file_path)
        features['has_extension'] = 1 if '.' in file_path.split('/')[-1] else 0
        
        # File extension patterns (more behavior-focused)
        if '.' in file_path:
            extension = file_path.split('.')[-1].lower()
            features['extension_length'] = len(extension)
            # Common extension categories
            features['is_document_ext'] = 1 if extension in ['doc', 'docx', 'pdf', 'txt', 'rtf', 'odt'] else 0
            features['is_spreadsheet_ext'] = 1 if extension in ['xls', 'xlsx', 'csv', 'ods'] else 0
            features['is_image_ext'] = 1 if extension in ['jpg', 'jpeg', 'png', 'gif', 'bmp'] else 0
            features['is_executable_ext'] = 1 if extension in ['exe', 'dll', 'bat', 'ps1', 'msi'] else 0
            features['is_encrypted_like_ext'] = 1 if extension in ['lock', 'enc', 'encrypted', 'crypt', 'locked'] else 0
        else:
            features['extension_length'] = 0
            features['is_document_ext'] = 0
            features['is_spreadsheet_ext'] = 0
            features['is_image_ext'] = 0
            features['is_executable_ext'] = 0
            features['is_encrypted_like_ext'] = 0

        # File type features - BEHAVIOR PATTERN
        file_type = str(event.get('file_type', 'unknown')).lower()
        features['is_system_file'] = 1 if any(sys in file_type for sys in ['system', 'dll', 'exe', 'sys']) else 0
        features['is_document'] = 1 if any(doc in file_type for doc in ['doc', 'pdf', 'txt', 'xls', 'docx', 'xlsx']) else 0
        features['is_media'] = 1 if any(media in file_type for media in ['jpg', 'png', 'mp4', 'avi', 'mp3', 'wav']) else 0

        # File size behavior pattern
        file_size = event.get('file_size', 0)
        features['file_size_category'] = self._categorize_file_size(file_size)

        # Destination path features for MOVE actions - BEHAVIOR PATTERN
        if event.get('action', '').upper() == 'MOVE' and 'dest_path' in event:
            dest_path = str(event['dest_path'])
            features['dest_path_length'] = len(dest_path)
            features['dest_has_extension'] = 1 if '.' in dest_path.split('/')[-1] else 0

            # Suspicious destination indicators
            dest_lower = dest_path.lower()
            features['dest_is_temp'] = 1 if any(temp in dest_lower for temp in ['temp', 'tmp']) else 0
            features['dest_is_download'] = 1 if 'download' in dest_lower else 0
            features['dest_is_external'] = 1 if any(ext in dest_lower for ext in ['usb', 'removable', 'network', 'share']) else 0

        # Mass activity indicator (simplified)
        features['mass_activity'] = 0  # Will be updated during detection

        return features

    def smooth_scores(self, user, current_score):
        """Apply rolling window smoothing to scores per user."""
        buffer = self.user_score_buffers[user]
        buffer.append(current_score)

        if len(buffer) >= 5:  # Minimum window size
            return np.mean(buffer)
        return current_score

    def check_context_flags(self, event):
        """Check for context flags and assign weighted scores."""
        severity_score = 0
        flags = []

        user = event.get('user', 'unknown')
        normalized_action = self.normalize_action(event.get('action', ''))

        # Action rate scoring (BEHAVIOR-FOCUSED)
        rate_score = self.get_action_rate_score(user, normalized_action)
        severity_score += rate_score
        if rate_score >= 2:
            flags.append('high_action_rate')

        # Off-hours activity (10 PM to 6 AM) = +1
        if 'timestamp' in event:
            try:
                if isinstance(event['timestamp'], str):
                    dt = datetime.fromisoformat(event['timestamp'].replace('Z', '+00:00'))
                else:
                    dt = event['timestamp'] if hasattr(event['timestamp'], 'hour') else pd.Timestamp(event['timestamp'])

                if dt.hour >= 22 or dt.hour < 6:
                    severity_score += 1
                    flags.append('off_hours')
            except:
                pass

        # System file modification = +2
        file_path = str(event.get('file_path', '')).lower()
        system_dirs = ['system32', 'windows', 'program files', 'etc', 'sys', 'system']
        if any(dir in file_path for dir in system_dirs):
            severity_score += 2
            flags.append('system_file')

        # Sensitive keywords = +2
        sensitive_keywords = {'password', 'secret', 'confidential', 'private', 'bank', 'ssh', 'key', 'credential'}
        if any(keyword in file_path for keyword in sensitive_keywords):
            severity_score += 2
            flags.append('sensitive_file')

        # Suspicious destinations for MOVE actions = +2
        if normalized_action == 'MOVE' and 'dest_path' in event:
            dest_path = str(event['dest_path']).lower()
            suspicious_dests = ['download', 'temp', 'tmp', 'removable', 'usb', 'network', 'share']
            if any(dest in dest_path for dest in suspicious_dests):
                severity_score += 2
                flags.append('suspicious_destination')

        return flags, severity_score

    def classify_event(self, raw_score, smoothed_score, context_flags, severity_score):
        """Classify event based on thresholds and severity scoring."""
        base_classification = 'NORMAL'

        # Base classification on anomaly score
        if smoothed_score >= self.anomaly_threshold:
            base_classification = 'ANOMALY'
        elif smoothed_score >= self.normal_threshold:
            base_classification = 'SUSPICIOUS'

        # Apply severity scoring overlay
        if severity_score >= 5:
            final_classification = 'CRITICAL'
        elif severity_score >= 3:
            final_classification = 'ANOMALY'
        elif severity_score >= 2 and base_classification == 'SUSPICIOUS':
            final_classification = 'ANOMALY'
        else:
            final_classification = base_classification

        # Ensure CRITICAL from base classification is preserved
        if base_classification == 'CRITICAL' and final_classification != 'CRITICAL':
            final_classification = 'CRITICAL'

        return final_classification

    def _should_trigger_ransomware_alert(self, user, ransomware_metadata):
        """
        Enhanced ransomware alert triggering with strict duplicate prevention.
        """
        current_time = time.time()
        
        # CRITICAL FIX: Always extract IP from metadata, not from separate events
        ip_address = ransomware_metadata.get('ip_address', 'unknown')
        user_ip_key = f"{user}_{ip_address}"
        
        # Check for existing entries with the same user but different IP format
        existing_keys = list(self.active_ransomware_alerts.keys())
        for existing_key in existing_keys:
            existing_user = existing_key.split('_')[0]
            if existing_user == user and existing_key != user_ip_key:
                print(f"🔄 Migrating ransomware tracking from {existing_key} to {user_ip_key}")
                
                # Migrate all data from old key to new key
                self.active_ransomware_alerts[user_ip_key] = self.active_ransomware_alerts[existing_key]
                
                # Update the IP address in the migrated data
                if 'metadata' in self.active_ransomware_alerts[user_ip_key]:
                    self.active_ransomware_alerts[user_ip_key]['metadata']['ip_address'] = ip_address
                
                # Remove the old key
                del self.active_ransomware_alerts[existing_key]
                
                # Also migrate popup reference if it exists
                if existing_key in self.active_popups:
                    self.active_popups[user_ip_key] = self.active_popups[existing_key]
                    del self.active_popups[existing_key]
                    print(f"🔄 Migrated popup reference from {existing_key} to {user_ip_key}")
                break
        
        # Continue with normal alert triggering logic
        if user_ip_key in self.active_ransomware_alerts:
            alert_data = self.active_ransomware_alerts[user_ip_key]
            
            # Get counts for comparison
            current_count = ransomware_metadata['count']
            previous_count = alert_data['count']
            
            # Calculate time since last update
            time_since_last_update = current_time - alert_data['last_update_time']
            
            # Always update existing alert data
            alert_data['count'] = current_count
            alert_data['files'] = ransomware_metadata['affected_files']
            alert_data['last_update_time'] = current_time
            alert_data['metadata'] = ransomware_metadata
            alert_data['update_count'] = alert_data.get('update_count', 0) + 1
            
            # Mark as incremental update for GUI
            ransomware_metadata['incremental_update'] = True
            ransomware_metadata['previous_count'] = previous_count
            ransomware_metadata['update_number'] = alert_data['update_count']
            ransomware_metadata['file_increase'] = current_count - previous_count
            
            print(f"🔄 Updated ransomware alert for {user_ip_key}: {previous_count} → {current_count} files (+{current_count - previous_count} new, update #{alert_data['update_count']})")
            
            # Return False to prevent new alert creation - only update existing
            return False
            
        else:
            # NEW ATTACK - no active alert for this user/IP
            ransomware_metadata['new_attack'] = True
            
            # Initialize tracking for this attack
            self.active_ransomware_alerts[user_ip_key] = {
                'start_time': current_time,
                'count': ransomware_metadata['count'],
                'files': ransomware_metadata['affected_files'],
                'last_alert_time': current_time,
                'last_update_time': current_time,
                'metadata': ransomware_metadata,
                'update_count': 0,
                'alert_count': 1,
                'active': True
            }
            
            print(f"🔒 NEW Ransomware attack detected for {user_ip_key}: {ransomware_metadata['count']} files")
            return True
        
    def cleanup_duplicate_ransomware_entries(self):
        """Clean up duplicate ransomware entries for the same user."""
        if not hasattr(self, 'active_ransomware_alerts'):
            return
            
        users_found = {}
        duplicates_to_remove = []
        
        # Find duplicate entries for the same user
        for user_ip_key in list(self.active_ransomware_alerts.keys()):
            user_parts = user_ip_key.split('_')
            if len(user_parts) < 2:
                continue
                
            user = user_parts[0]
            ip_part = user_parts[1]
            
            if user in users_found:
                # We found a duplicate - keep the one with IP address, remove the one without
                existing_key = users_found[user]
                current_key = user_ip_key
                
                # Prefer the key with actual IP address over 'unknown'
                if 'unknown' in existing_key.lower() and 'unknown' not in current_key.lower():
                    # Keep current_key (has IP), remove existing_key (has unknown)
                    duplicates_to_remove.append(existing_key)
                    users_found[user] = current_key
                    print(f"🔄 Keeping {current_key}, removing {existing_key} (has unknown IP)")
                elif 'unknown' in current_key.lower() and 'unknown' not in existing_key.lower():
                    # Keep existing_key (has IP), remove current_key (has unknown)
                    duplicates_to_remove.append(current_key)
                    print(f"🔄 Keeping {existing_key}, removing {current_key} (has unknown IP)")
                else:
                    # Both have IP or both have unknown - keep the newer one based on activity
                    existing_data = self.active_ransomware_alerts[existing_key]
                    current_data = self.active_ransomware_alerts[current_key]
                    
                    # Keep the one with more recent activity
                    if current_data.get('last_update_time', 0) > existing_data.get('last_update_time', 0):
                        duplicates_to_remove.append(existing_key)
                        users_found[user] = current_key
                        print(f"🔄 Keeping newer {current_key}, removing older {existing_key}")
                    else:
                        duplicates_to_remove.append(current_key)
                        print(f"🔄 Keeping existing {existing_key}, removing newer {current_key}")
            else:
                users_found[user] = user_ip_key
        
        # Remove duplicates
        for duplicate_key in duplicates_to_remove:
            if duplicate_key in self.active_ransomware_alerts:
                del self.active_ransomware_alerts[duplicate_key]
                print(f"🧹 Removed duplicate ransomware entry: {duplicate_key}")
            
            # Also clean up popup references
            if duplicate_key in self.active_popups:
                popup = self.active_popups[duplicate_key]
                if popup and hasattr(popup, 'popup') and popup.popup and popup.popup.winfo_exists():
                    try:
                        popup.popup.destroy()
                    except:
                        pass
                del self.active_popups[duplicate_key]
                print(f"🧹 Removed duplicate popup reference: {duplicate_key}")

    def detect_anomalies(self, event):
        """Enhanced detect_anomalies with Mass Deletion, Ransomware, AND Mass Creation detection."""
        # Update all detection buffers FIRST
        self._update_mass_deletion_buffers(event)
        self._update_mass_creation_buffers(event)
        
        if not self.baseline_trained:
            # Simple rule-based detection before training
            return self._initial_detection(event)

        # Track action rate for rolling windows (BEHAVIOR-FOCUSED)
        user = event.get('user', 'unknown')
        action = event.get('action', 'unknown')
        timestamp = event.get('timestamp', datetime.now())
        self.track_action_rate(user, action, timestamp)

        # Extract features (BEHAVIOR-FOCUSED)
        features = self.extract_features(event)

        # Get raw score
        raw_score = self.model.score_one(features)

        # Smooth score per user
        smoothed_score = self.smooth_scores(user, raw_score)

        # Check context flags with severity scoring
        context_flags, severity_score = self.check_context_flags(event)

        # Classify event
        classification = self.classify_event(raw_score, smoothed_score, context_flags, severity_score)

        # Enhanced mass activity detection with BEHAVIOR-FOCUSED approach
        is_mass_activity, mass_metadata = self._check_mass_activity(
            event, classification, severity_score, smoothed_score
        )

        # **MASS DELETION DETECTION** - Run after other mass activity checks
        mass_deletion_detected = False
        mass_deletion_metadata = None
        
        normalized_action = self.normalize_action(action)
        if normalized_action == 'DELETE':
            mass_deletion_detected, mass_deletion_metadata = self._detect_mass_deletion_sabotage(
                user, timestamp, normalized_action
            )
            
            if mass_deletion_detected and mass_deletion_metadata:
                print(f"🚨 TRIGGERING MASS DELETION ALERT for {user}")
                # Override classification for mass deletion
                classification = 'CRITICAL'
                is_mass_activity = True
                mass_metadata = mass_deletion_metadata

        # **MASS CREATION DETECTION** - Run after other mass activity checks
        mass_creation_detected = False
        mass_creation_metadata = None
        
        if normalized_action == 'CREATE':
            mass_creation_detected, mass_creation_metadata = self._detect_mass_creation_flooding(
                user, timestamp, normalized_action
            )
            
            if mass_creation_detected and mass_creation_metadata:
                print(f"🚨 TRIGGERING MASS CREATION ALERT for {user}")
                # Override classification for mass creation
                classification = 'CRITICAL'
                is_mass_activity = True
                mass_metadata = mass_creation_metadata

        # CRITICAL FIX: Handle ransomware, mass deletion AND mass creation detection - override classification
        if mass_metadata and (mass_metadata.get('ransomware_detected', False) or 
                            mass_metadata.get('mass_deletion_detected', False) or
                            mass_metadata.get('mass_creation_detected', False)):
            classification = 'CRITICAL'
            # Ensure proper flag is passed to result
            result = {
                'classification': classification,
                'score': raw_score,
                'smoothed_score': smoothed_score,
                'context_flags': context_flags,
                'severity_score': severity_score,
                'features': features,
                'event': event,
                'reason': mass_metadata.get('ransomware_reason', 
                                        mass_metadata.get('mass_deletion_reason',
                                        mass_metadata.get('mass_creation_reason',
                                                        "Critical mass activity detected"))),
                'mass_activity_detected': is_mass_activity,
                'mass_activity_metadata': mass_metadata,
                'ransomware_detected': mass_metadata.get('ransomware_detected', False),
                'mass_deletion_detected': mass_metadata.get('mass_deletion_detected', False),
                'mass_creation_detected': mass_metadata.get('mass_creation_detected', False),
                'ransomware_reason': mass_metadata.get('ransomware_reason', ""),
                'mass_deletion_reason': mass_metadata.get('mass_deletion_reason', ""),
                'mass_creation_reason': mass_metadata.get('mass_creation_reason', "")
            }
        else:
            # Prepare result for non-critical cases
            result = {
                'classification': classification,
                'score': raw_score,
                'smoothed_score': smoothed_score,
                'context_flags': context_flags,
                'severity_score': severity_score,
                'features': features,
                'event': event,
                'reason': self.generate_reason(classification, smoothed_score, context_flags, severity_score),
                'mass_activity_detected': is_mass_activity,
                'mass_activity_metadata': mass_metadata
            }

        # Handle CRITICAL classification with mass activity requirements
        if classification == 'CRITICAL' and is_mass_activity and mass_metadata:
            if not mass_metadata.get('critical_qualified', True):
                # Downgrade to ANOMALY if mass activity doesn't meet CRITICAL requirements
                result['classification'] = 'ANOMALY'
                result['reason'] += " (mass activity detected but anomaly score below critical threshold)"

        # Enhance reason with mass activity info
        if is_mass_activity and mass_metadata:
            count = mass_metadata['count']
            duration = mass_metadata['duration_text']
            action_type = mass_metadata['action']

            # Use critical reason if available
            if mass_metadata.get('ransomware_detected', False):
                result['reason'] = mass_metadata.get('ransomware_reason', result['reason'])
            elif mass_metadata.get('mass_deletion_detected', False):
                result['reason'] = mass_metadata.get('mass_deletion_reason', result['reason'])
            elif mass_metadata.get('mass_creation_detected', False):
                result['reason'] = mass_metadata.get('mass_creation_reason', result['reason'])
            else:
                result['reason'] = f"Mass {action_type.lower()} activity - {count} operations in {duration}"

            # Add threshold info for debugging
            if mass_metadata.get('threshold_reason') == 'high_severity_context':
                result['reason'] += f" (adaptive threshold: {mass_metadata['threshold_used']} due to high severity)"

        # Online learning for normal events
        if result['classification'] == 'NORMAL':
            self.model.learn_one(features)
            self.normal_buffer.append(event)

        if result['classification'] in ['ANOMALY', 'CRITICAL']:
            alert = self.generate_alert(result)
            mass_activities = mass_metadata['affected_files'] if mass_metadata else None
            return alert, result, is_mass_activity, mass_activities
        else:
            return None, result, False, None

    def _initial_detection(self, event):
        """Simple rule-based detection before model is trained."""
        normalized_action = self.normalize_action(event.get('action', ''))

        # Basic heuristics
        if normalized_action == 'DELETE':
            alert_level = "SUSPICIOUS"
            reason = "File deletion detected (pre-training)"
        elif normalized_action == 'CREATE':
            file_size = event.get('file_size', 0)
            if file_size > 1000000:  # 1MB
                alert_level = "SUSPICIOUS"
                reason = "Large file creation (pre-training)"
            else:
                return None, {'event': event}, False, None
        else:
            return None, {'event': event}, False, None

        result = {
            'classification': alert_level,
            'score': 0.7,
            'smoothed_score': 0.7,
            'context_flags': [],
            'severity_score': 1,
            'features': self.extract_features(event),
            'event': event,
            'reason': reason
        }

        alert = self.generate_alert(result) 
        return alert, result, False, None

    def _check_mass_activity(self, event, classification, severity_score, anomaly_score):
        """
        Enhanced mass activity detection with MEDIUM-SENSITIVE ransomware and mass deletion detection.
        """
        if classification in ["NORMAL", "SUSPICIOUS"]:
            return False, None

        user = event.get('user', 'unknown')
        normalized_action = self.normalize_action(event.get('action', ''))
        current_time = event.get('timestamp', datetime.now())

        # Convert current time to timestamp for comparison
        if isinstance(current_time, (datetime, pd.Timestamp)):
            current_timestamp = current_time.timestamp()
        else:
            current_timestamp = pd.to_datetime(current_time).timestamp()

        # BEHAVIOR-FOCUSED THRESHOLDS - APPLY TO ALL USERS EQUALLY
        action_config = {
            'DELETE': {
                'window_seconds': 120,
                'threshold': 8,
                'high_severity_threshold': 6,
                'critical_anomaly_threshold': 0.7
            },
            'CREATE': {
                'window_seconds': 180,
                'threshold': 15,
                'high_severity_threshold': 12,
                'critical_anomaly_threshold': 0.6
            },
            'MODIFY': {
                'window_seconds': 180,
                'threshold': 12,
                'high_severity_threshold': 10,
                'critical_anomaly_threshold': 0.65
            },
            'MOVE': {
                'window_seconds': 120,
                'threshold': 8,
                'high_severity_threshold': 6,
                'critical_anomaly_threshold': 0.7
            },
            'RENAME': {
                'window_seconds': 120,
                'threshold': 10,
                'high_severity_threshold': 8,
                'critical_anomaly_threshold': 0.7
            }
        }

        # Skip if action not in our monitoring list
        if normalized_action not in action_config:
            return False, None

        config = action_config[normalized_action]

        # Initialize data structures if not exists
        if not hasattr(self, 'mass_activity_buffers'):
            self.mass_activity_buffers = defaultdict(lambda: defaultdict(lambda: deque(maxlen=200)))

        if not hasattr(self, 'mass_activity_metadata'):
            self.mass_activity_metadata = defaultdict(dict)

        # Use USER-based buffer for critical detection
        user_action_key = f"{user}_{normalized_action}"
        buffer = self.mass_activity_buffers[user][user_action_key]

        # Add current event to buffer with timestamp
        buffer.append({
            'event': event,
            'timestamp': current_timestamp,
            'original_time': current_time
        })

        # Clean old entries outside the time window
        window_seconds = config['window_seconds']
        while buffer and (current_timestamp - buffer[0]['timestamp']) > window_seconds:
            buffer.popleft()

        current_count = len(buffer)

        # Apply SAME thresholds to ALL users (BEHAVIOR-FOCUSED)
        base_threshold = config['threshold']
        if severity_score >= 5:
            adaptive_threshold = config['high_severity_threshold']
            threshold_reason = "high_severity_context"
        else:
            adaptive_threshold = base_threshold
            threshold_reason = "normal_threshold"

        # **MASS DELETION/SABOTAGE DETECTION LOGIC** - MOVED TO SEPARATE METHOD
        mass_deletion_detected = False
        mass_deletion_metadata = None

        if normalized_action == 'DELETE':
            mass_deletion_detected, mass_deletion_metadata = self._detect_mass_deletion_sabotage(
                user, current_time, normalized_action
            )
            
            if mass_deletion_detected and mass_deletion_metadata:
                # Trigger mass deletion alert
                should_trigger_alert = self._should_trigger_mass_deletion_alert(user, mass_deletion_metadata)
                return True, mass_deletion_metadata

        # **MASS CREATION DETECTION LOGIC** - MOVED TO SEPARATE METHOD
        mass_creation_detected = False
        mass_creation_metadata = None

        if normalized_action == 'CREATE':
            mass_creation_detected, mass_creation_metadata = self._detect_mass_creation_flooding(
                user, current_time, normalized_action
            )
            
            if mass_creation_detected and mass_creation_metadata:
                # Trigger mass creation alert
                should_trigger_alert = self._should_trigger_mass_creation_alert(user, mass_creation_metadata)
                return True, mass_creation_metadata

        # **MEDIUM-SENSITIVE RANSOMWARE DETECTION LOGIC**
        ransomware_detected = False
        ransomware_metadata = None

        # Only check for ransomware patterns in MODIFY and RENAME actions
        if normalized_action in ['MODIFY', 'RENAME']:
            # Get combined buffer for MODIFY and RENAME actions for THIS USER
            modify_buffer = self.mass_activity_buffers[user].get(f"{user}_MODIFY", deque(maxlen=200))
            rename_buffer = self.mass_activity_buffers[user].get(f"{user}_RENAME", deque(maxlen=200))

            # Combine and filter recent events within ransomware detection window (120 seconds)
            combined_events = list(modify_buffer) + list(rename_buffer)
            recent_events = [e for e in combined_events if (current_timestamp - e['timestamp']) <= 120]

            # **MEDIUM SENSITIVITY: Require significant activity**
            if len(recent_events) >= 15:  # Medium threshold - requires substantial activity
                # Count operations by type
                modify_count = len([e for e in recent_events if self.normalize_action(e['event'].get('action', '')) == 'MODIFY'])
                rename_count = len([e for e in recent_events if self.normalize_action(e['event'].get('action', '')) == 'RENAME'])

                # Check for encrypted file extensions in RENAME actions
                encrypted_extensions = {'.lock', '.enc', '.encrypted', '.crypt', '.cry', '.locked'}
                encrypted_rename_count = 0
                
                # Also check for suspicious file patterns
                suspicious_pattern_count = 0

                for event_data in recent_events:
                    file_event = event_data['event']
                    file_path = file_event.get('file_path', '').lower()
                    dest_path = file_event.get('dest_path', '').lower()
                    
                    # Check for encrypted extensions in RENAME actions
                    if self.normalize_action(file_event.get('action', '')) == 'RENAME':
                        if dest_path:  # Only check if there's a destination path
                            # Extract extension from destination path
                            if '.' in dest_path:
                                dest_ext = '.' + dest_path.split('.')[-1].lower()
                                if dest_ext in encrypted_extensions:
                                    encrypted_rename_count += 1
                    
                    # Check for ransom notes and suspicious patterns
                    if any(pattern in file_path for pattern in ['readme', 'decrypt', 'recover', 'ransom', 'how_to_decrypt']):
                        suspicious_pattern_count += 1
                    if dest_path and any(pattern in dest_path for pattern in ['readme', 'decrypt', 'recover', 'ransom', 'how_to_decrypt']):
                        suspicious_pattern_count += 1

                # Check file type diversity (multiple file types being affected)
                file_types_affected = set()
                file_extensions_affected = set()
                
                for event_data in recent_events:
                    file_path = event_data['event'].get('file_path', '')
                    if '.' in file_path:
                        ext = file_path.split('.')[-1].lower()
                        file_extensions_affected.add(ext)
                        if ext in ['doc', 'docx', 'pdf', 'txt', 'rtf', 'odt']:
                            file_types_affected.add('document')
                        elif ext in ['xls', 'xlsx', 'csv', 'ods']:
                            file_types_affected.add('spreadsheet')
                        elif ext in ['jpg', 'jpeg', 'png', 'gif', 'bmp', 'tiff', 'svg']:
                            file_types_affected.add('image')
                        elif ext in ['mp4', 'avi', 'mov', 'mkv', 'wmv', 'flv']:
                            file_types_affected.add('video')
                        elif ext in ['mp3', 'wav', 'flac', 'aac', 'ogg']:
                            file_types_affected.add('audio')
                        elif ext in ['zip', 'rar', '7z', 'tar', 'gz']:
                            file_types_affected.add('archive')

                print(f"🔍 Ransomware analysis for {user}: {len(recent_events)} events, {encrypted_rename_count} encrypted renames")

                # **MEDIUM-SENSITIVE RANSOMWARE DETECTION CONDITIONS**
                # These require clear ransomware patterns but aren't overly strict
                condition_a = encrypted_rename_count >= 8  # Clear pattern: 8+ encrypted renames
                condition_b = (encrypted_rename_count >= 5 and len(recent_events) >= 20)  # 5+ encrypted with high volume
                condition_c = (modify_count >= 10 and rename_count >= 10 and encrypted_rename_count >= 3)  # Mixed activity with encryption
                condition_d = (encrypted_rename_count >= 6 and len(file_types_affected) >= 3)  # Multiple file types being encrypted
                condition_e = (suspicious_pattern_count >= 2 and encrypted_rename_count >= 4)  # Ransom notes + encryption

                if condition_a or condition_b or condition_c or condition_d or condition_e:
                    ransomware_detected = True
                    ransomware_operations = len(recent_events)

                    # Calculate duration
                    if recent_events:
                        start_time = min(e['timestamp'] for e in recent_events)
                        end_time = max(e['timestamp'] for e in recent_events)
                        duration_seconds = end_time - start_time

                        minutes = int(duration_seconds // 60)
                        seconds = int(duration_seconds % 60)
                        if minutes > 0:
                            duration_text = f"{minutes}m {seconds}s"
                        else:
                            duration_text = f"{seconds}s"

                        # Build behavior-focused alert reason
                        reason_parts = []
                        if modify_count > 0:
                            reason_parts.append(f"{modify_count} modifications")
                        if rename_count > 0:
                            reason_parts.append(f"{rename_count} renames")
                        if encrypted_rename_count > 0:
                            reason_parts.append(f"{encrypted_rename_count} encrypted")
                        if len(file_types_affected) > 0:
                            reason_parts.append(f"{len(file_types_affected)} file types")

                        ransomware_reason = f"🚨 RANSOMWARE DETECTED: {', '.join(reason_parts)} in {duration_text}"

                        # FIX: Collect ALL affected files with proper details
                        affected_files = []
                        for entry in recent_events:
                            file_event = entry['event']
                            
                            # Extract file path details
                            file_path = file_event.get('file_path', 'Unknown')
                            dest_path = file_event.get('dest_path', '')
                            
                            # Determine if this is an encrypted file
                            is_encrypted = False
                            if dest_path and '.' in dest_path:
                                dest_ext = '.' + dest_path.split('.')[-1].lower()
                                if dest_ext in encrypted_extensions:
                                    is_encrypted = True
                            
                            affected_files.append({
                                'timestamp': entry['original_time'],
                                'user': file_event.get('user', 'Unknown'),
                                'action': file_event.get('action', 'Unknown'),
                                'file_path': file_path,
                                'file_type': file_event.get('file_type', 'Unknown'),
                                'file_size': file_event.get('file_size', 0),
                                'dest_path': dest_path,
                                'ip_address': file_event.get('ip_address', 'Unknown'),
                                'is_encrypted': is_encrypted,
                                'encrypted_extension': dest_ext if is_encrypted else ''
                            })

                        # Create ransomware metadata
                        ransomware_metadata = {
                            'count': ransomware_operations,
                            'duration_seconds': duration_seconds,
                            'duration_text': duration_text,
                            'start_time': datetime.fromtimestamp(start_time),
                            'end_time': datetime.fromtimestamp(end_time),
                            'affected_files': affected_files,  # Now contains actual file details
                            'threshold_used': adaptive_threshold,
                            'base_threshold': base_threshold,
                            'threshold_reason': threshold_reason,
                            'window_seconds': window_seconds,
                            'action': 'RANSOMWARE',
                            'user': user,
                            'ip_address': event.get('ip_address', 'Unknown'),
                            'ransomware_detected': True,
                            'ransomware_reason': ransomware_reason,
                            'modify_count': modify_count,
                            'rename_count': rename_count,
                            'encrypted_rename_count': encrypted_rename_count,
                            'file_types_affected': list(file_types_affected),
                            'file_extensions_affected': list(file_extensions_affected),
                            'critical_qualified': True,
                            'anomaly_score': anomaly_score,
                            'critical_threshold': 0.7,
                            'suspicious_pattern_count': suspicious_pattern_count,
                            'detection_confidence': 'HIGH'
                        }

                        print(f"🚨 RANSOMWARE DETECTED for {user}: {ransomware_reason}")
                        print(f"   Affected files: {len(affected_files)}")
                        
                        # Trigger ransomware alert
                        should_trigger_alert = self._should_trigger_ransomware_alert(user, ransomware_metadata)
                        
                        return True, ransomware_metadata

        # Standard mass activity detection with behavior-focused thresholds
        mass_activity_detected = current_count >= adaptive_threshold

        if mass_activity_detected and not ransomware_detected and not mass_deletion_detected and not mass_creation_detected:
            if len(buffer) >= 5:  # Require minimum files for mass activity
                start_time = min(entry['timestamp'] for entry in buffer)
                end_time = max(entry['timestamp'] for entry in buffer)
                duration_seconds = end_time - start_time

                # Convert back to datetime for display
                start_dt = datetime.fromtimestamp(start_time)
                end_dt = datetime.fromtimestamp(end_time)

                # Collect affected files
                affected_files = []
                for entry in buffer:
                    file_event = entry['event']
                    affected_files.append({
                        'timestamp': entry['original_time'],
                        'user': file_event.get('user', 'Unknown'),
                        'action': file_event.get('action', 'Unknown'),
                        'file_path': file_event.get('file_path', 'Unknown'),
                        'file_type': file_event.get('file_type', 'Unknown'),
                        'file_size': file_event.get('file_size', 0),
                        'dest_path': file_event.get('dest_path', ''),
                        'ip_address': file_event.get('ip_address', 'Unknown')
                    })

                # Format duration for display
                minutes = int(duration_seconds // 60)
                seconds = int(duration_seconds % 60)
                if minutes > 0:
                    duration_text = f"{minutes}m {seconds}s"
                else:
                    duration_text = f"{seconds}s"

                # Prepare metadata
                metadata = {
                    'count': current_count,
                    'duration_seconds': duration_seconds,
                    'duration_text': duration_text,
                    'start_time': start_dt,
                    'end_time': end_dt,
                    'affected_files': affected_files,
                    'threshold_used': adaptive_threshold,
                    'base_threshold': base_threshold,
                    'threshold_reason': threshold_reason,
                    'window_seconds': window_seconds,
                    'action': normalized_action,
                    'user': user
                }

                # CRITICAL alert integration with higher threshold
                requires_critical = classification == 'CRITICAL'
                if requires_critical:
                    critical_threshold = config['critical_anomaly_threshold']
                    if anomaly_score >= critical_threshold and current_count >= (adaptive_threshold * 1.5):
                        metadata['critical_qualified'] = True
                        metadata['anomaly_score'] = anomaly_score
                        metadata['critical_threshold'] = critical_threshold
                    else:
                        metadata['critical_qualified'] = False
                        metadata['anomaly_score'] = anomaly_score
                        metadata['critical_threshold'] = critical_threshold

                # Reset buffer after detection
                recent_event = buffer[-1] if buffer else None
                buffer.clear()
                if recent_event:
                    buffer.append(recent_event)

                # Store metadata
                self.mass_activity_metadata[user_action_key] = metadata

                return True, metadata

        return False, None

    def get_mass_activity_stats(self, user=None, action=None):
        """
        Get statistics about recent mass activity detections.

        Args:
            user: Filter by user (optional)
            action: Filter by action (optional)

        Returns:
            dict: Mass activity statistics
        """
        if not hasattr(self, 'mass_activity_metadata'):
            return {}

        stats = {}
        for key, metadata in self.mass_activity_metadata.items():
            user_action = key.split('_', 1)
            if len(user_action) == 2:
                current_user, current_action = user_action
                if user and current_user != user:
                    continue
                if action and current_action != action:
                    continue

                if current_user not in stats:
                    stats[current_user] = {}
                if current_action not in stats[current_user]:
                    stats[current_user][current_action] = []

                stats[current_user][current_action].append({
                    'timestamp': metadata.get('end_time', datetime.now()),
                    'count': metadata['count'],
                    'duration': metadata['duration_text'],
                    'threshold_used': metadata['threshold_used']
                })

        return stats

    def _extract_file_type_from_path(self, file_path):
        """Extract file type from file path."""
        if file_path == 'Unknown' or not file_path:
            return 'Unknown'

        if '.' in file_path:
            extension = file_path.split('.')[-1].upper()
            # Map common extensions to file types
            file_types = {
                'TXT': 'TEXT_FILE', 'PDF': 'PDF_FILE', 'DOC': 'DOCUMENT', 'DOCX': 'DOCUMENT',
                'XLS': 'SPREADSHEET', 'XLSX': 'SPREADSHEET', 'PPT': 'PRESENTATION', 'PPTX': 'PRESENTATION',
                'JPG': 'IMAGE', 'JPEG': 'IMAGE', 'PNG': 'IMAGE', 'GIF': 'IMAGE', 'BMP': 'IMAGE',
                'MP4': 'VIDEO', 'AVI': 'VIDEO', 'MOV': 'VIDEO', 'MKV': 'VIDEO',
                'MP3': 'AUDIO', 'WAV': 'AUDIO', 'FLAC': 'AUDIO',
                'ZIP': 'ARCHIVE', 'RAR': 'ARCHIVE', '7Z': 'ARCHIVE',
                'EXE': 'EXECUTABLE', 'MSI': 'INSTALLER', 'BAT': 'SCRIPT', 'PS1': 'SCRIPT',
                'DLL': 'SYSTEM_FILE', 'SYS': 'SYSTEM_FILE'
            }
            return file_types.get(extension, f"{extension}_FILE")
        else:
            return 'FILE'

    def generate_reason(self, classification, score, context_flags, severity_score):
        """Generate human-readable reason for classification."""
        reasons = []

        if severity_score >= 3:
            reasons.append(f"High severity score ({severity_score})")

        if classification == 'NORMAL':
            reasons.append("Normal activity pattern")
        else:
            if score >= self.anomaly_threshold:
                reasons.append("High anomaly score")
            elif score >= self.normal_threshold:
                reasons.append("Suspicious pattern")

            if 'off_hours' in context_flags:
                reasons.append("Off-hours activity")
            if 'system_file' in context_flags:
                reasons.append("System file modification")
            if 'sensitive_file' in context_flags:
                reasons.append("Sensitive file access")
            if 'suspicious_destination' in context_flags:
                reasons.append("Suspicious destination")

        return ", ".join(reasons) if reasons else "Unknown"

    def generate_alert(self, result):
        """Generate alert dictionary for GUI display with proper file details for all critical alert types."""
        event = result['event']

        # Ensure timestamp is properly formatted
        timestamp = event.get('timestamp', datetime.now())
        if isinstance(timestamp, (datetime, pd.Timestamp)):
            timestamp_str = timestamp.isoformat()
        else:
            timestamp_str = str(timestamp)

        # Enhanced ransomware, mass deletion, AND mass creation detection check
        mass_metadata = result.get('mass_activity_metadata', {})
        is_ransomware = False
        is_mass_deletion = False
        is_mass_creation = False
        ransomware_reason = ""
        mass_deletion_reason = ""
        mass_creation_reason = ""

        # Check both mass_metadata and result for critical flags
        if mass_metadata and isinstance(mass_metadata, dict):
            is_ransomware = mass_metadata.get('ransomware_detected', False)
            is_mass_deletion = mass_metadata.get('mass_deletion_detected', False)
            is_mass_creation = mass_metadata.get('mass_creation_detected', False)
            ransomware_reason = mass_metadata.get('ransomware_reason', "")
            mass_deletion_reason = mass_metadata.get('mass_deletion_reason', "")
            mass_creation_reason = mass_metadata.get('mass_creation_reason', "")

        # Also check if critical activity was detected in the result itself
        if not is_ransomware and result.get('ransomware_detected', False):
            is_ransomware = True
            ransomware_reason = result.get('ransomware_reason', "Ransomware activity detected")

        if not is_mass_deletion and result.get('mass_deletion_detected', False):
            is_mass_deletion = True
            mass_deletion_reason = result.get('mass_deletion_reason', "Mass deletion activity detected")

        if not is_mass_creation and result.get('mass_creation_detected', False):
            is_mass_creation = True
            mass_creation_reason = result.get('mass_creation_reason', "Mass file creation activity detected")

        # CRITICAL: Get IP address from event
        ip_address = event.get('ip_address', 'Unknown')

        # Use the actual file information from the event
        alert = {
            'original_timestamp': timestamp_str,
            'alert_level': result['classification'],
            'user': event.get('user', 'unknown'),
            'action': event.get('action', 'unknown'),
            'anomaly_score': result['smoothed_score'],
            'reason': result['reason'],
            'file_path': event.get('file_path', 'Unknown'),
            'file_type': event.get('file_type', 'Unknown'),
            'ip_address': ip_address,
            'severity_score': result.get('severity_score', 0)
        }

        # OVERRIDE FOR CRITICAL ALERTS - Include mass activity metadata
        if is_ransomware or is_mass_deletion or is_mass_creation:
            alert['alert_level'] = 'CRITICAL'
            
            # Set specific reason based on the detected attack type
            if is_ransomware and ransomware_reason:
                alert['reason'] = ransomware_reason
                alert['attack_type'] = 'RANSOMWARE'
                print(f"🔒 RANSOMWARE ALERT: {ransomware_reason}")
                
            elif is_mass_deletion and mass_deletion_reason:
                alert['reason'] = mass_deletion_reason
                alert['attack_type'] = 'MASS_DELETION'
                print(f"🗑️ MASS DELETION ALERT: {mass_deletion_reason}")
                
            elif is_mass_creation and mass_creation_reason:
                alert['reason'] = mass_creation_reason
                alert['attack_type'] = 'MASS_CREATION'
                print(f"📁 MASS CREATION ALERT: {mass_creation_reason}")
                
            else:
                alert['reason'] = "Mass destructive activity detected"
                alert['attack_type'] = 'UNKNOWN_CRITICAL'
            
            # Include mass activity metadata in the alert for proper details display
            if mass_metadata:
                alert['mass_metadata'] = mass_metadata
                alert['files_count'] = len(mass_metadata.get('affected_files', []))
                
                # Add specific metadata for each attack type
                if is_ransomware:
                    alert['ransomware_metadata'] = {
                        'encrypted_count': mass_metadata.get('encrypted_rename_count', 0),
                        'modify_count': mass_metadata.get('modify_count', 0),
                        'rename_count': mass_metadata.get('rename_count', 0),
                        'file_types_affected': mass_metadata.get('file_types_affected', []),
                        'suspicious_patterns': mass_metadata.get('suspicious_pattern_count', 0),
                        'detection_confidence': mass_metadata.get('detection_confidence', 'MEDIUM')
                    }
                    
                elif is_mass_deletion:
                    alert['mass_deletion_metadata'] = {
                        'sensitive_count': mass_metadata.get('sensitive_count', 0),
                        'sensitive_ratio': mass_metadata.get('sensitive_ratio', 0),
                        'detection_window': mass_metadata.get('window_seconds', 0),
                        'threshold_used': mass_metadata.get('threshold_used', 0),
                        'detection_confidence': mass_metadata.get('detection_confidence', 'MEDIUM')
                    }
                    
                elif is_mass_creation:
                    alert['mass_creation_metadata'] = {
                        'detection_window': mass_metadata.get('window_seconds', 0),
                        'threshold_used': mass_metadata.get('threshold_used', 0),
                        'duration_seconds': mass_metadata.get('duration_seconds', 0),
                        'detection_confidence': mass_metadata.get('detection_confidence', 'MEDIUM')
                    }
            
            # Set specific anomaly scores for critical alerts
            if is_ransomware:
                alert['anomaly_score'] = max(result['smoothed_score'], 0.9)  # Minimum 0.9 for ransomware
            elif is_mass_deletion:
                alert['anomaly_score'] = max(result['smoothed_score'], 0.85)  # Minimum 0.85 for mass deletion
            elif is_mass_creation:
                alert['anomaly_score'] = max(result['smoothed_score'], 0.8)  # Minimum 0.8 for mass creation
            
            # Set maximum severity score for critical alerts
            alert['severity_score'] = max(result.get('severity_score', 0), 5)
            
            # Add incremental update information if available
            if mass_metadata.get('incremental_update', False):
                alert['incremental_update'] = True
                alert['previous_count'] = mass_metadata.get('previous_count', 0)
                alert['file_increase'] = mass_metadata.get('file_increase', 0)
                alert['update_number'] = mass_metadata.get('update_number', 1)
                print(f"🔄 Incremental update #{alert['update_number']}: +{alert['file_increase']} new files")
            
            # Add new attack flag if this is the first detection
            if mass_metadata.get('new_attack', False):
                alert['new_attack'] = True
                print(f"🆕 NEW ATTACK DETECTED: {alert['attack_type']}")

        # Add severity score to alert if present (for non-critical alerts)
        elif 'severity_score' in result:
            alert['severity_score'] = result['severity_score']

        # Add context flags for additional information
        if 'context_flags' in result and result['context_flags']:
            alert['context_flags'] = result['context_flags']
            
            # Enhance reason with context information for non-critical alerts
            if alert['alert_level'] != 'CRITICAL':
                context_info = []
                if 'off_hours' in result['context_flags']:
                    context_info.append("off-hours")
                if 'system_file' in result['context_flags']:
                    context_info.append("system file")
                if 'sensitive_file' in result['context_flags']:
                    context_info.append("sensitive file")
                if 'suspicious_destination' in result['context_flags']:
                    context_info.append("suspicious destination")
                if 'high_action_rate' in result['context_flags']:
                    context_info.append("high frequency")
                    
                if context_info:
                    alert['reason'] += f" ({', '.join(context_info)})"

        # Log alert generation for debugging
        if alert['alert_level'] in ['ANOMALY', 'CRITICAL']:
            print(f"📢 Generated {alert['alert_level']} alert: {alert['reason']}")
            print(f"   User: {alert['user']}, IP: {alert['ip_address']}, Score: {alert['anomaly_score']:.3f}")
            if 'files_count' in alert:
                print(f"   Files affected: {alert['files_count']}")

        return alert

    def update_detection_metrics(self):
        """Calculate and display detection performance metrics."""
        total_alerts = len(self.true_positives) + len(self.false_positives)
        if total_alerts > 0:
            precision = len(self.true_positives) / total_alerts
            print(f"📊 Detection Metrics: Precision = {precision:.3f}")

            # Log metrics to file for analysis
            metrics = {
                'timestamp': datetime.now().isoformat(),
                'true_positives': len(self.true_positives),
                'false_positives': len(self.false_positives),
                'false_negatives': len(self.false_negatives),
                'precision': precision,
                'normal_threshold': self.normal_threshold,
                'anomaly_threshold': self.anomaly_threshold
            }

            metrics_file = "reports/detection_metrics.json"
            os.makedirs(os.path.dirname(metrics_file), exist_ok=True)
            with open(metrics_file, 'a') as f:
                f.write(json.dumps(metrics) + '\n')

    def train_baseline_model(self, data_path, progress_callback=None):
        """Train model on baseline normal data - LEARN BEHAVIOR PATTERNS, NOT USER IDENTITIES."""
        try:
            df = pd.read_csv(data_path)
            print(f"📊 Loaded {len(df)} samples for BEHAVIOR-FOCUSED baseline training")

            # Filter only normal activities and normalize actions
            normal_data = df.copy()
            normal_data['normalized_action'] = normal_data['action'].apply(self.normalize_action)
            normal_data = normal_data[normal_data['normalized_action'].isin(['CREATE', 'MODIFY', 'MOVE', 'RENAME', 'DELETE'])]

            if len(normal_data) < 100:
                print("⚠️  Insufficient normal data for training")
                return False

            print(f"🎯 Training on {len(normal_data)} NORMAL BEHAVIOR PATTERNS (user-agnostic)")

            total_samples = len(normal_data)
            scores = []

            for i, (_, row) in enumerate(normal_data.iterrows()):
                # Use the same file extraction logic
                file_path = 'Unknown'
                file_type = 'Unknown'

                # Priority 1: Use 'path' field if available
                if 'path' in row and pd.notna(row['path']) and row['path'] != 'Unknown':
                    file_path = row['path']

                # Priority 2: Use file_path if 'path' is not available
                if file_path == 'Unknown' and 'file_path' in row and pd.notna(row['file_path']) and row['file_path'] != 'Unknown':
                    file_path = row['file_path']

                # Priority 3: Use file_name as last resort
                if file_path == 'Unknown' and 'file_name' in row and pd.notna(row['file_name']):
                    file_path = row['file_name']

                # Extract file type from the path
                if file_path != 'Unknown':
                    if '.' in file_path:
                        file_type = file_path.split('.')[-1].upper() + '_FILE'
                    else:
                        file_type = 'FILE'

                # Priority 4: Use file_type field if available
                if 'file_type' in row and pd.notna(row['file_type']) and row['file_type'] != 'Unknown':
                    file_type = row['file_type']

                # CRITICAL FIX: Extract IP address from CSV for training
                ip_address = 'Unknown'
                if 'ip' in row and pd.notna(row['ip']):
                    ip_address = row['ip']
                elif 'ip_address' in row and pd.notna(row['ip_address']):
                    ip_address = row['ip_address']

                event = {
                    'timestamp': pd.to_datetime(row['timestamp']),
                    'user': row.get('user', 'Unknown'),
                    'action': row.get('action', 'Unknown'),
                    'file_path': file_path,
                    'file_type': file_type,
                    'file_size': row.get('file_size', 0),
                    'ip_address': ip_address  # ADDED: IP address for training
                }

                # Add ALL available fields from the CSV row
                for col in row.index:
                    if col not in event and pd.notna(row[col]):
                        event[col] = row[col]

                # Add destination path if available
                if 'dest_path' in row and pd.notna(row['dest_path']):
                    event['dest_path'] = row['dest_path']

                features = self.extract_features(event)
                self.model.learn_one(features)
                score = self.model.score_one(features)
                scores.append(score)

                # Store in normal buffer
                self.normal_buffer.append(event)

                if progress_callback and i % 100 == 0:
                    progress = (i + 1) / total_samples * 100
                    progress_callback(progress)

            # Set thresholds based on BEHAVIOR patterns
            if scores:
                scores_array = np.array(scores)
                self.normal_threshold = np.percentile(scores_array, 95)
                self.anomaly_threshold = np.percentile(scores_array, 99)

            self.baseline_trained = True
            self.training_samples = len(normal_data)

            print(f"✅ BEHAVIOR-FOCUSED baseline training completed")
            print(f"📈 Learned NORMAL BEHAVIOR patterns across all users")
            print(f"📊 Normal threshold (95th percentile): {self.normal_threshold:.3f}")
            print(f"🚨 Anomaly threshold (99th percentile): {self.anomaly_threshold:.3f}")

            self.save_state()
            return True

        except Exception as e:
            print(f"❌ Training error: {e}")
            return False

    def retrain_with_buffer(self):
        """Retrain model with confirmed normal activities from buffer."""
        if not self.normal_buffer:
            return False

        try:
            print(f"🔄 Retraining on {len(self.normal_buffer)} recent normal activities")

            scores = []
            for event in self.normal_buffer:
                features = self.extract_features(event)
                self.model.learn_one(features)
                score = self.model.score_one(features)
                scores.append(score)

            # Update thresholds if we have new scores
            if scores:
                scores_array = np.array(scores)
                self.normal_threshold = np.percentile(scores_array, 95)
                self.anomaly_threshold = np.percentile(scores_array, 99)

            print("✅ Model retrained on recent normal activities")
            self.save_state()
            return True

        except Exception as e:
            print(f"❌ Error in retraining: {e}")
            return False
        
    def get_ransomware_attack_status(self, user_ip_key=None):
        """
        Get current ransomware attack status for monitoring
        """
        if user_ip_key:
            return self.active_ransomware_alerts.get(user_ip_key, None)
        else:
            return {
                'active_attacks_count': len(self.active_ransomware_alerts),
                'active_popups_count': len(self.active_popups),
                'active_attacks': dict(self.active_ransomware_alerts)  # FIX: Return the actual dictionary, not count
            }

    def save_state(self):
        """Save model state and thresholds with enhanced persistence."""
        try:
            import pickle
            
            state = {
                'normal_threshold': self.normal_threshold,
                'anomaly_threshold': self.anomaly_threshold,
                'baseline_trained': self.baseline_trained,
                'training_samples': self.training_samples,
                'action_mapping': self.action_mapping,
                'action_time_windows': self.action_time_windows,
                # Don't save the full model here to avoid duplication
                'saved_timestamp': datetime.now().isoformat()
            }

            os.makedirs(os.path.dirname(self.state_file), exist_ok=True)
            
            with open(self.state_file, 'wb') as f:
                pickle.dump(state, f)

            print(f"💾 Model state saved to {self.state_file}")
            print(f"   Training status: {self.baseline_trained}")
            print(f"   Samples: {self.training_samples}")
            print(f"   Thresholds: normal={self.normal_threshold:.3f}, anomaly={self.anomaly_threshold:.3f}")
            
        except Exception as e:
            print(f"❌ Error saving state: {e}")

    def load_state(self):
        """Load model state and thresholds with enhanced error handling."""
        try:
            if os.path.exists(self.state_file):
                with open(self.state_file, 'rb') as f:
                    state = pickle.load(f)

                self.normal_threshold = state.get('normal_threshold', 0.5)
                self.anomaly_threshold = state.get('anomaly_threshold', 0.8)
                self.baseline_trained = state.get('baseline_trained', False)
                self.training_samples = state.get('training_samples', 0)
                
                # Load other components
                self.action_mapping = state.get('action_mapping', self.action_mapping)
                self.action_time_windows = state.get('action_time_windows', self.action_time_windows)
                
                saved_time = state.get('saved_timestamp', 'Unknown')
                print(f"📂 Model state loaded from {self.state_file}")
                print(f"   Saved: {saved_time}")
                print(f"   Training status: {self.baseline_trained}")
                print(f"   Samples: {self.training_samples}")
                print(f"   Thresholds: normal={self.normal_threshold:.3f}, anomaly={self.anomaly_threshold:.3f}")
                
                return True
                
        except Exception as e:
            print(f"❌ Error loading state: {e}")
            # Initialize fresh model if loading fails
            self.initialize_model()

        return False

def main():
    root = tk.Tk()
    app = AutomatedAnomalyDetectorGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()