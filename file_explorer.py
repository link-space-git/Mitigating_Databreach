# file_explorer.py
import os
import math
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
from tkinter.font import Font
from datetime import datetime
import ctypes
from cryptography.fernet import Fernet
import getpass
import shutil
import json
import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
import base64
import bcrypt
import time
import threading
import multiprocessing
import queue
from datetime import datetime
import sv_ttk
from PIL import Image, ImageTk
import pandas as pd
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure
import re
from datetime import datetime
import csv
import subprocess
from database_manager import db_manager

import MLmodel

# Import the modular file monitor tab
from file_monitor import FileMonitorTab

# import backup and restore
from tools.backup_manager import BackupManager

DARK_BG = "#0d1117"  
DARK_CARD = "#161b22"  
DARK_HOVER = "#21262d" 
ACCENT_BLUE = "#58a6ff"  
ACCENT_GREEN = "#3fb950"  
ACCENT_RED = "#f85149"  
TEXT_PRIMARY = "#f0f6fc"  
TEXT_SECONDARY = "#8b949e"  

class ModernButton(ttk.Button):
    """custom modern button"""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.configure(style="Modern.TButton")

class ModernEntry(ttk.Entry):
    """custom modern entry"""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.configure(style="Modern.TEntry")

class ModernCombobox(ttk.Combobox):
    """custom modern combobox"""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.configure(style="Modern.TCombobox")


class LoginWindow(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)  
        self.title("Login")
        self.geometry("400x350") 
        self.resizable(False, False)
        self.parent = parent
        self.auth_file = "auth_control.json"
        self.login_attempts = 0
        self.max_attempts = 100
        self.key_file = "auth_key.key"
        
        # Load or generate encryption key for auth data
        self.auth_key = self.load_or_generate_auth_key()
        
        self.use_db = True  # Set to False to use JSON file instead
        
        # UI elements (unchanged)
        ttk.Label(self, text="Login", font=('Segoe UI', 14, 'bold')).pack(pady=(20, 10))
        
        # username
        ttk.Label(self, text="Username:").pack()
        self.username_entry = ttk.Entry(self)
        self.username_entry.pack(pady=5)
        
        # password
        ttk.Label(self, text="Password:").pack()
        self.password_entry = ttk.Entry(self, show="•")
        self.password_entry.pack(pady=5)
        
        # forgot password link
        forgot_label = ttk.Label(self, text="Forgot password?", foreground="blue", cursor="hand2")
        forgot_label.pack(pady=2)
        forgot_label.bind("<Button-1>", self.forgot_password)
        
        # button frame
        btn_frame = ttk.Frame(self)
        btn_frame.pack(pady=10)
        
        ttk.Button(btn_frame, text="Login", command=self.authenticate).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Cancel", command=self.quit_app).pack(side=tk.RIGHT, padx=5)
        ttk.Button(btn_frame, text="Create Account", command=self.show_create_account).pack(side=tk.LEFT, padx=5)
        
        # status label
        self.status_label = ttk.Label(self, text="", foreground="red")
        self.status_label.pack(pady=5)
        
        # Initialize auth system if not exists (keep for backward compatibility)
        if not os.path.exists(self.auth_file):
            self.initialize_auth_system()
        
        # Focus username field
        self.username_entry.focus_set()


    def show_create_account(self):
        """Show the account creation dialog with database support"""
        create_dialog = tk.Toplevel(self)
        create_dialog.title("Create New Account")
        create_dialog.geometry("400x350")
        create_dialog.resizable(False, False)
        
        ttk.Label(create_dialog, text="Create New Account", font=('Segoe UI', 12, 'bold')).pack(pady=10)
        
        # username
        ttk.Label(create_dialog, text="Username:").pack()
        username_entry = ttk.Entry(create_dialog)
        username_entry.pack(pady=5)
        
        # password
        ttk.Label(create_dialog, text="Password:").pack()
        password_entry = ttk.Entry(create_dialog, show="•")
        password_entry.pack(pady=5)
        
        # confirm Password
        ttk.Label(create_dialog, text="Confirm Password:").pack()
        confirm_entry = ttk.Entry(create_dialog, show="•")
        confirm_entry.pack(pady=5)
        
        # status label
        status_label = ttk.Label(create_dialog, text="", foreground="red")
        status_label.pack(pady=5)
        
        def create_account():
            username = username_entry.get().strip()
            password = password_entry.get()
            confirm = confirm_entry.get()
            
            if not username or not password:
                status_label.config(text="Please enter both username and password")
                return
                
            if password != confirm:
                status_label.config(text="Passwords do not match")
                return
                
            # NEW: Use database for registration
            if self.use_db:
                success, message = db_manager.register_user(username, password, is_admin=False)
                if success:
                    messagebox.showinfo("Success", "Account created successfully! You can now login.", parent=create_dialog)
                    create_dialog.destroy()
                else:
                    status_label.config(text=message)
                return
            
            # Fallback to JSON registration (keep existing code)
            # Validate password against policy
            is_valid, message = self.validate_password_policy(password)
            if not is_valid:
                status_label.config(text=message)
                return
                
            # Load current auth data
            auth_data = self.load_auth_data()
            if not auth_data:
                return
                
            # Check if username already exists
            if username in auth_data["users"]:
                status_label.config(text="Username already exists")
                return
                
            # Hash the password
            hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
            
            # Create new user
            auth_data["users"][username] = {
                "password": hashed.decode('utf-8'),
                "is_admin": False,
                "last_login": None,
                "failed_attempts": 0,
                "security_questions": {
                    "question1": "What city were you born in?",
                    "answer1": self.encrypt_data("Example"),
                    "question2": "What was your first pet's name?",
                    "answer2": self.encrypt_data("Example")
                }
            }
            
            # Save the updated auth data
            self.save_auth_data(auth_data)
            self.audit_log(auth_data, username, "account_creation", "success")
            
            messagebox.showinfo("Success", "Account created successfully!", parent=create_dialog)
            create_dialog.destroy()
        
        ttk.Button(create_dialog, text="Create Account", command=create_account).pack(pady=10)


    def load_or_generate_auth_key(self):
        """load or generate encryption key for auth data"""
        if os.path.exists(self.key_file):
            with open(self.key_file, "rb") as f:
                return f.read()
        else:
            key = Fernet.generate_key()
            with open(self.key_file, "wb") as f:
                f.write(key)
            return key

    def encrypt_data(self, data):
        """encrypt sensitive data"""
        cipher = Fernet(self.auth_key)
        return cipher.encrypt(data.encode()).decode()

    def decrypt_data(self, encrypted_data):
        """decrypt sensitive data"""
        cipher = Fernet(self.auth_key)
        return cipher.decrypt(encrypted_data.encode()).decode()

    def initialize_auth_system(self):
        """initialize authentication system with secure defaults"""
        default_username = "admin"
        default_password = self.generate_strong_password()
        
        hashed = bcrypt.hashpw(default_password.encode('utf-8'), bcrypt.gensalt())
        
        auth_data = {
            "users": {
                default_username: {
                    "password": hashed.decode('utf-8'),
                    "is_admin": True,
                    "last_login": None,
                    "failed_attempts": 0,
                    "security_questions": {
                        "question1": "What city were you born in?",
                        "answer1": self.encrypt_data("Example"),
                        "question2": "What was your first pet's name?",
                        "answer2": self.encrypt_data("Example")
                    }
                }
            },
            "access_control": {
                "sensitive_extensions": [".enc", ".secret", ".confidential"],
                "admin_only_actions": [
                    "deep_scan",
                    "metadata_modification",
                    "log_export",
                    "user_management",
                    "encryption",
                    "decryption"
                ],
                "password_policy": {
                    "min_length": 12,
                    "require_upper": True,
                    "require_lower": True,
                    "require_number": True,
                    "require_special": True,
                    "max_age_days": 90
                }
            },
            "audit_log": []
        }
        
        self.save_auth_data(auth_data)
        
        # show the default credentials
        messagebox.showinfo(
            "Default Credentials",
            f"System initialized with default admin credentials\n\n"
            f"Username: {default_username}\n"
            f"Password: {default_password}\n\n"
            "Please change this password immediately!",
            parent=self
        )

    def generate_strong_password(self):
        """generate a strong random password that meets policy requirements"""
        import random
        import string
        
        policy = {
            "length": 12,
            "lower": 3,
            "upper": 3,
            "digits": 3,
            "special": 3
        }
        
        # generate character sets
        lower = random.choices(string.ascii_lowercase, k=policy["lower"])
        upper = random.choices(string.ascii_uppercase, k=policy["upper"])
        digits = random.choices(string.digits, k=policy["digits"])
        special = random.choices("!@#$%^&*()", k=policy["special"])
        
        # combine and shuffle
        password = lower + upper + digits + special
        random.shuffle(password)
        
        return ''.join(password)

    def save_auth_data(self, auth_data):
        """save auth data with encryption for sensitive fields"""
        # encrypt sensitive data before saving
        for user, data in auth_data["users"].items():
            if "security_questions" in data:
                for q, a in data["security_questions"].items():
                    if q.startswith("answer"):
                        data["security_questions"][q] = self.encrypt_data(a)
        
        with open(self.auth_file, 'w') as f:
            json.dump(auth_data, f, indent=2, ensure_ascii=False)

    def load_auth_data(self):
        """load and decrypt auth data"""
        try:
            with open(self.auth_file, 'r') as f:
                auth_data = json.load(f)
                
            # decrypt sensitive data
            for user, data in auth_data["users"].items():
                if "security_questions" in data:
                    for q, a in data["security_questions"].items():
                        if q.startswith("answer"):
                            data["security_questions"][q] = self.decrypt_data(a)
            
            return auth_data
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load auth data: {str(e)}")
            return None

    def validate_password_policy(self, password):
        """validate password against policy requirements"""
        auth_data = self.load_auth_data()
        if not auth_data:
            return False
            
        policy = auth_data["access_control"]["password_policy"]
        
        if len(password) < policy["min_length"]:
            return False, f"Password must be at least {policy['min_length']} characters"
            
        if policy["require_upper"] and not any(c.isupper() for c in password):
            return False, "Password must contain at least one uppercase letter"
            
        if policy["require_lower"] and not any(c.islower() for c in password):
            return False, "Password must contain at least one lowercase letter"
            
        if policy["require_number"] and not any(c.isdigit() for c in password):
            return False, "Password must contain at least one number"
            
        if policy["require_special"] and not any(c in "!@#$%^&*()" for c in password):
            return False, "Password must contain at least one special character"
            
        return True, ""

    def authenticate(self):
        username = self.username_entry.get().strip()
        password = self.password_entry.get()
        
        if not username or not password:
            self.status_label.config(text="Please enter both username and password")
            return
        
        # NEW: Try database authentication first
        if self.use_db:
            success, message, is_admin = db_manager.login_user(username, password)
            if success:
                self.handle_successful_login_db(username, is_admin)
            else:
                self.status_label.config(text=message)
                self.audit_log(None, username, "login", "failed", message)
            return
        
        # Fallback to JSON authentication (keep existing code)
        try:
            auth_data = self.load_auth_data()
            if not auth_data:
                return
                
            user_data = auth_data["users"].get(username)
            
            if not user_data:
                self.login_attempts += 1
                self.status_label.config(text="Invalid username or password")
                self.audit_log(auth_data, username, "login", "failed", "invalid username")
                return
            
            if user_data.get("locked", False):
                self.status_label.config(text="Account locked. Contact administrator.")
                self.audit_log(auth_data, username, "login", "failed", "account locked")
                return
            
            # Check password
            if bcrypt.checkpw(password.encode('utf-8'), user_data["password"].encode('utf-8')):
                self.handle_successful_login(auth_data, username)
            else:
                self.handle_failed_login(auth_data, username)
                
        except Exception as e:
            messagebox.showerror("Error", f"Authentication error: {str(e)}")

    def handle_successful_login_db(self, username, is_admin=False):
        """Handle successful login using database"""
        db_manager.set_current_user(username)
        
        self.parent.current_user = username
        self.parent.is_admin = is_admin  # Use the is_admin value from database
        self.parent.auth_data = None
        
        self.parent.enable_role_based_features()
        
        self.destroy()
        self.parent.deiconify()
        self.parent.log_activity(f"Session started for user '{username}' (Database)")

    def handle_successful_login(self, auth_data, username):
        """handle successful login"""
        user_data = auth_data["users"][username]
        user_data["last_login"] = datetime.now().isoformat()
        user_data["failed_attempts"] = 0
        
        # check if password needs to be changed
        last_changed = user_data.get("password_changed", None)
        policy = auth_data["access_control"]["password_policy"]
        
        if last_changed:
            last_changed_date = datetime.fromisoformat(last_changed)
            if (datetime.now() - last_changed_date).days > policy["max_age_days"]:
                if not self.change_password(username, enforce_change=True):
                    return
        
        self.audit_log(auth_data, username, "login", "success")
        self.save_auth_data(auth_data)
        
        self.parent.current_user = username
        self.parent.is_admin = user_data.get("is_admin", False)
        self.parent.auth_data = auth_data
        self.parent.enable_role_based_features()
        
        self.destroy()
        self.parent.deiconify()
        self.parent.log_activity(f"Session started for user '{username}'")

    def handle_failed_login(self, auth_data, username):
        """handle failed login attempt"""
        self.login_attempts += 1
        user_data = auth_data["users"][username]
        user_data["failed_attempts"] += 1
        
        attempts_left = self.max_attempts - user_data["failed_attempts"]
        
        if user_data["failed_attempts"] >= self.max_attempts:
            user_data["locked"] = True
            self.status_label.config(text="Account locked. Contact administrator.")
            self.audit_log(auth_data, username, "login", "failed", "account locked")
        else:
            self.status_label.config(text=f"Invalid credentials. {attempts_left} attempts remaining.")
            self.audit_log(auth_data, username, "login", "failed", "invalid password")
        
        self.save_auth_data(auth_data)

    def audit_log(self, auth_data, username, action, status, details=""):
        """log security events"""
        auth_data["audit_log"].append({
            "timestamp": datetime.now().isoformat(),
            "username": username,
            "action": action,
            "status": status,
            "details": details,
            "ip": "localhost" 
        })

    def change_password(self, username, enforce_change=False):
        """password change dialog"""
        change_dialog = tk.Toplevel(self)
        change_dialog.title("Change Password")
        change_dialog.geometry("400x300")
        change_dialog.resizable(False, False)
        
        if enforce_change:
            ttk.Label(change_dialog, 
                     text="Your password has expired. You must change it now.",
                     foreground="red").pack(pady=10)
        
        # current password (not required for admin reset)
        ttk.Label(change_dialog, text="Current Password:").pack()
        current_pass_entry = ttk.Entry(change_dialog, show="•")
        current_pass_entry.pack(pady=5)
        
        # new password
        ttk.Label(change_dialog, text="New Password:").pack()
        new_pass_entry = ttk.Entry(change_dialog, show="•")
        new_pass_entry.pack(pady=5)
        
        # confirm new password
        ttk.Label(change_dialog, text="Confirm New Password:").pack()
        confirm_pass_entry = ttk.Entry(change_dialog, show="•")
        confirm_pass_entry.pack(pady=5)
        
        # status label
        status_label = ttk.Label(change_dialog, text="", foreground="red")
        status_label.pack(pady=5)
        
        def save_new_password():
            current_pass = current_pass_entry.get()
            new_pass = new_pass_entry.get()
            confirm_pass = confirm_pass_entry.get()
            
            auth_data = self.load_auth_data()
            if not auth_data:
                return
                
            user_data = auth_data["users"][username]
            
            # verify current password unless admin reset
            if not enforce_change and not bcrypt.checkpw(
                current_pass.encode('utf-8'), 
                user_data["password"].encode('utf-8')
            ):
                status_label.config(text="Current password is incorrect")
                return
                
            # check new password matches confirmation
            if new_pass != confirm_pass:
                status_label.config(text="New passwords do not match")
                return
                
            # validate against password policy
            is_valid, message = self.validate_password_policy(new_pass)
            if not is_valid:
                status_label.config(text=message)
                return
                
            # hash and save new password
            hashed = bcrypt.hashpw(new_pass.encode('utf-8'), bcrypt.gensalt())
            user_data["password"] = hashed.decode('utf-8')
            user_data["password_changed"] = datetime.now().isoformat()
            
            self.save_auth_data(auth_data)
            self.audit_log(auth_data, username, "password_change", "success")
            
            messagebox.showinfo("Success", "Password changed successfully", parent=change_dialog)
            change_dialog.destroy()
            
            if enforce_change:
                self.handle_successful_login(auth_data, username)
        
        ttk.Button(change_dialog, text="Save", command=save_new_password).pack(pady=10)

    def forgot_password(self, event):
        """handle password recovery with improved security"""
        username = self.username_entry.get().strip()
        if not username:
            messagebox.showwarning("Username Required", "Please enter your username first", parent=self)
            return
            
        auth_data = self.load_auth_data()
        if not auth_data or username not in auth_data["users"]:
            messagebox.showwarning("Error", "Username not found", parent=self)
            return
            
        user_data = auth_data["users"][username]
        
        # check if account is locked
        if user_data.get("locked", False):
            messagebox.showwarning("Account Locked", "This account is locked. Please contact administrator.", parent=self)
            return
        
        # check if too many recovery attempts
        if user_data.get("recovery_attempts", 0) >= 3:
            user_data["locked"] = True
            self.save_auth_data(auth_data)
            messagebox.showwarning("Account Locked", 
                                "Too many password recovery attempts. Account has been locked. Contact administrator.",
                                parent=self)
            return
        
        # show security questions dialog
        recovery_dialog = tk.Toplevel(self)
        recovery_dialog.title("Password Recovery")
        recovery_dialog.geometry("500x400")
        recovery_dialog.resizable(False, False)
        
        ttk.Label(recovery_dialog, text="Answer your security questions to reset password").pack(pady=10)
        
        # display security questions
        questions = user_data.get("security_questions", {})
        answer_entries = []

        shown_questions = []
        question_indices = []
        
        # select 2 random questions from available ones
        available_questions = [q for q in questions.keys() if q.startswith("question")]
        if len(available_questions) < 2:
            messagebox.showerror("Error", "Not enough security questions configured", parent=self)
            return
        
        import random
        random.shuffle(available_questions)
        selected_questions = available_questions[:2]
        
        for i, q in enumerate(selected_questions):
            ttk.Label(recovery_dialog, text=questions[q]).pack()
            entry = ttk.Entry(recovery_dialog, show="•")  # hide answer input
            entry.pack(pady=5)
            answer_entries.append((q.replace("question", "answer"), entry))
        
        # status label
        status_label = ttk.Label(recovery_dialog, text="", foreground="red")
        status_label.pack(pady=5)
        
        # temporary password entry
        ttk.Label(recovery_dialog, text="New Password:").pack()
        new_pass_entry = ttk.Entry(recovery_dialog, show="•")
        new_pass_entry.pack(pady=5)
        
        ttk.Label(recovery_dialog, text="Confirm New Password:").pack()
        confirm_pass_entry = ttk.Entry(recovery_dialog, show="•")
        confirm_pass_entry.pack(pady=5)
        
        def verify_answers_and_reset():
            """verify security question answers and reset password if correct"""
            # verify answers
            correct = 0
            required = 2  # require both answers to be correct
            
            for q, entry in answer_entries:
                answer = entry.get().strip()
                encrypted_answer = questions.get(q, "")
                
                if encrypted_answer and bcrypt.checkpw(
                    answer.encode('utf-8'),
                    encrypted_answer.encode('utf-8')
                ):
                    correct += 1
            
            if correct < required:
                # increment failed attempts
                user_data["recovery_attempts"] = user_data.get("recovery_attempts", 0) + 1
                self.save_auth_data(auth_data)
                
                attempts_left = 3 - user_data["recovery_attempts"]
                if attempts_left <= 0:
                    user_data["locked"] = True
                    self.save_auth_data(auth_data)
                    status_label.config(text="Too many failed attempts. Account locked.")
                    recovery_dialog.after(3000, recovery_dialog.destroy)
                    messagebox.showwarning("Account Locked", 
                                        "Too many failed attempts. Account has been locked. Contact administrator.",
                                        parent=self)
                else:
                    status_label.config(text=f"Incorrect answers. {attempts_left} attempts remaining.")
                return
            
            # verify new password
            new_pass = new_pass_entry.get()
            confirm_pass = confirm_pass_entry.get()
            
            if new_pass != confirm_pass:
                status_label.config(text="New passwords do not match")
                return
                
            # validate against password policy
            is_valid, message = self.validate_password_policy(new_pass)
            if not is_valid:
                status_label.config(text=message)
                return
            
            # hash and save new password
            hashed = bcrypt.hashpw(new_pass.encode('utf-8'), bcrypt.gensalt())
            user_data["password"] = hashed.decode('utf-8')
            user_data["password_changed"] = datetime.now().isoformat()
            user_data["failed_attempts"] = 0  # reset failed attempts
            user_data.pop("recovery_attempts", None)  # clear recovery attempts
            
            self.save_auth_data(auth_data)
            self.audit_log(auth_data, username, "password_reset", "success", "via security questions")
            
            messagebox.showinfo("Success", 
                            "Password has been reset successfully.\n\nPlease login with your new password.",
                            parent=recovery_dialog)
            recovery_dialog.destroy()
        
        ttk.Button(recovery_dialog, text="Reset Password", command=verify_answers_and_reset).pack(pady=10)

    def quit_app(self):
        self.parent.destroy()

class FileExplorer(tk.Tk):
    def __init__(self):
        super().__init__()
        self.withdraw()
        
        # user properties
        self.current_user = None
        self.is_admin = False
        self.auth_data = None

        # navigation history
        self.history = []
        self.history_index = -1

        # initialize current_path with a default value first
        self.current_path = os.path.expanduser("~")

        # initialize backup manager
        self.backup_manager = BackupManager(main_app=self)

        # apply modern dark theme
        sv_ttk.set_theme("dark")

        # define color scheme
        self.bg_color = DARK_BG
        self.card_color = DARK_CARD
        self.hover_color = DARK_HOVER
        self.primary_color = ACCENT_BLUE
        self.secondary_color = ACCENT_GREEN
        self.accent_red = ACCENT_RED
        self.text_primary = TEXT_PRIMARY
        self.text_secondary = TEXT_SECONDARY

        # Custom fonts
        self.title_font = Font(family="Segoe UI", size=11, weight="bold")
        self.main_font = Font(family="Segoe UI", size=10)
        self.small_font = Font(family="Segoe UI", size=9)
        self.mono_font = Font(family="Cascadia Code", size=9) 

        # path and status variables
        self.path_var = tk.StringVar()
        self.status_var = tk.StringVar(value="Ready")
        self.search_var = tk.StringVar()
        self.filter_var = tk.StringVar(value="ALL")
        self.filter_action_var = tk.StringVar(value="ALL")
        self.filter_user_var = tk.StringVar()

        # original initialization
        self.title("Mitigating Databreach Explorer")
        self.geometry("1200x800")
        self.configure(bg=self.bg_color)
        self.minsize(1000, 700)
        
        # initialize backup directory with default value
        self.backup_directory = os.path.join(os.path.expanduser("~"), "Backups")

        # configure styles
        self.configure_styles()

        # load configuration BEFORE creating widgets
        self.load_configuration()

        # initialize widgets
        self.create_widgets()
        self.create_tabs()  # Create all tabs including file monitor
        self.report_tab()
        self.create_anomaly_detection_tab()

        # security tools setup
        self.key_file = "encryption_key.key"
        self.key = self.load_or_generate_key()
        self.metadata_file = "folder_metadata.json"
        self.metadata = self.load_metadata()
        self.load_or_generate_metadata_keys()

        # show login window
        self.login_window = LoginWindow(self)
        
        # load files after everything is initialized
        self.load_files(self.current_path, add_to_history=True)

        # Keyboard shortcuts
        self.bind("<BackSpace>", lambda e: self.go_up())
        self.bind("<Control-b>", lambda e: self.go_back())
        self.bind("<Control-f>", lambda e: self.go_forward())
        self.bind("<Control-h>", lambda e: self.go_home())
        self.bind("<F5>", lambda e: self.refresh_directory())
        self.bind("<Control-d>", lambda e: self.show_drives())
        self.bind('<Configure>', self.on_resize)

        # set app icon
        try:
            self.iconbitmap("shield_icon.ico")
        except:
            pass

    def create_tabs(self):
        """Create all application tabs including the file monitor"""
        # Create file monitor tab using the modular component
        self.file_monitor_tab = FileMonitorTab(self.notebook, self)
        self.notebook.add(self.file_monitor_tab, text="🔍 File Monitor")

    def save_configuration(self):
        """save application configuration to file"""
        config = {
            'backup_directory': getattr(self, 'backup_directory', os.path.join(os.path.expanduser("~"), "Backups")),
            'filter_action': self.filter_action_var.get(),
            'filter_user': self.filter_user_var.get(),
            'window_geometry': self.geometry(),
            'current_path': self.current_path,
            'history': self.history,
            'history_index': self.history_index
        }
        
        config_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "app_config.json")
        try:
            with open(config_file, 'w') as f:
                json.dump(config, f)
            print("Configuration saved successfully")
        except Exception as e:
            print(f"Error saving configuration: {e}")

    def load_configuration(self):
        """load application configuration from file"""
        config_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "app_config.json")
        if os.path.exists(config_file):
            try:
                with open(config_file, 'r') as f:
                    config = json.load(f)
                
                # load backup directory
                if 'backup_directory' in config:
                    self.backup_directory = config['backup_directory']
                    self.backup_manager.backup_directory = self.backup_directory 
                
                # load filter settings
                if 'filter_action' in config:
                    self.filter_action_var.set(config['filter_action'])
                if 'filter_user' in config:
                    self.filter_user_var.set(config['filter_user'])
                
                # load navigation history
                if 'history' in config:
                    self.history = config['history']
                if 'history_index' in config:
                    self.history_index = config['history_index']
                if 'current_path' in config and os.path.exists(config['current_path']):
                    self.current_path = config['current_path']  # restore last directory
                
                # load window geometry if available
                if 'window_geometry' in config:
                    self.geometry(config['window_geometry'])
                
                print("Configuration loaded successfully")
                return True
            except Exception as e:
                print(f"Error loading configuration: {e}")
                # if config file is corrupted, use default values
                self.current_path = os.path.expanduser("~")
                return False
        else:
            # config file doesn't exist yet, use default values
            print("No configuration file found, using defaults")
            self.current_path = os.path.expanduser("~")
            return False

    def on_tree_hover(self, event):
        """add hover effect to treeview items"""
        item = self.tree.identify_row(event.y)
        if item:
            self.tree.tk.call(self.tree, "tag", "remove", "hover")
            self.tree.tk.call(self.tree, "tag", "add", "hover", item)
            self.tree.tk.call(self.tree, "tag", "configure", "hover", 
                            "-background", self.hover_color)

    def configure_styles(self):
        """configure ttk styles"""
        style = ttk.Style()
        
        # general styles
        style.configure('.', 
                       background=self.bg_color, 
                       foreground=self.text_primary,
                       fieldbackground=self.card_color)
        
        # frame styles
        style.configure('Dark.TFrame', background=self.bg_color)
        style.configure('Card.TFrame', background=self.card_color, relief=tk.FLAT, borderwidth=1)
        
        # label styles
        style.configure('Dark.TLabel', background=self.bg_color, foreground=self.text_primary)
        style.configure('Card.TLabel', background=self.card_color, foreground=self.text_primary)
        style.configure('Secondary.TLabel', background=self.bg_color, foreground=self.text_secondary)
        
        # button styles
        style.configure('Modern.TButton', 
                       font=self.main_font,
                       padding=(12, 6),
                       relief=tk.FLAT,
                       background=self.primary_color,
                       foreground="white",
                       focuscolor=style.lookup('TButton', 'focuscolor'))
        
        style.map('Modern.TButton',
                 background=[('active', self.hover_color)],
                 relief=[('pressed', 'sunken')])
                 
        style.configure('Secondary.TButton', 
                       font=self.main_font,
                       padding=(12, 6),
                       relief=tk.FLAT,
                       background=self.card_color,
                       foreground=self.text_primary)
        
        style.map('Secondary.TButton',
                 background=[('active', self.hover_color)],
                 relief=[('pressed', 'sunken')])
        
        # alert button style
        style.configure('Alert.TButton', 
                       background=self.accent_red,
                       foreground="white",
                       font=('Segoe UI', 10, 'bold'))
        style.map('Alert.TButton',
                 background=[('active', '#ff5252')])
        
        # entry styles
        style.configure('Modern.TEntry',
                       font=self.main_font,
                       padding=8,
                       relief=tk.FLAT,
                       fieldbackground=self.card_color,
                       foreground=self.text_primary,
                       bordercolor="#30363d",
                       lightcolor=self.card_color,
                       darkcolor=self.card_color)
        
        style.map('Modern.TEntry',
                 fieldbackground=[('focus', self.card_color)],
                 bordercolor=[('focus', self.primary_color)])
        
        # combobox styles
        style.configure('Modern.TCombobox',
                       font=self.main_font,
                       padding=8,
                       relief=tk.FLAT,
                       fieldbackground=self.card_color,
                       foreground=self.text_primary,
                       bordercolor="#30363d")
        
        style.map('Modern.TCombobox',
                 fieldbackground=[('focus', self.card_color)],
                 bordercolor=[('focus', self.primary_color)])
        
        # treeview styles
        style.configure('Modern.Treeview',
                       font=self.main_font,
                       rowheight=28,
                       background=self.card_color,
                       fieldbackground=self.card_color,
                       foreground=self.text_primary,
                       bordercolor="#30363d",
                       borderwidth=0)
        
        style.configure('Modern.Treeview.Heading', 
                       font=self.title_font,
                       background=self.bg_color,
                       foreground=self.text_primary,
                       padding=8,
                       relief=tk.FLAT)
        
        style.map('Modern.Treeview.Heading',
                 background=[('active', self.hover_color)])
        
        # scrollbar styles
        style.configure('Modern.Vertical.TScrollbar',
                       background=self.bg_color,
                       troughcolor=self.bg_color,
                       bordercolor=self.bg_color,
                       arrowcolor=self.text_primary,
                       lightcolor=self.bg_color,
                       darkcolor=self.bg_color)
        
        style.configure('Modern.Horizontal.TScrollbar',
                       background=self.bg_color,
                       troughcolor=self.bg_color,
                       bordercolor=self.bg_color,
                       arrowcolor=self.text_primary,
                       lightcolor=self.bg_color,
                       darkcolor=self.bg_color)
        
        # notebook styles (tabs)
        style.configure('Modern.TNotebook',
                       background=self.bg_color,
                       bordercolor=self.bg_color,
                       tabmargins=(0, 2, 0, 0))
        
        style.configure('Modern.TNotebook.Tab',
                       background=self.bg_color,
                       foreground=self.text_secondary,
                       padding=(12, 6),
                       focuscolor=style.lookup('TNotebook.Tab', 'focuscolor'))
        
        style.map('Modern.TNotebook.Tab',
                 background=[('selected', self.card_color)],
                 foreground=[('selected', self.text_primary)])


    def create_widgets(self):
        """create all GUI widgets"""
        # create main notebook (tabs)
        self.notebook = ttk.Notebook(self, style="Modern.TNotebook")
        self.notebook.pack(fill=tk.BOTH, expand=True)
        
        # create main file explorer frame as first tab
        main_frame = ttk.Frame(self.notebook, style="Dark.TFrame")
        self.notebook.add(main_frame, text="📁 File Explorer")
        
        # top navigation bar with card style
        nav_frame = ttk.Frame(main_frame, style="Card.TFrame")
        nav_frame.pack(fill=tk.X, padx=10, pady=10)
        
        # navigation buttons with improved spacing
        btn_frame = ttk.Frame(nav_frame, style="Card.TFrame")
        btn_frame.pack(side=tk.LEFT, padx=(10, 0), pady=10)
        
        self.back_btn = ModernButton(btn_frame, text="←", command=self.go_back, width=3)
        self.back_btn.pack(side=tk.LEFT, padx=(0, 5))
        
        self.forward_btn = ModernButton(btn_frame, text="→", command=self.go_forward, width=3)
        self.forward_btn.pack(side=tk.LEFT, padx=5)
        
        ModernButton(btn_frame, text="↻", command=self.refresh_directory, width=3).pack(side=tk.LEFT, padx=5)
        
        ModernButton(btn_frame, text="🏠", command=self.go_home, width=3).pack(side=tk.LEFT, padx=5)
        
        # drive selection button
        ModernButton(btn_frame, text="💾", command=self.show_drives, width=3).pack(side=tk.LEFT, padx=5)
        
        # path entry with improved styling
        path_frame = ttk.Frame(nav_frame, style="Card.TFrame")
        path_frame.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=10, pady=10)
        
        ttk.Label(path_frame, text="Path:", style="Card.TLabel").pack(side=tk.LEFT, padx=(0, 5))
        
        path_entry = ModernEntry(path_frame, textvariable=self.path_var)
        path_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))
        path_entry.bind("<Return>", self.on_path_entered)
        
        # search bar
        search_frame = ttk.Frame(nav_frame, style="Card.TFrame")
        search_frame.pack(side=tk.RIGHT, padx=10, pady=10)
        
        ttk.Label(search_frame, text="Search:", style="Card.TLabel").pack(side=tk.LEFT, padx=(0, 5))
        
        search_entry = ModernEntry(search_frame, textvariable=self.search_var, width=20)
        search_entry.pack(side=tk.LEFT)
        search_entry.bind("<KeyRelease>", self.filter_files)

        notif_button_frame = ttk.Frame(nav_frame, style="Card.TFrame")
        notif_button_frame.pack(side=tk.RIGHT, padx=(0, 5), pady=10)
        
        self.notif_btn = ModernButton(notif_button_frame, text="🔔", 
                                    command=self.toggle_notification_panel, 
                                    width=3)
        self.notif_btn.pack(side=tk.RIGHT)
        
        # security tools frame
        tools_frame = ttk.Frame(nav_frame, style="Card.TFrame")
        tools_frame.pack(side=tk.RIGHT, padx=(0, 10), pady=10)
        
        # security tools buttons
        ModernButton(tools_frame, text="🔒 Encrypt", command=self.encrypt_selected, width=10).pack(side=tk.LEFT, padx=(0, 5))
        ModernButton(tools_frame, text="🔓 Decrypt", command=self.decrypt_selected, width=10).pack(side=tk.LEFT, padx=5)
        
        # treeview with improved scrollbars
        tree_frame = ttk.Frame(main_frame, style="Dark.TFrame")
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))
        
        # vertical scrollbar
        y_scroll = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, style="Modern.Vertical.TScrollbar")
        y_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        
        # horizontal scrollbar
        x_scroll = ttk.Scrollbar(tree_frame, orient=tk.HORIZONTAL, style="Modern.Horizontal.TScrollbar")
        x_scroll.pack(side=tk.BOTTOM, fill=tk.X)
        
        # treeview with improved columns
        self.tree = ttk.Treeview(tree_frame, 
                                columns=("Name", "Type", "Size", "Modified", "Status"), 
                                show='headings',
                                yscrollcommand=y_scroll.set,
                                xscrollcommand=x_scroll.set,
                                selectmode='browse',
                                style="Modern.Treeview")
        
        # configure columns with better widths
        self.tree.heading("Name", text="📄 Name", anchor=tk.W)
        self.tree.heading("Type", text="📁 Type", anchor=tk.W)
        self.tree.heading("Size", text="📦 Size", anchor=tk.W)
        self.tree.heading("Modified", text="🕒 Modified", anchor=tk.W)
        self.tree.heading("Status", text="🔐 Status", anchor=tk.W)
        
        self.tree.column("Name", width=350, anchor=tk.W)
        self.tree.column("Type", width=120, anchor=tk.W)
        self.tree.column("Size", width=100, anchor=tk.W)
        self.tree.column("Modified", width=150, anchor=tk.W)
        self.tree.column("Status", width=100, anchor=tk.W)
        
        self.tree.pack(fill=tk.BOTH, expand=True)
        self.tree.bind("<Double-1>", self.on_item_double_click)
        
        # configure scrollbars
        y_scroll.config(command=self.tree.yview)
        x_scroll.config(command=self.tree.xview)
        
        # add hover effect
        self.tree.bind("<Motion>", self.on_tree_hover)
        
        # status bar with improved styling
        status_frame = ttk.Frame(main_frame, style="Card.TFrame")
        status_frame.pack(fill=tk.X, padx=10, pady=(0, 10))
        
        # user info
        self.user_label = ttk.Label(status_frame, text="Not logged in", style="Secondary.TLabel")
        self.user_label.pack(side=tk.LEFT, padx=10, pady=5)
        
        # status info
        self.status_label = ttk.Label(status_frame, textvariable=self.status_var, style="Secondary.TLabel")
        self.status_label.pack(side=tk.RIGHT, padx=10, pady=5)
        
        # enhanced context menu with security options
        self.context_menu = tk.Menu(self, tearoff=0, 
                                   font=self.main_font,
                                   bg=self.card_color,
                                   fg=self.text_primary,
                                   activebackground=self.hover_color,
                                   activeforeground=self.text_primary,
                                   bd=0,
                                   relief=tk.FLAT)
        
        self.context_menu.add_command(label="Open", command=self.open_selected)
        self.context_menu.add_command(label="Open in File Explorer", command=self.open_in_explorer)
        self.context_menu.add_separator()

        # security submenu
        security_menu = tk.Menu(self.context_menu, tearoff=0, 
                            bg=self.card_color,
                            fg=self.text_primary,
                            activebackground=self.hover_color,
                            activeforeground=self.text_primary)
        security_menu.add_command(label="🔒 Encrypt", command=self.encrypt_selected)
        security_menu.add_command(label="🔓 Decrypt", command=self.decrypt_selected)

        # Add folder protection tools to security menu
        security_menu.add_separator()
        security_menu.add_command(label="🔒 Lock Folder", 
                                command=self.lock_folder_interactive)
        security_menu.add_command(label="🔓 Unlock Folder", 
                                command=self.unlock_folder_interactive)
        security_menu.add_separator()

        security_menu.add_command(label="🔄 Backup", command=self.backup)
        security_menu.add_command(label="🔄 Restore", command=self.restore_from_backup)
        self.context_menu.add_cascade(label="Security Tools", menu=security_menu)

        self.context_menu.add_separator()
        self.context_menu.add_command(label="Copy Path", command=self.copy_path)
        self.context_menu.add_command(label="Refresh", command=self.refresh_directory)
        
        self.tree.bind("<Button-3>", self.show_context_menu)

        self.create_notification_panel()

    # Notification Panel Methods
    def create_notification_panel(self):
        """Create the sliding notification panel with scrollable cards"""
        # Create the notification panel frame - make it wider for MLmodel-style alerts
        self.notif_panel = ttk.Frame(self, style="Card.TFrame", width=450)
        self.notif_panel.pack_propagate(False)
        
        # Panel header
        header_frame = ttk.Frame(self.notif_panel, style="Card.TFrame")
        header_frame.pack(fill=tk.X, padx=10, pady=10)
        
        tk.Label(header_frame, text="🔔 Security Alerts", 
                font=('Segoe UI', 12, 'bold'), bg=self.card_color, fg=self.text_primary).pack(side=tk.LEFT)
        
        # Clear all button
        clear_btn = tk.Button(header_frame, text="Clear All", command=self.clear_all_notifications,
                            bg='#6c757d', fg="white", font=("Arial", 9, "bold"),
                            relief=tk.RAISED, bd=1, width=8)
        clear_btn.pack(side=tk.RIGHT, padx=(5, 0))
        
        # Close button
        close_btn = tk.Button(header_frame, text="✕", command=self.hide_notification_panel,
                            bg=self.card_color, fg=self.text_primary, font=("Arial", 10),
                            relief=tk.FLAT, bd=0)
        close_btn.pack(side=tk.RIGHT)
        
        # Separator
        separator = ttk.Separator(self.notif_panel, orient=tk.HORIZONTAL)
        separator.pack(fill=tk.X, padx=10)
        
        # Create scrollable frame for notification cards
        canvas_frame = ttk.Frame(self.notif_panel, style="Card.TFrame")
        canvas_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Create canvas and scrollbar
        self.notification_canvas = tk.Canvas(canvas_frame, bg=self.card_color, highlightthickness=0)
        scrollbar = ttk.Scrollbar(canvas_frame, orient=tk.VERTICAL, command=self.notification_canvas.yview)
        
        # Create frame inside canvas for notifications
        self.notification_frame = ttk.Frame(self.notification_canvas, style="Card.TFrame")
        
        self.notification_frame.bind(
            "<Configure>",
            lambda e: self.notification_canvas.configure(scrollregion=self.notification_canvas.bbox("all"))
        )
        
        self.notification_canvas.create_window((0, 0), window=self.notification_frame, anchor="nw", width=430)
        self.notification_canvas.configure(yscrollcommand=scrollbar.set)
        
        # Pack canvas and scrollbar
        self.notification_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Bind mousewheel to scroll
        def _on_mousewheel(event):
            self.notification_canvas.yview_scroll(int(-1*(event.delta/120)), "units")
        
        self.notification_canvas.bind("<MouseWheel>", _on_mousewheel)
        self.notification_frame.bind("<MouseWheel>", _on_mousewheel)
        
        # Store notification cards
        self.notification_cards = []
        
        # Initially hide the panel
        self.notif_panel_visible = False
        self.after(100, self.initialize_notification_panel)

    def initialize_notification_panel(self):
        """Initialize notification panel position after window is fully rendered"""
        panel_width = 450
        # Place panel outside the visible area to the right
        self.notif_panel.place(x=self.winfo_width(), y=0, relheight=1)

    def add_to_notification_panel(self, alert_data):
        """Add alert as a visual card to notification panel using MLmodel AlertPopup"""
        try:
            # Ensure notification panel is visible when receiving alerts
            if not self.notif_panel_visible:
                self.show_notification_panel()
            
            # Create a replica of MLmodel AlertPopup in the notification panel
            self._create_mlmodel_style_alert(alert_data)
            
            print(f"📥 Added MLmodel-style alert to notification panel: {alert_data['reason']}")
            
        except Exception as e:
            print(f"❌ Error adding MLmodel-style alert to notification panel: {e}")

    def _create_mlmodel_style_alert(self, alert_data):
        """Create an exact replica of MLmodel.py AlertPopup in notification panel"""
        if not hasattr(self, 'notification_frame') or not self.notification_frame:
            return
        
        # Create a frame that will contain the alert
        alert_container = ttk.Frame(self.notification_frame, style="Card.TFrame")
        alert_container.pack(fill=tk.X, padx=10, pady=8)
        alert_container.pack_propagate(False)
        alert_container.configure(height=320)  # Same height as MLmodel popup
        
        # Store reference
        alert_container.alert_data = alert_data
        
        # Create the actual AlertPopup but embed it in our container
        self._create_embedded_alert(alert_container, alert_data)
        
        # Update scroll region
        if hasattr(self, 'notification_canvas'):
            self.notification_canvas.configure(scrollregion=self.notification_canvas.bbox("all"))

    def _create_embedded_alert(self, parent_frame, alert_data):
        """Create an embedded version of MLmodel AlertPopup"""
        # Create main popup frame (same as MLmodel.py)
        popup_frame = tk.Frame(parent_frame, bg='#2c2c2c', relief=tk.RAISED, bd=2)
        popup_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Header (exact copy from MLmodel.py)
        header_frame = tk.Frame(popup_frame, bg='#ff6b6b', height=40)
        header_frame.pack(fill=tk.X, padx=0, pady=(0, 0))
        header_frame.pack_propagate(False)
        
        alert_title = self._get_alert_title(alert_data)
        header_label = tk.Label(header_frame, text=f"⚠️  SECURITY ALERT - {alert_title}", 
                              font=("Arial", 12, "bold"), fg="white", bg='#ff6b6b')
        header_label.pack(expand=True)
        
        # Dismiss button for notification panel
        dismiss_btn = tk.Button(header_frame, text="×", 
                              command=lambda: self._dismiss_notification_card(parent_frame),
                              bg='#ff6b6b', fg="white", font=("Arial", 14, "bold"), 
                              relief=tk.FLAT, bd=0, width=3)
        dismiss_btn.place(relx=1.0, x=-2, y=2, anchor="ne")
        
        # Content frame (exact copy from MLmodel.py)
        content_frame = tk.Frame(popup_frame, bg='#2c2c2c')
        content_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Time - Use safe timestamp parsing
        timestamp = alert_data['original_timestamp']
        dt = self._parse_timestamp(timestamp)
        time_str = dt.strftime("%Y-%m-%d %H:%M:%S")
        tk.Label(content_frame, text=f"🕒  {time_str}", 
                font=("Arial", 9), fg="white", bg='#2c2c2c', justify=tk.LEFT).pack(anchor=tk.W, pady=(0, 5))
        
        # Severity
        severity_color = '#ff4757' if alert_data['alert_level'] == 'CRITICAL' else '#ffa502'
        severity_text = f"🔴  {alert_data['alert_level']}"
        tk.Label(content_frame, text=severity_text, 
                font=("Arial", 10, "bold"), fg=severity_color, bg='#2c2c2c').pack(anchor=tk.W, pady=(0, 10))
        
        # Alert message
        alert_msg = self._get_alert_message(alert_data)
        alert_msg_label = tk.Label(content_frame, text=f"ALERT: {alert_msg}", 
                                  font=("Arial", 10), fg="white", bg='#2c2c2c', justify=tk.LEFT, wraplength=350)
        alert_msg_label.pack(anchor=tk.W, pady=(0, 10))
        
        # User
        tk.Label(content_frame, text=f"User: {alert_data['user']}", 
                font=("Arial", 9), fg="white", bg='#2c2c2c').pack(anchor=tk.W, pady=(0, 5))
        
        # IP Address
        ip_address = alert_data.get('ip_address', 'Unknown')
        tk.Label(content_frame, text=f"IP Address: {ip_address}", 
                font=("Arial", 9), fg="white", bg='#2c2c2c').pack(anchor=tk.W, pady=(0, 5))
        
        # Files count
        files_count = alert_data.get('files_count', 1)
        files_label = tk.Label(content_frame, text=f"Operations: {files_count} file{'s' if files_count > 1 else ''}", 
                              font=("Arial", 9), fg="white", bg='#2c2c2c')
        files_label.pack(anchor=tk.W, pady=(0, 5))
        
        # Prediction
        prediction = self._get_prediction(alert_data)
        prediction_label = tk.Label(content_frame, text=f"Prediction: {prediction}", 
                                  font=("Arial", 9), fg="white", bg='#2c2c2c')
        prediction_label.pack(anchor=tk.W, pady=(0, 15))
        
        # Button frame (exact copy from MLmodel.py)
        button_frame = tk.Frame(content_frame, bg='#2c2c2c')
        button_frame.pack(side=tk.BOTTOM, fill=tk.X, pady=(20, 0))
        
        inner_button_frame = tk.Frame(button_frame, bg='#2c2c2c')
        inner_button_frame.pack(expand=True)
        
        # OK button - Modified for notification panel
        ok_btn = tk.Button(inner_button_frame, text="Dismiss", 
                          command=lambda: self._dismiss_notification_card(parent_frame),
                          bg='#4ecdc4', fg="white", font=("Arial", 9, "bold"), width=10)
        ok_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        # Details button - Opens full MLmodel-style details
        details_btn = tk.Button(inner_button_frame, text="Details ▶", 
                              command=lambda: self._show_mlmodel_details(alert_data),
                              bg='#45aaf2', fg="white", font=("Arial", 9, "bold"), width=12)
        details_btn.pack(side=tk.LEFT)
        
        # Mitigate button - Additional functionality
        mitigate_btn = tk.Button(inner_button_frame, text="Mitigate", 
                               command=lambda: self._mitigate_alert(alert_data, parent_frame),
                               bg='#ff6b6b', fg="white", font=("Arial", 9, "bold"), width=10)
        mitigate_btn.pack(side=tk.LEFT, padx=(10, 0))

    def _show_mlmodel_details(self, alert_data):
        """Show exact MLmodel.py details popup"""
        # Import and use the actual MLmodel AlertPopup details functionality
        from MLmodel import AlertPopup
        
        # Create a temporary detector instance for the AlertPopup
        class TempDetector:
            def __init__(self):
                self.active_popups = {}
        
        temp_detector = TempDetector()
        
        # Get mass activities from alert data
        mass_activities = []
        if 'mass_metadata' in alert_data:
            mass_activities = alert_data['mass_metadata'].get('affected_files', [])
        
        # Create the actual MLmodel AlertPopup for details
        # We create it as a child of the main window to get the full functionality
        alert_popup = AlertPopup(self, alert_data, temp_detector, mass_activities)
        # Immediately show details
        alert_popup.show_details()

    def _mitigate_alert(self, alert_data, card_frame):
        """Handle mitigate button with simplified mitigation actions including folder protection"""
        user = alert_data.get('user', 'Unknown')
        ip_address = alert_data.get('ip_address', 'Unknown')
        reason = alert_data.get('reason', 'Unknown')
        
        # Try to extract folder path from alert data for automatic protection
        auto_folder_path = None
        if 'file_path' in alert_data:
            auto_folder_path = os.path.dirname(alert_data['file_path'])
        elif 'mass_metadata' in alert_data:
            affected_files = alert_data['mass_metadata'].get('affected_files', [])
            if affected_files:
                auto_folder_path = os.path.dirname(affected_files[0])
        
        # Create mitigation popup
        mitigate_window = tk.Toplevel(self)
        mitigate_window.title("Mitigation Actions")
        mitigate_window.geometry("500x400")  # Reduced height since we removed options
        mitigate_window.configure(bg='#2c2c2c')
        mitigate_window.resizable(False, False)
        mitigate_window.attributes('-topmost', True)
        
        # Header
        header_frame = tk.Frame(mitigate_window, bg='#4ecdc4', height=40)
        header_frame.pack(fill=tk.X, padx=10, pady=(10, 0))
        header_frame.pack_propagate(False)
        
        tk.Label(header_frame, text="🛡️  Mitigation Actions", 
                font=("Arial", 12, "bold"), fg="white", bg='#4ecdc4').pack(expand=True)
        
        # Content
        content_frame = tk.Frame(mitigate_window, bg='#2c2c2c')
        content_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Alert info
        tk.Label(content_frame, text=f"Mitigating Alert:", 
                font=("Arial", 10, "bold"), fg="white", bg='#2c2c2c').pack(anchor=tk.W, pady=(0, 10))
        
        tk.Label(content_frame, text=f"User: {user}", 
                font=("Arial", 9), fg="white", bg='#2c2c2c').pack(anchor=tk.W)
        tk.Label(content_frame, text=f"IP: {ip_address}", 
                font=("Arial", 9), fg="white", bg='#2c2c2c').pack(anchor=tk.W)
        tk.Label(content_frame, text=f"Reason: {reason}", 
                font=("Arial", 9), fg="white", bg='#2c2c2c', wraplength=450).pack(anchor=tk.W, pady=(0, 20))
        
        # Folder Protection Tools Section
        protection_tools_frame = tk.Frame(content_frame, bg='#2c2c2c')
        protection_tools_frame.pack(fill=tk.X, pady=(0, 20))
        
        tk.Label(protection_tools_frame, text="📁 Folder Protection Tools:", 
                font=("Arial", 10, "bold"), fg="white", bg='#2c2c2c').pack(anchor=tk.W, pady=(0, 10))
        
        # First row of buttons
        protect_btn_frame1 = tk.Frame(protection_tools_frame, bg='#2c2c2c')
        protect_btn_frame1.pack(fill=tk.X, pady=(0, 5))
        
        lock_btn = tk.Button(protect_btn_frame1, text="🔒 Lock Folder", 
                            command=self.lock_folder_interactive,
                            bg='#ff6b6b', fg="white", font=("Arial", 9, "bold"), width=15)
        lock_btn.pack(side=tk.LEFT, padx=(0, 5))
        
        unlock_btn = tk.Button(protect_btn_frame1, text="🔓 Unlock Folder", 
                            command=self.unlock_folder_interactive,
                            bg='#4ecdc4', fg="white", font=("Arial", 9, "bold"), width=15)
        unlock_btn.pack(side=tk.LEFT, padx=5)
        
        # Second row of buttons with Restore
        protect_btn_frame2 = tk.Frame(protection_tools_frame, bg='#2c2c2c')
        protect_btn_frame2.pack(fill=tk.X, pady=(5, 0))
        
        restore_btn = tk.Button(protect_btn_frame2, text="🔄 Restore", 
                            command=self.restore_from_backup,
                            bg='#45aaf2', fg="white", font=("Arial", 9, "bold"), width=15)
        restore_btn.pack(side=tk.LEFT, padx=(0, 5))
        
        # Separator
        separator = ttk.Separator(content_frame, orient=tk.HORIZONTAL)
        separator.pack(fill=tk.X, pady=20)

    def _dismiss_notification_card(self, card_frame):
        """Remove a notification card from the panel"""
        if card_frame and card_frame.winfo_exists():
            card_frame.destroy()
            # Update scroll region
            if hasattr(self, 'notification_canvas'):
                self.notification_canvas.configure(scrollregion=self.notification_canvas.bbox("all"))

    def clear_all_notifications(self):
        """Clear all notification cards"""
        for widget in self.notification_frame.winfo_children():
            widget.destroy()
        self.notification_cards.clear()
        if hasattr(self, 'notification_canvas'):
            self.notification_canvas.configure(scrollregion=self.notification_canvas.bbox("all"))

    def add_notification(self, message):
        """Add a simple text notification (for non-alert messages)"""
        # Create a simple text card for non-alert notifications
        if not hasattr(self, 'notification_frame') or not self.notification_frame:
            return
        
        text_frame = ttk.Frame(self.notification_frame, style="Card.TFrame", relief=tk.RAISED, borderwidth=1)
        text_frame.pack(fill=tk.X, padx=10, pady=5)
        
        timestamp = datetime.now().strftime('%H:%M:%S')
        label = tk.Label(text_frame, text=f"[{timestamp}] {message}", 
                        font=("Arial", 9), fg=self.text_primary, bg=self.card_color,
                        justify=tk.LEFT, wraplength=300, padx=10, pady=8)
        label.pack(fill=tk.X)
        
        # Update scroll region
        if hasattr(self, 'notification_canvas'):
            self.notification_canvas.configure(scrollregion=self.notification_canvas.bbox("all"))

    def toggle_notification_panel(self):
        """Toggle notification panel visibility with animation"""
        if self.notif_panel_visible:
            self.hide_notification_panel()
        else:
            self.show_notification_panel()

    def show_notification_panel(self):
        """Show notification panel with sliding animation"""
        if self.notif_panel_visible:
            return
            
        self.notif_panel_visible = True
        panel_width = 450
        target_x = self.winfo_width() - panel_width
        current_x = self.winfo_width()
        
        def animate():
            nonlocal current_x
            if current_x > target_x:
                current_x = max(target_x, current_x - 12)
                self.notif_panel.place(x=current_x, y=0, relheight=1)
                if current_x > target_x:
                    self.after(6, animate)
        
        animate()

    def hide_notification_panel(self):
        """Hide notification panel with sliding animation"""
        if not self.notif_panel_visible:
            return
            
        self.notif_panel_visible = False
        panel_width = 450
        target_x = self.winfo_width()
        current_x = self.winfo_width() - panel_width
        
        def animate():
            nonlocal current_x
            if current_x < target_x:
                current_x = min(target_x, current_x + 15)
                self.notif_panel.place(x=current_x, y=0, relheight=1)
                if current_x < target_x:
                    self.after(8, animate)
        
        animate()

    def on_resize(self, event=None):
        """Handle window resize to keep notification panel positioned correctly"""
        if hasattr(self, 'notif_panel') and self.notif_panel_visible:
            panel_width = 450
            self.notif_panel.place(x=self.winfo_width() - panel_width, y=0, relheight=1)
        elif hasattr(self, 'notif_panel'):
            # Keep panel hidden if not visible
            self.notif_panel.place(x=self.winfo_width(), y=0, relheight=1)

    # Helper methods for alert display
    def _get_alert_title(self, alert_data):
        """Generate appropriate title for the details popup."""
        reason = alert_data['reason']
        if "MASS FILE CREATION / DATA FLOODING" in reason:
            return "Mass File Creation / Data Flooding Detected"
        elif "MASS DELETION/SABOTAGE" in reason:
            return "Mass Deletion / Sabotage Detected"
        elif any(keyword in reason.lower() for keyword in ['ransomware', 'encryption', '.lock', '.enc', '.crypt']):
            return "Ransomware / Mass Encryption Detected"
        elif "Mass deletion activity" in reason:
            return "Multiple Files Deleted"
        elif "Mass file creation" in reason:
            return "Multiple Files Created"
        elif "Mass modification activity" in reason:
            return "Multiple Files Modified"
        elif "Mass file movement/exfiltration" in reason:
            return "Multiple Files Moved"
        elif "Critical data movement" in reason:
            return "Critical Data Movement"
        elif "Sensitive file access" in reason:
            return "Sensitive File Access"
        elif "Off-hours activity" in reason:
            return "Off-Hours Activity"
        elif "System file modification" in reason:
            return "System File Modification"
        elif "Suspicious destination" in reason:
            return "Suspicious File Destination"
        else:
            return "Suspicious Activity"

    def _get_alert_message(self, alert_data):
        """Generate appropriate alert message."""
        reason = alert_data['reason']
        if "MASS DELETION/SABOTAGE" in reason:
            return "Mass Deletion / Sabotage Detected"
        elif any(keyword in reason.lower() for keyword in ['ransomware', 'encryption', '.lock', '.enc', '.crypt', 'encrypted']):
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

    def _get_prediction(self, alert_data):
        """Generate appropriate prediction."""
        reason = alert_data['reason']
        if "MASS DELETION/SABOTAGE" in reason:
            return "Ransomware / Mass Deletion"
        elif any(keyword in reason.lower() for keyword in ['ransomware', 'encryption', '.lock', '.enc', '.crypt', 'encrypted']):
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

    def _parse_timestamp(self, timestamp):
        """Safely parse timestamp to datetime object."""
        if isinstance(timestamp, str):
            try:
                if timestamp.endswith('Z'):
                    timestamp = timestamp.replace('Z', '+00:00')
                return datetime.fromisoformat(timestamp)
            except ValueError:
                for fmt in ['%Y-%m-%d %H:%M:%S', '%Y-%m-%dT%H:%M:%S', '%Y-%m-%d %H:%M:%S.%f']:
                    try:
                        return datetime.strptime(timestamp, fmt)
                    except ValueError:
                        continue
                return datetime.now()
        elif hasattr(timestamp, 'strftime'):
            return timestamp
        else:
            return datetime.now()

    def create_anomaly_detection_tab(self):
        """Initialize ML anomaly detection in background WITHOUT GUI tab"""
        # Create ML detector but don't show the tab
        # This preserves all backend functionality while hiding the UI
        
        # Create a hidden frame for the ML GUI (not added to notebook)
        hidden_frame = ttk.Frame(self, style="Dark.TFrame")
        
        # Initialize the ML model GUI in background
        self.anomaly_gui = MLmodel.AutomatedAnomalyDetectorGUI(hidden_frame)
        
        # CRITICAL: Pass the FileExplorer instance to the anomaly GUI for notification integration
        self.anomaly_gui.gui_parent = self
        self.anomaly_gui.detector.gui_parent = self
        
        print("✅ ML Anomaly Detection running in background (tab hidden)")

    def report_tab(self):
        # reports tab
        reports_tab = ttk.Frame(self.notebook, style="Dark.TFrame")
        self.notebook.add(reports_tab, text="📊 Reports & Analytics")

        # header with title and description
        header_frame = ttk.Frame(reports_tab, style="Card.TFrame")
        header_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Label(header_frame, text="File Activity Analytics Dashboard", 
                font=('Segoe UI', 16, 'bold'), style="Card.TLabel").pack(pady=(10, 5))
        
        ttk.Label(header_frame, 
                text="",
                style="Secondary.TLabel").pack(pady=(0, 10))

        # control panel with filters and options
        control_frame = ttk.Frame(reports_tab, style="Card.TFrame")
        control_frame.pack(fill=tk.X, padx=10, pady=(0, 10))

        # time range selector
        ttk.Label(control_frame, text="Time Range:", style="Card.TLabel").grid(row=0, column=0, padx=10, pady=10, sticky=tk.W)
        
        self.time_range_var = tk.StringVar(value="30")  # default to 30 days
        time_range_combo = ModernCombobox(
            control_frame, 
            textvariable=self.time_range_var,
            values=["7", "30", "90", "180", "365", "All"],
            state="readonly",
            width=10
        )
        time_range_combo.grid(row=0, column=1, padx=5, pady=10, sticky=tk.W)
        ttk.Label(control_frame, text="days", style="Card.TLabel").grid(row=0, column=2, padx=(0, 10), pady=10, sticky=tk.W)

        # user filter
        ttk.Label(control_frame, text="Filter by User:", style="Card.TLabel").grid(row=0, column=3, padx=10, pady=10, sticky=tk.W)
        
        self.report_user_var = tk.StringVar()
        user_combo = ModernCombobox(control_frame, textvariable=self.report_user_var, width=15)
        user_combo.grid(row=0, column=4, padx=5, pady=10, sticky=tk.W)
        
        # action type filter
        ttk.Label(control_frame, text="Action Type:", style="Card.TLabel").grid(row=0, column=5, padx=10, pady=10, sticky=tk.W)
        
        self.report_action_var = tk.StringVar(value="ALL")
        action_combo = ModernCombobox(
            control_frame, 
            textvariable=self.report_action_var,
            values=["ALL", "CREATED", "MODIFIED", "DELETED", "RENAME"],
            state="readonly",
            width=12
        )
        action_combo.grid(row=0, column=6, padx=5, pady=10, sticky=tk.W)

        # generate button
        generate_btn = ModernButton(control_frame, text="Generate Report", 
                                command=lambda: self.generate_charts(scrollable_frame))
        generate_btn.grid(row=0, column=7, padx=10, pady=10)

        # container for charts with scrollbar
        container = ttk.Frame(reports_tab, style="Dark.TFrame")
        container.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))

        # create a canvas and scrollbar
        canvas = tk.Canvas(container, bg=self.bg_color, highlightthickness=0)
        scrollbar = ttk.Scrollbar(container, orient="vertical", command=canvas.yview, style="Modern.Vertical.TScrollbar")
        scrollable_frame = ttk.Frame(canvas, style="Dark.TFrame")

        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )

        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        # bind mousewheel to scroll
        def _on_mousewheel(event):
            canvas.yview_scroll(int(-1*(event.delta/120)), "units")
        
        canvas.bind("<MouseWheel>", _on_mousewheel)
        scrollable_frame.bind("<MouseWheel>", _on_mousewheel)

        # Populate user filter with available users from logs
        def populate_user_filter():
            try:
                log_file_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "file_monitor_logs")
                if os.path.exists(log_file_path):
                    users = set()
                    for log_file in os.listdir(log_file_path):
                        if log_file.endswith(".log"):
                            try:
                                with open(os.path.join(log_file_path, log_file), 'r', encoding='utf-8') as f:
                                    for line in f:
                                        # Extract user from log line using multiple patterns
                                        user_match = re.search(r'User:\s*([^|\s@]+)', line)
                                        if user_match:
                                            users.add(user_match.group(1))
                                        else:
                                            # Try alternative pattern
                                            alt_match = re.search(r'User:\s*(.*?)\s*\|', line)
                                            if alt_match:
                                                users.add(alt_match.group(1))
                            except Exception as e:
                                print(f"Error reading log file {log_file}: {e}")
                                continue
                    if users:
                        user_combo['values'] = [""] + sorted(users)
            except Exception as e:
                print(f"Error populating user filter: {e}")

        # Populate users when tab is selected
        def on_tab_selected(event):
            if self.notebook.tab(self.notebook.select(), "text") == "📊 Reports & Analytics":
                populate_user_filter()

        self.notebook.bind("<<NotebookTabChanged>>", on_tab_selected)

        # generate charts initially
        self.generate_charts(scrollable_frame)

    def generate_charts(self, parent_frame):
        """generate enhanced pie charts for file action distribution"""
        # clear existing charts
        for widget in parent_frame.winfo_children():
            if hasattr(widget, '_is_chart_frame'):
                widget.destroy()

        # process log data
        try:
            # get all log files - FIXED PATH
            log_files = []
            # Use the same log path as file_monitor.py
            log_file_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "file_monitor_logs")
            if os.path.exists(log_file_path):
                log_files = sorted(
                    [f for f in os.listdir(log_file_path) if f.endswith(".log")],
                    reverse=True
                )
            
            if not log_files:
                no_data_frame = ttk.Frame(parent_frame, style="Card.TFrame")
                no_data_frame.pack(fill=tk.X, padx=10, pady=10)
                no_data_frame._is_chart_frame = True
                
                ttk.Label(no_data_frame, text="No log files found", 
                        style="Card.TLabel", font=('Segoe UI', 12)).pack(pady=20)
                return
            
            # read all log files
            log_data = []
            for log_file in log_files:
                try:
                    with open(os.path.join(log_file_path, log_file), 'r', encoding='utf-8') as f:
                        for line in f:
                            log_data.append(line.strip())
                except Exception as e:
                    print(f"Error reading log file {log_file}: {e}")
                    continue
            
            if not log_data:
                no_data_frame = ttk.Frame(parent_frame, style="Card.TFrame")
                no_data_frame.pack(fill=tk.X, padx=10, pady=10)
                no_data_frame._is_chart_frame = True
                
                ttk.Label(no_data_frame, text="No log data found", 
                        style="Card.TLabel", font=('Segoe UI', 12)).pack(pady=20)
                return
            
            # parse log data
            parsed_data = []
            # More flexible pattern to handle different log formats
            pattern = r'\[(.*?)\]\s*(?:User:\s*(.*?)\s*\|\s*)?(?:IP:\s*.*?\s*\|\s*)?(CREATED|MODIFIED|DELETED|RENAME):\s*(.*?)(?:\s*->\s*(.*?))?$'

            for line in log_data:
                match = re.search(pattern, line)
                if match:
                    timestamp_str = match.group(1)
                    user = match.group(2) if match.group(2) else "Unknown"
                    action = match.group(3)
                    path = match.group(4)
                    dest_path = match.group(5) if match.group(5) else None
                    
                    try:
                        timestamp = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S')
                        parsed_data.append({
                            'timestamp': timestamp,
                            'user': user,
                            'action': action,
                            'path': path,
                            'dest_path': dest_path if dest_path else None
                        })
                    except ValueError:
                        continue
            
            # If no data parsed with main pattern, try alternative patterns
            if not parsed_data:
                # Try alternative pattern for remote events
                remote_pattern = r'\[(.*?)\]\s*User:\s*(.*?)@.*?\s*\|\s*(CREATED|MODIFIED|DELETED|RENAME):\s*(.*?)(?:\s*->\s*(.*?))?$'
                for line in log_data:
                    match = re.search(remote_pattern, line)
                    if match:
                        timestamp_str, user, action, path, dest_path = match.groups()
                        try:
                            timestamp = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S')
                            parsed_data.append({
                                'timestamp': timestamp,
                                'user': user,
                                'action': action,
                                'path': path,
                                'dest_path': dest_path if dest_path else None
                            })
                        except ValueError:
                            continue
            
            # Try one more pattern for different log formats
            if not parsed_data:
                fallback_pattern = r'\[(.*?)\].*?(CREATED|MODIFIED|DELETED|RENAME):\s*(.*?)$'
                for line in log_data:
                    match = re.search(fallback_pattern, line)
                    if match:
                        timestamp_str, action, path = match.groups()
                        try:
                            timestamp = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S')
                            parsed_data.append({
                                'timestamp': timestamp,
                                'user': "Unknown",
                                'action': action,
                                'path': path,
                                'dest_path': None
                            })
                        except ValueError:
                            continue

            if not parsed_data:
                no_data_frame = ttk.Frame(parent_frame, style="Card.TFrame")
                no_data_frame.pack(fill=tk.X, padx=10, pady=10)
                no_data_frame._is_chart_frame = True
                
                ttk.Label(no_data_frame, text="No valid log entries found", 
                        style="Card.TLabel", font=('Segoe UI', 12)).pack(pady=20)
                return
            
            # create DataFrame
            df = pd.DataFrame(parsed_data)
            
            # apply filters if specified
            time_range = int(self.time_range_var.get()) if self.time_range_var.get() != "All" else None
            if time_range:
                cutoff_date = datetime.now() - pd.Timedelta(days=time_range)
                df = df[df['timestamp'] >= cutoff_date]
            
            user_filter = self.report_user_var.get()
            if user_filter and user_filter != "":
                df = df[df['user'] == user_filter]
            
            action_filter = self.report_action_var.get()
            if action_filter != "ALL":
                df = df[df['action'] == action_filter]
            
            if df.empty:
                no_data_frame = ttk.Frame(parent_frame, style="Card.TFrame")
                no_data_frame.pack(fill=tk.X, padx=10, pady=10)
                no_data_frame._is_chart_frame = True
                
                ttk.Label(no_data_frame, text="No data matching filters", 
                        style="Card.TLabel", font=('Segoe UI', 12)).pack(pady=20)
                return
            
            # summary statistics frame
            summary_frame = ttk.Frame(parent_frame, style="Card.TFrame")
            summary_frame.pack(fill=tk.X, padx=10, pady=10)
            summary_frame._is_chart_frame = True
            
            ttk.Label(summary_frame, text="Summary Statistics", 
                    font=('Segoe UI', 14, 'bold'), style="Card.TLabel").pack(anchor=tk.W, pady=(10, 5))
            
            # create metrics frame
            metrics_frame = ttk.Frame(summary_frame, style="Card.TFrame")
            metrics_frame.pack(fill=tk.X, padx=10, pady=(0, 10))
            
            # calculate metrics
            total_actions = len(df)
            unique_users = df['user'].nunique()
            most_common_action = df['action'].value_counts().idxmax() if not df.empty else "N/A"
            most_active_user = df['user'].value_counts().idxmax() if not df.empty else "N/A"
            
            # display metrics in a grid
            metrics = [
                ("Total Actions", f"{total_actions:,}"),
                ("Unique Users", str(unique_users)),
                ("Most Common Action", most_common_action),
                ("Most Active User", most_active_user)
            ]
            
            for i, (label, value) in enumerate(metrics):
                metric_frame = ttk.Frame(metrics_frame, style="Card.TFrame")
                metric_frame.grid(row=i//2, column=i%2, padx=10, pady=5, sticky=tk.W)
                
                ttk.Label(metric_frame, text=label, style="Secondary.TLabel").pack(anchor=tk.W)
                ttk.Label(metric_frame, text=value, style="Card.TLabel", 
                        font=('Segoe UI', 12, 'bold')).pack(anchor=tk.W)
            
            # group by different time periods and create charts
            time_periods = [
                ('Daily', 'D', 'Daily File Actions'),
                ('Weekly', 'W', 'Weekly File Actions'),
                ('Monthly', 'ME', 'Monthly File Actions'),
                ('Yearly', 'YE', 'Yearly File Actions')
            ]
            
            for period_name, freq, title in time_periods:
                # create frame for this chart
                chart_frame = ttk.Frame(parent_frame, style="Card.TFrame")
                chart_frame.pack(fill=tk.BOTH, padx=10, pady=10)
                chart_frame._is_chart_frame = True
                
                # title for this chart
                chart_title = ttk.Label(chart_frame, text=title, font=('Segoe UI', 14, 'bold'), style="Card.TLabel")
                chart_title.pack(pady=(10, 5))
                
                try:
                    # group data by time period and action
                    if freq == 'W':
                        grouped = df.groupby([pd.Grouper(key='timestamp', freq='W-MON'), 'action']).size().unstack(fill_value=0)
                    else:
                        grouped = df.groupby([pd.Grouper(key='timestamp', freq=freq), 'action']).size().unstack(fill_value=0)
                    
                    # get the latest time period data
                    if not grouped.empty:
                        latest_period = grouped.iloc[-1]
                        
                        # create pie chart with improved styling
                        fig = Figure(figsize=(8, 6), dpi=100, facecolor=self.card_color)
                        ax = fig.add_subplot(111)
                        
                        # modern color palette - green, orange, blue, red, purple
                        colors = ['#4CAF50', '#FF9800', '#2196F3', '#F44336', '#9C27B0']
                        
                        # filter out actions that don't exist in this period
                        action_labels = ['CREATED', 'MODIFIED', 'RENAME', 'DELETED']
                        existing_actions = [action for action in action_labels if action in latest_period.index and latest_period[action] > 0]
                        values = [latest_period[action] for action in existing_actions]
                        
                        if sum(values) > 0:
                            # create pie chart with improved styling
                            wedges, texts, autotexts = ax.pie(
                                values, 
                                labels=existing_actions, 
                                autopct=lambda pct: f'{pct:.1f}%\n({int(pct/100.*sum(values))})',
                                colors=colors[:len(existing_actions)],
                                startangle=90,
                                textprops={'fontsize': 9, 'color': 'white'},
                                wedgeprops={'edgecolor': self.bg_color, 'linewidth': 1.5}
                            )
                            
                            # style the text
                            for text in texts:
                                text.set_fontweight('bold')
                                text.set_fontsize(10)
                            
                            for autotext in autotexts:
                                autotext.set_fontweight('bold')
                                autotext.set_fontsize(9)
                            
                            ax.set_title(f'{period_name} Distribution - {grouped.index[-1].strftime("%Y-%m-%d")}', 
                                    color='white', fontsize=12, pad=20)
                            ax.axis('equal')  # equal aspect ratio ensures that pie is drawn as a circle
                            
                            # create canvas and add to frame
                            canvas = FigureCanvasTkAgg(fig, chart_frame)
                            canvas.draw()
                            canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
                            
                            # add download button
                            btn_frame = ttk.Frame(chart_frame, style="Card.TFrame")
                            btn_frame.pack(pady=(0, 10))
                            
                            ModernButton(btn_frame, text=f"Export {period_name} Data", 
                                    command=lambda f=fig, n=period_name: self.export_chart_data(f, n)).pack(side=tk.LEFT, padx=5)
                        else:
                            no_data_label = ttk.Label(chart_frame, text=f"No data for latest {period_name.lower()}", 
                                                    style="Secondary.TLabel")
                            no_data_label.pack(pady=20)
                    else:
                        no_data_label = ttk.Label(chart_frame, text=f"No data for {period_name.lower()} grouping", 
                                                style="Secondary.TLabel")
                        no_data_label.pack(pady=20)
                
                except Exception as e:
                    error_label = ttk.Label(chart_frame, text=f"Error generating {period_name.lower()} chart: {str(e)}", 
                                        style="Secondary.TLabel", foreground="red")
                    error_label.pack(pady=20)
                    print(f"Error generating {period_name.lower()} chart: {e}")
        
        except Exception as e:
            error_frame = ttk.Frame(parent_frame, style="Card.TFrame")
            error_frame.pack(fill=tk.X, padx=10, pady=10)
            error_frame._is_chart_frame = True
            
            ttk.Label(error_frame, text=f"Error generating charts: {str(e)}", 
                    style="Secondary.TLabel", foreground="red").pack(pady=20)
            print(f"Error generating charts: {e}")

    def export_chart_data(self, fig, period_name):
        """export chart data to CSV file"""
        file_path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
            title=f"Export {period_name} Chart Data",
            initialfile=f"{period_name.lower()}_file_actions_{datetime.now().strftime('%Y%m%d')}.csv"
        )
        
        if file_path:
            try:
                # get the axes from the figure
                ax = fig.axes[0]
                
                # extract data from the pie chart
                data = []
                for wedge, label in zip(ax.patches, ax.texts):
                    if isinstance(label, plt.Text) and label.get_text().startswith(('CREATED', 'MODIFIED', 'RENAME', 'DELETED')):
                        action = label.get_text()
                        count = int(wedge.get_height())  # for pie charts, get_height returns the value
                        percentage = wedge.get_height() / sum([p.get_height() for p in ax.patches]) * 100
                        data.append([action, count, f"{percentage:.1f}%"])
                
                # create DataFrame and save to CSV
                df = pd.DataFrame(data, columns=["Action", "Count", "Percentage"])
                df.to_csv(file_path, index=False)
                
                messagebox.showinfo("Export Successful", f"Data exported to:\n{file_path}")
            
            except Exception as e:
                messagebox.showerror("Export Failed", f"Could not export data:\n{str(e)}")

    def enable_role_based_features(self):
        """enable/disable features based on user role with visual feedback"""
        # update user label
        role = "Administrator" if self.is_admin else "Standard User"
        self.user_label.config(text=f"User: {self.current_user} ({role})")
        
        # disable all sensitive features by default
        if hasattr(self, 'deep_scan_btn'):
            self.deep_scan_btn.config(state=tk.DISABLED)
        
        if hasattr(self, 'metadata_menu'):
            self.metadata_menu.entryconfig("Edit Metadata", state=tk.DISABLED)
        
        # enable features based on role
        if self.is_admin:
            if hasattr(self, 'deep_scan_btn'):
                self.deep_scan_btn.config(state=tk.NORMAL)
            
            if hasattr(self, 'metadata_menu'):
                self.metadata_menu.entryconfig("Edit Metadata", state=tk.NORMAL)
        
        self.log_activity(f"Feature access updated for {self.current_user}")

    def check_access(self, action):
        """check if current user has permission for an action"""
        if not self.auth_data or not self.current_user:
            return False
            
        user_data = self.auth_data["users"].get(self.current_user, {})
        
        if user_data.get("is_admin", False):
            return True
            
        if action in self.auth_data["access_control"]["admin_only_actions"]:
            self.log_activity(f"Unauthorized access attempt to {action} by {self.current_user}")
            return False
            
        return True
    
    def log_activity(self, message):
        """log security-relevant activities"""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        log_entry = f"[{timestamp}] [USER:{self.current_user}] {message}\n"
        
        if self.auth_data:
            self.auth_data["audit_log"].append({
                "timestamp": timestamp,
                "username": self.current_user,
                "action": "security_log",
                "message": message
            })
            
            try:
                with open("auth_control.json", 'w') as f:
                    json.dump(self.auth_data, f, indent=2)
            except:
                pass
        
        # Also log to file monitor if available
        if hasattr(self, 'file_monitor_tab'):
            self.file_monitor_tab.log_file_event(log_entry, "security")

    def encrypt_selected(self):
        if not self.check_access("encryption"):
            messagebox.showerror("Access Denied", "You don't have permission to encrypt files")
            return
            
        selected_paths = self.get_selected_paths()
        if not selected_paths:
            messagebox.showwarning("No Selection", "Please select files or folders first")
            return
        
        cipher = Fernet(self.key)
        encrypted_count = 0
        
        for path in selected_paths:
            if os.path.isdir(path):
                for root, _, files in os.walk(path):
                    for file in files:
                        file_path = os.path.join(root, file)
                        try:
                            with open(file_path, "rb") as f:
                                data = f.read()
                            encrypted = cipher.encrypt(data)
                            with open(file_path, "wb") as f:
                                f.write(encrypted)
                            
                            if file_path in self.metadata:
                                self.metadata[file_path]['integrity_hash'] = self.calculate_file_hash(file_path)
                                self.metadata[file_path]['last_modified'] = datetime.now().isoformat()
                            
                            encrypted_count += 1
                        except Exception as e:
                            print(f"Error encrypting {file_path}: {e}")
            else:
                try:
                    with open(path, "rb") as f:
                        data = f.read()
                    encrypted = cipher.encrypt(data)
                    with open(path, "wb") as f:
                        f.write(encrypted)
                    
                    if path in self.metadata:
                        self.metadata[path]['integrity_hash'] = self.calculate_file_hash(path)
                        self.metadata[path]['last_modified'] = datetime.now().isoformat()
                    
                    encrypted_count += 1
                except Exception as e:
                    print(f"Error encrypting {path}: {e}")
        
        self.save_metadata()
        messagebox.showinfo("Encryption Complete", f"Successfully encrypted {encrypted_count} files")
        self.refresh_directory()
        self.log_activity(f"Encrypted {encrypted_count} files")

    def decrypt_selected(self):
        if not self.check_access("decryption"):
            messagebox.showerror("Access Denied", "You don't have permission to decrypt files")
            return
            
        selected_paths = self.get_selected_paths()
        if not selected_paths:
            messagebox.showwarning("No Selection", "Please select files or folders first")
            return
        
        cipher = Fernet(self.key)
        decrypted_count = 0
        
        for path in selected_paths:
            if os.path.isdir(path):
                for root, _, files in os.walk(path):
                    for file in files:
                        file_path = os.path.join(root, file)
                        try:
                            with open(file_path, "rb") as f:
                                data = f.read()
                            decrypted = cipher.decrypt(data)
                            with open(file_path, "wb") as f:
                                f.write(decrypted)
                            
                            if file_path in self.metadata:
                                self.metadata[file_path]['integrity_hash'] = self.calculate_file_hash(file_path)
                                self.metadata[file_path]['last_modified'] = datetime.now().isoformat()
                            
                            decrypted_count += 1
                        except Exception as e:
                            print(f"Error decrypting {file_path}: {e}")
            else:
                try:
                    with open(path, "rb") as f:
                        data = f.read()
                    decrypted = cipher.decrypt(data)
                    with open(path, "wb") as f:
                        f.write(decrypted)
                    
                    if path in self.metadata:
                        self.metadata[path]['integrity_hash'] = self.calculate_file_hash(path)
                        self.metadata[path]['last_modified'] = datetime.now().isoformat()
                    
                    decrypted_count += 1
                except Exception as e:
                    print(f"Error decrypting {path}: {e}")
        
        self.save_metadata()
        messagebox.showinfo("Decryption Complete", f"Successfully decrypted {decrypted_count} files")
        self.refresh_directory()
        self.log_activity(f"Decrypted {decrypted_count} files")


    def get_available_drives(self):
        """get all available drives on the system"""
        if os.name == 'nt':  # for windows
            drives = []
            bitmask = ctypes.windll.kernel32.GetLogicalDrives()
            for letter in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ':
                if bitmask & 1:
                    drives.append(f"{letter}:\\")
                bitmask >>= 1
            return drives
        else:  # for Linux/Mac
            return ["/"]  # return root for non-windows systems

    def show_drives(self):
        """show available drives in a popup menu"""
        drives = self.get_available_drives()
        
        # create drives menu
        drives_menu = tk.Menu(self, tearoff=0, 
                            font=self.main_font,
                            bg="white",
                            fg="black",  
                            activebackground="#e0e0e0",
                            activeforeground="black")   
        
        for drive in drives:
            # get drive label if available
            try:
                if os.name == 'nt':
                    drive_name = f"Local Disk ({drive[:-1]})"
                else:
                    drive_name = os.path.basename(drive.rstrip(os.sep)) or drive
            except:
                drive_name = drive
            
            drives_menu.add_command(
                label=f"💾 {drive_name}",
                command=lambda d=drive: [self.load_files(d, add_to_history=True), self.save_configuration()]
            )
        
        # show the menu below the drives button
        try:
            drives_menu.tk_popup(self.winfo_pointerx(), self.winfo_pointery())
        finally:
            drives_menu.grab_release()

    def filter_files(self, event):
        """filter files based on search text"""
        search_text = self.search_var.get().lower()
        if not search_text:
            for child in self.tree.get_children():
                self.tree.item(child, tags=())
            return
            
        for child in self.tree.get_children():
            values = self.tree.item(child)['values']
            if values and search_text in values[0].lower():
                self.tree.item(child, tags=('match',))
            else:
                self.tree.item(child, tags=('no-match',))
        
        self.tree.tag_configure('match', background='')
        self.tree.tag_configure('no-match', background='#f5f5f5')

    def refresh_directory(self):
        """refresh the current directory view"""
        self.load_files(self.current_path)

    def load_files(self, path, add_to_history=False):
        """load files from directory with history tracking and security status"""
        path = os.path.normpath(path)
        
        # don't reload the same directory
        if path == os.path.normpath(self.current_path):
            return
            
        # add to history if requested
        if add_to_history:
            if self.history_index < len(self.history) - 1:
                self.history = self.history[:self.history_index+1]
            self.history.append(path)
            self.history_index = len(self.history) - 1

        self.save_configuration()

        self.current_path = path
        self.path_var.set(path)


        self.tree.delete(*self.tree.get_children())

        try:
            if not os.path.ismount(path):
                self.tree.insert("", "end", values=("..", "Parent Folder", "", "", ""),
                                tags=('parent',))
            
            entries = os.listdir(path)
            for entry in sorted(entries, key=lambda x: x.lower()):
                full_path = os.path.join(path, entry)
                try:
                    if os.path.isdir(full_path):
                        icon = "📁"
                        ftype = "Folder"
                        size = ""
                        status = ""
                        tags = ('folder',)
                    else:
                        icon = "📄"
                        ext = os.path.splitext(entry)[1][1:].upper()
                        ftype = f"{ext} File" if ext else "File"
                        size = self.format_size(os.path.getsize(full_path))
                        
                        # determine security status
                        if full_path in self.metadata:
                            meta = self.metadata[full_path]
                            if meta.get("encrypted", False):
                                status = "🔒 Encrypted"
                                tags = ('encrypted',)
                            elif meta.get("signature"):
                                status = "✅ Signed"
                                tags = ('signed',)
                            elif meta.get("sensitivity") in ["High", "Critical"]:
                                status = "⚠️ Sensitive"
                                tags = ('sensitive',)
                            else:
                                status = "📝 Document"
                                tags = ('file',)
                        else:
                            status = "📝 Document"
                            tags = ('file',)
                    
                    modified = self.format_date(os.path.getmtime(full_path))
                    self.tree.insert("", "end", 
                                    values=(f"{icon} {entry}", ftype, size, modified, status),
                                    tags=tags)
                
                except Exception as e:
                    self.tree.insert("", "end", values=(entry, "Error", "", "", "❌ Error"),
                                    tags=('error',))
            
            self.status_var.set(f"{len(entries)} items in {os.path.basename(path) or path}")
            self.update_nav_buttons()
            
            # apply any existing search filter
            if self.search_var.get():
                self.filter_files(None)
                
        except Exception as e:
            messagebox.showerror("Error", str(e))
            self.status_var.set("Error loading directory")

    def update_nav_buttons(self):
        """update navigation buttons state"""
        self.back_btn.config(
            state=tk.NORMAL if self.history_index > 0 else tk.DISABLED,
            style='TButton' if self.history_index > 0 else 'Disabled.TButton'
        )
        self.forward_btn.config(
            state=tk.NORMAL if self.history_index < len(self.history) - 1 else tk.DISABLED,
            style='TButton' if self.history_index < len(self.history) - 1 else 'Disabled.TButton'
        )

    def format_size(self, size_bytes):
        """convert size in bytes to human-readable format"""
        if size_bytes == 0:
            return "0 B"
        size_name = ("B", "KB", "MB", "GB", "TB")
        i = int(math.floor(math.log(size_bytes, 1024)))
        p = math.pow(1024, i)
        return f"{round(size_bytes / p, 2)} {size_name[i]}"

    def format_date(self, timestamp):
        """format timestamp to readable date"""
        return datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M')

    def on_item_double_click(self, event):
        """handle double-click on items"""
        item = self.tree.focus()
        if not item:
            return
        selected = self.tree.item(item)["values"]
        name = selected[0].replace("📁 ", "").replace("📄 ", "")
        if name == "..":
            self.go_up()
            return
        new_path = os.path.join(self.current_path, name)
        
        if os.path.isdir(new_path):
            self.load_files(new_path, add_to_history=True)
        else:
            try:
                os.startfile(new_path)
            except Exception as e:
                messagebox.showerror("Error", f"Cannot open file: {e}")

    def browse_folder(self):
        """open folder browser dialog"""
        folder = filedialog.askdirectory(initialdir=self.current_path)
        if folder:
            self.load_files(folder, add_to_history=True)

    def go_back(self):
        """navigate back in history"""
        if self.history_index > 0:
            self.history_index -= 1
            self.load_files(self.history[self.history_index])
            self.save_configuration()

    def go_forward(self):
        """navigate forward in history"""
        if self.history_index < len(self.history) - 1:
            self.history_index += 1
            self.load_files(self.history[self.history_index])
            self.save_configuration()

    def go_home(self):
        """navigate to custom home directory (D:\\documents)"""
        custom_home = r"D:\\link\\Documents"
        if os.path.normpath(custom_home) != os.path.normpath(self.current_path):
            self.load_files(custom_home, add_to_history=True)
            self.save_configuration()

    def go_up(self):
        """navigate to parent directory"""
        parent = os.path.dirname(self.current_path)
        if parent and os.path.normpath(parent) != os.path.normpath(self.current_path):
            self.load_files(parent, add_to_history=True)
            self.save_configuration()

    def on_path_entered(self, event):
        """handle path entered manually"""
        path = self.path_var.get()
        if os.path.exists(path):
            self.load_files(path, add_to_history=True)
        else:
            messagebox.showerror("Error", "Path does not exist")
        self.save_configuration()

    def show_context_menu(self, event):
        """show context menu on right-click"""
        item = self.tree.identify_row(event.y)
        if item:
            self.tree.selection_set(item)
            self.context_menu.post(event.x_root, event.y_root)

    def open_selected(self):
        """open selected item from context menu"""
        self.on_item_double_click(None)

    def open_in_explorer(self):
        """open current directory in system file explorer"""
        os.startfile(self.current_path)

    def copy_path(self):
        """copy current path to clipboard"""
        self.clipboard_clear()
        self.clipboard_append(self.current_path)
        self.status_var.set("Path copied to clipboard")

    def get_selected_paths(self):
        """get paths of all selected items in treeview"""
        selected_items = self.tree.selection()
        if not selected_items:
            return []
        
        paths = []
        for item in selected_items:
            values = self.tree.item(item)['values']
            if values:
                name = values[0].replace("📁 ", "").replace("📄 ", "")
                if name == "..":
                    continue
                paths.append(os.path.join(self.current_path, name))
        
        return paths

    def get_file_owner(self, file_path):
        """get the owner of a file (cross-platform)"""
        try:
            if os.name == 'nt':  #for windows
                import win32security
                sd = win32security.GetFileSecurity(file_path, win32security.OWNER_SECURITY_INFORMATION)
                owner_sid = sd.GetSecurityDescriptorOwner()
                name, domain, _ = win32security.LookupAccountSid(None, owner_sid)
                return f"{domain}\\{name}"
            else:  # for Unix-like
                import pwd
                stat_info = os.stat(file_path)
                uid = stat_info.st_uid
                return pwd.getpwuid(uid).pw_name
        except Exception:
            return "Unknown"

    def is_suspicious_extension(self, file_path):
        """check for potentially malicious file extensions"""
        suspicious_extensions = {
            '.exe', '.bat', '.cmd', '.ps1', '.vbs', '.js', 
            '.jar', '.dll', '.scr', '.msi', '.pif', '.com'
        }
        return os.path.splitext(file_path)[1].lower() in suspicious_extensions
    
    def backup(self):
        """Backup selected files/folders without logging file activities"""
        import file_monitor
        print("💾 [BACKUP] Disabling file logging...")
        
        # Disable logging BEFORE starting backup
        file_monitor.set_logging_enabled(False)
        
        try:
            selected_paths = self.get_selected_paths()
            self.backup_manager.backup(selected_paths, self.current_path)
            print("✅ [BACKUP] Completed successfully")
        except Exception as e:
            print(f"❌ [BACKUP] Error: {e}")
            messagebox.showerror("Backup Error", f"Failed to backup: {str(e)}")
        finally:
            # Always re-enable logging
            import time
            time.sleep(0.5)  # Small delay to ensure all backup operations are complete
            file_monitor.set_logging_enabled(True)
            print("📝 [BACKUP] Re-enabled file logging")

    def restore_from_backup(self):
        """Complete backup restoration without logging file activities"""
        if not self.check_access("restore"):
            messagebox.showerror("Access Denied", "You don't have permission to restore from backups")
            return
        
        import file_monitor
        print("🔄 [RESTORE] Disabling file logging...")
        
        # Disable logging BEFORE starting restore
        file_monitor.set_logging_enabled(False)
        
        # Add a small delay to ensure logging is fully disabled
        self.after(100, self._perform_restore)

    def _perform_restore(self):
        """Perform restore with guaranteed logging control"""
        import file_monitor
        import time
        
        try:
            # Double-check logging is disabled
            file_monitor.set_logging_enabled(False)
            
            # Perform the actual restore
            self.backup_manager.restore_from_backup(self.current_path)
            print("✅ [RESTORE] Completed successfully")
            
        except Exception as e:
            print(f"❌ [RESTORE] Error during restore: {e}")
            messagebox.showerror("Restore Error", f"Failed to restore: {str(e)}")
        
        finally:
            # Always re-enable logging after restore completes
            time.sleep(0.5)  # Small delay to ensure all restore operations are complete
            file_monitor.set_logging_enabled(True)
            print("📝 [RESTORE] Re-enabled file logging")

    def lock_folder_interactive(self, predefined_path=None):
        """Interactive folder locking using direct imports like backup/restore"""
        from file_monitor import set_logging_enabled
        set_logging_enabled(False)
        
        try:
            if predefined_path and os.path.exists(predefined_path):
                folder_path = predefined_path
            else:
                folder_path = filedialog.askdirectory(
                    title="Select Folder to Disable Delete Access",
                    initialdir=self.current_path
                )
            
            if not folder_path:
                return  # User cancelled
            
            # Use direct import like backup/restore instead of subprocess
            try:
                from tools.lock_folder import lock_folder
                success = lock_folder(folder_path, use_acl=True)
            except ImportError as e:
                messagebox.showerror("Error", f"Folder protection module not available: {str(e)}")
                return
            
            if success:
                messagebox.showinfo("Folder Protected", 
                                f"✅ Delete disabled for selected folder.\nPath: {folder_path}")
                self.log_activity(f"Folder protection enabled: {folder_path}")
                print("✅ [FOLDER LOCK] Folder protection completed")
            else:
                messagebox.showerror("Error", "Failed to protect folder")
                
        except Exception as e:
            messagebox.showerror("Error", f"Failed to protect folder: {str(e)}")
            print(f"❌ [FOLDER LOCK] Error: {e}")
        finally:
            # Always re-enable file activity logging with delay
            import time
            time.sleep(0.5)
            set_logging_enabled(True)
            print("📝 [FOLDER LOCK] Re-enabled file logging")

    def unlock_folder_interactive(self, predefined_path=None):
        """Interactive folder unlocking using direct imports"""
        from file_monitor import set_logging_enabled
        set_logging_enabled(False)
        
        try:
            if predefined_path and os.path.exists(predefined_path):
                folder_path = predefined_path
            else:
                folder_path = filedialog.askdirectory(
                    title="Select Folder to Enable Delete Access",
                    initialdir=self.current_path
                )
            
            if not folder_path:
                return  # User cancelled
            
            # Use direct import like backup/restore
            try:
                from tools.unlock_folder import unlock_folder
                success = unlock_folder(folder_path, use_acl=True)
            except ImportError as e:
                messagebox.showerror("Error", f"Folder protection module not available: {str(e)}")
                return
            
            if success:
                messagebox.showinfo("Folder Restored", 
                                f"🗝️ Delete re-enabled for selected folder.\nPath: {folder_path}")
                self.log_activity(f"Folder protection disabled: {folder_path}")
                print("✅ [FOLDER UNLOCK] Folder restoration completed")
            else:
                messagebox.showerror("Error", "Failed to restore folder")
                
        except Exception as e:
            messagebox.showerror("Error", f"Failed to restore folder: {str(e)}")
            print(f"❌ [FOLDER UNLOCK] Error: {e}")
        finally:
            # Always re-enable file activity logging with delay
            import time
            time.sleep(0.5)
            set_logging_enabled(True)
            print("📝 [FOLDER UNLOCK] Re-enabled file logging")

    def load_or_generate_key(self):  # ✅ This should be at class level
        """load encryption key from file or generate a new one"""
        if os.path.exists(self.key_file):
            with open(self.key_file, "rb") as f:
                return f.read()
        else:
            key = Fernet.generate_key()
            with open(self.key_file, "wb") as f:
                f.write(key)
            return key

    def load_or_generate_metadata_keys(self):
        """load or generate RSA keys for metadata signing"""
        self.private_key_file = "private_key.pem"
        self.public_key_file = "public_key.pem"
        self.key_password = b"mysecurepassword"
        
        if os.path.exists(self.private_key_file) and os.path.exists(self.public_key_file):
            try:
                with open(self.private_key_file, "rb") as f:
                    self.private_key = serialization.load_pem_private_key(
                        f.read(),
                        password=self.key_password,
                        backend=default_backend()
                    )
                with open(self.public_key_file, "rb") as f:
                    self.public_key = serialization.load_pem_public_key(
                        f.read(),
                        backend=default_backend()
                    )
            except Exception as e:
                self.generate_metadata_keys()
        else:
            self.generate_metadata_keys()

    def generate_metadata_keys(self):
        """generate new RSA key pair for metadata signing"""
        try:
            self.private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )
            self.public_key = self.private_key.public_key()
            
            # save private key
            pem_private = self.private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.BestAvailableEncryption(self.key_password)
            )
            with open(self.private_key_file, "wb") as f:
                f.write(pem_private)
            
            # save public key
            pem_public = self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            with open(self.public_key_file, "wb") as f:
                f.write(pem_public)
        except Exception as e:
            messagebox.showerror("Key Generation Error", f"Failed to generate keys: {str(e)}")

    def calculate_file_hash(self, file_path):
        """calculate SHA-256 hash of file contents"""
        hash_sha256 = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_sha256.update(chunk)
            return hash_sha256.hexdigest()
        except Exception as e:
            return None

    def sign_file(self, file_path):
        """create digital signature for a file"""
        file_hash = self.calculate_file_hash(file_path)
        if not file_hash:
            return None
            
        try:
            signature = self.private_key.sign(
                file_hash.encode(),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return base64.b64encode(signature).decode()
        except Exception:
            return None

    def verify_signature(self, file_path, signature_b64):
        """verify a file's digital signature"""
        file_hash = self.calculate_file_hash(file_path)
        if not file_hash:
            return False
            
        try:
            signature = base64.b64decode(signature_b64)
            self.public_key.verify(
                signature,
                file_hash.encode(),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception:
            return False

    def load_metadata(self):
        """load metadata from JSON file"""
        if os.path.exists(self.metadata_file):
            try:
                with open(self.metadata_file, 'r') as f:
                    return json.load(f)
            except Exception:
                return {}
        return {}

    def save_metadata(self):
        """save metadata to JSON file"""
        try:
            with open(self.metadata_file, 'w') as f:
                json.dump(self.metadata, f, indent=2)
        except Exception:
            pass

    def on_closing(self):
        """clean up when closing the application"""
        # Stop file monitoring if active
        if hasattr(self, 'file_monitor_tab'):
            self.file_monitor_tab.stop_file_monitoring()
        self.save_configuration()
        # Ensure notification panel is properly destroyed
        if hasattr(self, 'notif_panel'):
            self.notif_panel.destroy()
        self.destroy()

if __name__ == "__main__":
    app = FileExplorer()
    app.protocol("WM_DELETE_WINDOW", app.on_closing)
    app.mainloop()