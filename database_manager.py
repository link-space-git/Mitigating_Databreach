# database_manager.py - Safe version
import mysql.connector
from mysql.connector import Error
import bcrypt
from datetime import datetime
import os
import threading

class DatabaseManager:
    """Manages MySQL database operations for user authentication and logging"""
    
    def __init__(self, config=None):
        self.connection = None
        self.current_user = None
        self.enabled = False
        self._lock = threading.Lock()  # Thread safety
        
        # Default configuration
        self.config = {
            'host': 'localhost',
            'user': 'root',
            'password': 'G@spar123',
            'database': 'file_monitor_db'
        }
        
        if config:
            self.config.update(config)
        
        # Try to connect in background (don't block startup)
        threading.Thread(target=self._init_connection, daemon=True).start()
    
    def _init_connection(self):
        """Initialize connection in background"""
        try:
            self.connect()
            if self.connection and self.connection.is_connected():
                self.create_tables()
                self.enabled = True
                print("✅ Database manager initialized")
                self.create_default_admin()
            else:
                print("⚠️ Database manager running in DISABLED mode")
        except Exception as e:
            print(f"⚠️ Database initialization error: {e}")
            self.enabled = False
    
    def connect(self):
        """Establish database connection"""
        try:
            temp_config = self.config.copy()
            temp_db = temp_config.pop('database', 'file_monitor_db')
            
            self.connection = mysql.connector.connect(**temp_config)
            
            if self.connection and self.connection.is_connected():
                cursor = self.connection.cursor()
                cursor.execute(f"CREATE DATABASE IF NOT EXISTS {temp_db}")
                cursor.execute(f"USE {temp_db}")
                cursor.close()
                return True
        except Exception as e:
            print(f"❌ Database connection error: {e}")
            self.connection = None
            return False
        return False
    
    def create_tables(self):
        """Create necessary tables if they don't exist"""
        if not self.connection or not self.connection.is_connected():
            return False
        
        try:
            with self._lock:
                cursor = self.connection.cursor()
                
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS users (
                        id INT AUTO_INCREMENT PRIMARY KEY,
                        username VARCHAR(100) UNIQUE NOT NULL,
                        password_hash VARCHAR(255) NOT NULL,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        last_login TIMESTAMP NULL,
                        is_admin BOOLEAN DEFAULT FALSE
                    )
                """)
                
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS file_logs (
                        id INT AUTO_INCREMENT PRIMARY KEY,
                        username VARCHAR(100) NOT NULL,
                        action VARCHAR(50) NOT NULL,
                        file_path TEXT NOT NULL,
                        file_type VARCHAR(100),
                        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        anomaly_score FLOAT,
                        INDEX idx_username (username),
                        INDEX idx_timestamp (timestamp)
                    )
                """)
                
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS alerts (
                        id INT AUTO_INCREMENT PRIMARY KEY,
                        username VARCHAR(100) NOT NULL,
                        alert_level VARCHAR(50) NOT NULL,
                        reason TEXT NOT NULL,
                        prediction VARCHAR(200),
                        file_count INT DEFAULT 1,
                        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        INDEX idx_username (username),
                        INDEX idx_timestamp (timestamp)
                    )
                """)
                
                self.connection.commit()
                cursor.close()
                return True
        except Exception as e:
            print(f"❌ Table creation error: {e}")
            return False
    
    def register_user(self, username, password, is_admin=False):
        """Register a new user"""
        if not self.enabled:
            return False, "Database not available"
        
        try:
            with self._lock:
                cursor = self.connection.cursor()
                cursor.execute("SELECT id FROM users WHERE username = %s", (username,))
                if cursor.fetchone():
                    cursor.close()
                    return False, "Username already exists"
                
                password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
                cursor.execute(
                    "INSERT INTO users (username, password_hash, is_admin) VALUES (%s, %s, %s)",
                    (username, password_hash.decode('utf-8'), is_admin)
                )
                self.connection.commit()
                cursor.close()
                return True, "User registered successfully"
        except Exception as e:
            print(f"❌ Registration error: {e}")
            return False, f"Database error: {e}"
    
    def login_user(self, username, password):
        """Authenticate user"""
        if not self.enabled:
            return False, "Database not available", False
        
        try:
            with self._lock:
                cursor = self.connection.cursor(dictionary=True)
                cursor.execute(
                    "SELECT id, username, password_hash, is_admin FROM users WHERE username = %s",
                    (username,)
                )
                user = cursor.fetchone()
                
                if not user:
                    cursor.close()
                    return False, "Invalid username or password", False
                
                if bcrypt.checkpw(password.encode('utf-8'), user['password_hash'].encode('utf-8')):
                    cursor.execute(
                        "UPDATE users SET last_login = NOW() WHERE id = %s",
                        (user['id'],)
                    )
                    self.connection.commit()
                    cursor.close()
                    self.current_user = username
                    return True, "Login successful", user.get('is_admin', False)
                else:
                    cursor.close()
                    return False, "Invalid username or password", False
        except Exception as e:
            print(f"❌ Login error: {e}")
            return False, f"Database error: {e}", False
    
    def log_file_activity(self, username, action, file_path, file_type=None, anomaly_score=None):
        """Log file activity - safe, non-blocking"""
        if not self.enabled:
            return False
        
        try:
            with self._lock:
                cursor = self.connection.cursor()
                cursor.execute(
                    """INSERT INTO file_logs 
                       (username, action, file_path, file_type, anomaly_score) 
                       VALUES (%s, %s, %s, %s, %s)""",
                    (username[:100], action[:50], file_path[:1000], 
                     (file_type or '')[:100], anomaly_score)
                )
                self.connection.commit()
                cursor.close()
                return True
        except Exception as e:
            print(f"❌ File log error: {e}")
            return False
    
    def log_alert(self, username, alert_level, reason, prediction=None, file_count=1):
        """Log alert - safe, non-blocking"""
        if not self.enabled:
            return False
        
        try:
            with self._lock:
                cursor = self.connection.cursor()
                cursor.execute(
                    """INSERT INTO alerts 
                       (username, alert_level, reason, prediction, file_count) 
                       VALUES (%s, %s, %s, %s, %s)""",
                    (username[:100], alert_level[:50], reason[:1000], 
                     (prediction or '')[:200], file_count)
                )
                self.connection.commit()
                cursor.close()
                return True
        except Exception as e:
            print(f"❌ Alert log error: {e}")
            return False
    
    def get_current_user(self):
        return self.current_user
    
    def set_current_user(self, username):
        self.current_user = username
    
    def create_default_admin(self):
        """Create default admin if no users exist"""
        if not self.enabled:
            return
        
        try:
            with self._lock:
                cursor = self.connection.cursor()
                cursor.execute("SELECT COUNT(*) as count FROM users")
                result = cursor.fetchone()
                
                if result and result[0] == 0:
                    default_password = "Admin123!"
                    password_hash = bcrypt.hashpw(default_password.encode('utf-8'), bcrypt.gensalt())
                    cursor.execute(
                        "INSERT INTO users (username, password_hash, is_admin) VALUES (%s, %s, %s)",
                        ("admin", password_hash.decode('utf-8'), True)
                    )
                    self.connection.commit()
                    print(f"✅ Default admin created: admin / {default_password}")
                cursor.close()
        except Exception as e:
            print(f"❌ Error creating default admin: {e}")
    
    def close(self):
        """Close database connection"""
        if self.connection and self.connection.is_connected():
            self.connection.close()
            print("📁 Database connection closed")

# Create global instance
db_manager = DatabaseManager()