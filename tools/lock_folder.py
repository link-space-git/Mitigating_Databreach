#!/usr/bin/env python3
"""
Folder Lock Script - Disables delete access on selected folders
"""

import os
import sys
import json
import platform
import subprocess
from datetime import datetime
from pathlib import Path

def lock_folder(folder_path, use_acl=True):
    """
    Disable delete access recursively in a folder
    """
    folder_path = os.path.abspath(folder_path)
    
    if not os.path.exists(folder_path):
        print(f"❌ Error: Folder does not exist: {folder_path}")
        return False
    
    if not os.path.isdir(folder_path):
        print(f"❌ Error: Path is not a folder: {folder_path}")
        return False
    
    protected_items = 0
    errors = 0
    
    try:
        # Walk through all files and subdirectories
        for root, dirs, files in os.walk(folder_path):
            # Process files
            for file in files:
                file_path = os.path.join(root, file)
                if set_file_readonly(file_path, use_acl):
                    protected_items += 1
                else:
                    errors += 1
            
            # Process directories
            for dir_name in dirs:
                dir_path = os.path.join(root, dir_name)
                if set_file_readonly(dir_path, use_acl):
                    protected_items += 1
                else:
                    errors += 1
        
        # Also protect the root folder itself
        if set_file_readonly(folder_path, use_acl):
            protected_items += 1
        
        # Log the action
        log_action(folder_path, "locked", protected_items, errors)
        
        print(f"✅ Folder protected: {folder_path}")
        print(f"   Items locked: {protected_items}")
        if errors > 0:
            print(f"   Errors: {errors}")
        
        return True
        
    except Exception as e:
        print(f"❌ Error protecting folder: {str(e)}")
        return False

def set_file_readonly(file_path, use_acl=True):
    """
    Set file/directory to read-only based on platform
    """
    try:
        system = platform.system().lower()
        
        if system == "windows":
            # Remove read-only attribute first to ensure clean state
            subprocess.run(['attrib', '-R', file_path], 
                         capture_output=True, shell=True)
            
            # Set read-only attribute
            result = subprocess.run(['attrib', '+R', file_path], 
                                  capture_output=True, shell=True)
            
            if use_acl:
                # Deny delete permission for Everyone
                try:
                    subprocess.run([
                        'icacls', file_path, '/deny', 'Everyone:(D)'
                    ], capture_output=True, shell=True)
                except Exception:
                    pass  # icacls might not be available
            
            return result.returncode == 0
            
        else:  # Linux/Mac
            # Set read-only permissions (555: read & execute for all)
            os.chmod(file_path, 0o555)
            return True
            
    except Exception as e:
        print(f"   ⚠️ Failed to protect: {file_path} - {str(e)}")
        return False

def log_action(folder_path, action, items_count, errors=0):
    """
    Log protection actions to JSON file
    """
    log_file = "locked_folders_log.json"
    
    # Create log entry
    log_entry = {
        "timestamp": datetime.now().isoformat(),
        "folder": folder_path,
        "action": action,
        "items_affected": items_count,
        "errors": errors,
        "platform": platform.system()
    }
    
    # Read existing log or create new
    log_data = []
    if os.path.exists(log_file):
        try:
            with open(log_file, 'r', encoding='utf-8') as f:
                log_data = json.load(f)
        except:
            log_data = []
    
    # Add new entry
    log_data.append(log_entry)
    
    # Write back to file
    try:
        with open(log_file, 'w', encoding='utf-8') as f:
            json.dump(log_data, f, indent=2, ensure_ascii=False)
    except Exception as e:
        print(f"⚠️ Could not write to log file: {str(e)}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python lock_folder.py <folder_path> [--acl]")
        sys.exit(1)
    
    folder_path = sys.argv[1]
    use_acl = "--acl" in sys.argv
    
    print(f"🔒 Locking folder: {folder_path}")
    success = lock_folder(folder_path, use_acl)
    sys.exit(0 if success else 1)