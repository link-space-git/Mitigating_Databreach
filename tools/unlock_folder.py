#!/usr/bin/env python3
"""
Folder Unlock Script - Enables delete access on selected folders
"""

import os
import sys
import json
import platform
import subprocess
from datetime import datetime
from pathlib import Path

def unlock_folder(folder_path, use_acl=True):
    """
    Enable delete access recursively in a folder
    """
    folder_path = os.path.abspath(folder_path)
    
    if not os.path.exists(folder_path):
        print(f"❌ Error: Folder does not exist: {folder_path}")
        return False
    
    if not os.path.isdir(folder_path):
        print(f"❌ Error: Path is not a folder: {folder_path}")
        return False
    
    restored_items = 0
    errors = 0
    
    try:
        # First, make the root folder accessible so we can traverse subfolders
        if set_file_writable(folder_path, use_acl):
            restored_items += 1
        
        # Walk through all files and subdirectories
        # Use topdown=False to process deepest folders first (important for permission changes)
        for root, dirs, files in os.walk(folder_path, topdown=False):
            # Process files first
            for file in files:
                file_path = os.path.join(root, file)
                if set_file_writable(file_path, use_acl):
                    restored_items += 1
                else:
                    errors += 1
            
            # Process directories (deepest first)
            for dir_name in dirs:
                dir_path = os.path.join(root, dir_name)
                if set_file_writable(dir_path, use_acl):
                    restored_items += 1
                else:
                    errors += 1
        
        # Log the action
        log_action(folder_path, "unlocked", restored_items, errors)
        
        print(f"🗝️ Folder unlocked: {folder_path}")
        print(f"   Items restored: {restored_items}")
        if errors > 0:
            print(f"   Errors: {errors}")
        
        return True
        
    except Exception as e:
        print(f"❌ Error unlocking folder: {str(e)}")
        return False

def set_file_writable(file_path, use_acl=True):
    """
    Set file/directory to writable based on platform
    """
    try:
        system = platform.system().lower()
        
        if system == "windows":
            # Remove read-only attribute
            result = subprocess.run(['attrib', '-R', file_path], 
                                  capture_output=True, shell=True)
            
            if use_acl:
                # Remove deny delete permission for Everyone
                try:
                    # Try multiple icacls commands to ensure permissions are removed
                    subprocess.run([
                        'icacls', file_path, '/remove:d', 'Everyone'
                    ], capture_output=True, shell=True, timeout=10)
                    
                    # Also try to reset permissions to inheritance
                    subprocess.run([
                        'icacls', file_path, '/reset'
                    ], capture_output=True, shell=True, timeout=10)
                    
                    # Grant full control to current user
                    subprocess.run([
                        'icacls', file_path, '/grant:r', '*S-1-1-0:(F)'
                    ], capture_output=True, shell=True, timeout=10)
                    
                except subprocess.TimeoutExpired:
                    print(f"   ⚠️ Timeout modifying ACLs for: {file_path}")
                except Exception as e:
                    print(f"   ⚠️ ACL modification failed for {file_path}: {str(e)}")
            
            return result.returncode == 0
            
        else:  # Linux/Mac
            try:
                # For directories: set to 755 (rwxr-xr-x)
                if os.path.isdir(file_path):
                    os.chmod(file_path, 0o755)
                # For files: set to 644 (rw-r--r--)  
                else:
                    os.chmod(file_path, 0o644)
                return True
            except PermissionError:
                print(f"   ⚠️ Permission denied: {file_path}")
                return False
            except Exception as e:
                print(f"   ⚠️ Chmod failed for {file_path}: {str(e)}")
                return False
            
    except Exception as e:
        print(f"   ⚠️ Failed to unlock: {file_path} - {str(e)}")
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
        print("Usage: python unlock_folder.py <folder_path> [--acl]")
        sys.exit(1)
    
    folder_path = sys.argv[1]
    use_acl = "--acl" in sys.argv
    
    print(f"🔓 Unlocking folder: {folder_path}")
    success = unlock_folder(folder_path, use_acl)
    sys.exit(0 if success else 1)