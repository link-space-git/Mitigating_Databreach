import os
import shutil
import datetime
import tkinter.messagebox as messagebox
from tkinter import filedialog
import tkinter as tk
from tkinter import ttk

class BackupManager:
    def __init__(self, main_app=None):
        self.main_app = main_app
        self.backup_directory = os.path.join(os.path.expanduser("~"), "Backups")
        os.makedirs(self.backup_directory, exist_ok=True)

    def set_main_app(self, main_app):
        """Set reference to main application for logging and status updates"""
        self.main_app = main_app

    def backup(self, selected_paths, current_path):
        """Backup selected files/folders with GUI options"""
        if not selected_paths:
            messagebox.showwarning("No Selection", "Please select files or folders first")
            return False
        
        # Create a popup window for backup options
        backup_window = tk.Toplevel()
        backup_window.title("Backup Options")
        backup_window.geometry("400x250")
        
        # Backup name entry
        tk.Label(backup_window, text="Backup Name:").pack(pady=(10, 0))
        backup_name_entry = tk.Entry(backup_window, width=40)
        backup_name_entry.insert(0, f"Backup_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}")
        backup_name_entry.pack()
        
        # Backup directory selection
        tk.Label(backup_window, text="Backup Location:").pack(pady=(10, 0))
        
        backup_dir_frame = tk.Frame(backup_window)
        backup_dir_frame.pack(fill=tk.X, padx=10)
        
        backup_dir_var = tk.StringVar(value=self.backup_directory)
        backup_dir_entry = tk.Entry(backup_dir_frame, textvariable=backup_dir_var, width=30)
        backup_dir_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        def browse_backup_dir():
            dir_path = filedialog.askdirectory(initialdir=backup_dir_var.get())
            if dir_path:
                backup_dir_var.set(dir_path)
                self.backup_directory = dir_path
                if self.main_app:
                    self.main_app.backup_directory = dir_path
                    self.main_app.save_configuration()

        browse_btn = tk.Button(backup_dir_frame, text="Browse...", command=browse_backup_dir)
        browse_btn.pack(side=tk.RIGHT, padx=(5, 0))
        
        # Backup button
        def perform_backup():
            backup_name = backup_name_entry.get().strip()
            if not backup_name:
                messagebox.showerror("Error", "Backup name cannot be empty!")
                return
            
            backup_dir = backup_dir_var.get()
            if not backup_dir:
                messagebox.showerror("Error", "Please select a backup location!")
                return
            
            # Save the backup directory
            self.backup_directory = backup_dir
            if self.main_app:
                self.main_app.backup_directory = backup_dir
                self.main_app.save_configuration()
            
            destination = os.path.join(backup_dir, backup_name)
            
            try:
                # Create destination directory if it doesn't exist
                os.makedirs(backup_dir, exist_ok=True)
                
                # Check if destination already exists
                if os.path.exists(destination):
                    if not messagebox.askyesno("Confirm Overwrite", 
                                            f"'{backup_name}' already exists at this location.\nOverwrite?"):
                        return
                
                # Create the backup directory
                os.makedirs(destination, exist_ok=True)
                
                for path in selected_paths:
                    if os.path.isdir(path):
                        # Copy contents of the folder
                        for item in os.listdir(path):
                            src_path = os.path.join(path, item)
                            dst_path = os.path.join(destination, item)
                            
                            if os.path.isdir(src_path):
                                if os.path.exists(dst_path):
                                    shutil.rmtree(dst_path)
                                shutil.copytree(src_path, dst_path)
                            else:
                                if os.path.exists(dst_path):
                                    os.remove(dst_path)
                                shutil.copy2(src_path, dst_path)
                    else:
                        # Copy individual files directly to destination
                        item_name = os.path.basename(path)
                        dst_path = os.path.join(destination, item_name)
                        if os.path.exists(dst_path):
                            os.remove(dst_path)
                        shutil.copy2(path, dst_path)

                messagebox.showinfo("Backup Complete", 
                                f"Backup created successfully at:\n{destination}")
                
                if self.main_app:
                    self.main_app.status_var.set("Backup completed successfully")
                    self.main_app.log_activity(f"Created backup: {backup_name}")
                
                backup_window.destroy()
                return True
                
            except Exception as e:
                messagebox.showerror("Backup Failed", f"Error during backup: {str(e)}")
                if self.main_app:
                    self.main_app.status_var.set("Backup failed")
                return False
        
        tk.Button(backup_window, text="Create Backup", 
                command=perform_backup, bg="lightblue").pack(pady=20)
        
        return True

    def restore_from_backup(self, current_path):
        """Complete backup restoration - select backup folder and restore all contents"""
        # Select backup folder
        backup_path = filedialog.askdirectory(
            title="Select Backup Folder to Restore",
            initialdir=self.backup_directory
        )
        if not backup_path:
            return False

        # Select destination folder
        dest_path = filedialog.askdirectory(
            title="Select Where to Restore the Backup",
            initialdir=current_path
        )
        if not dest_path:
            return False

        # Verify paths
        if not os.path.exists(backup_path):
            messagebox.showerror("Error", "Backup folder no longer exists")
            return False

        # Get backup folder name for display
        backup_name = os.path.basename(backup_path.rstrip(os.sep))

        # Confirm restoration
        confirm_msg = f"Will restore ALL contents from:\n{backup_path}\n\n"
        confirm_msg += f"To destination:\n{dest_path}\n\n"
        confirm_msg += "This will:\n"
        confirm_msg += "- Copy all files and folders\n"
        confirm_msg += "- Preserve the original structure\n"
        confirm_msg += "- Overwrite existing files with same names\n\n"
        confirm_msg += "Continue?"

        if not messagebox.askyesno("Confirm Full Restore", confirm_msg):
            return False

        # Perform restoration with progress
        try:
            # Create progress window
            progress = tk.Toplevel()
            progress.title(f"Restoring {backup_name}...")
            progress.geometry("500x150")
            
            tk.Label(progress, 
                    text=f"Restoring ALL contents from:\n{backup_path}",
                    justify=tk.LEFT).pack(pady=(10,0))
            tk.Label(progress, 
                    text=f"To:\n{dest_path}",
                    justify=tk.LEFT).pack()
            
            progress_bar = ttk.Progressbar(progress, mode='indeterminate')
            progress_bar.pack(fill=tk.X, padx=20, pady=10)
            progress_bar.start()
            progress.update()

            # Count items first for better progress reporting
            total_count = 0
            for root, dirs, files in os.walk(backup_path):
                total_count += len(files)

            # Actual restore
            restored_count = 0
            for root, dirs, files in os.walk(backup_path):
                # Create relative path structure
                rel_path = os.path.relpath(root, backup_path)
                dest_dir = os.path.join(dest_path, rel_path)
                
                # Create target directory if needed
                if not os.path.exists(dest_dir):
                    os.makedirs(dest_dir)

                # Copy all files
                for file in files:
                    src_file = os.path.join(root, file)
                    dest_file = os.path.join(dest_dir, file)
                    
                    shutil.copy2(src_file, dest_file)
                    restored_count += 1
                    
                    # Update progress periodically
                    if restored_count % 10 == 0:
                        progress.update()
            
            progress.destroy()

            # Show completion
            messagebox.showinfo(
                "Restore Complete",
                f"Successfully restored {restored_count} items from:\n"
                f"{backup_name}\n\n"
                f"To:\n{dest_path}"
            )
            
            if self.main_app:
                self.main_app.log_activity(
                    f"Restored {restored_count} items from {backup_path} "
                    f"to {dest_path}"
                )

            # Refresh if destination is current directory
            if self.main_app and os.path.samefile(dest_path, self.main_app.current_path):
                self.main_app.refresh_directory()

            return True

        except Exception as e:
            if 'progress' in locals():
                progress.destroy()
            messagebox.showerror(
                "Restore Failed",
                f"Failed to complete restore:\n{str(e)}\n\n"
                f"Some files may have been partially restored."
            )
            return False

    def get_backup_directory(self):
        """Get the current backup directory"""
        return self.backup_directory

    def set_backup_directory(self, directory):
        """Set the backup directory"""
        self.backup_directory = directory
        os.makedirs(directory, exist_ok=True)