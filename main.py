#!/usr/bin/env python3
"""
Secure E-Waste Data Wiping Platform
Main entry point for the desktop application
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import os
import threading
from pathlib import Path
import json
from datetime import datetime

# Import our modules
from src.file_manager import FileManager
from src.ai_detector import SensitiveDataDetector
from src.wipe_engine import WipeEngine
from src.certificate_generator import CertificateGenerator
from src.audit_logger import AuditLogger

class SecureWipeApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure E-Waste Data Wiping Platform")
        self.root.geometry("1200x800")
        self.root.configure(bg='#2c3e50')
        
        # Initialize components
        self.file_manager = FileManager()
        self.ai_detector = SensitiveDataDetector()
        self.wipe_engine = WipeEngine()
        self.cert_generator = CertificateGenerator()
        self.audit_logger = AuditLogger()
        
        # Selected files for wiping
        self.selected_files = []
        
        self.setup_ui()
        
    def setup_ui(self):
        """Setup the main user interface"""
        # Main container
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=tk.W+tk.E+tk.N+tk.S)
        
        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(2, weight=1)
        
        # Title
        title_label = ttk.Label(main_frame, text="Secure E-Waste Data Wiping Platform", 
                               font=('Arial', 16, 'bold'))
        title_label.grid(row=0, column=0, columnspan=3, pady=(0, 20))
        
        # Left panel - Controls
        controls_frame = ttk.LabelFrame(main_frame, text="Wipe Configuration", padding="10")
        controls_frame.grid(row=1, column=0, sticky=tk.W+tk.E+tk.N+tk.S, padx=(0, 10))
        
        # Browse directory button
        ttk.Button(controls_frame, text="Browse Directory", 
                  command=self.browse_directory).grid(row=0, column=0, sticky=tk.W+tk.E, pady=5)
        
        # Wipe options
        ttk.Label(controls_frame, text="Wipe Passes:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.passes_var = tk.StringVar(value="3")
        passes_spinbox = ttk.Spinbox(controls_frame, from_=1, to=35, textvariable=self.passes_var, width=10)
        passes_spinbox.grid(row=2, column=0, sticky=tk.W+tk.E, pady=5)
        
        ttk.Label(controls_frame, text="Fill Pattern:").grid(row=3, column=0, sticky=tk.W, pady=5)
        self.pattern_var = tk.StringVar(value="random")
        pattern_combo = ttk.Combobox(controls_frame, textvariable=self.pattern_var, 
                                   values=["zero", "random", "dod"], state="readonly")
        pattern_combo.grid(row=4, column=0, sticky=tk.W+tk.E, pady=5)
        
        ttk.Label(controls_frame, text="Wipe Method:").grid(row=5, column=0, sticky=tk.W, pady=5)
        self.method_var = tk.StringVar(value="selected")
        method_combo = ttk.Combobox(controls_frame, textvariable=self.method_var,
                                  values=["selected", "full_device"], state="readonly")
        method_combo.grid(row=6, column=0, sticky=tk.W+tk.E, pady=5)
        
        # Action buttons
        ttk.Button(controls_frame, text="Scan for Sensitive Data", 
                  command=self.scan_sensitive_data).grid(row=7, column=0, sticky=tk.W+tk.E, pady=10)
        
        ttk.Button(controls_frame, text="Start Secure Wipe", 
                  command=self.start_wipe).grid(row=8, column=0, sticky=tk.W+tk.E, pady=5)
        
        # Right panel - File browser
        browser_frame = ttk.LabelFrame(main_frame, text="File Browser", padding="10")
        browser_frame.grid(row=1, column=1, rowspan=2, sticky=tk.W+tk.E+tk.N+tk.S)
        browser_frame.columnconfigure(0, weight=1)
        browser_frame.rowconfigure(0, weight=1)
        
        # File tree
        self.file_tree = ttk.Treeview(browser_frame, columns=('Size', 'Risk', 'Type'), show='tree headings')
        self.file_tree.heading('#0', text='File/Directory')
        self.file_tree.heading('Size', text='Size')
        self.file_tree.heading('Risk', text='Risk Score')
        self.file_tree.heading('Type', text='Type')
        
        # Configure column widths
        self.file_tree.column('#0', width=400)
        self.file_tree.column('Size', width=100)
        self.file_tree.column('Risk', width=100)
        self.file_tree.column('Type', width=100)
        
        # Scrollbar for tree
        tree_scroll = ttk.Scrollbar(browser_frame, orient="vertical", command=self.file_tree.yview)
        self.file_tree.configure(yscrollcommand=tree_scroll.set)
        
        self.file_tree.grid(row=0, column=0, sticky=tk.W+tk.E+tk.N+tk.S)
        tree_scroll.grid(row=0, column=1, sticky=tk.N+tk.S)
        
        # Bottom panel - Progress and logs
        progress_frame = ttk.LabelFrame(main_frame, text="Operation Progress", padding="10")
        progress_frame.grid(row=2, column=0, sticky=tk.W+tk.E+tk.N+tk.S, pady=(10, 0))
        progress_frame.columnconfigure(0, weight=1)
        
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(progress_frame, variable=self.progress_var, maximum=100)
        self.progress_bar.grid(row=0, column=0, sticky=tk.W+tk.E, pady=5)
        
        self.status_label = ttk.Label(progress_frame, text="Ready")
        self.status_label.grid(row=1, column=0, sticky=tk.W, pady=5)
        
        # Current directory label
        self.current_dir_label = ttk.Label(main_frame, text="No directory selected", 
                                         font=('Arial', 10, 'italic'))
        self.current_dir_label.grid(row=3, column=0, columnspan=2, pady=10)
        
    def browse_directory(self):
        """Browse and select a directory to analyze"""
        directory = filedialog.askdirectory(title="Select Directory to Analyze")
        if directory:
            self.current_directory = directory
            self.current_dir_label.config(text=f"Current Directory: {directory}")
            self.load_directory_files(directory)
            
    def load_directory_files(self, directory):
        """Load files from the selected directory into the tree view"""
        # Clear existing items
        for item in self.file_tree.get_children():
            self.file_tree.delete(item)
            
        try:
            files = self.file_manager.list_files(directory)
            for file_info in files:
                file_path = file_info['path']
                file_size = file_info['size']
                file_type = file_info['type']
                
                # Format size
                size_str = self.format_file_size(file_size) if file_size else ""
                
                # Insert into tree
                item_id = self.file_tree.insert('', 'end', 
                                              text=os.path.basename(file_path),
                                              values=(size_str, "", file_type))
                
                # Store full path in item
                self.file_tree.set(item_id, 'path', file_path)
                
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load directory: {str(e)}")
            
    def format_file_size(self, size_bytes):
        """Format file size in human readable format"""
        if size_bytes == 0:
            return "0 B"
        size_names = ["B", "KB", "MB", "GB", "TB"]
        import math
        i = int(math.floor(math.log(size_bytes, 1024)))
        p = math.pow(1024, i)
        s = round(size_bytes / p, 2)
        return f"{s} {size_names[i]}"
        
    def scan_sensitive_data(self):
        """Scan files for sensitive data using AI"""
        if not hasattr(self, 'current_directory'):
            messagebox.showwarning("Warning", "Please select a directory first")
            return
            
        def scan_thread():
            self.status_label.config(text="Scanning for sensitive data...")
            self.progress_var.set(0)
            
            try:
                # Get all files from tree
                total_items = len(self.file_tree.get_children())
                processed = 0
                
                for item_id in self.file_tree.get_children():
                    file_path = self.file_tree.set(item_id, 'path')
                    
                    # Skip directories
                    if os.path.isdir(file_path):
                        continue
                        
                    # Analyze file
                    risk_score = self.ai_detector.analyze_file(file_path)
                    
                    # Update tree with risk score
                    self.file_tree.set(item_id, 'Risk', f"{risk_score:.2f}")
                    
                    # Color code based on risk
                    if risk_score > 0.7:
                        self.file_tree.item(item_id, tags=('high_risk',))
                    elif risk_score > 0.4:
                        self.file_tree.item(item_id, tags=('medium_risk',))
                    else:
                        self.file_tree.item(item_id, tags=('low_risk',))
                    
                    processed += 1
                    progress = (processed / total_items) * 100
                    self.progress_var.set(progress)
                    
                    # Update UI
                    self.root.update_idletasks()
                    
                # Configure tag colors
                self.file_tree.tag_configure('high_risk', background='#e74c3c')
                self.file_tree.tag_configure('medium_risk', background='#f39c12')
                self.file_tree.tag_configure('low_risk', background='#27ae60')
                
                self.status_label.config(text="Sensitive data scan completed")
                self.progress_var.set(100)
                
            except Exception as e:
                messagebox.showerror("Error", f"Scan failed: {str(e)}")
                self.status_label.config(text="Scan failed")
                
        # Run scan in separate thread
        threading.Thread(target=scan_thread, daemon=True).start()
        
    def start_wipe(self):
        """Start the secure wipe process"""
        if not hasattr(self, 'current_directory'):
            messagebox.showwarning("Warning", "Please select a directory first")
            return
            
        # Get selected items
        selected_items = self.file_tree.selection()
        if not selected_items and self.method_var.get() == "selected":
            messagebox.showwarning("Warning", "Please select files to wipe")
            return
            
        # Confirmation dialog
        method = self.method_var.get()
        if method == "full_device":
            response = messagebox.askyesno("CRITICAL WARNING", 
                                         "This will PERMANENTLY DELETE ALL DATA on the device!\n"
                                         "This action CANNOT be undone!\n\n"
                                         "Are you absolutely sure you want to proceed?")
        else:
            file_count = len(selected_items)
            response = messagebox.askyesno("Confirmation", 
                                         f"This will permanently delete {file_count} selected file(s).\n"
                                         "This action cannot be undone!\n\n"
                                         "Do you want to proceed?")
        
        if not response:
            return
            
        def wipe_thread():
            try:
                self.status_label.config(text="Starting secure wipe...")
                self.progress_var.set(0)
                
                wipe_config = {
                    'passes': int(self.passes_var.get()),
                    'pattern': self.pattern_var.get(),
                    'method': self.method_var.get()
                }
                
                if method == "full_device":
                    # Full device wipe
                    result = self.wipe_engine.wipe_device(self.current_directory, wipe_config)
                else:
                    # Selected files wipe
                    files_to_wipe = []
                    for item_id in selected_items:
                        file_path = self.file_tree.set(item_id, 'path')
                        files_to_wipe.append(file_path)
                    
                    result = self.wipe_engine.wipe_files(files_to_wipe, wipe_config)
                
                # Generate certificate
                cert_data = self.cert_generator.generate_certificate(result)
                
                # Log operation
                self.audit_logger.log_operation("WIPE", result)
                
                self.status_label.config(text="Wipe completed successfully")
                self.progress_var.set(100)
                
                messagebox.showinfo("Success", 
                                  f"Secure wipe completed!\n"
                                  f"Certificate saved to: {cert_data['pdf_path']}")
                
                # Refresh file list
                if hasattr(self, 'current_directory'):
                    self.load_directory_files(self.current_directory)
                    
            except Exception as e:
                messagebox.showerror("Error", f"Wipe failed: {str(e)}")
                self.status_label.config(text="Wipe failed")
                
        # Run wipe in separate thread
        threading.Thread(target=wipe_thread, daemon=True).start()

def main():
    """Main application entry point"""
    root = tk.Tk()
    app = SecureWipeApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()