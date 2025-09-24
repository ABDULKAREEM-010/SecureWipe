#!/usr/bin/env python3
"""
Secure E-Waste Data Wiping Platform - Portable Version
This standalone application can access real files on your computer
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import os
import sys
import threading
from pathlib import Path
import json
from datetime import datetime
import platform

# Add the src directory to the path for imports
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

# Import our modules with error handling
try:
    from file_manager import FileManager
    from ai_detector import SensitiveDataDetector
    from wipe_engine import WipeEngine
    from audit_logger import AuditLogger
except ImportError as e:
    print(f"Error importing modules: {e}")
    print("Please ensure all required files are in the 'src' directory")
    sys.exit(1)

# Import certificate generator with graceful fallback
try:
    from certificate_generator import CertificateGenerator
    CERTIFICATES_AVAILABLE = True
except ImportError as e:
    print(f"Certificate generation disabled: {e}")
    CERTIFICATES_AVAILABLE = False
    CertificateGenerator = None

class PortableSecureWipeApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure E-Waste Data Wiping Platform - Portable")
        self.root.geometry("1400x900")
        self.root.configure(bg='#2c3e50')
        
        # Initialize components
        self.file_manager = FileManager()
        self.ai_detector = SensitiveDataDetector()
        self.wipe_engine = WipeEngine()
        self.audit_logger = AuditLogger()
        
        # Initialize certificate generator if available
        if CERTIFICATES_AVAILABLE:
            try:
                self.cert_generator = CertificateGenerator()
            except Exception as e:
                print(f"Certificate generator initialization failed: {e}")
                self.cert_generator = None
        else:
            self.cert_generator = None
        
        # Selected files for wiping
        self.selected_files = []
        self.current_directory = None
        
        self.setup_ui()
        self.show_startup_info()
        
    def setup_ui(self):
        """Setup the main user interface"""
        # Main container
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=tk.W+tk.E+tk.N+tk.S)
        
        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(3, weight=1)
        
        # Title and system info
        title_frame = ttk.Frame(main_frame)
        title_frame.grid(row=0, column=0, columnspan=3, pady=(0, 10), sticky=tk.W+tk.E)
        
        title_label = ttk.Label(title_frame, text="Secure E-Waste Data Wiping Platform", 
                               font=('Arial', 16, 'bold'))
        title_label.grid(row=0, column=0, sticky=tk.W)
        
        # System info
        system_info = f"Platform: {platform.system()} {platform.release()} | Python: {platform.python_version()}"
        system_label = ttk.Label(title_frame, text=system_info, font=('Arial', 8))
        system_label.grid(row=1, column=0, sticky=tk.W)
        
        # Status indicators
        status_frame = ttk.Frame(title_frame)
        status_frame.grid(row=0, column=1, sticky=tk.E)
        
        # AI status
        ai_status = "🟢 AI Detection" if self.ai_detector.openai_available else "🟡 Regex Only"
        ai_label = ttk.Label(status_frame, text=ai_status)
        ai_label.grid(row=0, column=0, padx=5)
        
        # Certificate status
        cert_status = "🟢 Certificates" if self.cert_generator else "🔴 Cert Disabled"
        cert_label = ttk.Label(status_frame, text=cert_status)
        cert_label.grid(row=0, column=1, padx=5)
        
        # Warning banner
        warning_frame = ttk.LabelFrame(main_frame, text="⚠️ IMPORTANT WARNING", padding="10")
        warning_frame.grid(row=1, column=0, columnspan=3, pady=(0, 10), sticky=tk.W+tk.E)
        warning_frame.configure(style='Warning.TLabelframe')
        
        warning_text = ("This application performs PERMANENT data deletion on your real computer files. "
                       "Deleted files CANNOT be recovered. Always backup important data before proceeding.")
        warning_label = ttk.Label(warning_frame, text=warning_text, foreground='red', 
                                 font=('Arial', 10, 'bold'), wraplength=800)
        warning_label.grid(row=0, column=0)
        
        # Left panel - Controls
        controls_frame = ttk.LabelFrame(main_frame, text="Wipe Configuration", padding="10")
        controls_frame.grid(row=2, column=0, sticky=tk.W+tk.E+tk.N+tk.S, padx=(0, 10))
        
        # Browse directory button
        ttk.Button(controls_frame, text="📁 Browse Your Computer", 
                  command=self.browse_directory).grid(row=0, column=0, sticky=tk.W+tk.E, pady=5)
        
        # Current directory display
        self.current_dir_label = ttk.Label(controls_frame, text="No directory selected", 
                                         font=('Arial', 9, 'italic'), wraplength=200)
        self.current_dir_label.grid(row=1, column=0, sticky=tk.W, pady=5)
        
        # Wipe options
        ttk.Label(controls_frame, text="Wipe Passes:", font=('Arial', 10, 'bold')).grid(row=2, column=0, sticky=tk.W, pady=(15,5))
        self.passes_var = tk.StringVar(value="3")
        passes_spinbox = ttk.Spinbox(controls_frame, from_=1, to=35, textvariable=self.passes_var, width=15)
        passes_spinbox.grid(row=3, column=0, sticky=tk.W+tk.E, pady=5)
        
        ttk.Label(controls_frame, text="Fill Pattern:", font=('Arial', 10, 'bold')).grid(row=4, column=0, sticky=tk.W, pady=(10,5))
        self.pattern_var = tk.StringVar(value="random")
        pattern_combo = ttk.Combobox(controls_frame, textvariable=self.pattern_var, 
                                   values=["zero", "random", "dod"], state="readonly")
        pattern_combo.grid(row=5, column=0, sticky=tk.W+tk.E, pady=5)
        
        ttk.Label(controls_frame, text="Wipe Method:", font=('Arial', 10, 'bold')).grid(row=6, column=0, sticky=tk.W, pady=(10,5))
        self.method_var = tk.StringVar(value="selected")
        method_combo = ttk.Combobox(controls_frame, textvariable=self.method_var,
                                  values=["selected", "full_directory"], state="readonly")
        method_combo.grid(row=7, column=0, sticky=tk.W+tk.E, pady=5)
        
        # Action buttons
        ttk.Button(controls_frame, text="🔍 Scan for Sensitive Data", 
                  command=self.scan_sensitive_data).grid(row=8, column=0, sticky=tk.W+tk.E, pady=(20,10))
        
        ttk.Button(controls_frame, text="🗑️ Start Secure Wipe", 
                  command=self.start_wipe).grid(row=9, column=0, sticky=tk.W+tk.E, pady=5)
        
        # Help button
        ttk.Button(controls_frame, text="❓ Help & Info", 
                  command=self.show_help).grid(row=10, column=0, sticky=tk.W+tk.E, pady=(20,5))
        
        # Right panel - File browser
        browser_frame = ttk.LabelFrame(main_frame, text="Your Computer Files", padding="10")
        browser_frame.grid(row=2, column=1, rowspan=2, sticky=tk.W+tk.E+tk.N+tk.S)
        browser_frame.columnconfigure(0, weight=1)
        browser_frame.rowconfigure(0, weight=1)
        
        # File tree with path storage
        self.file_tree = ttk.Treeview(browser_frame, columns=('Path', 'Size', 'Risk', 'Type'), show='tree headings')
        self.file_tree.heading('#0', text='File/Directory')
        self.file_tree.heading('Path', text='Full Path')
        self.file_tree.heading('Size', text='Size')
        self.file_tree.heading('Risk', text='Risk Score')
        self.file_tree.heading('Type', text='Type')
        
        # Configure column widths (hide Path column but keep data)
        self.file_tree.column('#0', width=500)
        self.file_tree.column('Path', width=0, stretch=False)  # Hidden but stores data
        self.file_tree.column('Size', width=100)
        self.file_tree.column('Risk', width=100)
        self.file_tree.column('Type', width=150)
        
        # Scrollbar for tree
        tree_scroll = ttk.Scrollbar(browser_frame, orient="vertical", command=self.file_tree.yview)
        self.file_tree.configure(yscrollcommand=tree_scroll.set)
        
        self.file_tree.grid(row=0, column=0, sticky=tk.W+tk.E+tk.N+tk.S)
        tree_scroll.grid(row=0, column=1, sticky=tk.N+tk.S)
        
        # Bottom panel - Progress and logs
        progress_frame = ttk.LabelFrame(main_frame, text="Operation Progress", padding="10")
        progress_frame.grid(row=3, column=0, sticky=tk.W+tk.E+tk.N+tk.S, pady=(10, 0))
        progress_frame.columnconfigure(0, weight=1)
        
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(progress_frame, variable=self.progress_var, maximum=100)
        self.progress_bar.grid(row=0, column=0, sticky=tk.W+tk.E, pady=5)
        
        self.status_label = ttk.Label(progress_frame, text="Ready to scan your computer files")
        self.status_label.grid(row=1, column=0, sticky=tk.W, pady=5)
        
    def show_startup_info(self):
        """Show startup information to user"""
        info_msg = (
            "🖥️ DESKTOP FILE ACCESS ENABLED 🖥️\n\n"
            "This application can now access real files on your computer.\n\n"
            "FEATURES:\n"
            f"• AI Detection: {'✅ Available' if self.ai_detector.openai_available else '⚠️ Using regex only'}\n"
            f"• Certificates: {'✅ Available' if self.cert_generator else '⚠️ Disabled (missing dependencies)'}\n"
            "• Secure Wiping: ✅ Available\n"
            "• Audit Logging: ✅ Available\n\n"
            "SAFETY FEATURES:\n"
            "• System file protection\n"
            "• Multiple confirmation dialogs\n"
            "• Secure overwrite patterns\n"
            "• Real-time progress tracking\n\n"
            "Click 'Browse Your Computer' to start!"
        )
        
        messagebox.showinfo("Secure Wipe - Ready", info_msg)
        
    def browse_directory(self):
        """Browse and select a directory from the user's actual computer"""
        # Start from user's home directory
        initial_dir = str(Path.home())
        
        directory = filedialog.askdirectory(
            title="Select Directory to Analyze (YOUR COMPUTER)", 
            initialdir=initial_dir
        )
        
        if directory:
            self.current_directory = directory
            self.current_dir_label.config(text=f"📁 {directory}")
            self.status_label.config(text=f"Loading files from: {directory}")
            self.load_directory_files(directory)
            
    def load_directory_files(self, directory):
        """Load files from the selected directory into the tree view"""
        # Clear existing items
        for item in self.file_tree.get_children():
            self.file_tree.delete(item)
            
        def load_files_thread():
            def update_ui(func):
                """Thread-safe UI update wrapper"""
                self.root.after(0, func)
            try:
                update_ui(lambda: self.status_label.config(text="Scanning directory..."))
                files = self.file_manager.list_files(directory, recursive=False)
                
                total_files = len(files)
                update_ui(lambda: self.status_label.config(text=f"Found {total_files} files/directories"))
                
                for i, file_info in enumerate(files):
                    file_path = file_info['path']
                    file_size = file_info['size']
                    file_type = file_info['type']
                    
                    # Format size
                    size_str = self.format_file_size(file_size) if file_size else "Directory"
                    
                    # Determine icon based on type
                    if os.path.isdir(file_path):
                        icon = "📁"
                    elif file_info.get('is_text', False):
                        icon = "📄"
                    else:
                        icon = "📋"
                    
                    # Insert into tree with path in values (thread-safe)
                    display_name = f"{icon} {os.path.basename(file_path)}"
                    def insert_item():
                        return self.file_tree.insert('', 'end', 
                                                    text=display_name,
                                                    values=(file_path, size_str, "", file_type))
                    update_ui(insert_item)
                    
                    # Update progress (thread-safe)
                    if i % 10 == 0:  # Update every 10 files to avoid UI freeze
                        progress = (i / total_files) * 100
                        update_ui(lambda: self.progress_var.set(progress))
                
                update_ui(lambda: self.progress_var.set(100))
                update_ui(lambda: self.status_label.config(text=f"Loaded {total_files} items from your computer"))
                
            except Exception as e:
                update_ui(lambda: messagebox.showerror("Error", f"Failed to load directory: {str(e)}"))
                update_ui(lambda: self.status_label.config(text="Failed to load directory"))
                
        # Run in separate thread to avoid UI freeze
        threading.Thread(target=load_files_thread, daemon=True).start()
            
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
        if not self.current_directory:
            messagebox.showwarning("Warning", "Please select a directory first")
            return
            
        def scan_thread():
            def update_ui(func):
                """Thread-safe UI update wrapper"""
                self.root.after(0, func)
            update_ui(lambda: self.status_label.config(text="Scanning for sensitive data on your computer..."))
            update_ui(lambda: self.progress_var.set(0))
            
            try:
                # Get all files from tree
                items = self.file_tree.get_children()
                total_items = len(items)
                processed = 0
                
                for item_id in items:
                    file_path = self.file_tree.item(item_id)['values'][0]  # Get path from first column
                    
                    # Skip directories
                    if os.path.isdir(file_path):
                        processed += 1
                        continue
                        
                    # Analyze file
                    risk_score = self.ai_detector.analyze_file(file_path)
                    
                    # Update tree with risk score - need to update full values tuple
                    current_values = list(self.file_tree.item(item_id)['values'])
                    current_values[2] = f"{risk_score:.2f}"  # Risk is 3rd column (index 2)
                    self.file_tree.item(item_id, values=current_values)
                    
                    # Color code based on risk
                    if risk_score > 0.7:
                        self.file_tree.item(item_id, tags=('high_risk',))
                    elif risk_score > 0.4:
                        self.file_tree.item(item_id, tags=('medium_risk',))
                    else:
                        self.file_tree.item(item_id, tags=('low_risk',))
                    
                    processed += 1
                    progress = (processed / total_items) * 100
                    update_ui(lambda: self.progress_var.set(progress))
                    
                # Configure tag colors
                self.file_tree.tag_configure('high_risk', background='#ffe6e6')
                self.file_tree.tag_configure('medium_risk', background='#fff3cd')
                self.file_tree.tag_configure('low_risk', background='#e6f4ea')
                
                update_ui(lambda: self.status_label.config(text="Sensitive data scan completed on your files"))
                update_ui(lambda: self.progress_var.set(100))
                
                # Show summary
                high_risk_files = len([item for item in items if 'high_risk' in self.file_tree.item(item)['tags']])
                messagebox.showinfo("Scan Complete", 
                                  f"Scan completed!\n"
                                  f"High-risk files found: {high_risk_files}\n"
                                  f"Files analyzed: {processed}")
                
            except Exception as e:
                messagebox.showerror("Error", f"Scan failed: {str(e)}")
                update_ui(lambda: self.status_label.config(text="Scan failed"))
                
        # Run scan in separate thread
        threading.Thread(target=scan_thread, daemon=True).start()
        
    def is_safe_directory(self, directory_path):
        """Check if directory is safe to wipe"""
        dangerous_paths = [
            # Windows system paths
            'C:\\Windows', 'C:\\Program Files', 'C:\\Program Files (x86)',
            'C:\\System32', 'C:\\Boot', 'C:\\Recovery',
            # Linux/Mac system paths  
            '/bin', '/sbin', '/usr', '/etc', '/boot', '/sys', '/proc', '/dev', '/root', '/var',
            # Common application paths
            '/Applications', 'C:\\ProgramData'
        ]
        
        abs_path = os.path.abspath(directory_path)
        for dangerous in dangerous_paths:
            if abs_path.startswith(dangerous):
                return False
        return True
    
    def start_wipe(self):
        """Start the secure wipe process on real files"""
        if not self.current_directory:
            messagebox.showwarning("Warning", "Please select a directory first")
            return
            
        # Safety check for dangerous directories
        if not self.is_safe_directory(self.current_directory):
            messagebox.showerror("Safety Error", 
                               f"Cannot wipe system directory: {self.current_directory}\n"
                               "This location contains critical system files.")
            return
            
        # Get selected items
        selected_items = self.file_tree.selection()
        if not selected_items and self.method_var.get() == "selected":
            messagebox.showwarning("Warning", "Please select files to wipe")
            return
            
        # Show detailed confirmation with file paths
        method = self.method_var.get()
        if method == "full_directory":
            response = messagebox.askyesno(
                "🚨 CRITICAL WARNING - DIRECTORY WIPE",
                f"This will PERMANENTLY DELETE ALL FILES in:\n{self.current_directory}\n\n"
                "⚠️ THIS ACTION CANNOT BE UNDONE! ⚠️\n"
                "All files in this directory will be destroyed forever.\n\n"
                "Type 'DELETE ALL' in the next dialog to confirm."
            )
            if not response:
                return
                
            # Additional typed confirmation for directory wipe
            from tkinter import simpledialog
            confirmation = simpledialog.askstring("Final Confirmation", 
                                                 "Type 'DELETE ALL' to confirm directory wipe:")
            if confirmation != "DELETE ALL":
                messagebox.showinfo("Cancelled", "Operation cancelled.")
                return
                
        else:
            file_count = len(selected_items)
            file_list = []
            for item_id in selected_items:
                file_path = self.file_tree.item(item_id)['values'][0]  # Get path from first column
                file_list.append(os.path.basename(file_path))
            
            file_names = '\n'.join(file_list[:10])  # Show first 10 files
            if len(file_list) > 10:
                file_names += f"\n... and {len(file_list) - 10} more files"
                
            response = messagebox.askyesno(
                "⚠️ Confirm File Deletion", 
                f"This will permanently delete {file_count} selected file(s):\n\n"
                f"{file_names}\n\n"
                "This action cannot be undone!\n\n"
                "Do you want to proceed?"
            )
        
        if not response:
            return
            
        def wipe_thread():
            def update_ui(func):
                """Thread-safe UI update wrapper"""
                self.root.after(0, func)
            try:
                update_ui(lambda: self.status_label.config(text="Starting secure wipe on your files..."))
                update_ui(lambda: self.progress_var.set(0))
                
                wipe_config = {
                    'passes': int(self.passes_var.get()),
                    'pattern': self.pattern_var.get(),
                    'method': self.method_var.get()
                }
                
                if method == "full_directory":
                    # Full directory wipe (using wipe_device for directory)
                    result = self.wipe_engine.wipe_device(self.current_directory, wipe_config)
                else:
                    # Selected files wipe
                    files_to_wipe = []
                    for item_id in selected_items:
                        file_path = self.file_tree.item(item_id)['values'][0]  # Get path from first column
                        if os.path.isfile(file_path):  # Only wipe files, not directories
                            files_to_wipe.append(file_path)
                    
                    result = self.wipe_engine.wipe_files(files_to_wipe, wipe_config)
                
                # Generate certificate if available
                if self.cert_generator:
                    try:
                        cert_data = self.cert_generator.generate_certificate(result)
                        cert_info = f"\nCertificate saved to: {cert_data['pdf_path']}"
                    except Exception as e:
                        cert_info = f"\nCertificate generation failed: {e}"
                else:
                    cert_info = "\nCertificate generation not available"
                
                # Log operation
                self.audit_logger.log_operation("WIPE", result)
                
                update_ui(lambda: self.status_label.config(text="Secure wipe completed successfully"))
                update_ui(lambda: self.progress_var.set(100))
                
                update_ui(lambda: messagebox.showinfo("Success", 
                                            f"Secure wipe completed!\n"
                                            f"Files processed: {len(result.get('files_processed', []))}\n"
                                            f"Files failed: {len(result.get('files_failed', []))}"
                                            f"{cert_info}"))
                
                # Refresh file list
                if self.current_directory and os.path.exists(self.current_directory):
                    self.load_directory_files(self.current_directory)
                    
            except Exception as e:
                update_ui(lambda: messagebox.showerror("Error", f"Wipe failed: {str(e)}"))
                update_ui(lambda: self.status_label.config(text="Wipe failed"))
                
        # Run wipe in separate thread
        threading.Thread(target=wipe_thread, daemon=True).start()
    
    def show_help(self):
        """Show help information"""
        help_text = """
🔒 SECURE E-WASTE DATA WIPING PLATFORM 🔒

PURPOSE:
This application securely deletes files from your computer using military-grade overwriting techniques.

HOW TO USE:
1. Click 'Browse Your Computer' to select a directory
2. Click 'Scan for Sensitive Data' to identify risky files
3. Select files in the file browser (or choose full directory)
4. Configure wipe settings (passes, pattern, method)
5. Click 'Start Secure Wipe' to permanently delete files

WIPE PATTERNS:
• Zero: Overwrites with zeros (fastest)
• Random: Overwrites with random data (secure)
• DoD: DoD 5220.22-M standard (most secure)

SAFETY FEATURES:
• System file protection
• Multiple confirmation dialogs
• Scope restrictions
• Audit logging

⚠️ IMPORTANT: Deleted files cannot be recovered!
        """
        
        messagebox.showinfo("Help & Information", help_text)

def main():
    """Main application entry point"""
    # Check Python version
    if sys.version_info < (3, 7):
        print("Error: Python 3.7 or higher is required")
        sys.exit(1)
    
    # Create main window
    root = tk.Tk()
    
    # Set application icon (if available)
    try:
        # You can add an icon file here
        # root.iconbitmap('icon.ico')
        pass
    except:
        pass
    
    # Create and run application
    app = PortableSecureWipeApp(root)
    
    # Handle window close
    def on_closing():
        if messagebox.askokcancel("Quit", "Do you want to quit the Secure Wipe application?"):
            root.destroy()
    
    root.protocol("WM_DELETE_WINDOW", on_closing)
    
    # Start the application
    root.mainloop()

if __name__ == "__main__":
    main()