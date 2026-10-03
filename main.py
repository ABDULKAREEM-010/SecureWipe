#!/usr/bin/env python3
"""
Secure E-Waste Data Wiping Platform
Main entry point for the desktop application
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import customtkinter as ctk
import os
import threading
import queue
import shutil
import base64
import secrets
import hashlib
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
        self.root.geometry("1280x820")
        self.root.minsize(1020, 680)
        self.root.configure(bg="#0b1220")
        
        # Initialize components
        self.file_manager = FileManager()
        self.ai_detector = SensitiveDataDetector()
        self.wipe_engine = WipeEngine()
        self.cert_generator = CertificateGenerator()
        self.audit_logger = AuditLogger()
        
        # Selected files for wiping
        self.selected_files = []
        self.file_paths = {}
        self.ui_queue = queue.Queue()
        
        self.current_user = None
        self.setup_home()

    def setup_modern_ui(self):
        self.clear_screen()
        colors = {
            "bg": "#08111f", "surface": "#101d31", "surface_2": "#16263e",
            "border": "#233a59", "text": "#f5f7fb", "muted": "#8fa3bd",
            "mint": "#3de0c0", "mint_dark": "#126b68", "amber": "#f6b73c",
            "rose": "#ff6b86", "green": "#43d89d",
        }
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("dark-blue")
        self.root.configure(fg_color=colors["bg"])

        table_style = ttk.Style(self.root)
        try:
            table_style.theme_use("clam")
        except tk.TclError:
            pass
        table_style.configure("Modern.Treeview", background=colors["surface_2"], fieldbackground=colors["surface_2"], foreground=colors["text"], rowheight=38, borderwidth=0, font=("Segoe UI", 10))
        table_style.configure("Modern.Treeview.Heading", background=colors["border"], foreground=colors["muted"], relief="flat", font=("Segoe UI", 9, "bold"), padding=(10, 10))
        table_style.map("Modern.Treeview", background=[("selected", colors["mint_dark"])], foreground=[("selected", "#ffffff")])

        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        shell = ctk.CTkFrame(self.root, fg_color=colors["bg"], corner_radius=0)
        shell.grid(row=0, column=0, sticky="nsew", padx=28, pady=25)
        shell.columnconfigure(1, weight=1)
        shell.rowconfigure(1, weight=1)

        header = ctk.CTkFrame(shell, fg_color="transparent")
        header.grid(row=0, column=0, columnspan=2, sticky="ew", pady=(0, 22))
        header.columnconfigure(0, weight=1)
        ctk.CTkLabel(header, text="DATAWIPE / CONTROL CENTER", text_color=colors["mint"], font=("Segoe UI", 10, "bold"), anchor="w").grid(row=0, column=0, sticky="w")
        ctk.CTkLabel(header, text="Secure e-waste data wiping", text_color=colors["text"], font=("Segoe UI", 29, "bold"), anchor="w").grid(row=1, column=0, sticky="w", pady=(2, 2))
        ctk.CTkLabel(header, text="A clear, auditable path from discovery to certified destruction.", text_color=colors["muted"], font=("Segoe UI", 11), anchor="w").grid(row=2, column=0, sticky="w")
        ready = ctk.CTkFrame(header, fg_color=colors["surface"], border_color=colors["border"], border_width=1, corner_radius=18)
        ready.grid(row=1, column=1, rowspan=2, sticky="e", padx=(20, 0))
        ctk.CTkLabel(ready, text="●", text_color=colors["mint"], font=("Segoe UI", 12, "bold")).pack(side="left", padx=(13, 4), pady=9)
        ctk.CTkLabel(ready, text="SYSTEM READY", text_color=colors["text"], font=("Segoe UI", 9, "bold")).pack(side="left", padx=(0, 13), pady=9)
        initials = (self.current_user or {}).get("name", "U").strip()[:1].upper() or "U"
        self.profile_button = ctk.CTkButton(header, text=initials, command=self.show_profile_menu, width=42, height=42, corner_radius=21, fg_color=colors["mint_dark"], hover_color=colors["mint"], text_color="#ffffff", font=("Segoe UI", 14, "bold"))
        self.profile_button.grid(row=0, column=1, sticky="e")

        sidebar = ctk.CTkFrame(shell, fg_color=colors["surface"], border_color=colors["border"], border_width=1, corner_radius=18, width=290)
        sidebar.grid(row=1, column=0, sticky="nsew", padx=(0, 18))
        sidebar.grid_propagate(False)
        sidebar.columnconfigure(0, weight=1)
        ctk.CTkLabel(sidebar, text="WIPE WORKFLOW", text_color=colors["muted"], font=("Segoe UI", 10, "bold"), anchor="w").grid(row=0, column=0, sticky="w", padx=22, pady=(22, 4))
        ctk.CTkLabel(sidebar, text="Configure your operation", text_color=colors["text"], font=("Segoe UI", 17, "bold"), anchor="w").grid(row=1, column=0, sticky="w", padx=22)
        ctk.CTkLabel(sidebar, text="Every wipe produces a certificate and audit entry.", text_color=colors["muted"], font=("Segoe UI", 10), wraplength=240, justify="left", anchor="w").grid(row=2, column=0, sticky="w", padx=22, pady=(5, 20))
        ctk.CTkButton(sidebar, text="＋  Choose directory", command=self.browse_directory, height=42, corner_radius=10, fg_color=colors["surface_2"], hover_color=colors["border"], border_width=1, border_color=colors["border"], text_color=colors["text"], font=("Segoe UI", 11, "bold")).grid(row=3, column=0, sticky="ew", padx=22, pady=(0, 23))

        for row, label in ((4, "WIPE PASSES"), (6, "FILL PATTERN"), (8, "WIPE METHOD")):
            ctk.CTkLabel(sidebar, text=label, text_color=colors["muted"], font=("Segoe UI", 9, "bold"), anchor="w").grid(row=row, column=0, sticky="w", padx=22, pady=(0, 6))
        self.passes_var = tk.StringVar(value="3")
        ctk.CTkEntry(sidebar, textvariable=self.passes_var, height=38, corner_radius=9, fg_color=colors["surface_2"], border_color=colors["border"], text_color=colors["text"], font=("Segoe UI", 11)).grid(row=5, column=0, sticky="ew", padx=22, pady=(0, 14))
        self.pattern_var = tk.StringVar(value="random")
        ctk.CTkComboBox(sidebar, variable=self.pattern_var, values=["zero", "random", "dod"], height=38, corner_radius=9, fg_color=colors["surface_2"], border_color=colors["border"], button_color=colors["mint_dark"], button_hover_color=colors["mint"], dropdown_fg_color=colors["surface"], text_color=colors["text"], font=("Segoe UI", 11)).grid(row=7, column=0, sticky="ew", padx=22, pady=(0, 14))
        self.method_var = tk.StringVar(value="selected")
        ctk.CTkComboBox(sidebar, variable=self.method_var, values=["selected", "full_device"], height=38, corner_radius=9, fg_color=colors["surface_2"], border_color=colors["border"], button_color=colors["mint_dark"], button_hover_color=colors["mint"], dropdown_fg_color=colors["surface"], text_color=colors["text"], font=("Segoe UI", 11)).grid(row=9, column=0, sticky="ew", padx=22, pady=(0, 22))
        ctk.CTkLabel(sidebar, text="Wiping is permanent. Review every selection before starting.", text_color=colors["muted"], font=("Segoe UI", 9), wraplength=235, justify="left", anchor="w").grid(row=10, column=0, sticky="sw", padx=22, pady=(20, 22))

        workspace = ctk.CTkFrame(shell, fg_color=colors["surface"], border_color=colors["border"], border_width=1, corner_radius=18)
        workspace.grid(row=1, column=1, sticky="nsew")
        workspace.columnconfigure(0, weight=1)
        workspace.rowconfigure(3, weight=1)
        top = ctk.CTkFrame(workspace, fg_color="transparent")
        top.grid(row=0, column=0, sticky="ew", padx=22, pady=(20, 14))
        top.columnconfigure(0, weight=1)
        ctk.CTkLabel(top, text="File inventory", text_color=colors["text"], font=("Segoe UI", 18, "bold"), anchor="w").grid(row=0, column=0, sticky="w")
        self.selection_label = ctk.CTkLabel(top, text="0 selected", text_color=colors["mint"], font=("Segoe UI", 10, "bold"))
        self.selection_label.grid(row=0, column=1, sticky="e")
        ctk.CTkLabel(workspace, text="Select files to inspect, then scan for sensitive content before wiping.", text_color=colors["muted"], font=("Segoe UI", 10), anchor="w").grid(row=1, column=0, sticky="w", padx=22)
        action_bar = ctk.CTkFrame(workspace, fg_color="transparent")
        action_bar.grid(row=1, column=1, sticky="e", padx=(12, 22))
        ctk.CTkButton(action_bar, text="Scan files", command=self.scan_sensitive_data, width=118, height=34, corner_radius=9, fg_color=colors["surface_2"], hover_color=colors["border"], border_width=1, border_color=colors["border"], text_color=colors["text"], font=("Segoe UI", 10, "bold")).pack(side="left", padx=(0, 8))
        ctk.CTkButton(action_bar, text="Secure wipe  →", command=self.start_wipe, width=134, height=34, corner_radius=9, fg_color=colors["mint_dark"], hover_color=colors["mint"], text_color="#ffffff", font=("Segoe UI", 10, "bold")).pack(side="left")

        metrics = ctk.CTkFrame(workspace, fg_color="transparent")
        metrics.grid(row=2, column=0, sticky="ew", padx=22, pady=(16, 14))
        for column in range(3):
            metrics.columnconfigure(column, weight=1)
        self.file_count_var = tk.StringVar(value="0")
        self.risk_var = tk.StringVar(value="--")
        for column, label, variable, accent in ((0, "FILES DISCOVERED", self.file_count_var, colors["text"]), (1, "RISK ASSESSED", self.risk_var, colors["amber"]), (2, "OPERATION STATUS", None, colors["mint"])):
            card = ctk.CTkFrame(metrics, fg_color=colors["surface_2"], corner_radius=12)
            card.grid(row=0, column=column, sticky="ew", padx=(0 if column == 0 else 6, 6 if column < 2 else 0))
            ctk.CTkLabel(card, text=label, text_color=colors["muted"], font=("Segoe UI", 8, "bold"), anchor="w").pack(anchor="w", padx=14, pady=(11, 1))
            if variable is None:
                ctk.CTkLabel(card, text="READY", text_color=accent, font=("Segoe UI", 15, "bold"), anchor="w").pack(anchor="w", padx=14, pady=(0, 11))
            else:
                ctk.CTkLabel(card, textvariable=variable, text_color=accent, font=("Segoe UI", 15, "bold"), anchor="w").pack(anchor="w", padx=14, pady=(0, 11))

        table_frame = ctk.CTkFrame(workspace, fg_color=colors["surface_2"], corner_radius=12)
        table_frame.grid(row=3, column=0, sticky="nsew", padx=22, pady=(0, 14))
        table_frame.columnconfigure(0, weight=1)
        table_frame.rowconfigure(0, weight=1)
        self.file_tree = ttk.Treeview(table_frame, columns=("Size", "Risk", "Type"), show="tree headings", selectmode="extended", style="Modern.Treeview")
        for column, heading in (("#0", "FILE / DIRECTORY"), ("Size", "SIZE"), ("Risk", "RISK"), ("Type", "TYPE")):
            self.file_tree.heading(column, text=heading, anchor="w")
        self.file_tree.column("#0", width=360, minwidth=220, anchor="w")
        self.file_tree.column("Size", width=90, minwidth=70, anchor="w")
        self.file_tree.column("Risk", width=90, minwidth=70, anchor="w")
        self.file_tree.column("Type", width=150, minwidth=100, anchor="w")
        self.file_tree.tag_configure("high_risk", foreground=colors["rose"])
        self.file_tree.tag_configure("medium_risk", foreground=colors["amber"])
        self.file_tree.tag_configure("low_risk", foreground=colors["green"])
        self.file_tree.bind("<<TreeviewSelect>>", self.update_selection_summary)
        tree_scroll = ttk.Scrollbar(table_frame, orient="vertical", command=self.file_tree.yview)
        self.file_tree.configure(yscrollcommand=tree_scroll.set)
        self.file_tree.grid(row=0, column=0, sticky="nsew")
        tree_scroll.grid(row=0, column=1, sticky="ns")
        self.empty_state = ctk.CTkFrame(table_frame, fg_color=colors["surface_2"], corner_radius=0)
        self.empty_state.place(relx=0.5, rely=0.5, anchor="center")
        ctk.CTkLabel(self.empty_state, text="No directory selected", text_color=colors["text"], font=("Segoe UI", 16, "bold")).pack(pady=(18, 3))
        ctk.CTkLabel(self.empty_state, text="Choose a directory to populate your secure inventory.", text_color=colors["muted"], font=("Segoe UI", 10)).pack(pady=(0, 18))

        footer = ctk.CTkFrame(workspace, fg_color="transparent")
        footer.grid(row=4, column=0, sticky="ew", padx=22, pady=(0, 18))
        footer.columnconfigure(0, weight=1)
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ctk.CTkProgressBar(footer, variable=self.progress_var, height=8, corner_radius=4, fg_color=colors["border"], progress_color=colors["mint"])
        self.progress_bar.set(0)
        self.progress_bar.grid(row=0, column=0, sticky="ew", pady=(0, 8))
        self.status_label = ctk.CTkLabel(footer, text="Ready for a directory", text_color=colors["muted"], font=("Segoe UI", 9), anchor="w")
        self.status_label.grid(row=1, column=0, sticky="w")
        self.current_dir_label = ctk.CTkLabel(shell, text="No directory selected", text_color=colors["muted"], font=("Segoe UI", 9), anchor="w")
        self.current_dir_label.grid(row=2, column=0, columnspan=2, sticky="w", pady=(14, 0))

        self.root.after(50, self._process_ui_queue)

    def clear_screen(self):
        """Remove the current screen before navigating to another app view."""
        for widget in self.root.winfo_children():
            widget.destroy()

    def transition_to(self, target):
        """Fade between app screens, with a direct fallback for unsupported window managers."""
        try:
            def fade_out(alpha):
                if alpha <= 0.08:
                    target()
                    fade_in(0.08)
                    return
                self.root.attributes("-alpha", alpha)
                self.root.after(18, fade_out, alpha - 0.16)

            def fade_in(alpha):
                if alpha >= 1:
                    self.root.attributes("-alpha", 1.0)
                    return
                self.root.attributes("-alpha", alpha)
                self.root.after(18, fade_in, alpha + 0.16)

            fade_out(1.0)
        except tk.TclError:
            target()

    def show_profile_menu(self):
        """Show the current account and logout action beside the avatar."""
        if getattr(self, "profile_menu", None) and self.profile_menu.winfo_exists():
            self.profile_menu.destroy()
            return
        colors = {"surface": "#101d31", "surface_2": "#16263e", "border": "#233a59", "text": "#f5f7fb", "muted": "#8fa3bd", "mint": "#3de0c0"}
        self.profile_menu = ctk.CTkToplevel(self.root)
        self.profile_menu.title("Account")
        self.profile_menu.geometry("280x178")
        self.profile_menu.resizable(False, False)
        self.profile_menu.configure(fg_color=colors["surface"])
        self.profile_menu.transient(self.root)
        self.profile_menu.grab_set()
        user = self.current_user or {}
        ctk.CTkLabel(self.profile_menu, text=user.get("name", "SecureWipe user"), text_color=colors["text"], font=("Segoe UI", 13, "bold"), anchor="w").pack(fill="x", padx=20, pady=(18, 1))
        ctk.CTkLabel(self.profile_menu, text=user.get("email", ""), text_color=colors["muted"], font=("Segoe UI", 9), anchor="w").pack(fill="x", padx=20, pady=(0, 15))
        ctk.CTkButton(self.profile_menu, text="Log out", command=self.logout, height=36, corner_radius=8, fg_color=colors["surface_2"], hover_color=colors["border"], border_width=1, border_color=colors["border"], text_color=colors["mint"], font=("Segoe UI", 10, "bold")).pack(fill="x", padx=20, pady=(0, 18))

    def logout(self):
        """Close the account menu and return to the public homepage."""
        if getattr(self, "profile_menu", None) and self.profile_menu.winfo_exists():
            self.profile_menu.grab_release()
            self.profile_menu.destroy()
        self.current_user = None
        self.transition_to(self.setup_home)

    def setup_home(self):
        """Render the SecureWipe product homepage."""
        self.clear_screen()
        colors = {"bg": "#08111f", "surface": "#101d31", "surface_2": "#16263e", "border": "#233a59", "text": "#f5f7fb", "muted": "#8fa3bd", "mint": "#3de0c0", "mint_dark": "#126b68", "amber": "#f6b73c"}
        self.root.configure(fg_color=colors["bg"])
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        page = ctk.CTkFrame(self.root, fg_color=colors["bg"], corner_radius=0)
        page.grid(row=0, column=0, sticky="nsew", padx=48, pady=34)
        page.columnconfigure(0, weight=1)
        page.rowconfigure(2, weight=1)

        nav = ctk.CTkFrame(page, fg_color="transparent")
        nav.grid(row=0, column=0, sticky="ew", pady=(0, 52))
        nav.columnconfigure(0, weight=1)
        ctk.CTkLabel(nav, text="◈  SECUREWIPE", text_color=colors["mint"], font=("Segoe UI", 13, "bold"), anchor="w").grid(row=0, column=0, sticky="w")
        ctk.CTkLabel(nav, text="SECURE DATA DESTRUCTION / 01", text_color=colors["muted"], font=("Segoe UI", 9, "bold")).grid(row=0, column=1, sticky="e")

        hero = ctk.CTkFrame(page, fg_color="transparent")
        hero.grid(row=1, column=0, sticky="ew")
        hero.columnconfigure(0, weight=1)
        hero.columnconfigure(1, weight=1)
        ctk.CTkLabel(hero, text="Erase with confidence.\nProve it afterwards.", text_color=colors["text"], font=("Segoe UI", 43, "bold"), justify="left", anchor="w").grid(row=0, column=0, sticky="w")
        ctk.CTkLabel(hero, text="SecureWipe helps teams permanently remove sensitive data from retired devices and leave behind a verifiable chain of evidence.", text_color=colors["muted"], font=("Segoe UI", 14), wraplength=460, justify="left", anchor="w").grid(row=1, column=0, sticky="w", pady=(20, 0))
        ctk.CTkButton(hero, text="Get started  →", command=lambda: self.transition_to(self.setup_auth), width=190, height=48, corner_radius=10, fg_color=colors["mint_dark"], hover_color=colors["mint"], text_color="#ffffff", font=("Segoe UI", 12, "bold")).grid(row=2, column=0, sticky="w", pady=(28, 0))

        signal = ctk.CTkFrame(hero, fg_color=colors["surface"], border_color=colors["border"], border_width=1, corner_radius=18)
        signal.grid(row=0, column=1, rowspan=3, sticky="e", padx=(60, 0))
        ctk.CTkLabel(signal, text="RETIREMENT CONTROL", text_color=colors["mint"], font=("Segoe UI", 10, "bold"), anchor="w").pack(anchor="w", padx=26, pady=(25, 6))
        ctk.CTkLabel(signal, text="From discovery\nto certificate", text_color=colors["text"], font=("Segoe UI", 25, "bold"), justify="left", anchor="w").pack(anchor="w", padx=26)
        ctk.CTkLabel(signal, text="01  Scan sensitive files\n02  Overwrite selected data\n03  Download proof of destruction", text_color=colors["muted"], font=("Segoe UI", 11), justify="left", anchor="w").pack(anchor="w", padx=26, pady=(18, 25))

        benefits = ctk.CTkFrame(page, fg_color="transparent")
        benefits.grid(row=2, column=0, sticky="sew", pady=(62, 0))
        for column in range(3):
            benefits.columnconfigure(column, weight=1)
        cards = (("01", "Detect what matters", "Regex and optional AI analysis surface sensitive files before they leave your control."), ("02", "Destroy permanently", "Use configurable overwrite passes and patterns for selected files or a complete directory."), ("03", "Keep defensible proof", "Every operation produces a signed certificate and an audit trail for your records."))
        for column, (number, title, body) in enumerate(cards):
            card = ctk.CTkFrame(benefits, fg_color=colors["surface"], border_color=colors["border"], border_width=1, corner_radius=14)
            card.grid(row=0, column=column, sticky="nsew", padx=(0 if column == 0 else 7, 7 if column < 2 else 0))
            ctk.CTkLabel(card, text=number, text_color=colors["amber"], font=("Segoe UI", 11, "bold"), anchor="w").pack(anchor="w", padx=20, pady=(20, 10))
            ctk.CTkLabel(card, text=title, text_color=colors["text"], font=("Segoe UI", 15, "bold"), anchor="w").pack(anchor="w", padx=20)
            ctk.CTkLabel(card, text=body, text_color=colors["muted"], font=("Segoe UI", 10), wraplength=270, justify="left", anchor="w").pack(anchor="w", padx=20, pady=(7, 20))

    def setup_auth(self):
        """Render the local sign-in and account creation screen."""
        self.clear_screen()
        colors = {"bg": "#08111f", "surface": "#101d31", "surface_2": "#16263e", "border": "#233a59", "text": "#f5f7fb", "muted": "#8fa3bd", "mint": "#3de0c0", "mint_dark": "#126b68", "rose": "#ff6b86"}
        self.auth_mode = getattr(self, "auth_mode", "signin")
        self.root.configure(fg_color=colors["bg"])
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        page = ctk.CTkFrame(self.root, fg_color=colors["bg"], corner_radius=0)
        page.grid(row=0, column=0, sticky="nsew")
        card = ctk.CTkFrame(page, fg_color=colors["surface"], border_color=colors["border"], border_width=1, corner_radius=18, width=440)
        card.place(relx=0.5, rely=0.5, anchor="center")
        card.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(card, text="◈  SECUREWIPE", text_color=colors["mint"], font=("Segoe UI", 12, "bold")).grid(row=0, column=0, sticky="w", padx=38, pady=(34, 8))
        self.auth_title = ctk.CTkLabel(card, text="Welcome back", text_color=colors["text"], font=("Segoe UI", 25, "bold"), anchor="w")
        self.auth_title.grid(row=1, column=0, sticky="w", padx=38)
        self.auth_subtitle = ctk.CTkLabel(card, text="Sign in to access your secure wipe workspace.", text_color=colors["muted"], font=("Segoe UI", 10), anchor="w")
        self.auth_subtitle.grid(row=2, column=0, sticky="w", padx=38, pady=(5, 22))
        switch = ctk.CTkFrame(card, fg_color=colors["surface_2"], corner_radius=9)
        switch.grid(row=3, column=0, sticky="ew", padx=38, pady=(0, 18))
        switch.grid_columnconfigure(0, weight=1)
        switch.grid_columnconfigure(1, weight=1)
        ctk.CTkButton(switch, text="Sign in", command=lambda: self.set_auth_mode("signin"), height=34, corner_radius=7, fg_color=colors["mint_dark"] if self.auth_mode == "signin" else "transparent", hover_color=colors["border"], text_color=colors["text"], font=("Segoe UI", 10, "bold")).grid(row=0, column=0, sticky="ew", padx=3, pady=3)
        ctk.CTkButton(switch, text="Create account", command=lambda: self.set_auth_mode("signup"), height=34, corner_radius=7, fg_color=colors["mint_dark"] if self.auth_mode == "signup" else "transparent", hover_color=colors["border"], text_color=colors["text"], font=("Segoe UI", 10, "bold")).grid(row=0, column=1, sticky="ew", padx=3, pady=3)
        self.name_label = ctk.CTkLabel(card, text="NAME", text_color=colors["muted"], font=("Segoe UI", 9, "bold"), anchor="w")
        self.name_label.grid(row=4, column=0, sticky="w", padx=38, pady=(0, 5))
        self.name_entry = ctk.CTkEntry(card, height=40, corner_radius=9, fg_color=colors["surface_2"], border_color=colors["border"], text_color=colors["text"], placeholder_text="Your name")
        self.name_entry.grid(row=5, column=0, sticky="ew", padx=38, pady=(0, 14))
        ctk.CTkLabel(card, text="EMAIL", text_color=colors["muted"], font=("Segoe UI", 9, "bold"), anchor="w").grid(row=6, column=0, sticky="w", padx=38, pady=(0, 5))
        self.email_entry = ctk.CTkEntry(card, height=40, corner_radius=9, fg_color=colors["surface_2"], border_color=colors["border"], text_color=colors["text"], placeholder_text="you@company.com")
        self.email_entry.grid(row=7, column=0, sticky="ew", padx=38, pady=(0, 14))
        ctk.CTkLabel(card, text="PASSWORD", text_color=colors["muted"], font=("Segoe UI", 9, "bold"), anchor="w").grid(row=8, column=0, sticky="w", padx=38, pady=(0, 5))
        self.password_entry = ctk.CTkEntry(card, height=40, corner_radius=9, fg_color=colors["surface_2"], border_color=colors["border"], text_color=colors["text"], placeholder_text="At least 8 characters", show="•")
        self.password_entry.grid(row=9, column=0, sticky="ew", padx=38, pady=(0, 8))
        self.auth_error = ctk.CTkLabel(card, text="", text_color=colors["rose"], font=("Segoe UI", 9), anchor="w", wraplength=350)
        self.auth_error.grid(row=10, column=0, sticky="w", padx=38, pady=(0, 8))
        self.auth_button = ctk.CTkButton(card, text="Sign in  →", command=self.authenticate, height=44, corner_radius=9, fg_color=colors["mint_dark"], hover_color=colors["mint"], text_color="#ffffff", font=("Segoe UI", 11, "bold") )
        self.auth_button.grid(row=11, column=0, sticky="ew", padx=38, pady=(0, 12))
        ctk.CTkButton(card, text="← Back to homepage", command=lambda: self.transition_to(self.setup_home), height=30, fg_color="transparent", hover_color=colors["surface_2"], text_color=colors["muted"], font=("Segoe UI", 10)).grid(row=12, column=0, pady=(0, 28))
        self.set_auth_mode(self.auth_mode)

    def set_auth_mode(self, mode):
        """Switch between sign-in and local account creation."""
        self.auth_mode = mode
        is_signup = mode == "signup"
        self.auth_title.configure(text="Create your workspace" if is_signup else "Welcome back")
        self.auth_subtitle.configure(text="Create a local account to begin wiping securely." if is_signup else "Sign in to access your secure wipe workspace.")
        self.auth_button.configure(text="Create account  →" if is_signup else "Sign in  →")
        if is_signup:
            self.name_label.grid()
            self.name_entry.grid()
        else:
            self.name_label.grid_remove()
            self.name_entry.grid_remove()
        self.auth_error.configure(text="")

    def _users_path(self):
        users_dir = Path.home() / ".secure_wipe"
        users_dir.mkdir(mode=0o700, exist_ok=True)
        return users_dir / "users.json"

    def _load_users(self):
        try:
            with open(self._users_path(), "r", encoding="utf-8") as file:
                return json.load(file)
        except (FileNotFoundError, json.JSONDecodeError):
            return {}

    def _hash_password(self, password, salt=None):
        salt_bytes = base64.b64decode(salt) if salt else secrets.token_bytes(16)
        digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt_bytes, 180000)
        return base64.b64encode(salt_bytes).decode(), base64.b64encode(digest).decode()

    def authenticate(self):
        """Create or verify a local account before entering the wipe workspace."""
        email = self.email_entry.get().strip().lower()
        password = self.password_entry.get()
        users = self._load_users()
        if "@" not in email or "." not in email:
            self.auth_error.configure(text="Enter a valid email address.")
            return
        if len(password) < 8:
            self.auth_error.configure(text="Password must be at least 8 characters.")
            return
        if self.auth_mode == "signup":
            name = self.name_entry.get().strip()
            if not name:
                self.auth_error.configure(text="Enter your name to create an account.")
                return
            if email in users:
                self.auth_error.configure(text="An account with this email already exists.")
                return
            salt, password_hash = self._hash_password(password)
            users[email] = {"name": name, "salt": salt, "password_hash": password_hash}
            with open(self._users_path(), "w", encoding="utf-8") as file:
                json.dump(users, file, indent=2)
            self.current_user = {"email": email, "name": name}
        else:
            user = users.get(email)
            if not user:
                self.auth_error.configure(text="No local account was found for this email.")
                return
            _, password_hash = self._hash_password(password, user["salt"])
            if not secrets.compare_digest(password_hash, user["password_hash"]):
                self.auth_error.configure(text="The email or password is incorrect.")
                return
            self.current_user = {"email": email, "name": user.get("name", email)}
        self.transition_to(self.setup_modern_ui)

    def update_selection_summary(self, _event=None):
        selected_count = len(self.file_tree.selection())
        self.selection_label.configure(text=f"{selected_count} selected")

    def show_certificate(self, certificate, wipe_result):
        """Display the generated certificate and offer a PDF download."""
        dialog = ctk.CTkToplevel(self.root)
        dialog.title("Wipe certificate")
        dialog.geometry("620x560")
        dialog.minsize(560, 500)
        dialog.configure(fg_color="#08111f")
        dialog.transient(self.root)
        dialog.grab_set()
        dialog.columnconfigure(0, weight=1)
        dialog.rowconfigure(2, weight=1)

        ctk.CTkLabel(dialog, text="WIPE COMPLETE", text_color="#3de0c0", font=("Segoe UI", 10, "bold"), anchor="w").grid(row=0, column=0, sticky="w", padx=28, pady=(26, 4))
        ctk.CTkLabel(dialog, text="Certificate of secure destruction", text_color="#f5f7fb", font=("Segoe UI", 23, "bold"), anchor="w").grid(row=1, column=0, sticky="w", padx=28)

        certificate_data = certificate.get("certificate_data", {})
        results = certificate_data.get("results", {})
        configuration = certificate_data.get("configuration", {})
        details = (
            f"Certificate ID\n{certificate.get('certificate_id', 'Unavailable')}\n\n"
            f"Issued\n{certificate_data.get('timestamp', 'Unavailable')}\n\n"
            f"Files securely destroyed\n{results.get('files_processed', len(wipe_result.get('files_processed', [])))}\n\n"
            f"Failed files\n{results.get('files_failed', len(wipe_result.get('files_failed', [])))}\n\n"
            f"Method\n{configuration.get('method', wipe_result.get('config', {}).get('method', 'selected'))}\n\n"
            f"Pattern / passes\n{configuration.get('pattern', 'unknown')} / {configuration.get('passes', 0)}\n\n"
            "This certificate is digitally signed and available as a PDF."
        )
        details_box = ctk.CTkTextbox(dialog, height=290, corner_radius=12, fg_color="#16263e", border_width=1, border_color="#233a59", text_color="#dce6f2", font=("Segoe UI", 11), wrap="word")
        details_box.grid(row=2, column=0, sticky="nsew", padx=28, pady=(20, 16))
        details_box.insert("1.0", details)
        details_box.configure(state="disabled")

        actions = ctk.CTkFrame(dialog, fg_color="transparent")
        actions.grid(row=3, column=0, sticky="e", padx=28, pady=(0, 24))
        ctk.CTkButton(actions, text="Close", command=dialog.destroy, width=100, height=40, corner_radius=9, fg_color="#16263e", hover_color="#233a59", border_width=1, border_color="#233a59", text_color="#f5f7fb", font=("Segoe UI", 10, "bold")).pack(side="left", padx=(0, 10))
        ctk.CTkButton(actions, text="Download certificate PDF", command=lambda: self.download_certificate(certificate, dialog), width=210, height=40, corner_radius=9, fg_color="#126b68", hover_color="#3de0c0", text_color="#ffffff", font=("Segoe UI", 10, "bold")).pack(side="left")

    def download_certificate(self, certificate, dialog):
        """Copy the generated PDF certificate to a user-selected location."""
        source_path = certificate.get("pdf_path")
        if not source_path or not os.path.exists(source_path):
            messagebox.showerror("Download failed", "The generated certificate PDF could not be found.", parent=dialog)
            return

        destination = filedialog.asksaveasfilename(
            parent=dialog,
            title="Save wipe certificate",
            initialfile=f"{certificate.get('certificate_id', 'wipe_certificate')}.pdf",
            defaultextension=".pdf",
            filetypes=[("PDF certificate", "*.pdf"), ("All files", "*.*")],
        )
        if not destination:
            return

        try:
            shutil.copy2(source_path, destination)
            messagebox.showinfo("Certificate downloaded", f"Certificate saved to:\n{destination}", parent=dialog)
        except OSError as error:
            messagebox.showerror("Download failed", f"Could not save the certificate:\n{error}", parent=dialog)

    def _run_on_ui(self, callback, *args, **kwargs):
        """Queue a callback for execution on Tk's main thread."""
        self.ui_queue.put((callback, args, kwargs))

    def _process_ui_queue(self):
        """Run queued worker updates without touching Tk from background threads."""
        try:
            while True:
                callback, args, kwargs = self.ui_queue.get_nowait()
                callback(*args, **kwargs)
        except queue.Empty:
            pass
        except tk.TclError:
            return
        self.root.after(50, self._process_ui_queue)
        
    def setup_ui(self):
        """Setup the main user interface"""
        colors = {
            "navy": "#0b1220", "panel": "#111c2f", "panel_light": "#17243a",
            "line": "#263650", "text": "#f6f8fb", "muted": "#9ba9bd",
            "teal": "#2dd4bf", "teal_dark": "#0f766e", "orange": "#f59e0b",
            "red": "#fb7185", "green": "#34d399",
        }
        style = ttk.Style(self.root)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure("App.TFrame", background=colors["navy"])
        style.configure("Panel.TFrame", background=colors["panel"])
        style.configure("Title.TLabel", background=colors["navy"], foreground=colors["text"], font=("Segoe UI", 22, "bold"))
        style.configure("Subtitle.TLabel", background=colors["navy"], foreground=colors["muted"], font=("Segoe UI", 10))
        style.configure("PanelTitle.TLabel", background=colors["panel"], foreground=colors["text"], font=("Segoe UI", 12, "bold"))
        style.configure("PanelText.TLabel", background=colors["panel"], foreground=colors["muted"], font=("Segoe UI", 9))
        style.configure("Field.TLabel", background=colors["panel"], foreground=colors["muted"], font=("Segoe UI", 9, "bold"))
        style.configure("Status.TLabel", background=colors["panel_light"], foreground=colors["muted"], font=("Segoe UI", 9))
        style.configure("Primary.TButton", background=colors["teal_dark"], foreground="#ffffff", borderwidth=0, padding=(14, 10), font=("Segoe UI", 10, "bold"))
        style.map("Primary.TButton", background=[("active", colors["teal"]), ("pressed", colors["teal"])])
        style.configure("Secondary.TButton", background=colors["panel_light"], foreground=colors["text"], borderwidth=0, padding=(12, 9), font=("Segoe UI", 9, "bold"))
        style.map("Secondary.TButton", background=[("active", colors["line"]), ("pressed", colors["line"])])
        style.configure("App.TCombobox", fieldbackground=colors["panel_light"], background=colors["panel_light"], foreground=colors["text"], arrowcolor=colors["teal"], padding=6)
        style.configure("App.TSpinbox", fieldbackground=colors["panel_light"], background=colors["panel_light"], foreground=colors["text"], arrowcolor=colors["teal"], padding=6)
        style.configure("App.Horizontal.TProgressbar", background=colors["teal"], troughcolor=colors["line"], borderwidth=0, thickness=8)
        style.configure("Treeview", background=colors["panel_light"], fieldbackground=colors["panel_light"], foreground=colors["text"], rowheight=34, borderwidth=0, font=("Segoe UI", 9))
        style.configure("Treeview.Heading", background=colors["line"], foreground=colors["muted"], relief="flat", font=("Segoe UI", 9, "bold"), padding=(8, 9))
        style.map("Treeview", background=[("selected", colors["teal_dark"])], foreground=[("selected", "#ffffff")])

        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame = ttk.Frame(self.root, style="App.TFrame", padding=(28, 24))
        main_frame.grid(row=0, column=0, sticky="nsew")
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(1, weight=1)

        header = ttk.Frame(main_frame, style="App.TFrame")
        header.grid(row=0, column=0, columnspan=2, sticky="ew", pady=(0, 22))
        header.columnconfigure(0, weight=1)
        ttk.Label(header, text="SECURE WIPE", style="Subtitle.TLabel").grid(row=0, column=0, sticky="w")
        ttk.Label(header, text="Secure E-Waste Data Wiping Platform", style="Title.TLabel").grid(row=1, column=0, sticky="w", pady=(2, 3))
        ttk.Label(header, text="Inspect sensitive files, erase them with confidence, and keep a verifiable record.", style="Subtitle.TLabel").grid(row=2, column=0, sticky="w")
        ttk.Label(header, text="●  SYSTEM READY", background=colors["navy"], foreground=colors["teal"], font=("Segoe UI", 9, "bold")).grid(row=1, column=1, rowspan=2, sticky="e")

        sidebar = ttk.Frame(main_frame, style="Panel.TFrame", padding=20)
        sidebar.grid(row=1, column=0, sticky="nsew", padx=(0, 18))
        sidebar.columnconfigure(0, weight=1)
        ttk.Label(sidebar, text="Wipe configuration", style="PanelTitle.TLabel").grid(row=0, column=0, sticky="w")
        ttk.Label(sidebar, text="Choose how the selected data should be overwritten.", style="PanelText.TLabel", wraplength=245).grid(row=1, column=0, sticky="w", pady=(5, 20))
        ttk.Button(sidebar, text="Browse directory", command=self.browse_directory, style="Secondary.TButton").grid(row=2, column=0, sticky="ew", pady=(0, 22))
        ttk.Label(sidebar, text="WIPE PASSES", style="Field.TLabel").grid(row=3, column=0, sticky="w", pady=(0, 5))
        self.passes_var = tk.StringVar(value="3")
        ttk.Spinbox(sidebar, from_=1, to=35, textvariable=self.passes_var, style="App.TSpinbox").grid(row=4, column=0, sticky="ew", pady=(0, 16))
        ttk.Label(sidebar, text="FILL PATTERN", style="Field.TLabel").grid(row=5, column=0, sticky="w", pady=(0, 5))
        self.pattern_var = tk.StringVar(value="random")
        ttk.Combobox(sidebar, textvariable=self.pattern_var, values=["zero", "random", "dod"], state="readonly", style="App.TCombobox").grid(row=6, column=0, sticky="ew", pady=(0, 16))
        ttk.Label(sidebar, text="WIPE METHOD", style="Field.TLabel").grid(row=7, column=0, sticky="w", pady=(0, 5))
        self.method_var = tk.StringVar(value="selected")
        ttk.Combobox(sidebar, textvariable=self.method_var, values=["selected", "full_device"], state="readonly", style="App.TCombobox").grid(row=8, column=0, sticky="ew", pady=(0, 22))
        ttk.Button(sidebar, text="Scan for sensitive data", command=self.scan_sensitive_data, style="Secondary.TButton").grid(row=9, column=0, sticky="ew", pady=(0, 10))
        ttk.Button(sidebar, text="Start secure wipe", command=self.start_wipe, style="Primary.TButton").grid(row=10, column=0, sticky="ew")
        ttk.Label(sidebar, text="Wiping is permanent. Review your selection before starting.", style="PanelText.TLabel", wraplength=245).grid(row=11, column=0, sticky="sw", pady=(28, 0))

        workspace = ttk.Frame(main_frame, style="Panel.TFrame", padding=20)
        workspace.grid(row=1, column=1, sticky="nsew")
        workspace.columnconfigure(0, weight=1)
        workspace.rowconfigure(2, weight=1)
        ttk.Label(workspace, text="File inventory", style="PanelTitle.TLabel").grid(row=0, column=0, sticky="w")
        ttk.Label(workspace, text="Select files to inspect or securely erase.", style="PanelText.TLabel").grid(row=1, column=0, sticky="w", pady=(5, 14))
        table_frame = ttk.Frame(workspace, style="Panel.TFrame")
        table_frame.grid(row=2, column=0, sticky="nsew")
        table_frame.columnconfigure(0, weight=1)
        table_frame.rowconfigure(0, weight=1)
        self.file_tree = ttk.Treeview(table_frame, columns=("Size", "Risk", "Type"), show="tree headings", selectmode="extended")
        self.file_tree.heading("#0", text="FILE / DIRECTORY", anchor="w")
        self.file_tree.heading("Size", text="SIZE", anchor="w")
        self.file_tree.heading("Risk", text="RISK", anchor="w")
        self.file_tree.heading("Type", text="TYPE", anchor="w")
        self.file_tree.column("#0", width=360, minwidth=220, anchor="w")
        self.file_tree.column("Size", width=90, minwidth=70, anchor="w")
        self.file_tree.column("Risk", width=90, minwidth=70, anchor="w")
        self.file_tree.column("Type", width=150, minwidth=100, anchor="w")
        self.file_tree.tag_configure("high_risk", foreground=colors["red"])
        self.file_tree.tag_configure("medium_risk", foreground=colors["orange"])
        self.file_tree.tag_configure("low_risk", foreground=colors["green"])
        tree_scroll = ttk.Scrollbar(table_frame, orient="vertical", command=self.file_tree.yview)
        self.file_tree.configure(yscrollcommand=tree_scroll.set)
        self.file_tree.grid(row=0, column=0, sticky="nsew")
        tree_scroll.grid(row=0, column=1, sticky="ns")

        progress_frame = ttk.Frame(workspace, style="Panel.TFrame")
        progress_frame.grid(row=3, column=0, sticky="ew", pady=(18, 0))
        progress_frame.columnconfigure(0, weight=1)
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(progress_frame, variable=self.progress_var, maximum=100, style="App.Horizontal.TProgressbar")
        self.progress_bar.grid(row=0, column=0, sticky="ew", pady=(0, 9))
        self.status_label = ttk.Label(progress_frame, text="Ready for a directory", style="Status.TLabel")
        self.status_label.grid(row=1, column=0, sticky="w")

        self.current_dir_label = ttk.Label(main_frame, text="No directory selected", style="Subtitle.TLabel")
        self.current_dir_label.grid(row=2, column=0, columnspan=2, sticky="w", pady=(16, 0))
        
    def browse_directory(self):
        """Browse and select a directory to analyze"""
        directory = filedialog.askdirectory(title="Select Directory to Analyze")
        if directory:
            self.current_directory = directory
            self.current_dir_label.configure(text=f"Current Directory: {directory}")
            self.load_directory_files(directory)
            
    def load_directory_files(self, directory):
        """Load files from the selected directory into the tree view"""
        # Clear existing items
        for item in self.file_tree.get_children():
            self.file_tree.delete(item)
        self.file_paths.clear()
            
        try:
            files = self.file_manager.list_files(directory)
            self.file_count_var.set(str(len(files)))
            if files:
                self.empty_state.place_forget()
            else:
                self.empty_state.place(relx=0.5, rely=0.5, anchor="center")
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
                
                # Treeview columns are display-only; keep the absolute path separately.
                self.file_paths[item_id] = file_path
                
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

        item_ids = list(self.file_tree.get_children())
        file_paths = {item_id: self.file_paths.get(item_id) for item_id in item_ids}
            
        def scan_thread():
            self._run_on_ui(self.status_label.configure, text="Scanning for sensitive data...")
            self._run_on_ui(self.progress_var.set, 0)
            
            try:
                total_items = len(item_ids)
                processed = 0
                high_risk = 0

                if not total_items:
                    self._run_on_ui(self.status_label.configure, text="No files found to scan")
                    self._run_on_ui(self.progress_var.set, 1)
                    return
                
                for item_id in item_ids:
                    file_path = file_paths.get(item_id)
                    if not file_path:
                        continue
                    
                    # Skip directories
                    if os.path.isdir(file_path):
                        continue
                        
                    # Analyze file
                    risk_score = self.ai_detector.analyze_file(file_path)
                    if risk_score > 0.7:
                        high_risk += 1
                        risk_tag = 'high_risk'
                    elif risk_score > 0.4:
                        risk_tag = 'medium_risk'
                    else:
                        risk_tag = 'low_risk'

                    self._run_on_ui(self.file_tree.set, item_id, 'Risk', f"{risk_score:.2f}")
                    self._run_on_ui(self.file_tree.item, item_id, tags=(risk_tag,))
                    processed += 1
                    progress = (processed / total_items) * 100
                    self._run_on_ui(self.progress_var.set, progress / 100)
                    self._run_on_ui(self.risk_var.set, f"{high_risk} high risk")
                    
                self._run_on_ui(self.status_label.configure, text="Sensitive data scan completed")
                self._run_on_ui(self.progress_var.set, 1)
                
            except Exception as e:
                self._run_on_ui(messagebox.showerror, "Error", f"Scan failed: {str(e)}")
                self._run_on_ui(self.status_label.configure, text="Scan failed")
                
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

        try:
            wipe_config = {
                'passes': int(self.passes_var.get()),
                'pattern': self.pattern_var.get(),
                'method': method
            }
        except (TypeError, ValueError) as error:
            messagebox.showerror("Invalid configuration", f"Wipe settings are invalid: {error}")
            return
            
        def wipe_thread():
            try:
                self._run_on_ui(self.status_label.configure, text="Starting secure wipe...")
                self._run_on_ui(self.progress_var.set, 0)
                
                if method == "full_device":
                    # Full device wipe
                    result = self.wipe_engine.wipe_device(self.current_directory, wipe_config)
                else:
                    # Selected files wipe
                    files_to_wipe = []
                    for item_id in selected_items:
                        file_path = self.file_paths.get(item_id)
                        if file_path:
                            files_to_wipe.append(file_path)
                    
                    result = self.wipe_engine.wipe_files(files_to_wipe, wipe_config)
                
                # Generate certificate
                cert_data = self.cert_generator.generate_certificate(result)
                
                # Log operation
                self.audit_logger.log_operation("WIPE", result)
                
                self._run_on_ui(self.status_label.configure, text="Wipe completed successfully")
                self._run_on_ui(self.progress_var.set, 1)
                self._run_on_ui(self.show_certificate, cert_data, result)
                if hasattr(self, 'current_directory'):
                    self._run_on_ui(self.load_directory_files, self.current_directory)
                    
            except Exception as e:
                self._run_on_ui(messagebox.showerror, "Error", f"Wipe failed: {str(e)}")
                self._run_on_ui(self.status_label.configure, text="Wipe failed")
                
        # Run wipe in separate thread
        threading.Thread(target=wipe_thread, daemon=True).start()

def main():
    """Main application entry point"""
    root = ctk.CTk()
    app = SecureWipeApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()