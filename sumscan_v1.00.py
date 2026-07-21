#!/usr/bin/env python3

"""
===================================================================
Project Name : SumScan - Advanced Security & Reconnaissance Suite
Author       : Sumon Mahmud
GitHub       : https://github.com/creationbd5
Contact      : connect.sumon.mahmud@gmail.com
License      : MIT License
Description  : High-performance CustomTkinter GUI utility for 
               network diagnostics, web directory enumeration, 
               and OSINT reconnaissance.
===================================================================
"""

import os
import io
import socket
import time
import json
import sqlite3
import urllib.request
import urllib.parse
import threading
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import customtkinter as ctk

# Optional External Libraries
try:
    import dns.resolver
    HAS_DNSPYTHON = True
except Exception:
    HAS_DNSPYTHON = False

try:
    from PIL import Image, ImageTk, ImageSequence
    HAS_PIL = True
except ImportError:
    HAS_PIL = False

ctk.set_appearance_mode("Dark")

# UI Base Theme Colors (Pure Dark Black Aesthetic)
BG_DARK = "#000000"         # Pure Black
CARD_BG = "#050505"         # Deep Dark Surface
BORDER_COLOR = "#121824"     # Subtle Border
CYAN_ACCENT = "#38BDF8"
PURPLE_ACCENT = "#A855F7"
GREEN_ACCENT = "#22C55E"
RED_ACCENT = "#EF4444"
YELLOW_ACCENT = "#EAB308"

# Remote Asset Links
URL_LOGO_MAIN = "https://drive.google.com/uc?export=download&id=1qMedAAFeKVLzQMxQ6RM15dtQewxm6U7k"
URL_LOGO_KALI = "https://drive.google.com/uc?export=download&id=1BfsNdiXvOKxnHNE_Jq9hCvm5Cmov2zA6"
URL_SCAN_ANIMATION = "https://drive.google.com/uc?export=download&id=1nvQyWEMN2h1VwcQ8kvvKQuUafciTZdDn"

# Known Local Kali / SecLists Wordlist Paths
COMMON_WORDLIST_PATHS = [
    "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt",
    "/usr/share/seclists/Discovery/Web-Content/common.txt",
    "/usr/share/wordlists/dirb/common.txt"
]

# Comprehensive Directory Enumeration Wordlist
DEFAULT_DIRECTORIES = [
    "index.php", "index.asp", "index.aspx", "index.html", "index.htm", "default.php",
    "default.asp", "default.aspx", "home.php", "home.asp", "home.aspx", "main.php",
    "main.asp", "main.aspx", "about.php", "about.asp", "about.aspx", "contact.php",
    "contact.asp", "contact.aspx", "search.php", "search.asp", "search.aspx", "login.php",
    "login.asp", "login.aspx", "signin.php", "signin.asp", "signin.aspx", "logout.php",
    "logout.asp", "logout.aspx", "register.php", "register.asp", "register.aspx",
    "signup.php", "signup.asp", "signup.aspx", "account.php", "account.asp", "account.aspx",
    "profile.php", "profile.asp", "profile.aspx", "forgot-password.php", "reset-password.php",
    "admin", "admin/", "admin.php", "admin.asp", "admin.aspx", "administrator",
    "administrator/", "dashboard", "dashboard/", "dashboard.php", "dashboard.asp",
    "dashboard.aspx", "panel", "panel/", "panel.php", "controlpanel", "controlpanel/",
    "controlpanel.php", "api", "api/", "api/v1", "api/v1/", "api/v2", "api/v2/",
    "api/index.php", "api/login.php", "api/auth.php", "api/users.php", "api/user.php",
    "api/status.php", "api/data.php", "api/docs", "api/swagger.json", "api/openapi.json",
    "api.json", "api.xml", "rest", "rest/", "graphql", "graphql/", "graphql.php",
    "webapi", "webapi/", "service", "services", "data.json", "config.json", "settings.json",
    "manifest.json", "package.json", "composer.json", "users.json", "user.json",
    "status.json", "health.json", "version.json", "swagger.json", "openapi.json",
    "appsettings.json", "data.xml", "config.xml", "settings.xml", "sitemap.xml",
    "feed.xml", "rss.xml", "users.xml", "status.xml", "crossdomain.xml", "clientaccesspolicy.xml",
    "config.php", "settings.php", "database.php", "db.php", "connect.php", "connection.php",
    "functions.php", "header.php", "footer.php", "users.php", "user.php", "upload.php",
    "download.php", "status.php", "health.php", "info.php", "config.asp", "settings.asp",
    "database.asp", "db.asp", "users.asp", "user.asp", "upload.asp", "download.asp",
    "config.aspx", "settings.aspx", "database.aspx", "db.aspx", "users.aspx", "user.aspx",
    "upload.aspx", "download.aspx", "Global.asax", "web.config", "app.js", "main.js",
    "index.js", "bundle.js", "config.js", "settings.js", "api.js", "auth.js", "login.js",
    "admin.js", "dashboard.js", "runtime.js", "vendor.js", "robots.txt", "security.txt",
    ".well-known/security.txt", "README.md", "readme.txt", "CHANGELOG.md", "version.txt",
    "license.txt", "swagger-ui", "swagger-ui/", "docs", "docs/", "documentation",
    "documentation/", "account", "accounts", "user", "users", "profile", "uploads",
    "upload", "downloads", "download", "files", "assets", "static", "public",
    "includes", "inc", "scripts", "js", "css", "images", "img", "media", "test",
    "dev", "staging", "beta", "health", "healthcheck", "status", "ping", "version",
    "metrics", "monitor", "monitoring"
]


class SumScanApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("SUMSCAN - Web & Network Security Recon Suite")
        
        # Exact Dimensions matching screenshot floating aspect ratio
        self.default_width = 1040
        self.default_height = 620
        self.minsize(960, 580)
        self.configure(fg_color=BG_DARK)

        # Center Window on Launch
        self.center_window_on_screen()

        # Engine State Variables
        self.is_scanning = False
        self.stop_requested = False
        self.is_maximized = False
        self.anim_step = 0
        self.open_count = 0
        self.closed_count = 0
        self.start_time = None
        self.anim_frames = []
        self.anim_idx = 0

        self._init_db()

        self.img_logo = None
        self.img_kali = None
        self._load_logos_auto()

        self._build_ui()

        # Keyboard Shortcut & State Bindings
        self.bind("<F11>", lambda e: self.toggle_maximize())
        self.bind("<Configure>", self._on_window_configure)

        # Download and optimize scan GIF asset in background
        threading.Thread(target=self._load_scan_animation_asset, daemon=True).start()

    # -------------------------------------------------------------
    # WINDOW POSITIONING & RESTORE HANDLERS
    # -------------------------------------------------------------
    def center_window_on_screen(self):
        """Center application window precisely on screen based on display resolution"""
        self.update_idletasks()
        
        screen_width = self.winfo_screenwidth()
        screen_height = self.winfo_screenheight()

        x_coordinate = int((screen_width / 2) - (self.default_width / 2))
        y_coordinate = int((screen_height / 2) - (self.default_height / 2))

        self.geometry(f"{self.default_width}x{self.default_height}+{x_coordinate}+{y_coordinate}")

    def toggle_maximize(self):
        """Explicit Maximize / Restore Down toggle"""
        try:
            if self.is_maximized or self.state() == "zoomed":
                self.state("normal")
                self.center_window_on_screen()
                self.is_maximized = False
            else:
                self.state("zoomed")
                self.is_maximized = True
        except Exception:
            if not self.is_maximized:
                sw = self.winfo_screenwidth()
                sh = self.winfo_screenheight()
                self.geometry(f"{sw}x{sh}+0+0")
                self.is_maximized = True
            else:
                self.center_window_on_screen()
                self.is_maximized = False

    def _on_window_configure(self, event):
        """Detect OS Titlebar Restore Down events"""
        if event.widget == self:
            current_state = self.state()
            if current_state == "normal" and self.is_maximized:
                self.is_maximized = False

    # -------------------------------------------------------------
    # DATABASE MANAGEMENT
    # -------------------------------------------------------------
    def _init_db(self):
        self.conn = sqlite3.connect("sumscan_history.db", check_same_thread=False)
        self.cursor = self.conn.cursor()
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                target TEXT,
                scan_mode TEXT,
                open_ports INTEGER,
                closed_ports INTEGER,
                duration TEXT
            )
        """)
        self.conn.commit()

    def _save_scan_history(self, target, scan_mode, open_p, closed_p, duration):
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.cursor.execute("""
            INSERT INTO scan_history (timestamp, target, scan_mode, open_ports, closed_ports, duration)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (now, target, scan_mode, open_p, closed_p, duration))
        self.conn.commit()

    # -------------------------------------------------------------
    # ASSET LOADER & FAST GIF PROCESSSOR
    # -------------------------------------------------------------
    def _download_and_load_image(self, url, filename, size_tuple):
        if not HAS_PIL:
            return None
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=3) as resp:
                img_bytes = resp.read()
                with open(filename, "wb") as f:
                    f.write(img_bytes)
                pil_img = Image.open(io.BytesIO(img_bytes))
                return ctk.CTkImage(light_image=pil_img, dark_image=pil_img, size=size_tuple)
        except Exception:
            if os.path.exists(filename):
                try:
                    pil_img = Image.open(filename)
                    return ctk.CTkImage(light_image=pil_img, dark_image=pil_img, size=size_tuple)
                except Exception:
                    pass
            return None

    def _load_logos_auto(self):
        self.img_logo = self._download_and_load_image(URL_LOGO_MAIN, "logo.png", (120, 120))
        self.img_kali = self._download_and_load_image(URL_LOGO_KALI, "kali.png", (100, 75))

    def _load_scan_animation_asset(self):
        """Download and optimize GIF frames for fast low-memory playback"""
        if not HAS_PIL:
            return
        try:
            req = urllib.request.Request(URL_SCAN_ANIMATION, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=5) as resp:
                img_bytes = resp.read()
                
                pil_gif = Image.open(io.BytesIO(img_bytes))
                frames = []
                for frame in ImageSequence.Iterator(pil_gif):
                    f_resized = frame.copy().convert("RGBA").resize((100, 75), Image.Resampling.LANCZOS)
                    frames.append(ctk.CTkImage(light_image=f_resized, dark_image=f_resized, size=(100, 75)))
                self.anim_frames = frames
        except Exception:
            pass

    # -------------------------------------------------------------
    # UI CONSTRUCTION
    # -------------------------------------------------------------
    def _build_ui(self):
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # 1. SIDEBAR
        sidebar = ctk.CTkFrame(self, width=200, corner_radius=12, fg_color=CARD_BG, border_color=BORDER_COLOR, border_width=1)
        sidebar.grid(row=0, column=0, padx=(10, 5), pady=10, sticky="nsew")
        sidebar.grid_rowconfigure(3, weight=1)

        logo_box = ctk.CTkFrame(sidebar, fg_color="transparent")
        logo_box.pack(pady=(12, 8))

        if self.img_logo:
            ctk.CTkLabel(logo_box, image=self.img_logo, text="").pack()
        else:
            ctk.CTkLabel(logo_box, text="SUMSCAN", font=ctk.CTkFont(size=20, weight="bold"), text_color=CYAN_ACCENT).pack()

        nav_frame = ctk.CTkFrame(sidebar, fg_color="transparent")
        nav_frame.pack(fill="x", padx=10, pady=5)

        self.btn_nav_scanner = ctk.CTkButton(nav_frame, text="🎯 SCAN ENGINE", fg_color="#0284C7", hover_color="#0369A1", font=ctk.CTkFont(size=12, weight="bold"), anchor="w", height=36)
        self.btn_nav_scanner.pack(fill="x", pady=3)

        self.btn_nav_history = ctk.CTkButton(nav_frame, text="🕒 SCAN HISTORY", fg_color="transparent", hover_color="#121824", font=ctk.CTkFont(size=12, weight="bold"), text_color="#94A3B8", anchor="w", height=36, command=self.show_history_popup)
        self.btn_nav_history.pack(fill="x", pady=3)

        self.btn_nav_about = ctk.CTkButton(nav_frame, text="ℹ ABOUT", fg_color="transparent", hover_color="#121824", font=ctk.CTkFont(size=12, weight="bold"), text_color="#94A3B8", anchor="w", height=36, command=self.show_about_popup)
        self.btn_nav_about.pack(fill="x", pady=3)

        # Bottom Kali Logo / Active Animation Box
        kali_box = ctk.CTkFrame(sidebar, fg_color="#020203", border_color=BORDER_COLOR, border_width=1, corner_radius=10)
        kali_box.pack(side="bottom", fill="x", padx=10, pady=10)

        self.lbl_kali = ctk.CTkLabel(kali_box, image=self.img_kali, text="")
        if not self.img_kali:
            self.lbl_kali.configure(text="KALI LINUX", font=ctk.CTkFont(size=13, weight="bold"), text_color=PURPLE_ACCENT)
        self.lbl_kali.pack(pady=(8, 2))

        ctk.CTkLabel(kali_box, text="PENETRATION TESTING SUITE", font=ctk.CTkFont(size=8, weight="bold"), text_color="#64748B").pack(pady=(0, 8))

        # 2. MAIN WORKSPACE
        main_area = ctk.CTkFrame(self, fg_color="transparent")
        main_area.grid(row=0, column=1, padx=(5, 10), pady=10, sticky="nsew")
        main_area.grid_columnconfigure(0, weight=3)
        main_area.grid_columnconfigure(1, weight=2)
        main_area.grid_rowconfigure(2, weight=1)

        header_frame = ctk.CTkFrame(main_area, fg_color="transparent")
        header_frame.grid(row=0, column=0, columnspan=2, sticky="ew", pady=(0, 6))

        ctk.CTkLabel(header_frame, text="SUMSCAN - Security Diagnostic Suite", font=ctk.CTkFont(size=14, weight="bold"), text_color="#F8FAFC").pack(side="left")

        # Dynamic Pulse Indicator Label
        self.lbl_live_indicator = ctk.CTkLabel(header_frame, text="● ENGINE READY", font=ctk.CTkFont(size=11, weight="bold"), text_color=GREEN_ACCENT)
        self.lbl_live_indicator.pack(side="left", padx=15)

        self.btn_restore = ctk.CTkButton(header_frame, text="🗖 Restore / Maximize (F11)", fg_color="#121824", hover_color="#1E293B", font=ctk.CTkFont(size=10, weight="bold"), width=150, height=24, command=self.toggle_maximize)
        self.btn_restore.pack(side="right", padx=5)

        # 2A. CONFIGURATION CARD
        self.config_card = ctk.CTkFrame(main_area, fg_color=CARD_BG, corner_radius=12, border_color=BORDER_COLOR, border_width=1)
        self.config_card.grid(row=1, column=0, sticky="nsew", padx=(0, 5), pady=4, ipady=4)

        ctk.CTkLabel(self.config_card, text="SCAN CONFIGURATION", font=ctk.CTkFont(size=11, weight="bold"), text_color=CYAN_ACCENT).grid(row=0, column=0, columnspan=2, sticky="w", padx=12, pady=(8, 6))

        # Target Field
        ctk.CTkLabel(self.config_card, text="Target Host / URL", font=ctk.CTkFont(size=10), text_color="#94A3B8").grid(row=1, column=0, sticky="w", padx=12)
        self.entry_target = ctk.CTkEntry(self.config_card, fg_color="#000000", border_color=BORDER_COLOR, font=ctk.CTkFont(size=11), placeholder_text="e.g. example.com or 192.168.1.1")
        self.entry_target.grid(row=2, column=0, sticky="ew", padx=(12, 4), pady=(2, 4))

        # Scan Mode Option Menu
        ctk.CTkLabel(self.config_card, text="Scan Mode", font=ctk.CTkFont(size=10), text_color="#94A3B8").grid(row=1, column=1, sticky="w", padx=12)
        self.combo_scan_type = ctk.CTkOptionMenu(
            self.config_card, 
            values=[
                "TCP Fast Connect Scan", 
                "Web Directory Enumeration (SecLists)",
                "Urlscan.io Threat Search & Intel",
                "Subdomain Finder (OSINT)",
                "Social Media & Footprint Recon",
                "Web & Tech Stack Recon", 
                "DNS Resolver & Enumeration", 
                "WHOIS Lookup", 
                "Shodan Public Host Info"
            ],
            fg_color="#000000", button_color=BORDER_COLOR, font=ctk.CTkFont(size=11)
        )
        self.combo_scan_type.grid(row=2, column=1, sticky="ew", padx=(4, 12), pady=(2, 4))

        ctk.CTkLabel(self.config_card, text="Start Port", font=ctk.CTkFont(size=10), text_color="#94A3B8").grid(row=3, column=0, sticky="w", padx=12)
        self.entry_start_port = ctk.CTkEntry(self.config_card, fg_color="#000000", border_color=BORDER_COLOR, font=ctk.CTkFont(size=11))
        self.entry_start_port.insert(0, "1")
        self.entry_start_port.grid(row=4, column=0, sticky="ew", padx=(12, 4), pady=(2, 4))

        ctk.CTkLabel(self.config_card, text="End Port / Wordlist Path", font=ctk.CTkFont(size=10), text_color="#94A3B8").grid(row=3, column=1, sticky="w", padx=12)
        self.entry_wordlist = ctk.CTkEntry(self.config_card, fg_color="#000000", border_color=BORDER_COLOR, font=ctk.CTkFont(size=11))
        self.entry_wordlist.insert(0, "1024")
        self.entry_wordlist.grid(row=4, column=1, sticky="ew", padx=(4, 12), pady=(2, 4))

        btn_box = ctk.CTkFrame(self.config_card, fg_color="transparent")
        btn_box.grid(row=5, column=0, columnspan=2, sticky="ew", padx=12, pady=(8, 6))

        self.btn_start = ctk.CTkButton(btn_box, text="▶ Start Scan", fg_color="#16A34A", hover_color="#15803D", font=ctk.CTkFont(size=11, weight="bold"), width=100, command=self.start_scan_thread)
        self.btn_start.pack(side="left", padx=(0, 4))

        self.btn_stop = ctk.CTkButton(btn_box, text="■ Stop Scan", fg_color="#991B1B", hover_color="#7F1D1D", font=ctk.CTkFont(size=11, weight="bold"), width=100, state="disabled", command=self.stop_scan)
        self.btn_stop.pack(side="left", padx=4)

        self.btn_export = ctk.CTkButton(btn_box, text="📥 Export Report", fg_color="#0284C7", hover_color="#0369A1", font=ctk.CTkFont(size=11, weight="bold"), width=110, command=self.export_report)
        self.btn_export.pack(side="left", padx=4)

        # 2B. OVERVIEW CARD
        self.overview_card = ctk.CTkFrame(main_area, fg_color=CARD_BG, corner_radius=12, border_color=BORDER_COLOR, border_width=1)
        self.overview_card.grid(row=1, column=1, sticky="nsew", padx=(4, 0), pady=4, ipady=4)

        ctk.CTkLabel(self.overview_card, text="SCAN OVERVIEW", font=ctk.CTkFont(size=11, weight="bold"), text_color=PURPLE_ACCENT).grid(row=0, column=0, columnspan=2, sticky="w", padx=12, pady=(8, 6))

        metrics_grid = ctk.CTkFrame(self.overview_card, fg_color="transparent")
        metrics_grid.grid(row=1, column=0, columnspan=2, sticky="ew", padx=8)

        # Open Ports Box
        open_box = ctk.CTkFrame(metrics_grid, fg_color="#022C22", border_color="#15803D", border_width=2, width=135, height=85, corner_radius=10)
        open_box.grid(row=0, column=0, padx=4, pady=4)
        open_box.pack_propagate(False)
        ctk.CTkLabel(open_box, text="FOUND / OPEN 🛡️", font=ctk.CTkFont(size=10, weight="bold"), text_color=GREEN_ACCENT).pack(anchor="w", padx=10, pady=(6, 0))
        self.lbl_open_cnt = ctk.CTkLabel(open_box, text="0", font=ctk.CTkFont(size=32, weight="bold"), text_color="#FFFFFF")
        self.lbl_open_cnt.pack(anchor="w", padx=10)

        # Closed Ports Box
        closed_box = ctk.CTkFrame(metrics_grid, fg_color="#450A0A", border_color="#B91C1C", border_width=2, width=135, height=85, corner_radius=10)
        closed_box.grid(row=0, column=1, padx=4, pady=4)
        closed_box.pack_propagate(False)
        ctk.CTkLabel(closed_box, text="CLOSED / FAIL 🔒", font=ctk.CTkFont(size=10, weight="bold"), text_color=RED_ACCENT).pack(anchor="w", padx=10, pady=(6, 0))
        self.lbl_closed_cnt = ctk.CTkLabel(closed_box, text="0", font=ctk.CTkFont(size=32, weight="bold"), text_color="#FFFFFF")
        self.lbl_closed_cnt.pack(anchor="w", padx=10)

        prog_sec = ctk.CTkFrame(self.overview_card, fg_color="transparent")
        prog_sec.grid(row=2, column=0, columnspan=2, sticky="ew", padx=12, pady=(8, 0))

        self.lbl_pct = ctk.CTkLabel(prog_sec, text="0.00%", font=ctk.CTkFont(size=12, weight="bold"), text_color=CYAN_ACCENT)
        self.lbl_pct.pack(anchor="e")

        self.progress_bar = ctk.CTkProgressBar(prog_sec, fg_color="#000000", progress_color="#0284C7", height=8)
        self.progress_bar.set(0)
        self.progress_bar.pack(fill="x", pady=2)

        # 2C. RESULTS DISPLAY
        self.results_card = ctk.CTkFrame(main_area, fg_color=CARD_BG, corner_radius=12, border_color=BORDER_COLOR, border_width=1)
        self.results_card.grid(row=2, column=0, columnspan=2, sticky="nsew", pady=(8, 0))
        self.results_card.grid_rowconfigure(1, weight=1)
        self.results_card.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(self.results_card, text="RESULTS DISPLAY", font=ctk.CTkFont(size=11, weight="bold"), text_color=PURPLE_ACCENT).grid(row=0, column=0, sticky="w", padx=12, pady=6)

        style = ttk.Style()
        style.theme_use("default")
        style.configure("Treeview", background="#000000", foreground="#E2E8F0", fieldbackground="#000000", rowheight=26, font=("Consolas", 10))
        style.configure("Treeview.Heading", background="#0A0F1D", foreground=CYAN_ACCENT, font=("Consolas", 10, "bold"))
        style.map("Treeview", background=[("selected", "#121824")])

        cols = ("PROPERTY / PATH", "STATUS / VERDICT", "DETAILS / URL")
        self.tree = ttk.Treeview(self.results_card, columns=cols, show="headings")

        self.tree.heading("PROPERTY / PATH", text="PROPERTY / PATH", anchor="w")
        self.tree.heading("STATUS / VERDICT", text="STATUS / VERDICT", anchor="center")
        self.tree.heading("DETAILS / URL", text="DETAILS / URL", anchor="w")

        self.tree.column("PROPERTY / PATH", width=230, anchor="w")
        self.tree.column("STATUS / VERDICT", width=160, anchor="center")
        self.tree.column("DETAILS / URL", width=380, anchor="w")

        self.tree.grid(row=1, column=0, sticky="nsew", padx=12, pady=(0, 10))
        self.tree.tag_configure("OPEN", foreground=GREEN_ACCENT)
        self.tree.tag_configure("REDIRECT", foreground=YELLOW_ACCENT)
        self.tree.tag_configure("CLOSED", foreground=RED_ACCENT)
        self.tree.tag_configure("INFO", foreground=CYAN_ACCENT)

        # 3. FOOTER
        footer = ctk.CTkFrame(self, height=26, fg_color="#000000", corner_radius=0)
        footer.grid(row=1, column=0, columnspan=2, sticky="ew")

        self.lbl_status = ctk.CTkLabel(footer, text="🟢 Status: System Ready", font=ctk.CTkFont(size=10), text_color="#94A3B8")
        self.lbl_status.pack(side="left", padx=15)

        self.lbl_scanned_cnt = ctk.CTkLabel(footer, text="⚙️ Items Scanned: 0", font=ctk.CTkFont(size=10), text_color="#94A3B8")
        self.lbl_scanned_cnt.pack(side="right", padx=15)

    # -------------------------------------------------------------
    # LIVE ANIMATION LOOP (FAST PLAYBACK AT 50ms INTERVAL)
    # -------------------------------------------------------------
    def _animate_status(self):
        """Fast dynamic dot animation and smooth GIF playback"""
        if self.is_scanning:
            dots = "." * ((self.anim_step % 3) + 1)
            self.lbl_status.configure(text=f"🟡 Status: Running Active Recon{dots}", text_color=YELLOW_ACCENT)
            self.lbl_live_indicator.configure(text=f"● SCANNING ACTIVE{dots}", text_color=YELLOW_ACCENT)
            
            if self.anim_frames:
                self.lbl_kali.configure(image=self.anim_frames[self.anim_idx % len(self.anim_frames)])
                self.anim_idx += 1

            self.anim_step += 1
            self.after(50, self._animate_status)
        else:
            self.lbl_live_indicator.configure(text="● ENGINE READY", text_color=GREEN_ACCENT)
            if self.img_kali:
                self.lbl_kali.configure(image=self.img_kali)

    # -------------------------------------------------------------
    # POPUPS
    # -------------------------------------------------------------
    def show_history_popup(self):
        pop = ctk.CTkToplevel(self)
        pop.title("SumScan - Scan History")
        pop.geometry("800x420")
        pop.configure(fg_color=BG_DARK)
        pop.grab_set()

        ctk.CTkLabel(pop, text="📜 PAST SCAN HISTORY", font=ctk.CTkFont(size=15, weight="bold"), text_color=CYAN_ACCENT).pack(pady=10)

        tree_frame = ctk.CTkFrame(pop, fg_color=CARD_BG)
        tree_frame.pack(fill="both", expand=True, padx=12, pady=(0, 12))

        h_cols = ("ID", "TIMESTAMP", "TARGET", "MODE", "OPEN", "CLOSED", "DURATION")
        h_tree = ttk.Treeview(tree_frame, columns=h_cols, show="headings")
        
        for c in h_cols:
            h_tree.heading(c, text=c)
            h_tree.column(c, anchor="center")

        h_tree.pack(fill="both", expand=True, padx=8, pady=8)

        self.cursor.execute("SELECT * FROM scan_history ORDER BY id DESC")
        for r in self.cursor.fetchall():
            h_tree.insert("", "end", values=r)

    def show_about_popup(self):
        pop = ctk.CTkToplevel(self)
        pop.title("About SumScan")
        pop.geometry("640x400")
        pop.configure(fg_color=BG_DARK)
        pop.grab_set()

        ctk.CTkLabel(pop, text="ℹ️ ABOUT SUMSCAN UTILITY", font=ctk.CTkFont(size=15, weight="bold"), text_color=PURPLE_ACCENT).pack(pady=(12, 4))

        txt_box = ctk.CTkTextbox(pop, fg_color="#000000", text_color=GREEN_ACCENT, font=ctk.CTkFont(family="Consolas", size=11), border_color=BORDER_COLOR, border_width=1)
        txt_box.pack(fill="both", expand=True, padx=15, pady=12)

        notice_text = (
            "===========================================================\n"
            "               SUMSCAN RECON & DIAGNOSTIC UTILITY           \n"
            "===========================================================\n\n"
            "[+] DEVELOPER : Sumon Mahmud\n"
            "[+] ROLE      : Penetration Tester & Security Consultant\n"
            "[+] GITHUB    : https://github.com/creationbd5\n"
            "[+] CONTACT   : connect.sumon.mahmud@gmail.com\n\n"
            "----------------------- ETHICAL NOTICE ---------------------\n"
            "SumScan is designed for defensive cybersecurity,\n"
            "authorized Web Application Penetration Testing, and Recon.\n\n"
            "Always secure explicit permission before auditing target systems.\n"
            "==========================================================="
        )

        def type_writer(index=0):
            if index < len(notice_text):
                txt_box.insert("end", notice_text[index])
                txt_box.see("end")
                pop.after(8, type_writer, index + 1)

        type_writer()

    # -------------------------------------------------------------
    # SCAN ENGINE CONTROLLER
    # -------------------------------------------------------------
    def start_scan_thread(self):
        if self.is_scanning:
            return

        target = self.entry_target.get().strip()
        if not target:
            messagebox.showerror("Error", "Target Entry cannot be empty.")
            return

        mode = self.combo_scan_type.get()
        self.is_scanning = True
        self.stop_requested = False
        self.start_time = time.time()
        self.anim_step = 0
        self.anim_idx = 0
        self.btn_start.configure(state="disabled", fg_color="#121824")
        self.btn_stop.configure(state="normal", fg_color="#991B1B")

        for item in self.tree.get_children():
            self.tree.delete(item)
        self.open_count = 0
        self.closed_count = 0
        self.lbl_open_cnt.configure(text="0")
        self.lbl_closed_cnt.configure(text="0")

        self._animate_status()

        threading.Thread(target=self._dispatch_scan, args=(target, mode), daemon=True).start()

    def stop_scan(self):
        if self.is_scanning:
            self.stop_requested = True

    def _dispatch_scan(self, target, mode):
        try:
            if mode == "TCP Fast Connect Scan":
                self._run_fast_tcp_scan(target)
            elif mode == "Web Directory Enumeration (SecLists)":
                self._run_dir_enumeration(target)
            elif mode == "Urlscan.io Threat Search & Intel":
                self._run_urlscan_intel(target)
            elif mode == "Subdomain Finder (OSINT)":
                self._run_subdomain_finder(target)
            elif mode == "Social Media & Footprint Recon":
                self._run_social_recon(target)
            elif mode == "Web & Tech Stack Recon":
                self._run_web_tech_recon(target)
            elif mode == "DNS Resolver & Enumeration":
                self._run_dns_enum(target)
            elif mode == "WHOIS Lookup":
                self._run_whois_lookup(target)
            elif mode == "Shodan Public Host Info":
                self._run_shodan_lookup(target)
        except Exception as e:
            self.tree.insert("", "end", values=("ERROR", "FAILED", str(e)), tags=("CLOSED",))
        finally:
            elapsed = time.strftime('%H:%M:%S', time.gmtime(max(time.time() - self.start_time, 1)))
            self._save_scan_history(target, mode, self.open_count, self.closed_count, elapsed)
            self.is_scanning = False
            self.btn_start.configure(state="normal", fg_color="#16A34A")
            self.btn_stop.configure(state="disabled", fg_color="#991B1B")
            self.lbl_status.configure(text="🟢 Status: Scan Finished", text_color=GREEN_ACCENT)

    # -------------------------------------------------------------
    # FAST TCP PORT SCANNER
    # -------------------------------------------------------------
    def _check_port_socket(self, target_ip, port):
        if self.stop_requested:
            return None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.4)
            res = sock.connect_ex((target_ip, port))
            sock.close()
            return (port, res == 0)
        except Exception:
            return (port, False)

    def _run_fast_tcp_scan(self, target):
        try:
            start_p = int(self.entry_start_port.get())
            end_p = int(self.entry_wordlist.get()) if self.entry_wordlist.get().isdigit() else 1024
            target_clean = target.replace("https://", "").replace("http://", "").split("/")[0]
            target_ip = socket.gethostbyname(target_clean)
            self.tree.insert("", "end", values=("TARGET RESOLVED", "OK", f"IP: {target_ip}"), tags=("INFO",))
        except Exception as e:
            self.tree.insert("", "end", values=("INIT FAILED", "ERROR", str(e)), tags=("CLOSED",))
            return

        total_ports = end_p - start_p + 1
        scanned = 0

        with ThreadPoolExecutor(max_workers=60) as executor:
            futures = {executor.submit(self._check_port_socket, target_ip, p): p for p in range(start_p, end_p + 1)}

            for future in futures:
                if self.stop_requested:
                    executor.shutdown(wait=False)
                    break

                result = future.result()
                if result:
                    port, is_open = result
                    if is_open:
                        try:
                            srv = socket.getservbyport(port, "tcp")
                        except OSError:
                            srv = "unknown"
                        self.open_count += 1
                        self.tree.insert("", "end", values=(f"{port}/tcp", "OPEN", f"Service: {srv}"), tags=("OPEN",))
                        self.lbl_open_cnt.configure(text=str(self.open_count))
                    else:
                        self.closed_count += 1
                        self.lbl_closed_cnt.configure(text=str(self.closed_count))

                scanned += 1
                pct = scanned / total_ports
                self.progress_bar.set(pct)
                self.lbl_pct.configure(text=f"{pct*100:.1f}%")
                self.lbl_scanned_cnt.configure(text=f"⚙️ Tested: {scanned} / {total_ports}")

    # -------------------------------------------------------------
    # WEB DIRECTORY ENUMERATION ENGINE
    # -------------------------------------------------------------
    def _load_wordlist_words(self):
        custom_path = self.entry_wordlist.get().strip()
        if os.path.exists(custom_path) and os.path.isfile(custom_path):
            with open(custom_path, "r", encoding="utf-8", errors="ignore") as f:
                return [line.strip() for line in f if line.strip() and not line.startswith("#")]

        for wpath in COMMON_WORDLIST_PATHS:
            if os.path.exists(wpath):
                with open(wpath, "r", encoding="utf-8", errors="ignore") as f:
                    return [line.strip() for line in f if line.strip() and not line.startswith("#")][:5000]

        return DEFAULT_DIRECTORIES

    def _check_directory_endpoint(self, base_url, path):
        if self.stop_requested:
            return None
        target_url = f"{base_url.rstrip('/')}/{path.lstrip('/')}"
        try:
            req = urllib.request.Request(target_url, headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'})
            with urllib.request.urlopen(req, timeout=3.5) as resp:
                return (path, resp.status, target_url)
        except urllib.error.HTTPError as e:
            if e.code in [301, 302, 401, 403]:
                return (path, e.code, target_url)
            return (path, e.code, None)
        except Exception:
            return (path, 0, None)

    def _run_dir_enumeration(self, target):
        base_url = target if target.startswith("http") else f"https://{target}"
        wordlist = self._load_wordlist_words()
        total = len(wordlist)
        scanned = 0

        self.tree.insert("", "end", values=("TARGET BASE URL", "INFO", base_url), tags=("INFO",))

        with ThreadPoolExecutor(max_workers=25) as executor:
            futures = {executor.submit(self._check_directory_endpoint, base_url, w): w for w in wordlist}

            for future in futures:
                if self.stop_requested:
                    executor.shutdown(wait=False)
                    break

                res = future.result()
                if res:
                    path, code, url = res
                    if code in [200, 201, 204]:
                        self.open_count += 1
                        self.tree.insert("", "end", values=(f"/{path}", f"HTTP {code}", url), tags=("OPEN",))
                        self.lbl_open_cnt.configure(text=str(self.open_count))
                    elif code in [301, 302, 307, 308]:
                        self.open_count += 1
                        self.tree.insert("", "end", values=(f"/{path}", f"REDIRECT ({code})", url), tags=("REDIRECT",))
                        self.lbl_open_cnt.configure(text=str(self.open_count))
                    elif code in [401, 403]:
                        self.open_count += 1
                        self.tree.insert("", "end", values=(f"/{path}", f"FORBIDDEN ({code})", url), tags=("INFO",))
                        self.lbl_open_cnt.configure(text=str(self.open_count))
                    else:
                        self.closed_count += 1
                        self.lbl_closed_cnt.configure(text=str(self.closed_count))

                scanned += 1
                pct = scanned / total
                self.progress_bar.set(pct)
                self.lbl_pct.configure(text=f"{pct*100:.1f}%")
                self.lbl_scanned_cnt.configure(text=f"⚙️ Tested: {scanned} / {total}")

    # -------------------------------------------------------------
    # URLSCAN.IO THREAT INTELLIGENCE
    # -------------------------------------------------------------
    def _run_urlscan_intel(self, target):
        domain = target.replace("https://", "").replace("http://", "").split("/")[0]
        api_url = f"https://urlscan.io/api/v1/search/?q=domain:{domain}"

        self.tree.insert("", "end", values=("SEARCHING URLSCAN DB", "QUERYING", f"domain:{domain}"), tags=("INFO",))

        try:
            req = urllib.request.Request(api_url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=6) as resp:
                data = json.loads(resp.read().decode('utf-8'))
                results = data.get("results", [])

                if not results:
                    self.tree.insert("", "end", values=("URLSCAN DB", "NO RECORD", "No past scans found in Urlscan.io database"), tags=("CLOSED",))
                    self.closed_count = 1
                    self.lbl_closed_cnt.configure(text="1")
                    self.progress_bar.set(1.0)
                    return

                total = len(results[:15])
                scanned = 0

                for item in results[:15]:
                    if self.stop_requested:
                        break

                    page = item.get("page", {})
                    verdicts = item.get("verdicts", {}).get("overall", {})

                    item_url = page.get("url", "N/A")
                    ip = page.get("ip", "N/A")
                    country = page.get("country", "N/A")
                    malicious = verdicts.get("malicious", False)
                    screenshot = item.get("screenshot", "N/A")

                    status_str = "MALICIOUS 🚨" if malicious else "CLEAN / BENIGN 🛡️"
                    tag_color = "CLOSED" if malicious else "OPEN"

                    self.open_count += 1
                    self.tree.insert("", "end", values=("URL / Domain", status_str, item_url), tags=(tag_color,))
                    self.tree.insert("", "end", values=("Server IP / Loc", f"IP: {ip}", f"Country: {country}"), tags=("INFO",))
                    self.tree.insert("", "end", values=("Screenshot Link", "URLSCAN ASSET", screenshot), tags=("INFO",))
                    
                    self.lbl_open_cnt.configure(text=str(self.open_count))

                    scanned += 1
                    pct = scanned / total
                    self.progress_bar.set(pct)
                    self.lbl_pct.configure(text=f"{pct*100:.1f}%")
                    self.lbl_scanned_cnt.configure(text=f"⚙️ Records: {scanned} / {total}")

        except Exception as e:
            self.tree.insert("", "end", values=("URLSCAN API", "FAILED", str(e)), tags=("CLOSED",))

    # -------------------------------------------------------------
    # SUBDOMAIN & FOOTPRINT RECON
    # -------------------------------------------------------------
    def _run_subdomain_finder(self, target):
        sublist = [
            "www", "mail", "dev", "admin", "blog", "webmail", "server", "api", 
            "portal", "cpanel", "vpn", "test", "staging", "m", "mobile", "corp", 
            "internal", "git", "jenkins", "db", "demo", "app", "support", "cloud"
        ]
        total = len(sublist)
        scanned = 0
        target_clean = target.replace("https://", "").replace("http://", "").split("/")[0]

        for sub in sublist:
            if self.stop_requested:
                break
            domain = f"{sub}.{target_clean}"
            try:
                ip = socket.gethostbyname(domain)
                self.open_count += 1
                self.tree.insert("", "end", values=(domain, "RESOLVED", f"IP: {ip}"), tags=("OPEN",))
                self.lbl_open_cnt.configure(text=str(self.open_count))
            except Exception:
                self.closed_count += 1
                self.lbl_closed_cnt.configure(text=str(self.closed_count))

            scanned += 1
            pct = scanned / total
            self.progress_bar.set(pct)
            self.lbl_pct.configure(text=f"{pct*100:.1f}%")
            self.lbl_scanned_cnt.configure(text=f"⚙️ Tested: {scanned} / {total}")

    def _run_social_recon(self, target):
        target_clean = target.replace("https://", "").replace("http://", "").split(".")[0]
        platforms = {
            "Facebook": f"https://facebook.com/{target_clean}",
            "Twitter / X": f"https://x.com/{target_clean}",
            "LinkedIn": f"https://linkedin.com/company/{target_clean}",
            "GitHub": f"https://github.com/{target_clean}",
            "Instagram": f"https://instagram.com/{target_clean}",
            "YouTube": f"https://youtube.com/@{target_clean}"
        }
        total = len(platforms)
        scanned = 0

        for platform, url in platforms.items():
            if self.stop_requested:
                break
            try:
                req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
                with urllib.request.urlopen(req, timeout=3) as resp:
                    if resp.status == 200:
                        self.open_count += 1
                        self.tree.insert("", "end", values=(platform, "FOUND", url), tags=("OPEN",))
                        self.lbl_open_cnt.configure(text=str(self.open_count))
            except Exception:
                self.closed_count += 1
                self.tree.insert("", "end", values=(platform, "NOT FOUND", url), tags=("CLOSED",))
                self.lbl_closed_cnt.configure(text=str(self.closed_count))

            scanned += 1
            pct = scanned / total
            self.progress_bar.set(pct)
            self.lbl_pct.configure(text=f"{pct*100:.1f}%")
            self.lbl_scanned_cnt.configure(text=f"⚙️ Tested: {scanned} / {total}")

    # -------------------------------------------------------------
    # ADDITIONAL RECON MODULES
    # -------------------------------------------------------------
    def _run_web_tech_recon(self, target):
        url = target if target.startswith("http") else f"https://{target}"
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=5) as resp:
                headers = resp.headers
                html_body = resp.read().decode('utf-8', errors='ignore')

                self.tree.insert("", "end", values=("Web Server", "DETECTED", headers.get('Server', 'Hidden')), tags=("INFO",))
                self.tree.insert("", "end", values=("Framework", "DETECTED", headers.get('X-Powered-By', 'Hidden')), tags=("INFO",))
                
                cms = "WordPress" if "wp-content" in html_body else "Custom / Standard"
                self.tree.insert("", "end", values=("CMS System", "DETECTED", cms), tags=("OPEN",))
                
                self.open_count = 3
                self.lbl_open_cnt.configure(text=str(self.open_count))
                self.progress_bar.set(1.0)
        except Exception as e:
            self.tree.insert("", "end", values=("Web Recon", "FAILED", str(e)), tags=("CLOSED",))

    def _run_dns_enum(self, target):
        target_clean = target.replace("https://", "").replace("http://", "").split("/")[0]
        try:
            ip = socket.gethostbyname(target_clean)
            self.tree.insert("", "end", values=("A Record", "RESOLVED", f"IP: {ip}"), tags=("OPEN",))
            self.open_count += 1

            if HAS_DNSPYTHON:
                for qtype in ['MX', 'NS', 'TXT']:
                    try:
                        answers = dns.resolver.resolve(target_clean, qtype)
                        for rdata in answers:
                            self.tree.insert("", "end", values=(f"{qtype} Record", "RESOLVED", str(rdata)), tags=("INFO",))
                    except Exception:
                        pass
            
            self.progress_bar.set(1.0)
            self.lbl_open_cnt.configure(text=str(self.open_count))
        except Exception as e:
            self.tree.insert("", "end", values=("DNS Enum", "FAILED", str(e)), tags=("CLOSED",))

    def _run_whois_lookup(self, target):
        target_clean = target.replace("https://", "").replace("http://", "").split("/")[0]
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(4.0)
            sock.connect(("whois.iana.org", 43))
            sock.send((target_clean + "\r\n").encode("utf-8"))

            response = ""
            while True:
                data = sock.recv(4096)
                if not data:
                    break
                response += data.decode("utf-8", errors="ignore")
            sock.close()

            for line in response.splitlines():
                if ":" in line and not line.startswith("%"):
                    parts = line.split(":", 1)
                    if parts[0].strip() and parts[1].strip():
                        self.tree.insert("", "end", values=(parts[0].strip(), "INFO", parts[1].strip()), tags=("INFO",))
            self.progress_bar.set(1.0)
        except Exception as e:
            self.tree.insert("", "end", values=("WHOIS Query", "FAILED", str(e)), tags=("CLOSED",))

    def _run_shodan_lookup(self, target):
        try:
            target_clean = target.replace("https://", "").replace("http://", "").split("/")[0]
            target_ip = socket.gethostbyname(target_clean)
            url = f"https://internetdb.shodan.io/{target_ip}"
            
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = json.loads(resp.read().decode('utf-8'))
                
                self.tree.insert("", "end", values=("Target IP", "SHODAN IP", data.get("ip", target_ip)), tags=("INFO",))
                self.tree.insert("", "end", values=("Hostnames", "SHODAN HOSTS", ", ".join(data.get("hostnames", []))), tags=("INFO",))
                self.tree.insert("", "end", values=("Open Ports", "SHODAN PORTS", str(data.get("ports", []))), tags=("OPEN",))
                
            self.progress_bar.set(1.0)
        except Exception as e:
            self.tree.insert("", "end", values=("Shodan Lookup", "FAILED", str(e)), tags=("CLOSED",))

    def export_report(self):
        filepath = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text Files", "*.txt")])
        if filepath:
            with open(filepath, "w") as f:
                f.write(f"SumScan Utility Report\nTarget: {self.entry_target.get()}\nDate: {datetime.now()}\n\n")
                for child in self.tree.get_children():
                    f.write(str(self.tree.item(child)["values"]) + "\n")
            messagebox.showinfo("Success", f"Report saved to {filepath}")


if __name__ == "__main__":
    app = SumScanApp()
    app.mainloop()
