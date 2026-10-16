'''
***************************************************************************
 sanitizzer.pyw               file name

 Description: Config / log file sanitizer for network and telecom equipment
              (Cisco, Fortinet, Juniper, Huawei, Palo Alto, Gigamon).
              Removes passwords, keys, secrets, SNMP communities and
              certificates before a file is shared with a third party.

 Usage: python sanitizzer.pyw

 @since version 1.8.0
 @return <typnone>
 @Date: GitHub version - May 15 2025 / Spaghetti code version - June 2022
        v1.8.0 - Oct 2026: bug fix (BooleanVar shadowing create_backup),
                 refactor of the sanitization engine, thread-safe UI.
****************************************************************************
'''

import logging
import os
import re
import shutil
import sys
import threading
import tkinter as tk
from datetime import datetime
from pathlib import Path
from tkinter import Button, Menu, filedialog, messagebox, scrolledtext, ttk
from typing import Callable, Dict, List, Tuple

APP_VERSION = "1.8.0"
VENDORS = ["auto", "cisco", "fortinet", "juniper", "huawei", "paloalto", "gigamon"]

ICON_DATA = '''
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
'''


# ===========================================================================
#  Sanitization engine (pure logic, no GUI - easy to test and reuse)
# ===========================================================================
class Sanitizer:
    """Vendor-aware sanitization of configuration / log text."""

    # Signatures used for auto-detection. Each is a regex evaluated with
    # re.MULTILINE so that short tokens like "end" / "next" only count when
    # they are a whole line, not when they appear inside other words.
    SIGNATURES: Dict[str, List[str]] = {
        "cisco":    [r"^hostname ", r"^interface ", r"^service ", r"^boot system", r"^enable secret"],
        "fortinet": [r"^config ", r"^end$", r"^\s+next$", r"^config vdom", r"#config-version="],
        "juniper":  [r"^set system host-name", r"^set interfaces", r"^set security", r"^system \{"],
        "huawei":   [r"^sysname ", r"^return$", r"^#\s*$", r"^\s*quit$"],
        "paloalto": [r"^set deviceconfig", r"^set network interface", r"<vsys>", r"^set mgt-config"],
        "gigamon":  [r"^chassis ", r"^gigasmart ", r"^port-pair ", r"^traffic-map ", r"^nhp-profile ", r"^map alias "],
    }

    # Vendor rules: (regex, replacement). Group 1 is always the keyword to
    # keep, the rest of the line is replaced by a marker.
    RULES: Dict[str, List[Tuple[str, str]]] = {
        "cisco": [
            (r"(^\s*enable secret\s+)[^\n]+",                        r"\1[SECRET-REMOVED]"),
            (r"(^\s*enable password\s+)[^\n]+",                      r"\1[PASSWORD-REMOVED]"),
            (r"(^\s*username\s+\S+\s+(?:privilege\s+\d+\s+)?(?:secret|password)\s+)[^\n]+", r"\1[PASSWORD-REMOVED]"),
            (r"(^\s*snmp-server community\s+)[^\n]+",                r"\1[COMMUNITY-REMOVED]"),
            (r"(^\s*snmp-server user\s+)[^\n]+",                     r"\1[SNMP-USER-REMOVED]"),
            (r"(^\s*(?:tacacs|radius)(?:-server)?\s+.*?\bkey\s+)[^\n]+", r"\1[KEY-REMOVED]"),
            (r"(^\s*key\s+\d+\s*$\n\s*key-string\s+)[^\n]+",         r"\1[KEY-REMOVED]"),
            (r"(^\s*key-string\s+)[^\n]+",                           r"\1[KEY-REMOVED]"),
            (r"(^\s*crypto isakmp key\s+)[^\n]+",                    r"\1[KEY-REMOVED]"),
            (r"(^\s*pre-shared-key\s+)[^\n]+",                       r"\1[KEY-REMOVED]"),
            (r"(^\s*neighbor\s+\S+\s+password\s+)[^\n]+",            r"\1[PASSWORD-REMOVED]"),
            (r"(^\s*ip ospf message-digest-key\s+\d+\s+md5\s+)[^\n]+", r"\1[KEY-REMOVED]"),
            (r"(^\s*standby\s+\d*\s*authentication\s+)[^\n]+",       r"\1[KEY-REMOVED]"),
            (r"(^\s*wpa-psk\s+)[^\n]+",                              r"\1[KEY-REMOVED]"),
            (r"(^\s*password\s+)[^\n]+",                             r"\1[PASSWORD-REMOVED]"),
            (r"(^\s*secret\s+)[^\n]+",                               r"\1[SECRET-REMOVED]"),
        ],
        "fortinet": [
            (r"(\bENC\s+)[^\n]+",                                    r"\1[NO-VALID-INFO]"),
            (r"(^\s*set (?:password|passwd|psksecret|secret|key|auth-password-l1|auth-password-l2|priv-password|"
             r"community|shared-secret|certificate|ca|private-key|api-key|login-passwd|ha-mgmt-password|"
             r"presharedkey|fortitoken|secondary-secret|tertiary-secret)\s+)[^\n]+",
             r"\1[REMOVED]"),
        ],
        "juniper": [
            (r"((?:encrypted-password|secret|authentication-key|pre-shared-key|md5|hmac-sha1-96|ssh-rsa|ssh-dsa|ssh-ed25519|key)\s+)[^\n;]+",
             r"\1[REMOVED]"),
            (r"(^\s*set snmp community\s+)\S+",                     r"\1[COMMUNITY-REMOVED]"),
        ],
        "huawei": [
            (r"((?:password|community|public-key|pre-shared-key|authentication-mode|cipher|simple|irreversible-cipher)\s+)[^\n]+",
             r"\1[REMOVED]"),
        ],
        "paloalto": [
            (r"((?:password|secret|api-key|phash|passphrase|private-key|psk|shared-secret)\s+)[^\n]+", r"\1[REMOVED]"),
            (r"<(phash|password|secret|api-key|private-key|psk)>.*?</\1>", r"<\1>[REMOVED]</\1>"),
        ],
        "gigamon": [
            (r"((?:admin-password|trap-community|auth-password|priv-password|ssh-key|snmp-community|"
             r"encrypted-password|password)\s+)[^\n]+",              r"\1[REMOVED]"),
            (r"(cluster\s+shared-secret\s+)[^\n]+",                  r"\1[SHARED-SECRET-REMOVED]"),
            (r"((?:tacacs|radius)-server\s+(?:host\s+\S+\s+)?key\s+)[^\n]+", r"\1[KEY-REMOVED]"),
            (r"(certificate\s+\S+\s+(?:private-key|public-cert)\s+)[^\n]+", r"\1[CERTIFICATE-REMOVED]"),
        ],
        "generic": [
            (r"((?:password|passwd|secret|community|key|token|api-key|encrypted-password|auth-password|priv-password)\s+)[^\n]+",
             r"\1[SENSITIVE-DATA-REMOVED]"),
        ],
    }

    # Multi-line blocks: everything between the two markers is removed.
    BLOCKS = [
        (r"-----BEGIN [A-Z ]*(?:CERTIFICATE|PRIVATE KEY|PUBLIC KEY|RSA PRIVATE KEY|EC PRIVATE KEY)-----",
         r"-----END [A-Z ]*(?:CERTIFICATE|PRIVATE KEY|PUBLIC KEY|RSA PRIVATE KEY|EC PRIVATE KEY)-----"),
    ]

    # SSH public keys (single line, any vendor).
    SSH_KEY_RE = re.compile(r'\b(ssh-(?:rsa|dss|ed25519)|ecdsa-sha2-nistp\d+)\s+[A-Za-z0-9+/=]{20,}(?:\s+[^\s"]+)?')

    # Lines that are only screen noise from "show" commands.
    NOISE = ["<--- More --->", "--More--"]

    def __init__(self, common_passwords: List[str], log_cb: Callable[[str], None] = None):
        # Longest first so that "Password123" is wiped before "Password".
        self.common_passwords = sorted({p for p in common_passwords if p}, key=len, reverse=True)
        self._log = log_cb or (lambda msg: None)
        self._compiled = {
            vendor: [(re.compile(rx, re.MULTILINE | re.IGNORECASE), rep) for rx, rep in rules]
            for vendor, rules in self.RULES.items()
        }
        self._blocks = [(re.compile(b), re.compile(e)) for b, e in self.BLOCKS]
        self._signatures = {
            vendor: [re.compile(rx, re.MULTILINE | re.IGNORECASE) for rx in sigs]
            for vendor, sigs in self.SIGNATURES.items()
        }

    # ---------------------------------------------------------------- public
    def detect_vendor(self, content: str) -> str:
        scores = {v: sum(1 for rx in sigs if rx.search(content)) for v, sigs in self._signatures.items()}
        vendor, score = max(scores.items(), key=lambda kv: kv[1])
        return vendor if score > 0 else "cisco"

    def sanitize(self, content: str, vendor: str = "auto") -> Tuple[str, str, int]:
        """Return (sanitized_content, vendor_used, changed_line_count)."""
        original_lines = content.split("\n")

        if vendor == "auto":
            vendor = self.detect_vendor(content)
            self._log(f"Auto-detected device type: {vendor}\n")
        else:
            self._log(f"Device type: {vendor}\n")

        self._log("Removing common and usual passwords....\n")
        for pwd in self.common_passwords:
            content = content.replace(pwd, "*****")

        self._log("Removing certificates and encryption keys....\n")
        content = self._remove_blocks(content)
        content = self.SSH_KEY_RE.sub(r"\1 [SSH-KEY-REMOVED]", content)

        rules = self._compiled.get(vendor)
        if rules is None:
            self._log(f"Warning: unsupported device type '{vendor}'. Using generic sanitization.\n")
            rules = self._compiled["generic"]
        self._log(f"Applying {vendor} rules....\n")
        for rx, rep in rules:
            content = rx.sub(rep, content)

        self._log("Removing extra lines....\n")
        content = self._remove_noise(content)

        changed = sum(1 for a, b in zip(original_lines, content.split("\n")) if a != b)
        return content, vendor, changed

    # --------------------------------------------------------------- helpers
    def _remove_blocks(self, content: str) -> str:
        lines = content.split("\n")
        out, i = [], 0
        while i < len(lines):
            line = lines[i]
            matched = False
            for begin, end in self._blocks:
                m = begin.search(line)
                if m:
                    out.append(line[:m.start()] + "[CERTIFICATE/KEY-DATA-REMOVED]")
                    i += 1
                    while i < len(lines) and not end.search(lines[i]):
                        i += 1
                    matched = True
                    break
            if not matched:
                out.append(line)
            i += 1
        return "\n".join(out)

    def _remove_noise(self, content: str) -> str:
        cleaned = []
        for line in content.split("\n"):
            stripped = line.strip()
            if stripped in self.NOISE:
                continue
            cleaned.append(line.rstrip())
        return "\n".join(cleaned)


# ===========================================================================
#  GUI application
# ===========================================================================
class ConfigSanitizerApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.processing = False

        self.setup_paths()
        self.setup_logging()
        self.setup_window()
        self.load_sensitive_data()
        self.create_widgets()
        self.create_menus()

    # ------------------------------------------------------------- setup
    def setup_paths(self):
        """Resolve working, backup and log directories (absolute paths)."""
        self.dir_path = Path(os.path.dirname(os.path.realpath(__file__)))
        temp_dir = Path("c:/temp/temp")
        if temp_dir.is_dir():
            self.dir_path = temp_dir
        os.chdir(self.dir_path)

        self.backup_dir = self.dir_path / "backups"
        self.log_dir = self.dir_path / "logs"
        self.secret_file = self.dir_path / "secret.txt"
        self.backup_dir.mkdir(exist_ok=True)
        self.log_dir.mkdir(exist_ok=True)

    def setup_logging(self):
        log_file = self.log_dir / f"sanitizer_{datetime.now().strftime('%Y%m%d')}.log"
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
            filename=log_file,
            filemode="a",
        )
        self.logger = logging.getLogger("ConfigSanitizer")
        self.logger.info("Application started")

    def setup_window(self):
        self.root.title("Config file Sanitizer Tool")
        self.root.resizable(False, False)
        try:
            self.root.iconphoto(True, tk.PhotoImage(data=ICON_DATA))
        except tk.TclError:
            pass

        app_width, app_height = 635, 500
        x_pos = self.root.winfo_screenwidth() // 2 - app_width // 2
        y_pos = self.root.winfo_screenheight() // 2 - app_height // 2
        self.root.geometry(f"{app_width}x{app_height}+{x_pos}+{y_pos}")
        self.root.protocol("WM_DELETE_WINDOW", self.exit_program)

    def load_sensitive_data(self):
        """Load the list of known passwords from secret.txt (create it if missing)."""
        passwords: List[str] = []
        try:
            if self.secret_file.exists():
                with open(self.secret_file, "r", encoding="utf-8") as f:
                    passwords = [ln.strip() for ln in f if ln.strip() and not ln.lstrip().startswith("#")]
                self.logger.info(f"Loaded {len(passwords)} passwords from {self.secret_file}")
            else:
                passwords = ["Pass1", "pass2", "pass3", "pass4", "pass5"]
                with open(self.secret_file, "w", encoding="utf-8") as f:
                    f.write("# This file contains sensitive passwords to be sanitized\n"
                            "# Add one password per line\n"
                            "# Lines starting with # are comments\n\n")
                    f.write("\n".join(passwords) + "\n")
                self.logger.info("Created secret.txt with sample passwords")
                messagebox.showinfo("Secret File Created",
                                    "Created 'secret.txt' file with sample passwords.\n"
                                    "You can edit this file to add your own passwords to sanitize.")
        except Exception as e:
            self.logger.error(f"Error loading secret.txt: {e}")
            passwords = ["Pass1", "pass2", "pass3"]
            messagebox.showwarning("Warning",
                                   "Could not load passwords from secret.txt.\n"
                                   "Using default sample passwords instead.")
        self.sanitizer = Sanitizer(passwords, log_cb=self.update_ui)

    # ----------------------------------------------------------- widgets
    def create_widgets(self):
        ttk.Label(self.root, text="SANiTiZZER", font=("Raavi", 40, "bold"),
                  foreground="red").place(x=180, y=40)
        ttk.Label(self.root, text=f"@ Mar-2022 lgp V{APP_VERSION}",
                  font=("Arial", 7, "italic")).place(x=470, y=470)

        ttk.Label(self.root, text="Config filename", font=("Courier", 10)).place(x=20, y=110)
        self.filename = tk.StringVar()
        ttk.Entry(self.root, width=60, textvariable=self.filename).place(x=150, y=110)
        Button(self.root, text="Browse Files", command=self.browse_files).place(x=517, y=105)

        ttk.Label(self.root, text="Device Type:", font=("Courier", 10)).place(x=20, y=145)
        self.vendor = tk.StringVar(value="auto")
        ttk.Combobox(self.root, width=15, textvariable=self.vendor,
                     values=VENDORS, state="readonly").place(x=150, y=145)

        # NOTE: this variable is named backup_enabled, NOT create_backup -
        # using the method name here was what caused the
        # "'BooleanVar' object is not callable" error.
        self.backup_enabled = tk.BooleanVar(value=True)
        ttk.Checkbutton(self.root, text="Create backup before sanitizing",
                        variable=self.backup_enabled).place(x=320, y=145)

        Button(self.root, text="Preview", width=10,
               command=lambda: self.preview_sanitize(self.filename.get())).place(x=100, y=180)
        self.sanitize_button = Button(self.root, text="SANITIZE", width=10,
                                      command=lambda: self.start_sanitize_thread(self.filename.get()))
        self.sanitize_button.place(x=220, y=180)
        Button(self.root, text="Exit", width=10, command=self.exit_program).place(x=380, y=180)

        self.progress_var = tk.DoubleVar()
        ttk.Progressbar(self.root, variable=self.progress_var, orient="horizontal",
                        length=595, mode="determinate").place(x=20, y=220)

        self.status_var = tk.StringVar(value="Ready")
        ttk.Label(self.root, textvariable=self.status_var).place(x=20, y=240)

        self.results_text = scrolledtext.ScrolledText(
            self.root, height=10, width=67, background="white",
            highlightbackground="grey", highlightcolor="grey", highlightthickness=1)
        self.results_text.place(x=20, y=260)

        # Post-processing buttons: created once, shown/hidden as needed.
        self.another_button = Button(self.root, text="Another File", width=10, command=self.reset_ui)
        self.restart_button = Button(self.root, text="Restart", width=10, command=self.restart_program)
        self.post_exit_button = Button(self.root, text="Exit", width=10, command=self.exit_program)

    def create_menus(self):
        menubar = Menu(self.root)

        file_menu = Menu(menubar, tearoff=0)
        file_menu.add_command(label="Open File", command=self.browse_files)
        file_menu.add_command(label="Edit Passwords", command=self.edit_passwords)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.exit_program)
        menubar.add_cascade(label=" File ", menu=file_menu)

        tools_menu = Menu(menubar, tearoff=0)
        tools_menu.add_command(label="Preview Sanitization",
                               command=lambda: self.preview_sanitize(self.filename.get()))
        tools_menu.add_command(label="View Logs", command=lambda: self.open_path(self.log_dir))
        tools_menu.add_command(label="View Backup Files", command=lambda: self.open_path(self.backup_dir))
        menubar.add_cascade(label=" Tools ", menu=tools_menu)

        help_menu = Menu(menubar, tearoff=0)
        help_menu.add_command(label="Help", command=self.show_help)
        help_menu.add_command(label="About", command=self.show_about)
        menubar.add_cascade(label=" Info ", menu=help_menu)

        self.root.config(menu=menubar)

    # ------------------------------------------------------- thread-safe UI
    def update_ui(self, message: str):
        self.root.after(0, self._do_update_ui, message)

    def _do_update_ui(self, message: str):
        self.results_text.insert(tk.END, message)
        self.results_text.see(tk.END)

    def update_progress(self, value: float, status: str = None):
        self.root.after(0, self._do_update_progress, value, status)

    def _do_update_progress(self, value: float, status: str):
        self.progress_var.set(value)
        if status:
            self.status_var.set(status)

    def show_error(self, title: str, message: str):
        """Message boxes must be shown from the main thread."""
        self.root.after(0, messagebox.showerror, title, message)

    # ----------------------------------------------------------- actions
    def browse_files(self):
        filename = filedialog.askopenfilename(
            initialdir=self.dir_path, title="Select a File",
            filetypes=(("config files", "*.conf* *.cfg *.log* *.txt*"), ("all files", "*.*")))
        if filename:
            self.filename.set(filename)

    def open_path(self, target: Path):
        """Open a file or folder with the OS default application."""
        if not target.exists():
            messagebox.showinfo("Not found", f"{target} does not exist.")
            return
        try:
            if sys.platform == "win32":
                os.startfile(target)
            elif sys.platform == "darwin":
                os.system(f'open "{target}"')
            else:
                os.system(f'xdg-open "{target}"')
        except Exception as e:
            self.logger.error(f"Could not open {target}: {e}")
            messagebox.showerror("Error", f"Could not open {target}:\n{e}")

    def edit_passwords(self):
        if not self.secret_file.exists():
            with open(self.secret_file, "w", encoding="utf-8") as f:
                f.write("# This file contains sensitive passwords to be sanitized\n"
                        "# Add one password per line\n"
                        "# Lines starting with # are comments\n\n")
        self.open_path(self.secret_file)

    def make_backup(self, path: Path) -> bool:
        """Copy the original file into the backups folder (timestamped)."""
        try:
            stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
            backup_path = self.backup_dir / f"{path.stem}_{stamp}{path.suffix}.bak"
            shutil.copy2(path, backup_path)
            self.logger.info(f"Created backup: {backup_path}")
            self.update_ui(f"Backup created: {backup_path.name}\n")
            return True
        except Exception as e:
            self.logger.error(f"Failed to create backup: {e}")
            return False

    def start_sanitize_thread(self, filename: str):
        if not filename:
            self.results_text.delete(1.0, tk.END)
            self.results_text.insert(tk.END, "Nothing to Sanitize...\n")
            messagebox.showwarning("No file to Sanitize",
                                   "     WARNING:\n\nPlease, select a config or\nlog file to sanitize first...")
            return
        path = Path(filename)
        if not path.is_file():
            messagebox.showerror("File not found", f"Cannot find:\n{filename}")
            return
        if self.processing:
            messagebox.showinfo("Processing", "Already processing a file. Please wait.")
            return

        self.results_text.delete(1.0, tk.END)
        self.progress_var.set(0)
        self.status_var.set("Starting sanitization...")
        self.hide_action_buttons()

        # Backup is done here, on the main thread, so the user can be asked
        # what to do if it fails (dialogs are not safe from worker threads).
        if self.backup_enabled.get():
            self.update_progress(10, "Creating backup...")
            if not self.make_backup(path):
                if not messagebox.askokcancel("Backup Failed",
                                              "Failed to create backup file. Continue anyway?"):
                    self.status_var.set("Cancelled")
                    return

        self.processing = True
        self.sanitize_button.config(state="disabled")
        threading.Thread(target=self.sanitize_file, args=(path,), daemon=True).start()

    def sanitize_file(self, path: Path):
        """Worker thread: read, sanitize and write the file."""
        try:
            self.update_progress(20, f"Processing {path.name}...")
            self.update_ui(f"Working on file:\n{path}\n")
            content = self.read_file(path)

            self.update_progress(40, "Sanitizing...")
            content, vendor, changed = self.sanitizer.sanitize(content, self.vendor.get())

            stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
            output_path = path.with_name(f"{path.stem}_CLEAN_{stamp}{path.suffix}")

            self.update_progress(90, "Writing sanitized file...")
            with open(output_path, "w", encoding="utf-8", newline="") as f:
                f.write(content)

            self.update_ui(f"Writing file:\n{output_path}\n")
            self.update_ui(f"Device type: {vendor} - {changed:,} line(s) modified\n")
            self.update_progress(100, "Complete!")
            self.update_ui("Done!!!\n")
            self.logger.info(f"Sanitized {path.name} -> {output_path.name} ({vendor}, {changed} lines)")
            self.root.after(0, self.show_action_buttons)
        except Exception as e:
            self.logger.exception("Error during sanitization")
            self.update_ui(f"Error during sanitization: {e}\n")
            self.update_progress(0, "Error")
            self.show_error("Error", f"Failed to sanitize file: {e}")
        finally:
            self.processing = False
            self.root.after(0, lambda: self.sanitize_button.config(state="normal"))

    @staticmethod
    def read_file(path: Path) -> str:
        """Read text keeping any non-ASCII characters instead of dropping them."""
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read()

    def show_action_buttons(self):
        self.another_button.place(x=120, y=430)
        self.restart_button.place(x=220, y=430)
        self.post_exit_button.place(x=320, y=430)

    def hide_action_buttons(self):
        for b in (self.another_button, self.restart_button, self.post_exit_button):
            b.place_forget()

    def reset_ui(self):
        self.filename.set("")
        self.results_text.delete(1.0, tk.END)
        self.progress_var.set(0)
        self.status_var.set("Ready")
        self.hide_action_buttons()

    # ----------------------------------------------------------- preview
    def preview_sanitize(self, filename: str):
        if not filename:
            messagebox.showwarning("No file to Sanitize",
                                   "     WARNING:\n\nPlease, select a config or\nlog file to sanitize first...")
            return
        path = Path(filename)
        if not path.is_file():
            messagebox.showerror("File not found", f"Cannot find:\n{filename}")
            return
        try:
            original = self.read_file(path)
            # Preview uses a silent engine so the main log window is not spammed.
            silent = Sanitizer(self.sanitizer.common_passwords)
            sanitized, vendor, changed = silent.sanitize(original, self.vendor.get())

            win = tk.Toplevel(self.root)
            win.title(f"Preview Sanitization: {path.name}")
            w, h = 900, 600
            win.geometry(f"{w}x{h}+{self.root.winfo_screenwidth() // 2 - w // 2}"
                         f"+{self.root.winfo_screenheight() // 2 - h // 2}")

            container = ttk.Frame(win)
            container.pack(fill="both", expand=True, padx=10, pady=10)
            container.columnconfigure((0, 1), weight=1)
            container.rowconfigure(0, weight=1)

            for col, (title, text) in enumerate((("Original Content", original),
                                                 ("Sanitized Preview", sanitized))):
                frame = ttk.LabelFrame(container, text=title)
                frame.grid(row=0, column=col, sticky="nsew", padx=5, pady=5)
                box = scrolledtext.ScrolledText(frame, wrap=tk.NONE, font=("Consolas", 9))
                box.pack(fill="both", expand=True)
                box.insert(tk.END, text)
                box.config(state="disabled")

            buttons = ttk.Frame(win)
            buttons.pack(fill="x", padx=10, pady=10)
            ttk.Button(buttons, text="Close Preview", command=win.destroy).pack(side=tk.RIGHT, padx=5)
            ttk.Button(buttons, text="Proceed with Sanitization",
                       command=lambda: (win.destroy(), self.start_sanitize_thread(filename))
                       ).pack(side=tk.RIGHT, padx=5)

            total = original.count("\n") + 1
            ttk.Label(buttons, text=(f"File: {path.name}\n"
                                     f"Size: {len(original):,} characters, {total:,} lines\n"
                                     f"Modified: {changed:,} lines ({changed / total * 100:.1f}%)\n"
                                     f"Detected device type: {vendor}")).pack(side=tk.LEFT, padx=5)
        except Exception as e:
            self.logger.exception("Error in preview")
            messagebox.showerror("Preview Error", f"Failed to preview file: {e}")

    # -------------------------------------------------------------- info
    def show_help(self):
        messagebox.showinfo("Sanitizer Info", (
            "CONFIG SANITIZER TOOL INSTRUCTIONS\n\n"
            "1. Select the log or config file (text format)\n"
            "2. Choose a device type or use Auto Detection\n"
            "3. Use Preview to see expected changes without modifying any files\n"
            "4. Press Sanitize button to process the file\n"
            "5. The new sanitized file will be saved in the same directory\n\n"
            "The tool removes the following sensitive information:\n"
            "- Passwords, authentication keys, and secret phrases\n"
            "- Certificates and encryption keys (PEM blocks, SSH keys)\n"
            "- SNMP community strings\n"
            "- API tokens and other credentials\n\n"
            "You can add your own passwords to sanitize by editing the secret.txt file\n"
            "in the File menu.\n\n"
            "A backup copy of the original file is created before sanitization."))

    def show_about(self):
        win = tk.Toplevel(self.root)
        win.geometry(f"300x380+{self.root.winfo_rootx() + 200}+{self.root.winfo_rooty() + 25}")
        win.title("About this")
        win.resizable(False, False)

        ttk.Label(win, text="\u26A0", foreground="Blue", font=("Arial", 30)).place(x=5, y=3)
        ttk.Label(win, text="\u26A0", foreground="Orange", font=("Arial", 30)).place(x=235, y=320)
        ttk.Label(win, font=("Arial", 10), text=(
            "This program will erase sensitive information\n"
            "like username, passwords, keys, and will modify \n"
            "certificates in configuration files and log files to \n"
            "avoid the exposure of this information in case \n"
            "you need to send the file to an external provider \n"
            "or contractor.")).place(x=10, y=75)
        ttk.Label(win, text=f"Sanitizzer V{APP_VERSION} \n@Mar 2022 lgp DevOps\n",
                  font=("Arial", 14, "bold")).place(x=20, y=200)
        Button(win, text="Exit", command=win.destroy, width=10).place(x=100, y=340)

    def restart_program(self):
        self.logger.info("Application restarted by user")
        os.execl(sys.executable, sys.executable, *sys.argv)

    def exit_program(self):
        if messagebox.askokcancel("Confirm Exit", "Are you sure you want to exit?"):
            self.logger.info("Application closed by user")
            self.root.destroy()


def main():
    try:
        root = tk.Tk()
        ConfigSanitizerApp(root)
        root.mainloop()
    except Exception as e:
        logging.error(f"Unhandled exception: {e}", exc_info=True)
        messagebox.showerror("Fatal Error",
                             f"An unexpected error occurred: {e}\n\nThe application will now close.")
        sys.exit(1)


if __name__ == "__main__":
    main()
