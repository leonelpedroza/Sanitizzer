'''
***************************************************************************
 sanitizzer.pyw               file name

 Description: Simple ICMP monitoring tool

 Usage: /python sanitizzer.pyw 

 @since version 1.7.1 
 @return <typnone>
 @Date: GitHub version - May 15 2025 / Spaghetti code version - June 2022
****************************************************************************
'''

import tkinter as tk
from tkinter import filedialog, ttk, messagebox, Menu, Text, Button, scrolledtext
import sys
import os
import re
import threading
import logging
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Set, Optional, Union, Tuple


class ConfigSanitizerApp:
    def __init__(self, root):
        """Initialize the application"""
        self.root = root
        self.setup_logging()
        self.setup_window()
        self.load_sensitive_data()
        self.create_widgets()
        self.create_menus()
        self.supported_vendors = {
            "cisco": self.sanitize_cisco,
            "fortinet": self.sanitize_fortinet,
            "juniper": self.sanitize_juniper,
            "huawei": self.sanitize_huawei,
            "paloalto": self.sanitize_paloalto,
            "gigamon": self.sanitize_gigamon
        }
        
    def setup_logging(self):
        """Configure application logging"""
        log_dir = Path("logs")
        if not log_dir.exists():
            log_dir.mkdir(exist_ok=True)
            
        log_file = log_dir / f"sanitizer_{datetime.now().strftime('%Y%m%d')}.log"
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            filename=log_file,
            filemode='a'
        )
        
        self.logger = logging.getLogger('ConfigSanitizer')
        self.logger.info("Application started")
        
    def setup_window(self):
        """Configure the main window properties"""
        self.root.title("Config file Sanitizer Tool")
        self.root.resizable(False, False)
        
        # Set icon
        icondata = '''
        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
        '''
        icon = tk.PhotoImage(data=icondata)
        self.root.iconphoto(True, icon)
        
        # Center window on screen
        app_width = 635
        app_height = 500  # Increased height for progress bar and additional features
        
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()
        x_pos = screen_width // 2 - app_width // 2
        y_pos = screen_height // 2 - app_height // 2
        
        self.root.geometry(f'{app_width}x{app_height}+{x_pos}+{y_pos}')
        
        # Set working directory
        self.dir_path = Path(os.path.dirname(os.path.realpath(__file__)))
        os.chdir(self.dir_path)
        
        # Use temp directory if available
        temp_dir = Path("c:/temp/temp")
        if temp_dir.is_dir():
            os.chdir(temp_dir)
            self.dir_path = temp_dir
            
        # Create backup directory if it doesn't exist
        self.backup_dir = self.dir_path / "backups"
        if not self.backup_dir.exists():
            self.backup_dir.mkdir(exist_ok=True)
            self.logger.info(f"Created backup directory: {self.backup_dir}")
            
        # Initialize progress variables
        self.processing = False
        self.progress_value = 0
    
    def load_sensitive_data(self):
        """Load sensitive passwords and patterns from external file"""
        self.sensitive_data = {
            "common_passwords": [],
            "cisco_patterns": ["username ", "secret ", " key ", "password ", "community ", "snmp-server user ", "key-string "],
            "fortinet_patterns": ["set private-key ", "BEGIN CERTIFICATE", "ENC "],
            "juniper_patterns": ["secret ", "authentication-key ", "pre-shared-key ", "md5 "],
            "huawei_patterns": ["password ", "community ", "authentication-mode ", "public-key "],
            "paloalto_patterns": ["password ", "secret ", "api-key ", "panorama-server "],
            "gigamon_patterns": ["admin-password ", "trap-community ", "auth-password ", "priv-password ", "ssh-key ", "snmp-community "]
        }
        
        # Try to load passwords from a file
        try:
            secret_file = self.dir_path / "secret.txt"
            if secret_file.exists():
                with open(secret_file, 'r', encoding='utf-8') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            self.sensitive_data["common_passwords"].append(line)
                self.logger.info(f"Loaded {len(self.sensitive_data['common_passwords'])} passwords from {secret_file}")
            else:
                # If file doesn't exist, create it with sample passwords
                with open(secret_file, 'w', encoding='utf-8') as f:
                    f.write("# This file contains sensitive passwords to be sanitized\n")
                    f.write("# Add one password per line\n")
                    f.write("# Lines starting with # are comments\n\n")
                    sample_passwords = ["Pass1", "pass2", "pass3", "pass4", "pass5"]
                    for pwd in sample_passwords:
                        f.write(f"{pwd}\n")
                    self.sensitive_data["common_passwords"] = sample_passwords
                self.logger.info(f"Created secret.txt file with sample passwords")
                messagebox.showinfo("Secret File Created", 
                    "Created 'secret.txt' file with sample passwords.\n"
                    "You can edit this file to add your own passwords to sanitize.")
        except Exception as e:
            self.logger.error(f"Error loading secret.txt: {str(e)}")
            # Fallback to hardcoded sample passwords if file can't be read
            self.sensitive_data["common_passwords"] = ["Pass1", "pass2", "pass3"]
            messagebox.showwarning("Warning", 
                                  "Could not load passwords from secret.txt.\n"
                                  "Using default sample passwords instead.")
    
    def create_widgets(self):
        """Create all GUI elements"""
        # Title label
        title_label = ttk.Label(self.root, text="SANiTiZZER")
        title_label.place(x=180, y=40)
        title_label.config(font=("Raavi", 40, "bold"), foreground="red")
        
        # Copyright label
        copyright_label = ttk.Label(self.root, text="@ Mar-2022 lgp V1.7.1 (Enhanced)")
        copyright_label.place(x=470, y=470)
        copyright_label.config(font=("Arial", 7, "italic"))
        
        # File selector label
        file_label = ttk.Label(self.root, text="Config filename")
        file_label.place(x=20, y=110)
        file_label.config(font=("Courier", 10))
        
        # File entry field
        self.filename = tk.StringVar()
        self.file_entry = ttk.Entry(self.root, width=60, textvariable=self.filename)
        self.file_entry.place(x=150, y=110)
        
        # Browse button
        self.browse_button = Button(
            self.root,
            text="Browse Files",
            command=self.browse_files
        )
        self.browse_button.place(x=517, y=105)
        
        # Create vendor selection dropdown
        vendor_label = ttk.Label(self.root, text="Device Type:")
        vendor_label.place(x=20, y=145)
        vendor_label.config(font=("Courier", 10))
        
        self.vendor = tk.StringVar(value="auto")
        vendor_choices = ["auto", "cisco", "fortinet", "juniper", "huawei", "paloalto", "gigamon"]
        vendor_dropdown = ttk.Combobox(self.root, width=15, textvariable=self.vendor)
        vendor_dropdown['values'] = vendor_choices
        vendor_dropdown.place(x=150, y=145)
        
        # Create checkbox for backup option
        self.create_backup = tk.BooleanVar(value=True)
        backup_checkbox = ttk.Checkbutton(
            self.root, 
            text="Create backup before sanitizing",
            variable=self.create_backup
        )
        backup_checkbox.place(x=320, y=145)
        
        # Exit button
        self.exit_button = Button(
            self.root,
            text="Exit",
            command=self.exit_program,
            width=10
        )
        self.exit_button.place(x=380, y=180)
        
        # Sanitize button
        self.sanitize_button = Button(
            self.root,
            text="SANITIZE",
            command=lambda: self.start_sanitize_thread(self.filename.get()),
            width=10
        )
        self.sanitize_button.place(x=220, y=180)
        
        # Preview button
        self.preview_button = Button(
            self.root,
            text="Preview",
            command=lambda: self.preview_sanitize(self.filename.get()),
            width=10
        )
        self.preview_button.place(x=100, y=180)
        
        # Progress bar
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(
            self.root, 
            variable=self.progress_var,
            orient='horizontal',
            length=595,
            mode='determinate'
        )
        self.progress_bar.place(x=20, y=220)
        
        # Status label
        self.status_var = tk.StringVar(value="Ready")
        self.status_label = ttk.Label(self.root, textvariable=self.status_var)
        self.status_label.place(x=20, y=240)
        
        # Results text area with scrollbar
        self.results_text = scrolledtext.ScrolledText(
            self.root, 
            height=10, 
            width=67,
            background='white',
            highlightbackground="grey",
            highlightcolor="grey",
            highlightthickness=1
        )
        self.results_text.place(x=20, y=260)
        
    def create_menus(self):
        """Create menu bar with items"""
        menubar = Menu(self.root)
        
        # File menu
        file_menu = Menu(menubar, tearoff=0)
        file_menu.add_command(label="Open File", command=self.browse_files)
        file_menu.add_command(label="Edit Passwords", command=self.edit_passwords)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.exit_program)
        menubar.add_cascade(label=" File ", menu=file_menu)
        
        # Tools menu
        tools_menu = Menu(menubar, tearoff=0)
        tools_menu.add_command(label="Preview Sanitization", 
                            command=lambda: self.preview_sanitize(self.filename.get()))
        tools_menu.add_command(label="View Logs", command=self.view_logs)
        tools_menu.add_command(label="View Backup Files", command=self.view_backups)
        menubar.add_cascade(label=" Tools ", menu=tools_menu)
        
        # Help menu
        help_menu = Menu(menubar, tearoff=0)
        help_menu.add_command(label="Help", command=self.show_help)
        help_menu.add_command(label="About", command=self.show_about)
        menubar.add_cascade(label=" Info ", menu=help_menu)
        
        self.root.config(menu=menubar)
    
    def browse_files(self):
        """Open file browser dialog"""
        filename = filedialog.askopenfilename(
            initialdir=self.dir_path,
            title="Select a File",
            filetypes=(
                ("config files", "*.conf* *.log* *.txt*"),
                ("all files", "*.*")
            )
        )
        self.filename.set(filename)
        
    def edit_passwords(self):
        """Open the secret.txt file in the default text editor"""
        secret_file = self.dir_path / "secret.txt"
        if not secret_file.exists():
            with open(secret_file, 'w', encoding='utf-8') as f:
                f.write("# This file contains sensitive passwords to be sanitized\n")
                f.write("# Add one password per line\n")
                f.write("# Lines starting with # are comments\n\n")
        
        try:
            if sys.platform == 'win32':
                os.startfile(secret_file)
            elif sys.platform == 'darwin':  # macOS
                os.system(f'open "{secret_file}"')
            else:  # Linux
                os.system(f'xdg-open "{secret_file}"')
        except Exception as e:
            self.logger.error(f"Could not open secret.txt: {str(e)}")
            messagebox.showerror("Error", f"Could not open secret.txt: {str(e)}")
            
    def view_logs(self):
        """Open the logs directory"""
        log_dir = Path("logs")
        if not log_dir.exists():
            messagebox.showinfo("No Logs", "No log files found.")
            return
            
        try:
            if sys.platform == 'win32':
                os.startfile(log_dir)
            elif sys.platform == 'darwin':  # macOS
                os.system(f'open "{log_dir}"')
            else:  # Linux
                os.system(f'xdg-open "{log_dir}"')
        except Exception as e:
            self.logger.error(f"Could not open logs directory: {str(e)}")
            messagebox.showerror("Error", f"Could not open logs directory: {str(e)}")
    
    def view_backups(self):
        """Open the backups directory"""
        if not self.backup_dir.exists():
            messagebox.showinfo("No Backups", "No backup files found.")
            return
            
        try:
            if sys.platform == 'win32':
                os.startfile(self.backup_dir)
            elif sys.platform == 'darwin':  # macOS
                os.system(f'open "{self.backup_dir}"')
            else:  # Linux
                os.system(f'xdg-open "{self.backup_dir}"')
        except Exception as e:
            self.logger.error(f"Could not open backups directory: {str(e)}")
            messagebox.showerror("Error", f"Could not open backups directory: {str(e)}")
            
    def start_sanitize_thread(self, filename):
        """Start sanitization in a separate thread to keep UI responsive"""
        if not filename:
            self.results_text.delete(1.0, tk.END)
            self.results_text.insert(tk.END, "Nothing to Sanitize...\n")
            messagebox.showwarning('No file to Sanitize', 
                            '     WARNING:\n\nPlease, select a config or\nlog file to sanitize first...')
            return
            
        if self.processing:
            messagebox.showinfo("Processing", "Already processing a file. Please wait.")
            return
            
        self.processing = True
        self.results_text.delete(1.0, tk.END)
        self.progress_var.set(0)
        self.status_var.set("Starting sanitization...")
        
        thread = threading.Thread(target=self.sanitize_file, args=(filename,))
        thread.daemon = True
        thread.start()
        
    def detect_device_type(self, content):
        """Auto-detect device type based on configuration content patterns"""
        self.update_progress(10, "Detecting device type...")
        
        # Define signature patterns for each vendor
        signatures = {
            "cisco": ["hostname ", "interface ", "service ", "boot system"],
            "fortinet": ["config ", "end", "next", "vdom"],
            "juniper": ["set system host-name", "set interfaces", "set security"],
            "huawei": ["sysname ", "interface ", "return", "quit"],
            "paloalto": ["set deviceconfig", "set network interface", "<vsys>"],
            "gigamon": ["chassis ", "gigasmart ", "port-pair ", "traffic-map ", "nhp-profile "]
        }
        
        # Count matches for each vendor
        matches = {vendor: 0 for vendor in signatures}
        for vendor, patterns in signatures.items():
            for pattern in patterns:
                if pattern in content:
                    matches[vendor] += 1
        
        # Find the vendor with the most matches
        best_match = max(matches.items(), key=lambda x: x[1])
        if best_match[1] > 0:
            self.logger.info(f"Auto-detected device type: {best_match[0]}")
            return best_match[0]
        
        # Default to cisco if no matches found
        self.logger.info("Could not auto-detect device type, defaulting to cisco")
        return "cisco"
        
    def create_backup(self, path):
        """Create a backup of the original file before sanitizing"""
        self.update_progress(15, "Creating backup...")
        try:
            backup_path = self.backup_dir / f"{path.name}.bak"
            import shutil
            shutil.copy2(path, backup_path)
            self.logger.info(f"Created backup: {backup_path}")
            return True
        except Exception as e:
            self.logger.error(f"Failed to create backup: {str(e)}")
            return False
        
    def sanitize_file(self, filename):
        """Sanitize the selected configuration file"""
        try:
            path = Path(filename)
            self.update_progress(5, f"Processing {path.name}...")
            
            # Create backup if option is selected
            if self.create_backup.get():
                backup_success = self.create_backup(path)
                if not backup_success:
                    messagebox.askokcancel("Backup Failed", 
                                       "Failed to create backup file. Continue anyway?")
            
            # Read input file
            with open(path, "r", encoding="ascii", errors='ignore') as f:
                content = f.read()
                
            # Update UI
            self.update_ui(f"Working on file: \n{filename}\n")
            
            # Determine device type - use selected or auto-detect
            vendor = self.vendor.get()
            if vendor == "auto":
                vendor = self.detect_device_type(content)
                self.update_ui(f"Auto-detected device type: {vendor}\n")
            
            # Remove common passwords
            self.update_progress(30, "Removing common passwords...")
            self.update_ui("Removing common and usual passwords....\n")
            for password in self.sensitive_data["common_passwords"]:
                content = content.replace(password, "*****")
            
            # Sanitize based on device type
            self.update_progress(50, f"Applying {vendor}-specific sanitization...")
            if vendor in self.supported_vendors:
                content = self.supported_vendors[vendor](content)
            else:
                self.update_ui(f"Warning: Unsupported device type '{vendor}'. Using generic sanitization.\n")
                content = self.sanitize_generic(content)
            
            # Remove extra lines
            self.update_progress(70, "Removing extra lines...")
            self.update_ui("Removing extra lines....\n")
            for extra in ["<--- More --->\n", "              \n"]:
                content = content.replace(extra, "")
                
            # Create output filename with timestamp
            timestamp = datetime.now().strftime("%Y-%B-%d %H;%M;%S")
            output_path = path.with_name(f"{path.stem}[{timestamp} CLEAN]{path.suffix}")
                
            # Write sanitized file
            self.update_progress(90, "Writing sanitized file...")
            self.update_ui(f"Writing file:\n{output_path}\n")
            with open(output_path, "w") as f:
                f.write(content)
                
            self.update_progress(100, "Complete!")
            self.update_ui("Done!!!\n")
            
            # Log completion
            self.logger.info(f"Successfully sanitized {path.name} to {output_path.name}")
            
            # Add buttons for next actions
            self.root.after(0, self.add_action_buttons)
            
        except Exception as e:
            self.logger.error(f"Error during sanitization: {str(e)}")
            self.update_ui(f"Error during sanitization: {str(e)}\n")
            messagebox.showerror("Error", f"Failed to sanitize file: {str(e)}")
        finally:
            self.processing = False
    
    def update_progress(self, value, status=None):
        """Update progress bar and status label"""
        self.progress_value = value
        self.root.after(0, self._do_update_progress, value, status)
    
    def _do_update_progress(self, value, status):
        """Update UI elements from main thread"""
        self.progress_var.set(value)
        if status:
            self.status_var.set(status)
    
    def update_ui(self, message):
        """Thread-safe update to the UI text area"""
        self.root.after(0, self._do_update_ui, message)
    
    def _do_update_ui(self, message):
        """Update UI text from main thread"""
        self.results_text.insert(tk.END, message)
        self.results_text.see(tk.END)  # Auto-scroll to the bottom
    
    def add_action_buttons(self):
        """Add action buttons after processing"""
        # Exit button
        self.exit_button = Button(
            self.root,
            text="Exit",
            command=self.exit_program,
            width=10
        )
        self.exit_button.place(x=320, y=430)
        
        # Restart button
        self.restart_button = Button(
            self.root,
            text="Restart",
            command=self.restart_program,
            width=10
        )
        self.restart_button.place(x=220, y=430)
        
        # Process another file button
        self.another_button = Button(
            self.root,
            text="Another File",
            command=self.reset_ui,
            width=10
        )
        self.another_button.place(x=120, y=430)
    
    def reset_ui(self):
        """Reset the UI for processing another file"""
        self.filename.set("")
        self.results_text.delete(1.0, tk.END)
        self.progress_var.set(0)
        self.status_var.set("Ready")
        
        # Remove action buttons
        if hasattr(self, 'exit_button'):
            self.exit_button.place_forget()
        if hasattr(self, 'restart_button'):
            self.restart_button.place_forget()
        if hasattr(self, 'another_button'):
            self.another_button.place_forget()
            
    def preview_sanitize(self, filename):
        """Preview sanitization without actually writing files"""
        if not filename:
            messagebox.showwarning('No file to Sanitize', 
                            '     WARNING:\n\nPlease, select a config or\nlog file to sanitize first...')
            return
            
        try:
            path = Path(filename)
            
            # Open preview window
            preview_win = tk.Toplevel(self.root)
            preview_win.title(f"Preview Sanitization: {path.name}")
            
            win_width = 800
            win_height = 600
            screen_width = self.root.winfo_screenwidth()
            screen_height = self.root.winfo_screenheight()
            x_pos = screen_width // 2 - win_width // 2
            y_pos = screen_height // 2 - win_height // 2
            preview_win.geometry(f'{win_width}x{win_height}+{x_pos}+{y_pos}')
            
            # Read input file
            with open(path, "r", encoding="ascii", errors='ignore') as f:
                original_content = f.read()
                
            # Create a copy of the content to sanitize
            sanitized_content = original_content
            
            # Determine device type
            vendor = self.vendor.get()
            if vendor == "auto":
                vendor = self.detect_device_type(original_content)
            
            # Remove common passwords
            for password in self.sensitive_data["common_passwords"]:
                sanitized_content = sanitized_content.replace(password, "*****")
            
            # Apply vendor-specific sanitization
            if vendor in self.supported_vendors:
                sanitized_content = self.supported_vendors[vendor](sanitized_content)
            else:
                sanitized_content = self.sanitize_generic(sanitized_content)
                
            # Remove extra lines
            for extra in ["<--- More --->\n", "              \n"]:
                sanitized_content = sanitized_content.replace(extra, "")
            
            # Create a frame for each text area
            frame_container = ttk.Frame(preview_win)
            frame_container.pack(fill="both", expand=True, padx=10, pady=10)
            
            # Split into two columns
            original_frame = ttk.LabelFrame(frame_container, text="Original Content")
            original_frame.grid(row=0, column=0, sticky="nsew", padx=5, pady=5)
            
            sanitized_frame = ttk.LabelFrame(frame_container, text="Sanitized Preview")
            sanitized_frame.grid(row=0, column=1, sticky="nsew", padx=5, pady=5)
            
            # Configure grid weights
            frame_container.columnconfigure(0, weight=1)
            frame_container.columnconfigure(1, weight=1)
            frame_container.rowconfigure(0, weight=1)
            
            # Create text areas with scrollbars
            original_text = scrolledtext.ScrolledText(original_frame, wrap=tk.WORD)
            original_text.pack(fill="both", expand=True)
            original_text.insert(tk.END, original_content)
            original_text.config(state="disabled")  # Make read-only
            
            sanitized_text = scrolledtext.ScrolledText(sanitized_frame, wrap=tk.WORD)
            sanitized_text.pack(fill="both", expand=True)
            sanitized_text.insert(tk.END, sanitized_content)
            sanitized_text.config(state="disabled")  # Make read-only
            
            # Add buttons at the bottom
            button_frame = ttk.Frame(preview_win)
            button_frame.pack(fill="x", padx=10, pady=10)
            
            # Close button
            close_button = ttk.Button(
                button_frame,
                text="Close Preview",
                command=preview_win.destroy
            )
            close_button.pack(side=tk.RIGHT, padx=5)
            
            # Proceed button
            proceed_button = ttk.Button(
                button_frame,
                text="Proceed with Sanitization",
                command=lambda: [preview_win.destroy(), self.start_sanitize_thread(filename)]
            )
            proceed_button.pack(side=tk.RIGHT, padx=5)
            
            # Add a stats label
            diff_count = sum(1 for a, b in zip(original_content, sanitized_content) if a != b)
            percentage = (diff_count / len(original_content)) * 100 if original_content else 0
            
            stats_text = (f"File: {path.name}\n"
                         f"Size: {len(original_content):,} characters\n"
                         f"Modified: {diff_count:,} characters ({percentage:.1f}%)\n"
                         f"Detected device type: {vendor}")
            
            stats_label = ttk.Label(button_frame, text=stats_text)
            stats_label.pack(side=tk.LEFT, padx=5)
            
        except Exception as e:
            self.logger.error(f"Error in preview: {str(e)}")
            messagebox.showerror("Preview Error", f"Failed to preview file: {str(e)}")
    
    def sanitize_fortinet(self, content):
        """Sanitize Fortinet configuration files"""
        self.update_ui("Detected Fortinet configuration\n")
        self.update_ui("Removing encrypted passwords....\n")
        
        # Use regular expressions for more robust pattern matching
        # Replace ENC patterns
        content = re.sub(r'(ENC\s+[^\n]+)', '[NO-VALID-INFO]\\\\par', content)
        
        # Remove certificates and keys
        self.update_ui("Removing certificates and encryption keys...\n")
        
        # Find and sanitize private keys
        content = re.sub(r'(set private-key\s+"[^"]*")', r'\1\n[NO-VALID-KEY]', content)
        
        # Find and sanitize certificates
        in_cert = False
        lines = content.split('\n')
        for i, line in enumerate(lines):
            if "BEGIN CERTIFICATE" in line:
                in_cert = True
            elif "END CERTIFICATE" in line:
                in_cert = False
                lines[i] = "[NO-VALID-CERTIFICATE]"
            elif in_cert:
                lines[i] = "[CERTIFICATE-DATA-REMOVED]"
                
        return '\n'.join(lines)
    
    def sanitize_cisco(self, content):
        """Sanitize Cisco configuration files"""
        self.update_ui("Detected Cisco configuration\n")
        self.update_ui("Removing CISCO passwords....\n")
        
        # Use regular expressions for more robust pattern matching
        patterns = self.sensitive_data["cisco_patterns"]
        
        for pattern in patterns:
            # Match pattern followed by text until end of line
            content = re.sub(f'{pattern}([^\n]+)', f'{pattern}[################]', content)
            
        # Special handling for enable secret
        content = re.sub(r'(enable secret)([^\n]+)', r'\1 [SECRET-REMOVED]', content)
        
        # Special handling for SNMP community strings
        content = re.sub(r'(snmp-server community)([^\n]+)', r'\1 [COMMUNITY-REMOVED]', content)
        
        return content
    
    def sanitize_juniper(self, content):
        """Sanitize Juniper configuration files"""
        self.update_ui("Detected Juniper configuration\n")
        self.update_ui("Removing Juniper sensitive data...\n")
        
        patterns = self.sensitive_data["juniper_patterns"]
        
        for pattern in patterns:
            content = re.sub(f'{pattern}([^\n;]+)', f'{pattern}[REMOVED]', content)
            
        # Handle SSH keys and certificates
        content = re.sub(r'ssh-[dr]sa\s+[^\n;]+', '[SSH-KEY-REMOVED]', content)
        
        return content
    
    def sanitize_huawei(self, content):
        """Sanitize Huawei configuration files"""
        self.update_ui("Detected Huawei configuration\n")
        self.update_ui("Removing Huawei sensitive data...\n")
        
        patterns = self.sensitive_data["huawei_patterns"]
        
        for pattern in patterns:
            content = re.sub(f'{pattern}([^\n]+)', f'{pattern}[REMOVED]', content)
            
        # Handle cipher and authentication data
        content = re.sub(r'(cipher|authentication-scheme)([^\n]+)', r'\1 [REMOVED]', content)
        
        return content
    
    def sanitize_paloalto(self, content):
        """Sanitize Palo Alto configuration files"""
        self.update_ui("Detected Palo Alto configuration\n")
        self.update_ui("Removing Palo Alto sensitive data...\n")
        
        patterns = self.sensitive_data["paloalto_patterns"]
        
        for pattern in patterns:
            content = re.sub(f'{pattern}([^\n]+)', f'{pattern}[REMOVED]', content)
            
        # Handle certificates and keys
        content = re.sub(r'(<key>.*?</key>)', '[KEY-REMOVED]', content, flags=re.DOTALL)
        content = re.sub(r'(<cert>.*?</cert>)', '[CERT-REMOVED]', content, flags=re.DOTALL)
        
        return content
        
    def sanitize_gigamon(self, content):
        """Sanitize Gigamon configuration files"""
        self.update_ui("Detected Gigamon configuration\n")
        self.update_ui("Removing Gigamon sensitive data...\n")
        
        patterns = self.sensitive_data["gigamon_patterns"]
        
        for pattern in patterns:
            content = re.sub(f'{pattern}([^\n]+)', f'{pattern}[REMOVED]', content)
            
        # Handle specific Gigamon patterns
        
        # SNMP communities
        content = re.sub(r'(snmp-community\s+)([^\n]+)', r'\1[SNMP-COMMUNITY-REMOVED]', content)
        
        # Cluster shared secret
        content = re.sub(r'(cluster\s+shared-secret\s+)([^\n]+)', r'\1[SHARED-SECRET-REMOVED]', content)
        
        # Tacacs/RADIUS server keys
        content = re.sub(r'(tacacs-server\s+key\s+)([^\n]+)', r'\1[KEY-REMOVED]', content)
        content = re.sub(r'(radius-server\s+key\s+)([^\n]+)', r'\1[KEY-REMOVED]', content)
        
        # SSH keys in authorized-keys sections
        in_ssh_section = False
        lines = content.split('\n')
        for i, line in enumerate(lines):
            if re.search(r'authorized-keys\s+\w+', line):
                in_ssh_section = True
            elif in_ssh_section and line.strip() == "exit":
                in_ssh_section = False
            elif in_ssh_section and line.strip() and not line.strip().startswith('#'):
                lines[i] = "[SSH-KEY-REMOVED]"
                
        # Certificates and encrypted content
        content = '\n'.join(lines)
        content = re.sub(r'(certificate\s+)([^\n]+)', r'\1[CERTIFICATE-REMOVED]', content)
        content = re.sub(r'(encrypted-password\s+)([^\n]+)', r'\1[ENCRYPTED-PASSWORD-REMOVED]', content)
        
        return content
    
    def sanitize_generic(self, content):
        """Generic sanitization for unknown device types"""
        self.update_ui("Using generic sanitization...\n")
        
        # Common sensitive patterns across network devices
        generic_patterns = [
            r'password\s+\S+', 
            r'secret\s+\S+',
            r'community\s+\S+',
            r'key\s+\S+',
            r'username\s+\S+\s+password\s+\S+',
            r'encrypted-password\s+\S+',
            r'auth-password\s+\S+'
        ]
        
        for pattern in generic_patterns:
            content = re.sub(pattern, '[SENSITIVE-DATA-REMOVED]', content)
            
        # Replace any base64/hex-like strings that might be keys or certificates
        content = re.sub(r'(?<!\w)[a-zA-Z0-9+/]{20,}={0,2}(?!\w)', '[POSSIBLE-ENCODED-DATA]', content)
        
        return content
    
    def show_help(self):
        """Display help message box"""
        help_text = (
            "CONFIG SANITIZER TOOL INSTRUCTIONS\n\n"
            "1. Select the log or config file (file must be in ASCII text format)\n"
            "2. Choose a device type or use Auto Detection\n"
            "3. Use Preview to see expected changes without modifying any files\n"
            "4. Press Sanitize button to process the file\n"
            "5. The new sanitized file will be saved in the same directory\n\n"
            "The tool removes the following sensitive information:\n"
            "- Passwords, authentication keys, and secret phrases\n"
            "- Certificates and encryption keys\n"
            "- SNMP community strings\n"
            "- API tokens and other credentials\n\n"
            "You can add your own passwords to sanitize by editing the secret.txt file\n"
            "in the File menu.\n\n"
            "A backup copy of the original file is created before sanitization."
        )
        
        messagebox.showinfo('Sanitizer Info', help_text)
    
    def show_about(self):
        """Show about dialog"""
        win_x = self.root.winfo_rootx() + 200
        win_y = self.root.winfo_rooty() + 25
        
        about_window = tk.Toplevel(self.root)
        about_window.geometry(f'300x380+{win_x}+{win_y}')
        about_window.title("About this")
        about_window.resizable(False, False)
        
        title_label = ttk.Label(
            about_window, 
            text="Sanitizzer V1.7.1 \n@Mar 2022 lgp DevOps\n"
        )
        title_label.config(font=("Arial", 14, "bold"))
        title_label.place(x=20, y=200)
        
        info_label = ttk.Label(
            about_window, 
            text="This program will erase sensitive information\n"
                 "like username, passwords, keys, and will modify \n"
                 "certificates in configuration files and log files to \n"
                 "avoid the exposure of this information in case \n"
                 "you need to send the file to an external provider \n"
                 "or contractor."
        )
        info_label.config(font=("Arial", 10))
        info_label.place(x=10, y=75)
        
        # Additional features label
        enhancements_label = ttk.Label(
            about_window,
            text=" "
                 ""
        )
        enhancements_label.config(font=("Arial", 9))
        enhancements_label.place(x=10, y=280)
        
        warning_label1 = ttk.Label(about_window, text=u"\u26A0")
        warning_label1.config(foreground="Blue", font=("Arial", 30))
        warning_label1.place(x=5, y=3)
        
        warning_label2 = ttk.Label(about_window, text=u"\u26A0")
        warning_label2.config(foreground="Orange", font=("Arial", 30))
        warning_label2.place(x=235, y=320)
        
        exit_button = Button(
            about_window,
            text="Exit",
            command=about_window.destroy,
            width=10
        )
        exit_button.place(x=100, y=340)
    
    def restart_program(self):
        """Restart the application"""
        python = sys.executable
        os.execl(python, python, *sys.argv)
    
    def exit_program(self):
        """Exit the application"""
        if messagebox.askokcancel("Confirm Exit", "Are you sure you want to exit?"):
            self.logger.info("Application closed by user")
            sys.exit(0)


def main():
    """Entry point for the application"""
    try:
        root = tk.Tk()
        app = ConfigSanitizerApp(root)
        root.mainloop()
    except Exception as e:
        # Catch any uncaught exceptions
        logging.error(f"Unhandled exception: {str(e)}", exc_info=True)
        messagebox.showerror("Fatal Error", f"An unexpected error occurred: {str(e)}\n\nThe application will now close.")
        sys.exit(1)


if __name__ == "__main__":
    main()