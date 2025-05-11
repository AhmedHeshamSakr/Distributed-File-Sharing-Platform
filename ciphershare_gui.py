# ciphershare_gui.py
import customtkinter as ctk
import threading
import time
import os
import socket
import json
from PIL import Image, ImageTk
import logging
from pathlib import Path

# Import backend components
from fileshare_peer import FileSharePeer
from fileshare_client import FileShareClient

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('CipherShareGUI')

# Constants
APP_NAME = "CipherShare"
APP_VERSION = "1.0.0"
DEFAULT_THEME = "dark"  # or "light", "system"
DEFAULT_WIDTH = 1200
DEFAULT_HEIGHT = 700

class CipherShareApp(ctk.CTk):
    """Main application window for CipherShare"""
    
    def __init__(self, host, port, rendezvous_host, rendezvous_port):
        super().__init__()
        
        # Initialize backend components
        self.peer = FileSharePeer(host, port, rendezvous_host, rendezvous_port)
        self.client = FileShareClient(rendezvous_host, rendezvous_port)
        
        # Start peer in background thread
        self.peer_thread = threading.Thread(target=self.peer.start)
        self.peer_thread.daemon = True
        self.peer_thread.start()
        
        # Set up the main window
        self.title(f"{APP_NAME} - Secure Distributed File Sharing")
        self.geometry(f"{DEFAULT_WIDTH}x{DEFAULT_HEIGHT}")
        self.minsize(800, 600)
        
        # Set theme
        ctk.set_appearance_mode(DEFAULT_THEME)
        ctk.set_default_color_theme("blue")
        
        # Create assets folder for icons and images
        self.assets_dir = Path("assets")
        if not self.assets_dir.exists():
            self.assets_dir.mkdir()
        
        # Initialize variables
        self.authenticated = False
        self.current_username = None
        self.search_results = []
        self.current_view = "login"  # login, register, main, settings
        
        # Set up the UI components
        self.setup_ui()
        
        # Periodic refresh of file lists
        self.refresh_running = True
        self.refresh_thread = threading.Thread(target=self.background_refresh)
        self.refresh_thread.daemon = True
        self.refresh_thread.start()
    
    def setup_ui(self):
        """Set up the main UI components"""
        # Create main container
        self.main_container = ctk.CTkFrame(self)
        self.main_container.pack(fill=ctk.BOTH, expand=True, padx=10, pady=10)
        
        # Set up the different views (only one will be visible at a time)
        self.setup_login_view()
        self.setup_register_view()
        self.setup_main_view()
        self.setup_settings_view()
        
        # Start with login view
        self.show_view("login")
    
    def setup_login_view(self):
        """Create the login screen"""
        self.login_frame = ctk.CTkFrame(self.main_container)
        
        # Logo at the top
        self.login_logo_label = ctk.CTkLabel(
            self.login_frame, 
            text="CipherShare", 
            font=ctk.CTkFont(size=24, weight="bold")
        )
        self.login_logo_label.pack(pady=(40, 20))
        
        # Subtitle
        self.login_subtitle = ctk.CTkLabel(
            self.login_frame,
            text="Secure Distributed File Sharing",
            font=ctk.CTkFont(size=14)
        )
        self.login_subtitle.pack(pady=(0, 40))
        
        # Login form
        self.login_form = ctk.CTkFrame(self.login_frame)
        self.login_form.pack(padx=80, pady=20, fill=ctk.X)
        
        self.username_label = ctk.CTkLabel(self.login_form, text="Username:")
        self.username_label.pack(anchor=ctk.W, pady=(10, 0))
        
        self.username_entry = ctk.CTkEntry(self.login_form, width=300)
        self.username_entry.pack(fill=ctk.X, pady=(0, 10))
        
        self.password_label = ctk.CTkLabel(self.login_form, text="Password:")
        self.password_label.pack(anchor=ctk.W, pady=(10, 0))
        
        self.password_entry = ctk.CTkEntry(self.login_form, width=300, show="•")
        self.password_entry.pack(fill=ctk.X, pady=(0, 20))
        
        # Buttons container
        self.login_buttons = ctk.CTkFrame(self.login_form)
        self.login_buttons.pack(fill=ctk.X, pady=(0, 10))
        
        self.login_button = ctk.CTkButton(
            self.login_buttons, 
            text="Login", 
            command=self.perform_login
        )
        self.login_button.pack(side=ctk.LEFT, padx=5, pady=10)
        
        self.register_redirect_button = ctk.CTkButton(
            self.login_buttons, 
            text="Create Account", 
            command=lambda: self.show_view("register"),
            fg_color="transparent", 
            border_width=1
        )
        self.register_redirect_button.pack(side=ctk.RIGHT, padx=5, pady=10)
        
        # Status message for login errors
        self.login_status = ctk.CTkLabel(self.login_frame, text="", text_color="red")
        self.login_status.pack(pady=10)
    
    def setup_register_view(self):
        """Create the registration screen"""
        self.register_frame = ctk.CTkFrame(self.main_container)
        
        # Title at the top
        self.register_title = ctk.CTkLabel(
            self.register_frame, 
            text="Create New Account", 
            font=ctk.CTkFont(size=20, weight="bold")
        )
        self.register_title.pack(pady=(40, 20))
        
        # Registration form
        self.register_form = ctk.CTkFrame(self.register_frame)
        self.register_form.pack(padx=80, pady=20, fill=ctk.X)
        
        self.reg_username_label = ctk.CTkLabel(self.register_form, text="Username:")
        self.reg_username_label.pack(anchor=ctk.W, pady=(10, 0))
        
        self.reg_username_entry = ctk.CTkEntry(self.register_form, width=300)
        self.reg_username_entry.pack(fill=ctk.X, pady=(0, 10))
        
        self.reg_password_label = ctk.CTkLabel(self.register_form, text="Password:")
        self.reg_password_label.pack(anchor=ctk.W, pady=(10, 0))
        
        self.reg_password_entry = ctk.CTkEntry(self.register_form, width=300, show="•")
        self.reg_password_entry.pack(fill=ctk.X, pady=(0, 10))
        
        self.reg_confirm_label = ctk.CTkLabel(self.register_form, text="Confirm Password:")
        self.reg_confirm_label.pack(anchor=ctk.W, pady=(10, 0))
        
        self.reg_confirm_entry = ctk.CTkEntry(self.register_form, width=300, show="•")
        self.reg_confirm_entry.pack(fill=ctk.X, pady=(0, 20))
        
        # Security info
        self.security_info = ctk.CTkLabel(
            self.register_form, 
            text="Your password will be secured using Argon2id hashing",
            font=ctk.CTkFont(size=10),
            text_color="gray"
        )
        self.security_info.pack(pady=(0, 10))
        
        # Buttons container
        self.register_buttons = ctk.CTkFrame(self.register_form)
        self.register_buttons.pack(fill=ctk.X, pady=(0, 10))
        
        self.register_button = ctk.CTkButton(
            self.register_buttons, 
            text="Register", 
            command=self.perform_registration
        )
        self.register_button.pack(side=ctk.LEFT, padx=5, pady=10)
        
        self.login_redirect_button = ctk.CTkButton(
            self.register_buttons, 
            text="Back to Login", 
            command=lambda: self.show_view("login"),
            fg_color="transparent", 
            border_width=1
        )
        self.login_redirect_button.pack(side=ctk.RIGHT, padx=5, pady=10)
        
        # Status message for registration errors
        self.register_status = ctk.CTkLabel(self.register_frame, text="", text_color="red")
        self.register_status.pack(pady=10)
    
    def setup_main_view(self):
        """Create the main application view"""
        self.main_frame = ctk.CTkFrame(self.main_container)
        
        # Sidebar (left)
        self.sidebar = ctk.CTkFrame(self.main_frame, width=200)
        self.sidebar.pack(side=ctk.LEFT, fill=ctk.Y, padx=10, pady=10)
        
        # User info at top of sidebar
        self.user_frame = ctk.CTkFrame(self.sidebar)
        self.user_frame.pack(fill=ctk.X, padx=10, pady=10)
        
        self.username_display = ctk.CTkLabel(
            self.user_frame,
            text="Not logged in",
            font=ctk.CTkFont(size=14, weight="bold")
        )
        self.username_display.pack(pady=5)
        
        # Navigation buttons
        self.nav_buttons_frame = ctk.CTkFrame(self.sidebar)
        self.nav_buttons_frame.pack(fill=ctk.X, padx=10, pady=10)
        
        self.my_files_button = ctk.CTkButton(
            self.nav_buttons_frame,
            text="My Files",
            command=self.show_my_files
        )
        self.my_files_button.pack(fill=ctk.X, pady=5)
        
        self.shared_with_me_button = ctk.CTkButton(
            self.nav_buttons_frame,
            text="Shared With Me",
            command=self.show_shared_with_me
        )
        self.shared_with_me_button.pack(fill=ctk.X, pady=5)
        
        self.search_button = ctk.CTkButton(
            self.nav_buttons_frame,
            text="Search Files",
            command=self.show_search
        )
        self.search_button.pack(fill=ctk.X, pady=5)
        
        self.upload_button = ctk.CTkButton(
            self.nav_buttons_frame,
            text="Upload File",
            command=self.show_upload
        )
        self.upload_button.pack(fill=ctk.X, pady=5)
        
        # Settings and logout at bottom of sidebar
        self.bottom_buttons_frame = ctk.CTkFrame(self.sidebar)
        self.bottom_buttons_frame.pack(fill=ctk.X, padx=10, pady=10, side=ctk.BOTTOM)
        
        self.settings_button = ctk.CTkButton(
            self.bottom_buttons_frame,
            text="Settings",
            command=lambda: self.show_view("settings"),
            fg_color="transparent",
            border_width=1
        )
        self.settings_button.pack(fill=ctk.X, pady=5)
        
        self.logout_button = ctk.CTkButton(
            self.bottom_buttons_frame,
            text="Logout",
            command=self.perform_logout,
            fg_color="#B22222"  # Red color for logout
        )
        self.logout_button.pack(fill=ctk.X, pady=5)
        
        # Main content area (right)
        self.content_frame = ctk.CTkFrame(self.main_frame)
        self.content_frame.pack(side=ctk.RIGHT, fill=ctk.BOTH, expand=True, padx=10, pady=10)
        
        # Content views (only one visible at a time)
        self.setup_my_files_view()
        self.setup_shared_with_me_view()  # New view for files shared with current user
        self.setup_search_view()
        self.setup_upload_view()
        
        # Default to my files view
        self.current_content = "my_files"
        self.show_content(self.current_content)
    
    def setup_my_files_view(self):
        """Create the 'My Files' view"""
        self.my_files_content = ctk.CTkFrame(self.content_frame)
        
        # Header
        self.my_files_header = ctk.CTkFrame(self.my_files_content)
        self.my_files_header.pack(fill=ctk.X, pady=10)
        
        self.my_files_title = ctk.CTkLabel(
            self.my_files_header,
            text="My Shared Files",
            font=ctk.CTkFont(size=18, weight="bold")
        )
        self.my_files_title.pack(side=ctk.LEFT, padx=10)
        
        self.refresh_button = ctk.CTkButton(
            self.my_files_header,
            text="Refresh",
            command=self.refresh_my_files,
            width=100
        )
        self.refresh_button.pack(side=ctk.RIGHT, padx=10)
        
        # Files list with scrollbar
        self.files_container = ctk.CTkFrame(self.my_files_content)
        self.files_container.pack(fill=ctk.BOTH, expand=True, padx=10, pady=10)
        
        self.files_scrollbar = ctk.CTkScrollbar(self.files_container)
        self.files_scrollbar.pack(side=ctk.RIGHT, fill=ctk.Y)
        
        self.files_canvas = ctk.CTkCanvas(
            self.files_container,
            yscrollcommand=self.files_scrollbar.set,
            highlightthickness=0
        )
        self.files_canvas.pack(side=ctk.LEFT, fill=ctk.BOTH, expand=True)
        
        self.files_scrollbar.configure(command=self.files_canvas.yview)
        
        self.files_frame = ctk.CTkFrame(self.files_canvas)
        self.files_canvas_window = self.files_canvas.create_window(
            (0, 0),
            window=self.files_frame,
            anchor="nw",
            width=self.files_canvas.winfo_width()
        )
        
        # Bind resize event to update canvas
        self.files_canvas.bind('<Configure>', self.on_canvas_configure)
        self.files_frame.bind('<Configure>', self.on_frame_configure)
        
        # Empty state message
        self.empty_files_label = ctk.CTkLabel(
            self.files_frame,
            text="You are not sharing any files.",
            font=ctk.CTkFont(size=14)
        )
        self.empty_files_label.pack(pady=50)

    def setup_shared_with_me_view(self):
        """Create the 'Shared With Me' view"""
        self.shared_with_me_content = ctk.CTkFrame(self.content_frame)
        
        # Header
        self.shared_with_me_header = ctk.CTkFrame(self.shared_with_me_content)
        self.shared_with_me_header.pack(fill=ctk.X, pady=10)
        
        self.shared_with_me_title = ctk.CTkLabel(
            self.shared_with_me_header,
            text="Files Shared With Me",
            font=ctk.CTkFont(size=18, weight="bold")
        )
        self.shared_with_me_title.pack(side=ctk.LEFT, padx=10)
        
        self.refresh_shared_button = ctk.CTkButton(
            self.shared_with_me_header,
            text="Refresh",
            command=self.refresh_shared_with_me,
            width=100
        )
        self.refresh_shared_button.pack(side=ctk.RIGHT, padx=10)
        
        # Files list with scrollbar
        self.shared_files_container = ctk.CTkFrame(self.shared_with_me_content)
        self.shared_files_container.pack(fill=ctk.BOTH, expand=True, padx=10, pady=10)
        
        self.shared_files_scrollbar = ctk.CTkScrollbar(self.shared_files_container)
        self.shared_files_scrollbar.pack(side=ctk.RIGHT, fill=ctk.Y)
        
        self.shared_files_canvas = ctk.CTkCanvas(
            self.shared_files_container,
            yscrollcommand=self.shared_files_scrollbar.set,
            highlightthickness=0
        )
        self.shared_files_canvas.pack(side=ctk.LEFT, fill=ctk.BOTH, expand=True)
        
        self.shared_files_scrollbar.configure(command=self.shared_files_canvas.yview)
        
        self.shared_files_frame = ctk.CTkFrame(self.shared_files_canvas)
        self.shared_files_canvas_window = self.shared_files_canvas.create_window(
            (0, 0),
            window=self.shared_files_frame,
            anchor="nw",
            width=self.shared_files_canvas.winfo_width()
        )
        
        # Bind resize event to update canvas
        self.shared_files_canvas.bind('<Configure>', lambda e: self.on_canvas_configure(e, "shared"))
        self.shared_files_frame.bind('<Configure>', lambda e: self.on_frame_configure(e, "shared"))
        
        # Empty state message
        self.empty_shared_files_label = ctk.CTkLabel(
            self.shared_files_frame,
            text="No files have been shared with you.",
            font=ctk.CTkFont(size=14)
        )
        self.empty_shared_files_label.pack(pady=50)
    
    def setup_search_view(self):
        """Create the 'Search Files' view"""
        self.search_content = ctk.CTkFrame(self.content_frame)
        
        # Search bar
        self.search_bar_frame = ctk.CTkFrame(self.search_content)
        self.search_bar_frame.pack(fill=ctk.X, padx=10, pady=10)
        
        self.search_entry = ctk.CTkEntry(
            self.search_bar_frame,
            placeholder_text="Search by filename or username...",
            height=40
        )
        self.search_entry.pack(side=ctk.LEFT, fill=ctk.X, expand=True, padx=(0, 10))
        
        self.search_execute_button = ctk.CTkButton(
            self.search_bar_frame,
            text="Search",
            command=self.perform_search,
            width=100,
            height=40
        )
        self.search_execute_button.pack(side=ctk.RIGHT)
        
        # Search results with scrollbar
        self.results_container = ctk.CTkFrame(self.search_content)
        self.results_container.pack(fill=ctk.BOTH, expand=True, padx=10, pady=10)
        
        self.results_scrollbar = ctk.CTkScrollbar(self.results_container)
        self.results_scrollbar.pack(side=ctk.RIGHT, fill=ctk.Y)
        
        self.results_canvas = ctk.CTkCanvas(
            self.results_container,
            yscrollcommand=self.results_scrollbar.set,
            highlightthickness=0
        )
        self.results_canvas.pack(side=ctk.LEFT, fill=ctk.BOTH, expand=True)
        
        self.results_scrollbar.configure(command=self.results_canvas.yview)
        
        self.results_frame = ctk.CTkFrame(self.results_canvas)
        self.results_canvas_window = self.results_canvas.create_window(
            (0, 0),
            window=self.results_frame,
            anchor="nw",
            width=self.results_canvas.winfo_width()
        )
        
        # Bind resize event to update canvas
        self.results_canvas.bind('<Configure>', lambda e: self.on_canvas_configure(e, "search"))
        self.results_frame.bind('<Configure>', lambda e: self.on_frame_configure(e, "search"))
        
        # Empty state message
        self.empty_results_label = ctk.CTkLabel(
            self.results_frame,
            text="Search for files across the network",
            font=ctk.CTkFont(size=14)
        )
        self.empty_results_label.pack(pady=50)
    
    def setup_upload_view(self):
        """Create the 'Upload File' view"""
        self.upload_content = ctk.CTkFrame(self.content_frame)
        
        # Header
        self.upload_header = ctk.CTkLabel(
            self.upload_content,
            text="Upload and Share File",
            font=ctk.CTkFont(size=18, weight="bold")
        )
        self.upload_header.pack(pady=(20, 10))
        
        # File selection section
        self.file_selection_frame = ctk.CTkFrame(self.upload_content)
        self.file_selection_frame.pack(fill=ctk.X, padx=50, pady=20)
        
        self.selected_file_label = ctk.CTkLabel(
            self.file_selection_frame,
            text="No file selected",
            font=ctk.CTkFont(size=12)
        )
        self.selected_file_label.pack(fill=ctk.X, padx=10, pady=10)
        
        self.select_file_button = ctk.CTkButton(
            self.file_selection_frame,
            text="Select File",
            command=self.choose_file_to_upload
        )
        self.select_file_button.pack(padx=10, pady=10)
        
        # Sharing options section
        self.sharing_options_frame = ctk.CTkFrame(self.upload_content)
        self.sharing_options_frame.pack(fill=ctk.X, padx=50, pady=20)
        
        self.sharing_type_label = ctk.CTkLabel(
            self.sharing_options_frame,
            text="Sharing Type:",
            font=ctk.CTkFont(size=14)
        )
        self.sharing_type_label.pack(anchor=ctk.W, padx=10, pady=(10, 0))
        
        # Sharing type radio buttons
        self.sharing_type_var = ctk.StringVar(value="public")
        
        self.public_radio = ctk.CTkRadioButton(
            self.sharing_options_frame,
            text="Public (all users can access)",
            variable=self.sharing_type_var,
            value="public",
            command=self.update_sharing_options
        )
        self.public_radio.pack(anchor=ctk.W, padx=20, pady=5)
        
        self.restricted_radio = ctk.CTkRadioButton(
            self.sharing_options_frame,
            text="Restricted (specific users only)",
            variable=self.sharing_type_var,
            value="restricted",
            command=self.update_sharing_options
        )
        self.restricted_radio.pack(anchor=ctk.W, padx=20, pady=5)
        
        # Users list for restricted sharing
        self.users_frame = ctk.CTkFrame(self.sharing_options_frame)
        self.users_frame.pack(fill=ctk.X, padx=20, pady=10)
        
        self.users_label = ctk.CTkLabel(
            self.users_frame,
            text="Enter usernames (comma separated):"
        )
        self.users_label.pack(anchor=ctk.W, pady=(5, 0))
        
        self.users_entry = ctk.CTkEntry(self.users_frame)
        self.users_entry.pack(fill=ctk.X, pady=5)
        
        # Initially hide users frame since public is default
        self.users_frame.pack_forget()
        
        # Upload button
        self.upload_button_frame = ctk.CTkFrame(self.upload_content)
        self.upload_button_frame.pack(fill=ctk.X, padx=50, pady=20)
        
        self.upload_button = ctk.CTkButton(
            self.upload_button_frame,
            text="Upload and Share",
            command=self.perform_upload,
            height=50,
            font=ctk.CTkFont(size=16)
        )
        self.upload_button.pack(pady=10)
        
        # Upload status
        self.upload_status_label = ctk.CTkLabel(
            self.upload_button_frame,
            text="",
            font=ctk.CTkFont(size=12)
        )
        self.upload_status_label.pack(pady=5)
        
        # Initial upload button state (disabled until file selected)
        self.upload_button.configure(state=ctk.DISABLED)
    
    def setup_settings_view(self):
        """Create the settings screen"""
        self.settings_frame = ctk.CTkFrame(self.main_container)
        
        # Header
        self.settings_header = ctk.CTkLabel(
            self.settings_frame,
            text="Settings",
            font=ctk.CTkFont(size=20, weight="bold")
        )
        self.settings_header.pack(pady=(20, 30))
        
        # Settings container
        self.settings_container = ctk.CTkFrame(self.settings_frame)
        self.settings_container.pack(fill=ctk.X, padx=50, pady=10)
        
        # Theme selection
        self.theme_frame = ctk.CTkFrame(self.settings_container)
        self.theme_frame.pack(fill=ctk.X, pady=10)
        
        self.theme_label = ctk.CTkLabel(
            self.theme_frame,
            text="Application Theme:",
            font=ctk.CTkFont(size=14)
        )
        self.theme_label.pack(anchor=ctk.W, padx=10, pady=5)
        
        self.theme_var = ctk.StringVar(value=DEFAULT_THEME)
        
        themes = {
            "light": "Light Theme",
            "dark": "Dark Theme",
            "system": "System Theme"
        }
        
        self.theme_menu = ctk.CTkOptionMenu(
            self.theme_frame,
            values=list(themes.keys()),
            variable=self.theme_var,
            command=self.change_theme,
            dynamic_resizing=False
        )
        self.theme_menu.pack(anchor=ctk.W, padx=20, pady=5)
        
        # Download location
        self.download_frame = ctk.CTkFrame(self.settings_container)
        self.download_frame.pack(fill=ctk.X, pady=10)
        
        self.download_label = ctk.CTkLabel(
            self.download_frame,
            text="Download Location:",
            font=ctk.CTkFont(size=14)
        )
        self.download_label.pack(anchor=ctk.W, padx=10, pady=5)
        
        self.download_path_frame = ctk.CTkFrame(self.download_frame)
        self.download_path_frame.pack(fill=ctk.X, padx=20, pady=5)
        
        self.download_path_entry = ctk.CTkEntry(
            self.download_path_frame,
            placeholder_text="Path to download directory"
        )
        self.download_path_entry.pack(side=ctk.LEFT, fill=ctk.X, expand=True, padx=(0, 5))
        
        self.download_browse_button = ctk.CTkButton(
            self.download_path_frame,
            text="Browse",
            width=100,
            command=self.browse_download_path
        )
        self.download_browse_button.pack(side=ctk.RIGHT)
        
        # Secure storage initialization
        self.secure_storage_frame = ctk.CTkFrame(self.settings_container)
        self.secure_storage_frame.pack(fill=ctk.X, pady=10)
        
        self.secure_storage_label = ctk.CTkLabel(
            self.secure_storage_frame,
            text="Secure Credential Storage:",
            font=ctk.CTkFont(size=14)
        )
        self.secure_storage_label.pack(anchor=ctk.W, padx=10, pady=5)
        
        self.init_secure_storage_button = ctk.CTkButton(
            self.secure_storage_frame,
            text="Initialize Secure Storage",
            command=self.init_secure_storage
        )
        self.init_secure_storage_button.pack(anchor=ctk.W, padx=20, pady=5)
        
        # Back button
        self.back_button = ctk.CTkButton(
            self.settings_frame,
            text="Back",
            command=lambda: self.show_view("main"),
            width=100
        )
        self.back_button.pack(pady=30)
        
        # Initialize download path from client
        self.download_path_entry.insert(0, str(self.client.download_dir))
    
    # Helper methods for UI management
    def show_view(self, view_name):
        """Switch between main application views"""
        # Hide all views first
        self.login_frame.pack_forget()
        self.register_frame.pack_forget()
        self.main_frame.pack_forget()
        self.settings_frame.pack_forget()
        
        # Show the requested view
        if view_name == "login":
            self.login_frame.pack(fill=ctk.BOTH, expand=True)
            # Clear any previous login status messages
            self.login_status.configure(text="")
        elif view_name == "register":
            self.register_frame.pack(fill=ctk.BOTH, expand=True)
            # Clear any previous registration status messages
            self.register_status.configure(text="")
        elif view_name == "main":
            if not self.authenticated:
                # If not authenticated, show login view instead
                self.show_view("login")
                return
            self.main_frame.pack(fill=ctk.BOTH, expand=True)
        elif view_name == "settings":
            self.settings_frame.pack(fill=ctk.BOTH, expand=True)
        
        self.current_view = view_name
    
    def show_content(self, content_name):
        """Switch between content views in the main view"""
        # Hide all content views first
        self.my_files_content.pack_forget()
        self.shared_with_me_content.pack_forget()
        self.search_content.pack_forget()
        self.upload_content.pack_forget()
        
        # Show the requested content
        if content_name == "my_files":
            self.my_files_content.pack(fill=ctk.BOTH, expand=True)
            self.refresh_my_files()
        elif content_name == "shared_with_me":
            self.shared_with_me_content.pack(fill=ctk.BOTH, expand=True)
            self.refresh_shared_with_me()
        elif content_name == "search":
            self.search_content.pack(fill=ctk.BOTH, expand=True)
        elif content_name == "upload":
            self.upload_content.pack(fill=ctk.BOTH, expand=True)
            # Reset upload form
            self.selected_file_label.configure(text="No file selected")
            self.upload_button.configure(state=ctk.DISABLED)
            self.upload_status_label.configure(text="")
        
        self.current_content = content_name
    
    def show_my_files(self):
        """Show the 'My Files' content view"""
        self.show_content("my_files")
    
    def show_shared_with_me(self):
        """Show the 'Shared With Me' content view"""
        self.show_content("shared_with_me")
    
    def show_search(self):
        """Show the 'Search Files' content view"""
        self.show_content("search")
    
    def show_upload(self):
        """Show the 'Upload File' content view"""
        self.show_content("upload")
    
    # Authentication and user management methods
    def perform_login(self):
        """Handle login form submission"""
        username = self.username_entry.get()
        password = self.password_entry.get()
        
        if not username or not password:
            self.login_status.configure(text="Please enter username and password")
            return
        
        # Try to login to local peer first
        success, message = self.peer.login_user(username, password)
        
        if success:
            self.authenticated = True
            self.current_username = username
            
            # Also login the client for file operations
            self.client.login("127.0.0.1", self.peer.port, username, password)
            
            # Update UI
            self.username_display.configure(text=f"Logged in as: {username}")
            
            # Switch to main view
            self.show_view("main")
            
            # Clear login form
            self.username_entry.delete(0, ctk.END)
            self.password_entry.delete(0, ctk.END)
        else:
            self.login_status.configure(text=f"Login failed: {message}")
    
    def perform_logout(self):
        """Handle logout button click"""
        if self.authenticated:
            self.peer.logout_user()
            self.client.logout()
            
            self.authenticated = False
            self.current_username = None
            
            # Switch to login view
            self.show_view("login")
    
    def perform_registration(self):
        """Handle registration form submission"""
        username = self.reg_username_entry.get()
        password = self.reg_password_entry.get()
        confirm = self.reg_confirm_entry.get()
        
        if not username or not password:
            self.register_status.configure(text="Please enter username and password")
            return
        
        if password != confirm:
            self.register_status.configure(text="Passwords do not match")
            return
        
        # Register new user
        success, message = self.peer.register_user(username, password)
        
        if success:
            self.register_status.configure(text="Registration successful!", text_color="green")
            
            # Clear registration form
            self.reg_username_entry.delete(0, ctk.END)
            self.reg_password_entry.delete(0, ctk.END)
            self.reg_confirm_entry.delete(0, ctk.END)
            
            # Switch to login view after a short delay
            self.after(2000, lambda: self.show_view("login"))
        else:
            self.register_status.configure(text=f"Registration failed: {message}")
    
    # File operations methods
    def refresh_my_files(self):
        """Refresh the list of user's shared files"""
        # Clear existing file entries
        for widget in self.files_frame.winfo_children():
            widget.destroy()
        
        # Get shared files from peer
        shared_files = self.peer.shared_files
        
        if not shared_files:
            # Show empty state message
            self.empty_files_label = ctk.CTkLabel(
                self.files_frame,
                text="You are not sharing any files.",
                font=ctk.CTkFont(size=14)
            )
            self.empty_files_label.pack(pady=50)
            return
        
        # Create headers
        headers_frame = ctk.CTkFrame(self.files_frame)
        headers_frame.pack(fill=ctk.X, padx=10, pady=(0, 10))
        
        header_labels = [
            ("Name", 0.3),
            ("Size", 0.15),
            ("Type", 0.15),
            ("Access", 0.2),
            ("Actions", 0.2)
        ]
        
        for text, width in header_labels:
            label = ctk.CTkLabel(
                headers_frame,
                text=text,
                font=ctk.CTkFont(weight="bold"),
                anchor="w"
            )
            label.pack(side=ctk.LEFT, fill=ctk.X, expand=True, padx=5, pady=5)
        
        # Add file entries
        for file_id, info in shared_files.items():
            file_frame = ctk.CTkFrame(self.files_frame)
            file_frame.pack(fill=ctk.X, padx=10, pady=5)
            
            # File name
            name_label = ctk.CTkLabel(
                file_frame,
                text=info['name'],
                anchor="w"
            )
            name_label.pack(side=ctk.LEFT, fill=ctk.X, expand=True, padx=5, pady=5)
            
            # File size
            size_str = self.format_size(info['size'])
            size_label = ctk.CTkLabel(
                file_frame,
                text=size_str,
                anchor="w"
            )
            size_label.pack(side=ctk.LEFT, fill=ctk.X, expand=True, padx=5, pady=5)
            
            # File type
            chunked = "Chunked" if info.get('chunked', False) else "Single"
            type_label = ctk.CTkLabel(
                file_frame,
                text=chunked,
                anchor="w"
            )
            type_label.pack(side=ctk.LEFT, fill=ctk.X, expand=True, padx=5, pady=5)
            
            # Access type
            allowed_users = info.get('allowed_users', [])
            access = f"Restricted ({len(allowed_users)})" if allowed_users else "Public"
            access_label = ctk.CTkLabel(
                file_frame,
                text=access,
                anchor="w"
            )
            access_label.pack(side=ctk.LEFT, fill=ctk.X, expand=True, padx=5, pady=5)
            
            # Actions
            actions_frame = ctk.CTkFrame(file_frame, fg_color="transparent")
            actions_frame.pack(side=ctk.LEFT, fill=ctk.X, expand=True, padx=5, pady=5)
            
            unshare_button = ctk.CTkButton(
                actions_frame,
                text="Unshare",
                command=lambda fid=file_id: self.unshare_file(fid),
                width=80,
                height=25,
                fg_color="#FF6347"  # Tomato red
            )
            unshare_button.pack(side=ctk.LEFT, padx=2)
            
            # If restricted, add edit button
            if allowed_users:
                edit_button = ctk.CTkButton(
                    actions_frame,
                    text="Edit",
                    command=lambda fid=file_id, users=allowed_users: self.edit_permissions(fid, users),
                    width=60,
                    height=25
                )
                edit_button.pack(side=ctk.LEFT, padx=2)
        
        # Update the canvas scroll region
        self.files_frame.update_idletasks()
        self.files_canvas.configure(scrollregion=self.files_canvas.bbox("all"))

    def refresh_shared_with_me(self):
        """Refresh the list of files shared with the current user"""
        # Clear existing shared file entries
        for widget in self.shared_files_frame.winfo_children():
            widget.destroy()
        
        # Show loading indicator
        please_wait = ctk.CTkLabel(
            self.shared_files_frame,
            text="Searching for files shared with you...",
            font=ctk.CTkFont(size=14)
        )
        please_wait.pack(pady=50)
        self.update_idletasks()
        
        # Get files shared with current user
        # This requires the peer to have the update_shared_with_me method implemented
        shared_files = {}
        try:
            # Call the method that we implemented in the backend
            if hasattr(self.peer, 'update_shared_with_me'):
                shared_files = self.peer.update_shared_with_me()
            else:
                # If method isn't implemented yet, use a temporary implementation
                self._temp_update_shared_with_me()
        except Exception as e:
            logger.error(f"Error getting shared files: {e}")
        
        # Remove waiting message
        please_wait.destroy()
        
        if not shared_files:
            # Show empty state message
            self.empty_shared_files_label = ctk.CTkLabel(
                self.shared_files_frame,
                text="No files have been shared with you.",
                font=ctk.CTkFont(size=14)
            )
            self.empty_shared_files_label.pack(pady=50)
            return
        
        # Create headers
        headers_frame = ctk.CTkFrame(self.shared_files_frame)
        headers_frame.pack(fill=ctk.X, padx=10, pady=(0, 10))
        
        header_labels = [
            ("Name", 0.3),
            ("Size", 0.15),
            ("Owner", 0.15),
            ("Source", 0.2),
            ("Actions", 0.2)
        ]
        
        for text, width in header_labels:
            label = ctk.CTkLabel(
                headers_frame,
                text=text,
                font=ctk.CTkFont(weight="bold"),
                anchor="w"
            )
            label.pack(side=ctk.LEFT, fill=ctk.X, expand=True, padx=5, pady=5)
        
        # Add file entries
        for i, (file_id, info) in enumerate(shared_files.items(), 1):
            file_frame = ctk.CTkFrame(self.shared_files_frame)
            file_frame.pack(fill=ctk.X, padx=10, pady=5)
            
            # File name
            name_label = ctk.CTkLabel(
                file_frame,
                text=info['name'],
                anchor="w"
            )
            name_label.pack(side=ctk.LEFT, fill=ctk.X, expand=True, padx=5, pady=5)
            
            # File size
            size_str = self.format_size(info['size'])
            size_label = ctk.CTkLabel(
                file_frame,
                text=size_str,
                anchor="w"
            )
            size_label.pack(side=ctk.LEFT, fill=ctk.X, expand=True, padx=5, pady=5)
            
            # Owner
            owner_label = ctk.CTkLabel(
                file_frame,
                text=info.get('owner', 'unknown'),
                anchor="w"
            )
            owner_label.pack(side=ctk.LEFT, fill=ctk.X, expand=True, padx=5, pady=5)
            
            # Source
            peer_str = f"{info['peer_ip']}:{info['peer_port']}"
            peer_label = ctk.CTkLabel(
                file_frame,
                text=peer_str,
                anchor="w"
            )
            peer_label.pack(side=ctk.LEFT, fill=ctk.X, expand=True, padx=5, pady=5)
            
            # Download button
            download_button = ctk.CTkButton(
                file_frame,
                text="Download",
                command=lambda fid=file_id, ip=info['peer_ip'], port=info['peer_port']: 
                    self.download_shared_file(fid, ip, port),
                width=100,
                height=30
            )
            download_button.pack(side=ctk.LEFT, padx=5, pady=5)
        
        # Update the canvas scroll region
        self.shared_files_frame.update_idletasks()
        self.shared_files_canvas.configure(scrollregion=self.shared_files_canvas.bbox("all"))
    
    def _temp_update_shared_with_me(self):
        """Temporary implementation to gather files shared with current user"""
        # Get peers from rendezvous server
        peers = self.client.get_peers()
        # Dictionary to store files shared with the current user
        shared_with_me = {}
        
        # Query each peer for files shared with current user
        for peer_ip, peer_port in peers:
            # Skip self
            if peer_ip == self.peer.host and peer_port == self.peer.port:
                continue
                
            try:
                # Search for files from this peer
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                sock.connect((peer_ip, peer_port))
                
                # Include authentication info in search request
                search_command = "SEARCH"
                if self.client.session_id and self.client.username:
                    search_command += f" {self.client.username} {self.client.session_id}"
                
                sock.send(search_command.encode())
                
                response = sock.recv(4096).decode()
                sock.close()
                
                if response and not response.startswith("ERROR"):
                    # Parse files shared by this peer
                    for file_line in response.split('\n'):
                        if file_line:
                            parts = file_line.split(':')
                            if len(parts) >= 5:  # Format: file_id:name:size:owner:access_type
                                file_id = parts[0]
                                file_name = parts[1]
                                file_size = int(parts[2])
                                owner = parts[3]
                                
                                # Skip files owned by the current user
                                if owner != self.current_username:
                                    # Store in shared_with_me dict with peer info
                                    shared_with_me[file_id] = {
                                        "name": file_name,
                                        "size": file_size,
                                        "owner": owner,
                                        "peer_ip": peer_ip,
                                        "peer_port": peer_port
                                    }
            except Exception as e:
                logger.warning(f"Error getting files from peer {peer_ip}:{peer_port}: {e}")
        
        # Return the results
        self.peer.files_shared_with_me = shared_with_me
        return shared_with_me
    
    def download_shared_file(self, file_id, peer_ip, peer_port):
        """Download a file that has been shared with the current user"""
        # Get file info first
        file_info = self.client.get_file_info(peer_ip, peer_port, file_id)
        
        if not file_info:
            self._show_message("Error", "Could not retrieve file information", "error")
            return
        
        # Extract file name and size    
        file_name = file_info.get("name", "unknown")
        file_size = file_info.get("size", 0)
        
        # For larger files, show a progress dialog
        if file_size > 1024 * 1024:  # 1 MB
            self._show_download_progress(peer_ip, peer_port, file_id, file_name, file_size, None, max_retries=3)
        else:
            # For smaller files, download directly with retries
            success = self.client.download_file(peer_ip, peer_port, file_id, None, max_retries=3)
            
            if success:
                self._show_message("Download Complete", f"File '{file_name}' has been downloaded successfully.")
            else:
                self._show_message("Download Failed", f"Failed to download file '{file_name}'.", "error")

    def perform_search(self):
        """Search for files in the network"""
        # Clear existing results
        for widget in self.results_frame.winfo_children():
            widget.destroy()
        
        # Show loading indicator
        loading_label = ctk.CTkLabel(
            self.results_frame,
            text="Searching for files...",
            font=ctk.CTkFont(size=14)
        )
        loading_label.pack(pady=50)
        
        # Update UI immediately to show loading state
        self.update_idletasks()
        
        # Perform search (this might take some time)
        search_results = self.client.search_files()
        
        # Remove loading indicator
        loading_label.destroy()
        
        if not search_results:
            # Show empty state message
            empty_label = ctk.CTkLabel(
                self.results_frame,
                text="No files found. Try again later.",
                font=ctk.CTkFont(size=14)
            )
            empty_label.pack(pady=50)
            return
        
        # Store search results for download operations
        self.search_results = search_results
        
        # Create headers
        headers_frame = ctk.CTkFrame(self.results_frame)
        headers_frame.pack(fill=ctk.X, padx=10, pady=(0, 10))
        
        header_labels = [
            ("Name", 0.3),
            ("Size", 0.15),
            ("Owner", 0.15),
            ("Peer", 0.2),
            ("Actions", 0.2)
        ]
        
        for text, width in header_labels:
            label = ctk.CTkLabel(
                headers_frame,
                text=text,
                font=ctk.CTkFont(weight="bold"),
                anchor="w"
            )
            label.pack(side=ctk.LEFT, fill=ctk.X, expand=True, padx=5, pady=5)
        
        # Add file entries
        for i, (ip, port, file_id, name, size, owner, access) in enumerate(search_results):
            result_frame = ctk.CTkFrame(self.results_frame)
            result_frame.pack(fill=ctk.X, padx=10, pady=5)
            
            # File name
            name_label = ctk.CTkLabel(
                result_frame,
                text=name,
                anchor="w"
            )
            name_label.pack(side=ctk.LEFT, fill=ctk.X, expand=True, padx=5, pady=5)
            
            # File size
            size_str = self.format_size(size)
            size_label = ctk.CTkLabel(
                result_frame,
                text=size_str,
                anchor="w"
            )
            size_label.pack(side=ctk.LEFT, fill=ctk.X, expand=True, padx=5, pady=5)
            
            # Owner
            owner_label = ctk.CTkLabel(
                result_frame,
                text=owner,
                anchor="w"
            )
            owner_label.pack(side=ctk.LEFT, fill=ctk.X, expand=True, padx=5, pady=5)
            
            # Peer
            peer_str = f"{ip}:{port}"
            peer_label = ctk.CTkLabel(
                result_frame,
                text=peer_str,
                anchor="w"
            )
            peer_label.pack(side=ctk.LEFT, fill=ctk.X, expand=True, padx=5, pady=5)
            
            # Download button
            download_button = ctk.CTkButton(
                result_frame,
                text="Download",
                command=lambda idx=i: self.download_file(idx),
                width=100,
                height=30
            )
            download_button.pack(side=ctk.LEFT, padx=5, pady=5)
        
        # Update the canvas scroll region
        self.results_frame.update_idletasks()
        self.results_canvas.configure(scrollregion=self.results_canvas.bbox("all"))
    
    def choose_file_to_upload(self):
        """Open file dialog to choose a file to upload"""
        import tkinter.filedialog as filedialog
        
        filename = filedialog.askopenfilename(
            title="Select a file to share",
            filetypes=(("All files", "*.*"),)
        )
        
        if filename:
            self.selected_file_path = filename
            self.selected_file_label.configure(text=os.path.basename(filename))
            self.upload_button.configure(state=ctk.NORMAL)
    
    def update_sharing_options(self):
        """Update UI based on sharing type selection"""
        sharing_type = self.sharing_type_var.get()
        
        if sharing_type == "restricted":
            self.users_frame.pack(fill=ctk.X, padx=20, pady=10)
        else:
            self.users_frame.pack_forget()
    
    def perform_upload(self):
        """Handle file upload and sharing"""
        if not hasattr(self, 'selected_file_path'):
            return
        
        sharing_type = self.sharing_type_var.get()
        
        # Disable button during upload and show status
        self.upload_button.configure(state=ctk.DISABLED)
        self.upload_status_label.configure(text="Uploading file...", text_color="blue")
        
        # Update UI immediately
        self.update_idletasks()
        
        # Start upload in a separate thread to avoid freezing UI
        threading.Thread(target=self._upload_thread).start()
    
    def _upload_thread(self):
        """Background thread for file upload operations"""
        try:
            sharing_type = self.sharing_type_var.get()
            
            if sharing_type == "public":
                # Share with all users
                file_id, message = self.peer.share_file(self.selected_file_path)
            else:
                # Share with specific users
                allowed_users = [user.strip() for user in self.users_entry.get().split(',') if user.strip()]
                if not allowed_users:
                    # If no users specified, revert to public
                    file_id, message = self.peer.share_file(self.selected_file_path)
                else:
                    file_id, message = self.peer.share_file_with_users(self.selected_file_path, allowed_users)
            
            # Update UI in the main thread
            self.after(0, lambda: self._update_upload_status(file_id, message))
            
        except Exception as e:
            # Update UI with error in the main thread
            self.after(0, lambda: self._update_upload_status(None, str(e)))
    
    def _update_upload_status(self, file_id, message):
        """Update UI after upload completes (called from main thread)"""
        if file_id:
            # Success
            self.upload_status_label.configure(text=f"Upload successful! File ID: {file_id}", text_color="green")
            # Reset form after a few seconds
            self.after(3000, self._reset_upload_form)
        else:
            # Error
            self.upload_status_label.configure(text=f"Upload failed: {message}", text_color="red")
            # Re-enable upload button
            self.upload_button.configure(state=ctk.NORMAL)
    
    def _reset_upload_form(self):
        """Reset the upload form after successful upload"""
        self.selected_file_label.configure(text="No file selected")
        if hasattr(self, 'selected_file_path'):
            del self.selected_file_path
        self.upload_button.configure(state=ctk.DISABLED)
        self.upload_status_label.configure(text="")
        self.sharing_type_var.set("public")
        self.users_entry.delete(0, ctk.END)
        self.users_frame.pack_forget()
    
    def download_file(self, index):
        """Download a file from search results"""
        if not self.search_results or index >= len(self.search_results):
            return
        
        # Get file info from search results
        ip, port, file_id, name, size, owner, access = self.search_results[index]
        
        # For larger files, show a progress dialog
        if size > 1024 * 1024:  # 1 MB
            self._show_download_progress(ip, port, file_id, name, size, None, max_retries=3)
        else:
            # For smaller files, download directly with retries
            success = self.client.download_file(ip, port, file_id, None, max_retries=3)
            
            if success:
                self._show_message("Download Complete", f"File '{name}' has been downloaded successfully.")
            else:
                self._show_message("Download Failed", f"Failed to download file '{name}'.", "error")
    
    def _show_download_progress(self, ip, port, file_id, name, size, save_path, max_retries=3):
        """Show download progress dialog and start download in background with retries"""
        # Create progress dialog
        progress_window = ctk.CTkToplevel(self)
        progress_window.title("Downloading File")
        progress_window.geometry("400x250")  # Make taller for status messages
        progress_window.resizable(False, False)
        progress_window.transient(self)  # Set as transient window to main window
        progress_window.grab_set()  # Make it modal
        
        # Center the window
        progress_window.update_idletasks()
        x = self.winfo_x() + (self.winfo_width() // 2) - (progress_window.winfo_width() // 2)
        y = self.winfo_y() + (self.winfo_height() // 2) - (progress_window.winfo_height() // 2)
        progress_window.geometry(f"+{x}+{y}")
        
        # Add content to progress dialog
        file_label = ctk.CTkLabel(
            progress_window,
            text=f"Downloading: {name}",
            font=ctk.CTkFont(size=14, weight="bold")
        )
        file_label.pack(pady=(20, 10))
        
        size_label = ctk.CTkLabel(
            progress_window,
            text=f"Size: {self.format_size(size)}"
        )
        size_label.pack(pady=5)
        
        progress_bar = ctk.CTkProgressBar(progress_window, width=350)
        progress_bar.pack(pady=10)
        progress_bar.set(0)  # Initial progress
        
        status_label = ctk.CTkLabel(
            progress_window,
            text="Initializing download..."
        )
        status_label.pack(pady=5)
        
        # Add retry information
        retry_label = ctk.CTkLabel(
            progress_window,
            text="Attempt 1 of 3"
        )
        retry_label.pack(pady=5)
        
        cancel_button = ctk.CTkButton(
            progress_window,
            text="Cancel",
            command=progress_window.destroy
        )
        cancel_button.pack(pady=10)
        
        # Create shared variables for progress and status
        download_vars = {
            "progress": 0,
            "status": "Starting download...",
            "completed": False,
            "success": False,
            "current_attempt": 1,
            "max_attempts": max_retries,
            "cancelled": False
        }
        
        # Set cancel callback
        def cancel_download():
            download_vars["cancelled"] = True
            progress_window.destroy()
        
        cancel_button.configure(command=cancel_download)
        
        # Start download in a separate thread
        download_thread = threading.Thread(
            target=self._download_thread_with_retry,
            args=(ip, port, file_id, save_path, download_vars, max_retries)
        )
        download_thread.daemon = True
        download_thread.start()
        
        # Periodic update of progress dialog
        def update_progress():
            if not progress_window.winfo_exists() or download_vars["cancelled"]:
                return
                
            progress_bar.set(download_vars["progress"])
            status_label.configure(text=download_vars["status"])
            retry_label.configure(text=f"Attempt {download_vars['current_attempt']} of {download_vars['max_attempts']}")
                
            if download_vars["completed"]:
                progress_window.after(1000, progress_window.destroy)
                if download_vars["success"]:
                    self._show_message("Download Complete", f"File '{name}' has been downloaded successfully.")
                else:
                    self._show_message("Download Failed", f"Failed to download file '{name}' after {max_retries} attempts.", "error")
            else:
                progress_window.after(100, update_progress)
            
        # Start progress updates
        update_progress()
    
    def _download_thread_with_retry(self, ip, port, file_id, save_path, download_vars, max_retries):
        """Background thread for file download with retries and progress tracking"""
        for attempt in range(1, max_retries + 1):
            if download_vars["cancelled"]:
                return
                
            download_vars["current_attempt"] = attempt
            download_vars["progress"] = 0
            download_vars["status"] = f"Starting download attempt {attempt}..."
            
            try:
                # Ensure authentication is valid
                if attempt > 1:
                    download_vars["status"] = "Re-authenticating with peer..."
                    self.client.authenticate_with_peer(ip, port)
                
                # Custom progress callback
                def progress_callback(progress, status):
                    if download_vars["cancelled"]:
                        raise Exception("Download cancelled by user")
                    download_vars["progress"] = progress
                    download_vars["status"] = status
                
                # Attempt download with current client implementation
                # (In a production environment, we'd modify the client to accept a progress callback)
                success = self.client.download_file(ip, port, file_id, save_path)
                
                # Handle result
                if success:
                    download_vars["completed"] = True
                    download_vars["success"] = True
                    download_vars["progress"] = 1.0
                    download_vars["status"] = "Download completed successfully!"
                    return
                elif attempt < max_retries:
                    download_vars["status"] = f"Attempt {attempt} failed. Retrying in 2 seconds..."
                    time.sleep(2)
                else:
                    download_vars["completed"] = True
                    download_vars["success"] = False
                    download_vars["status"] = "All download attempts failed"
                    
            except Exception as e:
                if download_vars["cancelled"]:
                    return
                    
                download_vars["status"] = f"Error: {str(e)}"
                if attempt < max_retries:
                    download_vars["status"] += f" Retrying in 2 seconds..."
                    time.sleep(2)
                else:
                    download_vars["completed"] = True
                    download_vars["success"] = False
    
    def unshare_file(self, file_id):
        """Remove a shared file"""
        if file_id in self.peer.shared_files:
            # Confirm unshare
            confirm = self._show_confirm("Confirm Unshare", 
                                        f"Are you sure you want to unshare file '{self.peer.shared_files[file_id]['name']}'?")
            
            if confirm:
                # Remove file from shared files
                if file_id in self.peer.shared_files:
                    # Delete physical file(s)
                    file_info = self.peer.shared_files[file_id]
                    path = file_info.get("path")
                    
                    if path:
                        if file_info.get("chunked", False):
                            # It's a directory with chunks
                            try:
                                import shutil
                                shutil.rmtree(path)
                            except Exception as e:
                                logger.error(f"Error removing chunks directory: {e}")
                        else:
                            # Single file
                            try:
                                os.remove(path)
                            except Exception as e:
                                logger.error(f"Error removing file: {e}")
                    
                    # Remove metadata
                    del self.peer.shared_files[file_id]
                    self.peer._save_shared_files()
                    
                    # Refresh view
                    self.refresh_my_files()
    
    def edit_permissions(self, file_id, current_users):
        """Edit file access permissions"""
        if file_id not in self.peer.shared_files:
            return
        
        # Create dialog
        permissions_window = ctk.CTkToplevel(self)
        permissions_window.title("Edit Access Permissions")
        permissions_window.geometry("500x300")
        permissions_window.resizable(False, False)
        permissions_window.transient(self)
        permissions_window.grab_set()
        
        # Center the window
        permissions_window.update_idletasks()
        x = self.winfo_x() + (self.winfo_width() // 2) - (permissions_window.winfo_width() // 2)
        y = self.winfo_y() + (self.winfo_height() // 2) - (permissions_window.winfo_height() // 2)
        permissions_window.geometry(f"+{x}+{y}")
        
        # File info
        file_info = self.peer.shared_files[file_id]
        
        file_label = ctk.CTkLabel(
            permissions_window,
            text=f"File: {file_info['name']}",
            font=ctk.CTkFont(size=16, weight="bold")
        )
        file_label.pack(pady=(20, 10))
        
        # Instructions
        instructions = ctk.CTkLabel(
            permissions_window,
            text="Enter usernames (comma separated) to allow access:"
        )
        instructions.pack(pady=(10, 5), padx=20, anchor=ctk.W)
        
        # Users entry
        users_entry = ctk.CTkEntry(permissions_window, width=400)
        users_entry.pack(padx=20, pady=5, fill=ctk.X)
        
        # Pre-fill current users
        users_entry.insert(0, ", ".join(current_users))
        
        # Public option
        public_var = ctk.BooleanVar(value=False)
        public_checkbox = ctk.CTkCheckBox(
            permissions_window,
            text="Make public (accessible to all users)",
            variable=public_var,
            command=lambda: users_entry.configure(state=ctk.DISABLED if public_var.get() else ctk.NORMAL)
        )
        public_checkbox.pack(padx=20, pady=10, anchor=ctk.W)
        
        # Buttons
        buttons_frame = ctk.CTkFrame(permissions_window)
        buttons_frame.pack(fill=ctk.X, padx=20, pady=20)
        
        cancel_button = ctk.CTkButton(
            buttons_frame,
            text="Cancel",
            command=permissions_window.destroy,
            fg_color="transparent",
            border_width=1
        )
        cancel_button.pack(side=ctk.LEFT, padx=10)
        
        save_button = ctk.CTkButton(
            buttons_frame,
            text="Save Changes",
            command=lambda: self._save_permissions(file_id, users_entry.get(), public_var.get(), permissions_window)
        )
        save_button.pack(side=ctk.RIGHT, padx=10)
    
    def _save_permissions(self, file_id, users_str, is_public, dialog):
        """Save updated file permissions"""
        if file_id in self.peer.shared_files:
            if is_public:
                # Make file public (empty allowed_users list)
                self.peer.shared_files[file_id]["allowed_users"] = []
            else:
                # Update allowed users
                allowed_users = [user.strip() for user in users_str.split(',') if user.strip()]
                self.peer.shared_files[file_id]["allowed_users"] = allowed_users
            
            # Save changes
            self.peer._save_shared_files()
            
            # Close dialog
            dialog.destroy()
            
            # Refresh view
            self.refresh_my_files()
    
    # Settings methods
    def change_theme(self, theme_name):
        """Change the application theme"""
        ctk.set_appearance_mode(theme_name)
    
    def browse_download_path(self):
        """Open directory dialog to choose download location"""
        import tkinter.filedialog as filedialog
        
        directory = filedialog.askdirectory(title="Select Download Directory")
        
        if directory:
            # Update entry field
            self.download_path_entry.delete(0, ctk.END)
            self.download_path_entry.insert(0, directory)
            
            # Update client download directory
            self.client.download_dir = Path(directory)
            self.client.download_dir.mkdir(exist_ok=True)
    
    def init_secure_storage(self):
        """Initialize secure credential storage"""
        # Create dialog for master password
        password_window = ctk.CTkToplevel(self)
        password_window.title("Secure Storage Setup")
        password_window.geometry("400x250")
        password_window.resizable(False, False)
        password_window.transient(self)
        password_window.grab_set()
        
        # Center the window
        password_window.update_idletasks()
        x = self.winfo_x() + (self.winfo_width() // 2) - (password_window.winfo_width() // 2)
        y = self.winfo_y() + (self.winfo_height() // 2) - (password_window.winfo_height() // 2)
        password_window.geometry(f"+{x}+{y}")
        
        # Content
        title_label = ctk.CTkLabel(
            password_window,
            text="Set Master Password",
            font=ctk.CTkFont(size=16, weight="bold")
        )
        title_label.pack(pady=(20, 5))
        
        info_label = ctk.CTkLabel(
            password_window,
            text="This password will protect your stored credentials.\nDo not forget it!",
            font=ctk.CTkFont(size=12)
        )
        info_label.pack(pady=(0, 20))
        
        # Password entry
        master_pass_label = ctk.CTkLabel(password_window, text="Master Password:")
        master_pass_label.pack(anchor=ctk.W, padx=20, pady=(10, 0))
        
        master_pass_entry = ctk.CTkEntry(password_window, show="•", width=360)
        master_pass_entry.pack(padx=20, pady=(0, 10))
        
        # Confirm password
        confirm_pass_label = ctk.CTkLabel(password_window, text="Confirm Password:")
        confirm_pass_label.pack(anchor=ctk.W, padx=20, pady=(10, 0))
        
        confirm_pass_entry = ctk.CTkEntry(password_window, show="•", width=360)
        confirm_pass_entry.pack(padx=20, pady=(0, 20))
        
        # Status message
        status_label = ctk.CTkLabel(password_window, text="", text_color="red")
        status_label.pack(pady=5)
        
        # Buttons
        def validate_and_init():
            master_pass = master_pass_entry.get()
            confirm_pass = confirm_pass_entry.get()
            
            if not master_pass:
                status_label.configure(text="Password cannot be empty")
                return
                
            if master_pass != confirm_pass:
                status_label.configure(text="Passwords do not match")
                return
            
            success = self.client.init_secure_storage(master_pass)
            
            if success:
                self.secure_storage_initialized = True
                status_label.configure(text="Secure storage initialized!", text_color="green")
                password_window.after(1500, password_window.destroy)
                
                # Update button state
                self.init_secure_storage_button.configure(
                    text="Secure Storage Initialized",
                    state=ctk.DISABLED
                )
            else:
                status_label.configure(text="Failed to initialize secure storage")
        
        buttons_frame = ctk.CTkFrame(password_window)
        buttons_frame.pack(fill=ctk.X, padx=20, pady=10)
        
        cancel_button = ctk.CTkButton(
            buttons_frame,
            text="Cancel",
            command=password_window.destroy,
            fg_color="transparent",
            border_width=1
        )
        cancel_button.pack(side=ctk.LEFT, padx=10)
        
        save_button = ctk.CTkButton(
            buttons_frame,
            text="Initialize",
            command=validate_and_init
        )
        save_button.pack(side=ctk.RIGHT, padx=10)
    
    # Utility methods
    def format_size(self, size_bytes):
        """Format file size in human-readable format"""
        if size_bytes < 1024:
            return f"{size_bytes} B"
        elif size_bytes < 1024 * 1024:
            return f"{size_bytes/1024:.1f} KB"
        elif size_bytes < 1024 * 1024 * 1024:
            return f"{size_bytes/(1024*1024):.1f} MB"
        else:
            return f"{size_bytes/(1024*1024*1024):.1f} GB"
    
    def _show_message(self, title, message, message_type="info"):
        """Show a modal message dialog"""
        dialog = ctk.CTkToplevel(self)
        dialog.title(title)
        dialog.geometry("400x200")
        dialog.resizable(False, False)
        dialog.transient(self)  # Set as transient window to main window
        dialog.grab_set()  # Make it modal
        
        # Center the window
        dialog.update_idletasks()
        x = self.winfo_x() + (self.winfo_width() // 2) - (dialog.winfo_width() // 2)
        y = self.winfo_y() + (self.winfo_height() // 2) - (dialog.winfo_height() // 2)
        dialog.geometry(f"+{x}+{y}")
        
        # Icon based on message type
        icon_label = ctk.CTkLabel(
            dialog,
            text="ℹ️" if message_type == "info" else "⚠️" if message_type == "warning" else "❌",
            font=ctk.CTkFont(size=48)
        )
        icon_label.pack(pady=(20, 10))
        
        # Message text
        msg_label = ctk.CTkLabel(
            dialog,
            text=message,
            wraplength=350
        )
        msg_label.pack(pady=10, padx=20)
        
        # OK button
        ok_button = ctk.CTkButton(
            dialog,
            text="OK",
            command=dialog.destroy,
            width=100
        )
        ok_button.pack(pady=20)
    
    def _show_confirm(self, title, message):
        """Show a confirmation dialog and return the result"""
        result = [False]  # Use list for mutable reference
        
        dialog = ctk.CTkToplevel(self)
        dialog.title(title)
        dialog.geometry("400x200")
        dialog.resizable(False, False)
        dialog.transient(self)
        dialog.grab_set()
        
        # Center the window
        dialog.update_idletasks()
        x = self.winfo_x() + (self.winfo_width() // 2) - (dialog.winfo_width() // 2)
        y = self.winfo_y() + (self.winfo_height() // 2) - (dialog.winfo_height() // 2)
        dialog.geometry(f"+{x}+{y}")
        
        # Warning icon
        icon_label = ctk.CTkLabel(
            dialog,
            text="⚠️",
            font=ctk.CTkFont(size=48)
        )
        icon_label.pack(pady=(20, 10))
        
        # Message text
        msg_label = ctk.CTkLabel(
            dialog,
            text=message,
            wraplength=350
        )
        msg_label.pack(pady=10, padx=20)
        
        # Buttons
        buttons_frame = ctk.CTkFrame(dialog)
        buttons_frame.pack(fill=ctk.X, padx=20, pady=20)
        
        cancel_button = ctk.CTkButton(
            buttons_frame,
            text="Cancel",
            command=dialog.destroy,
            fg_color="transparent",
            border_width=1
        )
        cancel_button.pack(side=ctk.LEFT, padx=10)
        
        def confirm_action():
            result[0] = True
            dialog.destroy()
        
        confirm_button = ctk.CTkButton(
            buttons_frame,
            text="Confirm",
            command=confirm_action,
            fg_color="#B22222"  # Red
        )
        confirm_button.pack(side=ctk.RIGHT, padx=10)
        
        # Wait for dialog to close
        self.wait_window(dialog)
        
        return result[0]
    
    def on_canvas_configure(self, event, view_type="files"):
        """Handle canvas resize event"""
        # Update the scrollable region to encompass the inner frame
        if view_type == "search":
            self.results_canvas.itemconfig(
                self.results_canvas_window,
                width=event.width
            )
        elif view_type == "shared":
            self.shared_files_canvas.itemconfig(
                self.shared_files_canvas_window,
                width=event.width
            )
        else:
            self.files_canvas.itemconfig(
                self.files_canvas_window,
                width=event.width
            )
    
    def on_frame_configure(self, event, view_type="files"):
        """Reset the scroll region to encompass the inner frame"""
        if view_type == "search":
            self.results_canvas.configure(
                scrollregion=self.results_canvas.bbox("all")
            )
        elif view_type == "shared":
            self.shared_files_canvas.configure(
                scrollregion=self.shared_files_canvas.bbox("all")
            )
        else:
            self.files_canvas.configure(
                scrollregion=self.files_canvas.bbox("all")
            )
    
    def background_refresh(self):
        """Background thread for periodic data refresh"""
        while self.refresh_running:
            time.sleep(5)  # Refresh every 5 seconds
            
            # Only refresh if authenticated and in the main view
            if not self.authenticated or self.current_view != "main":
                continue
            
            # Update UI in main thread
            if self.current_content == "my_files":
                # Only refresh my files if we're on that view
                self.after(0, self.refresh_my_files)
            elif self.current_content == "shared_with_me":
                # Refresh shared with me view if active
                self.after(0, self.refresh_shared_with_me)

def main():
    """Main entry point for the GUI application"""
    import argparse
    
    parser = argparse.ArgumentParser(description="CipherShare GUI")
    parser.add_argument("--host", default="127.0.0.1", help="Host IP for this peer")
    parser.add_argument("--port", type=int, default=0, help="Port for this peer (0 for random)")
    parser.add_argument("--rendezvous-host", default="127.0.0.1", help="Rendezvous server IP")
    parser.add_argument("--rendezvous-port", type=int, default=5555, help="Rendezvous server port")
    
    args = parser.parse_args()
    
    # Use random port if not specified
    if args.port == 0:
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(('', 0))
        args.port = s.getsockname()[1]
        s.close()
    
    # Start the GUI application
    app = CipherShareApp(args.host, args.port, args.rendezvous_host, args.rendezvous_port)
    app.mainloop()

if __name__ == "__main__":
    main()

    