import sys
import tkinter as tk
from tkinter import ttk, messagebox, filedialog, font as tkFont, simpledialog
import psycopg2
import psycopg2.pool # Example for potential future pooling
import psycopg2.errors # For specific error handling
from datetime import datetime
from tkcalendar import DateEntry
import logging
import configparser
import os
import pandas as pd
import bcrypt
try:
    from ttkwidgets import CheckboxTreeview # Option 1: ttkwidgets library
    logging.info("Successfully imported CheckboxTreeview from ttkwidgets.") # Ensure this is INFO
except ImportError:
    CheckboxTreeview = ttk.Treeview # Fallback if no library found
    logging.warning("CheckboxTreeview class (e.g., from ttkwidgets) not found or imported. Bulk checkbox selection in Report Tab will NOT work. Using standard Treeview.") # Ensure this is WARNING


# --- Minimalist Light Color Palette ---
COLOR_PRIMARY_BG = "#FAFAFA"
COLOR_SECONDARY_BG = "#EEEEEE"
COLOR_FRAME_BG = COLOR_PRIMARY_BG
COLOR_CARD_BG = COLOR_SECONDARY_BG
COLOR_TEXT = "#212121"
COLOR_TEXT_SECONDARY = "#757575"
COLOR_BORDER = "#CCCCCC"
COLOR_BORDER_FOCUS = "#9E9E9E"
COLOR_ACCENT = "#26A69A"
COLOR_ACCENT_HOVER = "#00897B"
COLOR_BUTTON_PRIMARY_BG = COLOR_ACCENT
COLOR_BUTTON_PRIMARY_FG = "#FFFFFF"
COLOR_BUTTON_PRIMARY_HOVER = COLOR_ACCENT_HOVER
COLOR_BUTTON_SECONDARY_BG = "#E0E0E0"
COLOR_BUTTON_SECONDARY_FG = COLOR_TEXT
COLOR_BUTTON_SECONDARY_HOVER = "#D5D5D5"
COLOR_ENTRY_BG = COLOR_SECONDARY_BG
COLOR_ENTRY_FG = COLOR_TEXT
COLOR_TREE_BG = COLOR_SECONDARY_BG
COLOR_TREE_FG = COLOR_TEXT
COLOR_HEADER_BG = "#E0E0E0"
COLOR_HEADER_FG = COLOR_TEXT
COLOR_PENDING_ROW = "#FFF59D"
COLOR_PAID_ROW = "#A5D6A7"
COLOR_VOID_ROW = "#EF9A9A"
COLOR_ROW_TEXT = COLOR_TEXT
COLOR_CLEARED_ROW = "#B3E5FC" # <<< ADDED: Light Blue for Cleared

# --- Constants ---
# Statuses
STATUS_PENDING = "Pending"
# Debit Statuses
STATUS_PAID = "Paid"
STATUS_VOID = "Void"
STATUS_CLEARED = "Clearance" # <<< ADDED
DEBIT_STATUS_OPTIONS = [STATUS_PAID, STATUS_PENDING, STATUS_VOID, STATUS_CLEARED] # <<< ADDED

# Credit Statuses
STATUS_RECEIVED = "Received"
STATUS_RETURNED = "Returned"
CREDIT_STATUS_OPTIONS = [STATUS_RECEIVED, STATUS_RETURNED]
# Combined list for filters/context menus
ALL_STATUS_OPTIONS = sorted(list(set([
    STATUS_PAID, STATUS_VOID, STATUS_PENDING, STATUS_CLEARED,
    STATUS_RECEIVED, STATUS_RETURNED
])))
# Transaction Types
TYPE_DEBIT = "Debit"
TYPE_CREDIT = "Credit"
TYPE_TRANSFER = "Transfer" # <<< NEW
TRANSACTION_TYPES = [TYPE_DEBIT, TYPE_CREDIT, TYPE_TRANSFER] # <<< UPDATED


# --- UPDATED Payment Methods ---
METHOD_CHECK = "Check"
METHOD_CASH = "Cash"
METHOD_EFT = "EFT"
METHOD_CC = "Credit Card"            # Unlikely for internal transfer, but keep for now
METHOD_WIRE = "Wire"                 # Unlikely for internal transfer, but keep for now
METHOD_ADJUSTMENT = "Adjustment"
METHOD_TRANSFER = "Internal Transfer Method" # Specific internal marker if needed, or reuse others
# Define methods specifically allowed for the Transfer type UI
TRANSFER_PAYMENT_METHODS = [METHOD_EFT, METHOD_CHECK, METHOD_CASH, METHOD_WIRE] # <<< Allowed for Transfer UI

# Full list for general use (dropdowns might filter based on type)
PAYMENT_METHODS = sorted(list(set([
    METHOD_CHECK, METHOD_CASH, METHOD_EFT, METHOD_CC, METHOD_WIRE,
    METHOD_ADJUSTMENT, METHOD_TRANSFER
]))) # <<< ADDED Transfer marker

# Default Statuses for Transfer Legs
DEFAULT_TRANSFER_DEBIT_STATUS = STATUS_PAID
DEFAULT_TRANSFER_CREDIT_STATUS = STATUS_RECEIVED

# MEMO_OPTIONS = ["Donation", "Business", "Properties", "Personal", "Other"] # Predefined list
MEMO_OTHER = "Other" # Constant for easy checking
DEFAULT_MEMO = "Personal" # Default memo selection

# Database Tables & Columns
TBL_TRANSACTIONS = "transactions"
TBL_COMPANIES = "companies"

COL_ID = "id"
COL_COMPANY_ID = "company_id"
COL_COMPANY_NAME = "company_name" # Alias used in JOINs
COL_BANK_NAME = "bank_name"
COL_DATE = "date"
COL_CHECK_NO = "check_no"
COL_VENDOR = "vendor_name" # Stores Vendor OR Customer Name
COL_REF = "reference"
COL_AMOUNT = "amount"
COL_STATUS = "status"
COL_MEMO = "memo"
COL_NOTES = "notes"
COL_CREATED_AT = "created_at"
# New DB Column Names
COL_TRANSACTION_TYPE = "transaction_type"
COL_PAYMENT_METHOD = "payment_method"
COL_CREATED_BY = "created_by_username" # <<< Alias for treeview column ID

# <<< --- ADD THESE LINES --- >>>
COL_BILL_NO = "bill_no"           # <<< NEW
COL_INVOICE_NO = "invoice_no"     # <<< NEW
# <<< --- END OF ADDED LINES --- >>>



# UI-specific column names for display purposes when splitting vendor/customer
COL_UI_VENDOR_NAME = "vendor_name_ui"  # For display in Treeview as "Vendor"
COL_UI_CUSTOMER_NAME = "customer_name_ui" # For display in Treeview as "Customer"


# Treeview Columns (Order: id, comp, bank, date, check, VENDOR, CUSTOMER, ref, bill, inv, memo, amount, status, type, method, creator)
TREE_COLUMNS_FULL = (
    COL_ID, COL_COMPANY_NAME, COL_BANK_NAME, COL_DATE, COL_CHECK_NO,
    COL_UI_VENDOR_NAME, COL_UI_CUSTOMER_NAME, # <<< MODIFIED: Separate UI Vendor/Customer
    COL_REF, COL_BILL_NO, COL_INVOICE_NO, COL_MEMO, COL_AMOUNT, COL_STATUS,
    COL_TRANSACTION_TYPE, COL_PAYMENT_METHOD,
    COL_CREATED_BY
)
# TREE_COLUMNS_PENDING needs similar adjustment if you want separate columns there too
TREE_COLUMNS_PENDING = (
    COL_ID, COL_COMPANY_NAME, COL_BANK_NAME, COL_DATE, COL_CHECK_NO,
    COL_UI_VENDOR_NAME, COL_UI_CUSTOMER_NAME, # <<< MODIFIED
    COL_REF, COL_BILL_NO, COL_INVOICE_NO, COL_MEMO, COL_AMOUNT, COL_STATUS, COL_CREATED_BY
)

TREE_COLUMNS_COMPANIES = (COL_ID, "name")
# Near the top of the file
TREE_COLUMNS_BANK_SUMMARY = ("Bank Name", "Total Credits", "Total Debits", "Posted Balance", "Difference", "Clearance") # <<< RENAMED
# --- CORRECTED ---
TREE_COLUMNS_MEMO_SUMMARY = ("Memo", "Status", "Count", "Total Amount")
# --- END CORRECTION ---
TREE_COLUMNS_USERS = ("user_id", "username", "role")

# --- Filter Constants ---
FILTER_ALL_COMPANIES = "All Companies"
FILTER_ALL_BANKS = "All Banks"
FILTER_ALL_STATUSES = "All Statuses"
FILTER_ALL_MEMOS = "All Memos"
# <<< NEW Filter Constants >>>
FILTER_ALL_VENDORS = "All Vendors"
FILTER_ALL_CUSTOMERS = "All Customers"
FILTER_ALL_TYPES = "All Types"
FILTER_ALL_METHODS = "All Methods"

# --- Logging Setup ---
log_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
log_file = 'bank_sheet.log'
logger = logging.getLogger()
logger.setLevel(logging.INFO)
for handler in logger.handlers[:]:
    logger.removeHandler(handler)
try:
    file_handler = logging.FileHandler(log_file, encoding='utf-8')
    file_handler.setLevel(logging.INFO)
    file_handler.setFormatter(log_formatter)
    logger.addHandler(file_handler)
except PermissionError as e:
    print(f"Warning: No permission to write log file {log_file}: {e}")
except Exception as e:
    print(f"Error setting up file logger: {e}")

console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
console_handler.setFormatter(log_formatter)
logger.addHandler(console_handler)
logging.info("--- Bank Sheet Application Starting ---")

# --- Configuration ---
DEFAULT_DB_HOST = "localhost"
DEFAULT_DB_PORT = 5433
DEFAULT_DB_NAME = "Bank_Register"
DEFAULT_DB_USER = "postgres"
DEFAULT_DB_PASSWORD = None
CONFIG_FILE = "config.ini"

def load_config():
    config = configparser.ConfigParser()
    db_config = {}
    try:
        if os.path.exists(CONFIG_FILE):
            config.read(CONFIG_FILE)
            if "database" in config:
                db_config.update(config['database'])
            logging.info(f"Loaded configuration from {CONFIG_FILE}")
        else:
            logging.warning(f"{CONFIG_FILE} not found. Using default database settings (password required).")
    except configparser.Error as e:
        logging.error(f"Error reading config file {CONFIG_FILE}: {e}")
        print(f"Config Error: Could not read config file: {e}")

    return {
        'host': db_config.get("host", DEFAULT_DB_HOST),
        'port': int(db_config.get("port", str(DEFAULT_DB_PORT))),
        'name': db_config.get("name", DEFAULT_DB_NAME),
        'user': db_config.get("user", DEFAULT_DB_USER),
        'password': db_config.get("password", DEFAULT_DB_PASSWORD)
    }

def save_config(db_config):
    config = configparser.ConfigParser()
    db_config_save = db_config.copy()
    db_config_save['port'] = str(db_config_save['port'])
    if db_config_save.get('password') is None and 'password' in db_config_save:
         del db_config_save['password']

    config['database'] = db_config_save
    try:
        with open(CONFIG_FILE, 'w') as configfile:
            config.write(configfile)
        logging.info(f"Saved configuration to {CONFIG_FILE}")
        return True
    except IOError as e:
        logging.error(f"Error saving config file {CONFIG_FILE}: {e}")
        messagebox.showerror("Config Error", f"Could not save config file: {e}")
        return False

def hash_password(password):
    """Hashes the given password using bcrypt."""
    if not password:
        return None
    pwd_bytes = password.encode('utf-8')
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(pwd_bytes, salt)
    return hashed.decode('utf-8') # Store hash as string

def verify_password(stored_hash, provided_password):
    """Verifies a provided password against a stored bcrypt hash."""
    if not stored_hash or not provided_password:
        return False
    stored_hash_bytes = stored_hash.encode('utf-8')
    provided_password_bytes = provided_password.encode('utf-8')
    return bcrypt.checkpw(provided_password_bytes, stored_hash_bytes)

# --- NEW: Security Questions Setup Dialog ---
class SecurityQuestionsDialog(tk.Toplevel):
    def __init__(self, parent, db_manager, user_id, username, existing_q1, existing_q2):
        super().__init__(parent)
        self.db_manager = db_manager
        self.user_id = user_id

        self.title(f"Set Security Questions for {username}")
        self.transient(parent)
        self.grab_set()
        self.resizable(False, False)
        self.configure(bg=COLOR_PRIMARY_BG)

        main_frame = ttk.Frame(self, padding="20", style='Card.TFrame')
        main_frame.pack(expand=True, fill="both", padx=15, pady=15)
        main_frame.columnconfigure(1, weight=1)

        ttk.Label(main_frame, text=f"Setup for: {username}", style='Header.TLabel').grid(row=0, column=0, columnspan=2, pady=(0, 15), sticky='w')

        pad_y = (5, 2)
        entry_pad_y = (0, 10)

        # --- Question 1 ---
        ttk.Label(main_frame, text="Question 1:", style='Card.TLabel').grid(row=1, column=0, sticky='nw', padx=5, pady=pad_y)
        self.q1_entry = ttk.Entry(main_frame, width=50, font=text_font)
        self.q1_entry.grid(row=1, column=1, sticky='ew', padx=5, pady=pad_y)
        if existing_q1: self.q1_entry.insert(0, existing_q1)

        ttk.Label(main_frame, text="Answer 1:", style='Card.TLabel').grid(row=2, column=0, sticky='nw', padx=5, pady=pad_y)
        self.a1_entry = ttk.Entry(main_frame, width=50, font=text_font, show='*')
        self.a1_entry.grid(row=2, column=1, sticky='ew', padx=5, pady=entry_pad_y)
        # Don't pre-fill answer, require re-entry if changing question

        # --- Question 2 ---
        ttk.Label(main_frame, text="Question 2:", style='Card.TLabel').grid(row=3, column=0, sticky='nw', padx=5, pady=pad_y)
        self.q2_entry = ttk.Entry(main_frame, width=50, font=text_font)
        self.q2_entry.grid(row=3, column=1, sticky='ew', padx=5, pady=pad_y)
        if existing_q2: self.q2_entry.insert(0, existing_q2)

        ttk.Label(main_frame, text="Answer 2:", style='Card.TLabel').grid(row=4, column=0, sticky='nw', padx=5, pady=pad_y)
        self.a2_entry = ttk.Entry(main_frame, width=50, font=text_font, show='*')
        self.a2_entry.grid(row=4, column=1, sticky='ew', padx=5, pady=entry_pad_y)
        # Don't pre-fill answer

        # --- Info/Error Label ---
        self.info_label = ttk.Label(main_frame, text="Enter question and answer pairs. Answers are case-sensitive.", style='Card.TLabel', foreground=COLOR_TEXT_SECONDARY, wraplength=350)
        self.info_label.grid(row=5, column=0, columnspan=2, pady=(5, 10), sticky='w')

        # --- Buttons ---
        button_frame = ttk.Frame(main_frame, style='Card.TFrame')
        button_frame.grid(row=6, column=0, columnspan=2, sticky='e', pady=(10, 0))

        save_button = ttk.Button(button_frame, text="Save Questions", command=self._save_questions, style='Accent.TButton')
        save_button.pack(side=tk.RIGHT, padx=(10, 0))

        cancel_button = ttk.Button(button_frame, text="Cancel", command=self.destroy)
        cancel_button.pack(side=tk.RIGHT)

        self.q1_entry.focus_set()
        self.protocol("WM_DELETE_WINDOW", self.destroy)
        self.center_window(parent)
        self.wait_window()

    def center_window(self, parent):
        self.update_idletasks()
        parent_x = parent.winfo_rootx(); parent_y = parent.winfo_rooty()
        parent_w = parent.winfo_width(); parent_h = parent.winfo_height()
        win_w = self.winfo_width(); win_h = self.winfo_height()
        x = parent_x + (parent_w // 2) - (win_w // 2)
        y = parent_y + (parent_h // 2) - (win_h // 2)
        self.geometry(f"+{x}+{y}")

    def _save_questions(self):
        q1 = self.q1_entry.get().strip()
        a1 = self.a1_entry.get() # Don't strip answer, case-sensitive
        q2 = self.q2_entry.get().strip()
        a2 = self.a2_entry.get() # Don't strip answer

        a1_hash = None
        a2_hash = None
        errors = []

        # Validate pairs: If question is entered, answer must be too.
        if q1 and not a1: errors.append("Answer 1 is required if Question 1 is entered.")
        if not q1 and a1: errors.append("Question 1 is required if Answer 1 is entered.")
        if q2 and not a2: errors.append("Answer 2 is required if Question 2 is entered.")
        if not q2 and a2: errors.append("Question 2 is required if Answer 2 is entered.")

        # Require at least one question/answer pair
        if not q1 and not q2:
             # Allow clearing questions by saving empty fields
             pass # Proceed to save empty/None values
        elif not q1 and not a1 and not q2 and not a2:
             pass # Also allow clearing

        if errors:
            messagebox.showerror("Input Error", "Please correct errors:\n- " + "\n- ".join(errors), parent=self)
            return

        # Hash answers if they exist
        if q1 and a1:
            a1_hash = hash_password(a1)
            if not a1_hash:
                messagebox.showerror("Error", "Failed to hash Answer 1.", parent=self)
                return
        if q2 and a2:
            a2_hash = hash_password(a2)
            if not a2_hash:
                messagebox.showerror("Error", "Failed to hash Answer 2.", parent=self)
                return

        # Save to DB
        if self.db_manager.update_user_security_info(self.user_id, q1, a1_hash, q2, a2_hash):
            messagebox.showinfo("Success", "Security questions updated successfully.", parent=self)
            self.destroy()
        else:
            messagebox.showerror("Database Error", "Failed to save security questions to the database. Check logs.", parent=self)

# --- NEW: Forgot Password Dialog ---
class ForgotPasswordDialog(tk.Toplevel):
    def __init__(self, parent, db_manager): # Accept db_manager
        logging.debug("ForgotPasswordDialog.__init__ - STARTING")
        try:
            super().__init__(parent)
            logging.debug("ForgotPasswordDialog.__init__ - after super()") # Add more logging
            self.parent = parent
            self.db_manager = db_manager # Store db_manager
            self.user_id = None
            self.username = None
            self.security_q1 = None
            self.security_q2 = None
            self.answer_hash1 = None
            self.answer_hash2 = None
            logging.debug("ForgotPasswordDialog.__init__ - attributes set")

            self.title("Forgot Password")
            self.transient(parent)
            self.grab_set() # Child dialog grabs focus
            self.resizable(False, False)
            self.configure(bg=COLOR_PRIMARY_BG)
            logging.debug("ForgotPasswordDialog.__init__ - window configured")

            # --- Main Frame ---
            self.main_frame = ttk.Frame(self, padding="20", style='Card.TFrame')
            self.main_frame.pack(expand=True, fill="both", padx=15, pady=15)
            self.main_frame.columnconfigure(1, weight=1)
            logging.debug("ForgotPasswordDialog.__init__ - main_frame created")

            # --- Info/Error Label ---
            self.info_label = ttk.Label(self.main_frame, text="", style='Error.TLabel', wraplength=350)
            self.info_label.grid(row=0, column=0, columnspan=2, pady=(0, 10), sticky='ew')
            logging.debug("ForgotPasswordDialog.__init__ - info_label created")

            # --- Step Frames ---
            self.step1_frame = ttk.Frame(self.main_frame, style='Card.TFrame')
            self.step2_frame = ttk.Frame(self.main_frame, style='Card.TFrame')
            self.step3_frame = ttk.Frame(self.main_frame, style='Card.TFrame')
            logging.debug("ForgotPasswordDialog.__init__ - step frames created")

            logging.debug("ForgotPasswordDialog.__init__ - BEFORE _setup_step_1_username()")
            self._setup_step_1_username() # Start with username entry
            logging.debug("ForgotPasswordDialog.__init__ - AFTER _setup_step_1_username()")

            # --- Close Button ---
            button_frame = ttk.Frame(self.main_frame, style='Card.TFrame')
            button_frame.grid(row=5, column=0, columnspan=2, sticky='e', pady=(15, 0)) # Use row 5
            close_button = ttk.Button(button_frame, text="Close", command=self.destroy)
            close_button.pack(side=tk.RIGHT)
            logging.debug("ForgotPasswordDialog.__init__ - close button created")

            self.protocol("WM_DELETE_WINDOW", self.destroy)
            logging.debug("ForgotPasswordDialog.__init__ - BEFORE center_window()")
            self.center_window(parent)
            logging.debug("ForgotPasswordDialog.__init__ - AFTER center_window()")

            logging.debug("ForgotPasswordDialog.__init__ - BEFORE wait_window()")
            self.update_idletasks()
            self.update()
            self.wait_window() # This blocks until the dialog is destroyed
            logging.debug("ForgotPasswordDialog.__init__ - after wait_window()")

        except Exception as e:
            logging.error(f"CRITICAL ERROR in ForgotPasswordDialog.__init__: {e}", exc_info=True)
            messagebox.showerror("Error", f"Failed to open Forgot Password dialog:\n{e}", parent=parent)
            try:
                self.destroy()
            except Exception:
                logging.error("ForgotPasswordDialog: Failed to self.destroy() after __init__ exception.")
                pass

    def center_window(self, parent):
        self.update_idletasks()
        parent_x = parent.winfo_rootx(); parent_y = parent.winfo_rooty()
        parent_w = parent.winfo_width(); parent_h = parent.winfo_height()
        win_w = self.winfo_width(); win_h = self.winfo_height()
        x = parent_x + (parent_w // 2) - (win_w // 2)
        y = parent_y + (parent_h // 2) - (win_h // 2)
        self.geometry(f"+{x}+{y}")

    def _clear_step_frames(self):
        """Hide all step frames."""
        self.step1_frame.grid_remove()
        self.step2_frame.grid_remove()
        self.step3_frame.grid_remove()

    def _show_error(self, message):
        self.info_label.configure(text=message, foreground=COLOR_VOID_ROW)

    def _show_info(self, message):
        self.info_label.configure(text=message, foreground=COLOR_TEXT_SECONDARY)

    # --- Step 1: Enter Username ---
    def _setup_step_1_username(self):
        logging.debug("ForgotPasswordDialog._setup_step_1_username - STARTING")
        self._clear_step_frames()
        self.step1_frame.grid(row=1, column=0, columnspan=2, sticky='nsew')
        self.step1_frame.columnconfigure(1, weight=1)

        self._show_info("Enter your username to begin password reset.")

        ttk.Label(self.step1_frame, text="Username:", style='Card.TLabel').grid(row=0, column=0, sticky='nw', padx=5, pady=(5,2))
        self.username_entry = ttk.Entry(self.step1_frame, width=30, font=text_font)
        self.username_entry.grid(row=0, column=1, sticky='ew', padx=5, pady=(5,10))
        self.username_entry.focus_set()
        self.username_entry.bind("<Return>", lambda e: self._find_user_and_questions())

        find_button = ttk.Button(self.step1_frame, text="Find Security Questions", command=self._find_user_and_questions, style='Accent.TButton')
        find_button.grid(row=1, column=0, columnspan=2, sticky='ew', pady=(5,0), ipady=4)
        logging.debug("ForgotPasswordDialog._setup_step_1_username - finished.")

    def _find_user_and_questions(self):
        self.username = self.username_entry.get().strip()
        if not self.username:
            self._show_error("Username cannot be empty.")
            return

        logging.debug(f"Attempting to find user and questions for: {self.username}")
        user_data = self.db_manager.get_user_by_username(self.username)

        if not user_data:
            self._show_error(f"Username '{self.username}' not found.")
            logging.warning(f"Password reset attempt: User '{self.username}' not found.")
            return

        self.user_id = user_data[0] # user_id is the first element
        logging.debug(f"User found. ID: {self.user_id}")

        # Fetch questions and answer hashes separately
        self.security_q1, self.security_q2 = self.db_manager.get_user_security_questions(self.user_id)
        self.answer_hash1, self.answer_hash2 = self.db_manager.get_user_security_answer_hashes(self.user_id)

        # Check if at least one question is set up
        if not self.security_q1 and not self.security_q2:
            self._show_error(f"No security questions are set up for user '{self.username}'. Cannot reset password.")
            logging.warning(f"Password reset attempt failed: No security questions for user ID {self.user_id}")
            return

        logging.debug(f"Security questions found for user ID {self.user_id}. Q1: {'Set' if self.security_q1 else 'Not Set'}, Q2: {'Set' if self.security_q2 else 'Not Set'}")
        self._setup_step_2_answer_questions()

    # --- Step 2: Answer Questions ---
    def _setup_step_2_answer_questions(self):
        logging.debug("ForgotPasswordDialog._setup_step_2_answer_questions - STARTING")
        self._clear_step_frames()
        self.step2_frame.grid(row=1, column=0, columnspan=2, sticky='nsew')
        self.step2_frame.columnconfigure(1, weight=1)

        self._show_info(f"Answer the security question(s) for user '{self.username}'. Answers are case-sensitive.")

        row_idx = 0
        pad_y = (5, 2)
        entry_pad_y = (0, 10)

        # Question 1 (if exists)
        if self.security_q1:
            ttk.Label(self.step2_frame, text=f"Q1: {self.security_q1}", style='Card.TLabel', wraplength=300).grid(row=row_idx, column=0, columnspan=2, sticky='nw', padx=5, pady=pad_y)
            row_idx += 1
            ttk.Label(self.step2_frame, text="Answer 1:", style='Card.TLabel').grid(row=row_idx, column=0, sticky='nw', padx=5, pady=pad_y)
            self.a1_entry = ttk.Entry(self.step2_frame, width=40, font=text_font, show='*')
            self.a1_entry.grid(row=row_idx, column=1, sticky='ew', padx=5, pady=entry_pad_y)
            self.a1_entry.focus_set() # Focus first answer entry
            row_idx += 1
        else:
            self.a1_entry = None # Ensure it's None if Q1 doesn't exist

        # Question 2 (if exists)
        if self.security_q2:
            ttk.Label(self.step2_frame, text=f"Q2: {self.security_q2}", style='Card.TLabel', wraplength=300).grid(row=row_idx, column=0, columnspan=2, sticky='nw', padx=5, pady=pad_y)
            row_idx += 1
            ttk.Label(self.step2_frame, text="Answer 2:", style='Card.TLabel').grid(row=row_idx, column=0, sticky='nw', padx=5, pady=pad_y)
            self.a2_entry = ttk.Entry(self.step2_frame, width=40, font=text_font, show='*')
            self.a2_entry.grid(row=row_idx, column=1, sticky='ew', padx=5, pady=entry_pad_y)
            if not self.a1_entry: self.a2_entry.focus_set() # Focus Q2 if Q1 doesn't exist
            row_idx += 1
        else:
            self.a2_entry = None # Ensure it's None if Q2 doesn't exist

        # Bind Enter key on last answer entry
        last_entry = self.a2_entry if self.a2_entry else self.a1_entry
        if last_entry:
            last_entry.bind("<Return>", lambda e: self._verify_answers())

        verify_button = ttk.Button(self.step2_frame, text="Verify Answers", command=self._verify_answers, style='Accent.TButton')
        verify_button.grid(row=row_idx, column=0, columnspan=2, sticky='ew', pady=(10,0), ipady=4)
        logging.debug("ForgotPasswordDialog._setup_step_2_answer_questions - finished.")

    def _verify_answers(self):
        logging.debug("Verifying security answers...")
        self._show_info("Verifying...") # Clear previous errors

        answers_correct = True

        # Verify Answer 1 if question exists
        if self.security_q1 and self.a1_entry:
            provided_a1 = self.a1_entry.get() # Don't strip, case-sensitive
            if not provided_a1:
                self._show_error("Answer 1 cannot be empty.")
                return
            if not verify_password(self.answer_hash1, provided_a1):
                answers_correct = False
                logging.warning(f"Password reset: Answer 1 verification failed for user ID {self.user_id}")
            else:
                 logging.debug(f"Password reset: Answer 1 verified for user ID {self.user_id}")

        # Verify Answer 2 if question exists
        if self.security_q2 and self.a2_entry:
            provided_a2 = self.a2_entry.get() # Don't strip, case-sensitive
            if not provided_a2:
                self._show_error("Answer 2 cannot be empty.")
                return
            if not verify_password(self.answer_hash2, provided_a2):
                answers_correct = False
                logging.warning(f"Password reset: Answer 2 verification failed for user ID {self.user_id}")
            else:
                 logging.debug(f"Password reset: Answer 2 verified for user ID {self.user_id}")

        if answers_correct:
            logging.info(f"Security answers verified successfully for user '{self.username}' (ID: {self.user_id}). Proceeding to password reset.")
            self._setup_step_3_reset_password()
        else:
            self._show_error("One or more answers are incorrect.")
            if self.a1_entry: self.a1_entry.delete(0, tk.END)
            if self.a2_entry: self.a2_entry.delete(0, tk.END)
            if self.a1_entry: self.a1_entry.focus_set()
            elif self.a2_entry: self.a2_entry.focus_set()

    # --- Step 3: Reset Password ---
    def _setup_step_3_reset_password(self):
        logging.debug("ForgotPasswordDialog._setup_step_3_reset_password - STARTING")
        self._clear_step_frames()
        self.step3_frame.grid(row=1, column=0, columnspan=2, sticky='nsew')
        self.step3_frame.columnconfigure(1, weight=1)

        self._show_info(f"Enter a new password for user '{self.username}'.")

        row_idx = 0
        pad_y = (5, 2)
        entry_pad_y = (0, 10)

        ttk.Label(self.step3_frame, text="New Password:", style='Card.TLabel').grid(row=row_idx, column=0, sticky='nw', padx=5, pady=pad_y)
        self.new_pass_entry = ttk.Entry(self.step3_frame, width=30, font=text_font, show='*')
        self.new_pass_entry.grid(row=row_idx, column=1, sticky='ew', padx=5, pady=entry_pad_y)
        self.new_pass_entry.focus_set()
        row_idx += 1

        ttk.Label(self.step3_frame, text="Confirm Password:", style='Card.TLabel').grid(row=row_idx, column=0, sticky='nw', padx=5, pady=pad_y)
        self.confirm_pass_entry = ttk.Entry(self.step3_frame, width=30, font=text_font, show='*')
        self.confirm_pass_entry.grid(row=row_idx, column=1, sticky='ew', padx=5, pady=entry_pad_y)
        self.confirm_pass_entry.bind("<Return>", lambda e: self._update_password())
        row_idx += 1

        reset_button = ttk.Button(self.step3_frame, text="Reset Password", command=self._update_password, style='Accent.TButton')
        reset_button.grid(row=row_idx, column=0, columnspan=2, sticky='ew', pady=(10,0), ipady=4)
        logging.debug("ForgotPasswordDialog._setup_step_3_reset_password - finished.")

    def _update_password(self):
        new_password = self.new_pass_entry.get()
        confirm_password = self.confirm_pass_entry.get()

        errors = []
        if not new_password: errors.append("New Password cannot be empty.")
        if len(new_password) < 6: errors.append("Password must be at least 6 characters.")
        if new_password != confirm_password: errors.append("Passwords do not match.")

        if errors:
            self._show_error("Errors:\n- " + "\n- ".join(errors))
            return

        new_hashed_password = hash_password(new_password)
        if not new_hashed_password:
            self._show_error("Failed to hash the new password. Please try again.")
            logging.error(f"Failed to hash password during reset for user ID {self.user_id}")
            return

        logging.info(f"Attempting password update via reset for User ID {self.user_id}")
        if self.db_manager.update_user_password(self.user_id, new_hashed_password):
            messagebox.showinfo("Success", f"Password for user '{self.username}' has been reset successfully.", parent=self)
            logging.info(f"Password reset successful for User ID {self.user_id}.")
            self.destroy() # Close the dialog on success
        else:
            self._show_error("Failed to update password in the database. Check logs.")
            logging.error(f"Database update failed during password reset for User ID {self.user_id}.")

# --- Login Dialog ---
class LoginDialog(tk.Toplevel):
    def __init__(self, parent, db_manager, callback):
        super().__init__(parent)
        self.parent = parent
        self.db_manager = db_manager
        self.callback = callback
        self.user_info = None

        self.title("Login - Bank Sheet")
        self.resizable(False, False)
        self.configure(bg=COLOR_PRIMARY_BG)

        main_frame = ttk.Frame(self, padding="20", style='Card.TFrame')
        main_frame.pack(expand=True, fill="both", padx=15, pady=15)

        ttk.Label(main_frame, text="Login Required", style='Header.TLabel').pack(pady=(0, 15))

        ttk.Label(main_frame, text="Username:", style='Card.TLabel').pack(anchor='w', padx=5)
        self.username_entry = ttk.Entry(main_frame, width=30, font=text_font)
        self.username_entry.pack(fill='x', pady=(0, 10), padx=5)

        ttk.Label(main_frame, text="Password:", style='Card.TLabel').pack(anchor='w', padx=5)
        self.password_entry = ttk.Entry(main_frame, width=30, show="*", font=text_font)
        self.password_entry.pack(fill='x', pady=(0, 15), padx=5)

        self.error_label = ttk.Label(main_frame, text="", style='Error.TLabel', wraplength=250)
        self.error_label.pack(pady=(0, 10))

        button_frame = ttk.Frame(main_frame, style='Card.TFrame')
        button_frame.pack(fill='x', pady=(5, 0))
        
        forgot_button = ttk.Button(button_frame, text="Forgot Password?", command=self._forgot_password, style='Link.TButton')
        forgot_button.pack(side=tk.LEFT, padx=(0, 10))

        login_button = ttk.Button(button_frame, text="Login", command=self._attempt_login, style='Accent.TButton')
        login_button.pack(side=tk.RIGHT, padx=(10, 0))
        cancel_button = ttk.Button(button_frame, text="Cancel", command=self._cancel_login)
        cancel_button.pack(side=tk.RIGHT)

        self.username_entry.focus_set()
        self.bind("<Return>", lambda e: self._attempt_login())
        self.protocol("WM_DELETE_WINDOW", self._cancel_login)

        # --- Centering Logic Update ---
        self.update_idletasks() # Ensure dialog's own dimensions are known

        dialog_width = self.winfo_width()
        dialog_height = self.winfo_height()

        # Use screen dimensions for centering, as parent might be withdrawn/unreliable
        screen_width = self.winfo_screenwidth()
        screen_height = self.winfo_screenheight()

        x = (screen_width // 2) - (dialog_width // 2)
        y = (screen_height // 2) - (dialog_height // 2)

        # Ensure x and y are not negative (can happen if dialog is larger than screen, though unlikely for login)
        x = max(0, x)
        y = max(0, y)
        
        self.geometry(f"{dialog_width}x{dialog_height}+{x}+{y}")
        # --- End Centering Logic Update ---


        self.update_idletasks() # Ensure UI is drawn
        self.update()           # Process events
        self.wait_window()      # Block until dialog is closed

    def _forgot_password(self):
        logging.debug("LoginDialog._forgot_password - Clicked!")
        try:
            ForgotPasswordDialog(self, self.db_manager) # Use self (LoginDialog) as parent
            logging.debug("LoginDialog._forgot_password - ForgotPasswordDialog finished.")
            try:
                if self.winfo_exists():
                    self.focus_force()
            except tk.TclError:
                logging.debug("LoginDialog._forgot_password - LoginDialog no longer exists.")
        except Exception as e:
            logging.error(f"Exception in _forgot_password: {e}", exc_info=True)
            messagebox.showerror("Error", f"Could not open the password reset window:\n{e}", parent=self.parent)

    def _attempt_login(self):
        username = self.username_entry.get().strip()
        password = self.password_entry.get()
        self.error_label.configure(text="")
        logging.debug(f"Attempting login for username: '{username}'")

        if not username or not password:
            self.error_label.configure(text="Username and Password required.")
            logging.warning("Login attempt failed: Username or password empty.")
            return

        user_data = self.db_manager.get_user_by_username(username)
        logging.debug(f"DB returned user_data: {'Found' if user_data else 'Not Found'}")

        if user_data:
            user_id, db_username, stored_hash, role, _, _ = user_data
            logging.debug(f"Retrieved user: ID={user_id}, Username='{db_username}', Role='{role}'")
            logging.debug(f"Stored Hash from DB: '{stored_hash}'")
            try:
                is_valid_password = verify_password(stored_hash, password)
                logging.debug(f"Password verification result: {is_valid_password}")
            except Exception as e:
                logging.error(f"Error during password verification: {e}", exc_info=True)
                is_valid_password = False

            if is_valid_password:
                logging.info(f"User '{username}' logged in successfully with role '{role}'.")
                self.user_info = (user_id, db_username, role)
                self.destroy()
                self.callback(self.user_info)
            else:
                logging.warning(f"Login failed for user '{username}': Invalid password.")
                self.error_label.configure(text="Invalid username or password.")
                self.password_entry.delete(0, tk.END)
        else:
            logging.warning(f"Login failed: User '{username}' not found.")
            self.error_label.configure(text="Invalid username or password.")
            self.password_entry.delete(0, tk.END)

    def _cancel_login(self):
        logging.info("Login cancelled by user.")
        self.user_info = None
        self.destroy()
        self.callback(None)

# --- Database Interaction Class ---
class DatabaseManager:
    def __init__(self, config_loader_func):
        self.config_loader = config_loader_func
        self.config = self.config_loader()
        self._connection = None
        self._ensure_password()

    def _ensure_password(self):
        if not self.config.get('password'):
            logging.warning("Database password not found in configuration.")
            pass # Prompt will happen in get_connection if needed

    def get_connection(self):
        try:
            if self._connection and not self._connection.closed:
                with self._connection.cursor() as cur:
                    cur.execute("SELECT 1")
                return self._connection
            elif self._connection and self._connection.closed:
                 logging.info("Previous connection was closed. Reconnecting.")
                 self._connection = None
        except (psycopg2.InterfaceError, psycopg2.OperationalError) as e:
            logging.warning(f"Connection check failed ({e}), attempting reconnect.")
            self._connection = None

        try:
            self.config = self.config_loader()
            if not self.config.get('password'):
                 parent_window = None
                 if 'app' in globals() and app and hasattr(app, 'root'):
                     parent_window = app.root
                 password = simpledialog.askstring("Database Password Required",
                                               f"Enter password for user '{self.config['user']}' on host '{self.config['host']}':",
                                               show='*', parent=parent_window)
                 if password is not None:
                     self.config['password'] = password
                 else:
                     logging.error("Password prompt cancelled. Cannot connect to database.")
                     messagebox.showerror("Connection Error", "Password required to connect to the database.")
                     return None

            if not self.config.get('password') and self.config.get('user') != 'postgres':
                 logging.error("Password still missing after check/prompt.")
                 messagebox.showerror("Connection Error", "Database password is required but was not provided.")
                 return None

            self._connection = psycopg2.connect(
                host=self.config['host'],
                port=self.config['port'],
                database=self.config['name'],
                user=self.config['user'],
                password=self.config['password']
            )
            self._connection.autocommit = False # Changed for safer transactions
            logging.info("Database connection established.")
            return self._connection

        except psycopg2.OperationalError as e:
            err_msg = f"Database connection error: {e}\n\n" \
                      f"Host: {self.config['host']}, Port: {self.config['port']}, " \
                      f"DB: {self.config['name']}, User: {self.config['user']}\n\n" \
                      "Check settings (File > Database Settings) and network connection."
            messagebox.showerror("Database Connection Error", err_msg)
            logging.error(f"DB connection operational error: {e}", exc_info=True)
            self._connection = None
            return None
        except psycopg2.Error as e:
            messagebox.showerror("Database Error", f"Error connecting to database: {e}")
            logging.error(f"Generic DB connection error: {e}", exc_info=True)
            self._connection = None
            return None
        except Exception as e:
            messagebox.showerror("Unexpected Error", f"Error during connection attempt: {e}")
            logging.error(f"Unexpected connection error: {e}", exc_info=True)
            self._connection = None
            return None

    def close_connection(self):
        if self._connection and not self._connection.closed:
            try:
                self._connection.close()
                logging.info("Database connection closed.")
            except psycopg2.Error as e:
                logging.error(f"Error closing database connection: {e}")
        self._connection = None

    def execute_sql(self, sql, params=None, fetch=False):
        conn = self.get_connection()
        if conn is None:
            logging.error("execute_sql: Cannot execute, no database connection.")
            return None if fetch else False
        result = None
        success = False
        log_sql_short = ' '.join(sql.splitlines()).strip()[:70] # For logging

        try:
            logging.debug(f"execute_sql: Connection autocommit status: {conn.autocommit}")
            with conn.cursor() as cur:
                logging.debug(f"execute_sql: Executing SQL: {log_sql_short}... with params: {params}")
                cur.execute(sql, params)
                logging.debug(f"execute_sql: SQL execution successful for: {log_sql_short}")

                if fetch:
                    result = cur.fetchall()
                    logging.debug(f"execute_sql: Fetched {len(result) if result else 0} rows.")

                is_modifying_statement = any(
                    keyword in sql.strip().upper().split()
                    for keyword in ["INSERT", "UPDATE", "DELETE"]
                )

                if not fetch or (fetch and is_modifying_statement):
                    logging.debug(f"execute_sql: Attempting commit for: {log_sql_short}...")
                    try:
                        conn.commit()
                        success = True # Commit succeeded
                        logging.info(f"SQL committed successfully: {log_sql_short}...")
                    except psycopg2.Error as commit_err:
                        success = False # Commit failed
                        logging.error(f"execute_sql: COMMIT FAILED for {log_sql_short}: {commit_err}", exc_info=True)
                        try: conn.rollback(); logging.warning("execute_sql: Rollback attempted after commit failure.")
                        except psycopg2.Error as rb_err: logging.error(f"execute_sql: Rollback FAILED after commit failure: {rb_err}")
                        messagebox.showerror("Database Commit Error", f"Failed to save changes.\n\nError: {commit_err}")
                elif fetch and not is_modifying_statement:
                    success = True # SELECT succeeded

        except psycopg2.errors.UniqueViolation as e: # First occurrence
            if conn: conn.rollback()
            logging.warning(f"DB unique constraint violation: {e}\nSQL: {sql}\nParams: {params}")
            messagebox.showwarning("Database Constraint Error", f"Operation failed: An entry with that value already exists.\n\n{e.pgerror if hasattr(e, 'pgerror') else e}")
            success = False
        except psycopg2.errors.ForeignKeyViolation as e: # First occurrence
            if conn: conn.rollback()
            logging.error(f"DB foreign key violation: {e}\nSQL: {sql}\nParams: {params}", exc_info=True)
            messagebox.showerror("Database Reference Error", f"Operation failed: Referenced item not found or cannot be deleted.\n\n{e.pgerror if hasattr(e, 'pgerror') else e}")
            success = False
        # <<< REMOVE THE DUPLICATED UniqueViolation and ForeignKeyViolation BLOCKS THAT WERE HERE >>>

        except psycopg2.Error as e: # General psycopg2 errors
            logging.error(f"DB error during SQL execution (before rollback): {e}\nSQL: {sql}\nParams: {params}", exc_info=True)
            try:
                if conn: conn.rollback(); logging.warning("execute_sql: Rollback successful after general DB error.")
            except psycopg2.Error as rb_err:
                logging.error(f"execute_sql: Rollback FAILED after general DB error: {rb_err}")
            err_detail = f"{e.pgcode}: {e.pgerror}" if hasattr(e, 'pgcode') and e.pgcode else str(e)
            messagebox.showerror("Database Error", f"Error executing SQL:\n{err_detail}")
            success = False
        except Exception as e: # Other unexpected errors
            logging.error(f"Unexpected error during SQL execution (before rollback): {e}\nSQL: {sql}\nParams: {params}", exc_info=True)
            if conn:
                try:
                    conn.rollback(); logging.warning("execute_sql: Rollback successful after unexpected error.")
                except psycopg2.Error as rb_err:
                    logging.error(f"execute_sql: Rollback FAILED after unexpected error: {rb_err}")
            messagebox.showerror("Execution Error", f"An unexpected error occurred: {e}")
            success = False

        logging.debug(f"execute_sql: Finished for {log_sql_short}. Success: {success}")
        if fetch:
            return result if success else None
        else:
            return success

    # --- Schema Management ---
    def initialize_database(self):
        """
        Initializes or updates the database schema. Ensures tables, columns,
        indexes, and constraints exist and critical column types are correct.
        Uses direct ALTER COLUMN TYPE commands for robustness.
        """
        logging.info("Initializing/Updating database schema...")
        # Add note about ALTER TABLE for status
        logging.info("DB INIT: Ensuring required column types (e.g., VARCHAR lengths) are set.")
        conn = self.get_connection()
        if not conn:
            logging.critical("Cannot initialize/update database without a connection.")
            # Use a more generic way to show error if root doesn't exist or isn't passed
            parent_window = None
            try:
                # Check if 'app' exists globally and has a root window
                if 'app' in globals() and app and hasattr(app, 'root') and app.root.winfo_exists():
                    parent_window = app.root
            except Exception: # Catch potential errors accessing app/root
                 pass
            messagebox.showerror("DB Error", "Cannot connect to database to initialize/update schema.", parent=parent_window)
            return False

        initialization_ok = True
        # --- Define all Schema Commands ---
        # Grouped for readability: Tables, Add Columns, Alter Types, Indexes, FKs, Roles
        commands = [
            # --- 1. Create Tables IF NOT EXISTS ---
            # Users Table (with security questions)
            f"""CREATE TABLE IF NOT EXISTS users (
                user_id SERIAL PRIMARY KEY,
                username VARCHAR(50) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                role VARCHAR(20) NOT NULL DEFAULT 'user',
                security_question_1 TEXT NULL,
                security_answer_hash_1 VARCHAR(255) NULL,
                security_question_2 TEXT NULL,
                security_answer_hash_2 VARCHAR(255) NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );""",
            # Companies Table
            f"""CREATE TABLE IF NOT EXISTS {TBL_COMPANIES} (
                {COL_ID} SERIAL PRIMARY KEY,
                name VARCHAR(255) UNIQUE NOT NULL,
                {COL_CREATED_AT} TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );""",
            # Banks Table
            """CREATE TABLE IF NOT EXISTS banks (
                bank_id SERIAL PRIMARY KEY,
                name VARCHAR(100) UNIQUE NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );""",
            # Payees Table
            """CREATE TABLE IF NOT EXISTS payees (
                payee_id SERIAL PRIMARY KEY,
                name VARCHAR(255) UNIQUE NOT NULL,
                type VARCHAR(10) NOT NULL CHECK (type IN ('Vendor', 'Customer')),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );""",
            # Memos Table
            """CREATE TABLE IF NOT EXISTS memos (
                memo_id SERIAL PRIMARY KEY,
                name VARCHAR(100) UNIQUE NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );""",
            # Transactions Table (Initial definition, types might be adjusted below)
            f"""CREATE TABLE IF NOT EXISTS {TBL_TRANSACTIONS} (
                {COL_ID} SERIAL PRIMARY KEY,
                {COL_COMPANY_ID} INTEGER,
                {COL_BANK_NAME} VARCHAR(100) NOT NULL,
                {COL_DATE} DATE NOT NULL,
                {COL_CHECK_NO} VARCHAR(50) NULL,         -- Nullable status checked below
                {COL_VENDOR} VARCHAR(255) NULL,          -- Vendor/Customer Name
                {COL_REF} TEXT,
                {COL_AMOUNT} NUMERIC(12, 2) NOT NULL CHECK ({COL_AMOUNT} > 0),
                {COL_STATUS} VARCHAR(10) NOT NULL,       -- Initial type, adjusted below
                {COL_MEMO} VARCHAR(50) NULL,             -- Initial type, adjusted below
                {COL_NOTES} TEXT NULL,
                transaction_type VARCHAR(10) NOT NULL DEFAULT '{TYPE_DEBIT}', -- Type adjusted below
                payment_method VARCHAR(10) NULL,         -- Initial type, adjusted below
                {COL_BILL_NO} VARCHAR(50) NULL,
                {COL_INVOICE_NO} VARCHAR(50) NULL,
                created_by_user_id INTEGER NULL,
                updated_at TIMESTAMP NULL,
                updated_by_user_id INTEGER NULL,
                {COL_CREATED_AT} TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );""",
            # Role Permissions Table
            """CREATE TABLE IF NOT EXISTS role_permissions (
                role_name VARCHAR(20) PRIMARY KEY,
                allowed_tabs TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );""",

            # --- 2. Add Columns IF NOT EXISTS (Idempotent) ---
            # User Security Question Columns
            f"""ALTER TABLE users ADD COLUMN IF NOT EXISTS security_question_1 TEXT NULL;""",
            f"""ALTER TABLE users ADD COLUMN IF NOT EXISTS security_answer_hash_1 VARCHAR(255) NULL;""",
            f"""ALTER TABLE users ADD COLUMN IF NOT EXISTS security_question_2 TEXT NULL;""",
            f"""ALTER TABLE users ADD COLUMN IF NOT EXISTS security_answer_hash_2 VARCHAR(255) NULL;""",
            # Transaction Columns
            f"""ALTER TABLE {TBL_TRANSACTIONS} ADD COLUMN IF NOT EXISTS {COL_COMPANY_ID} INTEGER;""",
            f"""ALTER TABLE {TBL_TRANSACTIONS} ADD COLUMN IF NOT EXISTS {COL_BANK_NAME} VARCHAR(100);""", # Ensure exists
            f"""ALTER TABLE {TBL_TRANSACTIONS} ADD COLUMN IF NOT EXISTS {COL_DATE} DATE;""", # Ensure exists
            f"""ALTER TABLE {TBL_TRANSACTIONS} ADD COLUMN IF NOT EXISTS {COL_CHECK_NO} VARCHAR(50);""", # Ensure exists
            f"""ALTER TABLE {TBL_TRANSACTIONS} ADD COLUMN IF NOT EXISTS {COL_VENDOR} VARCHAR(255);""", # Ensure exists
            f"""ALTER TABLE {TBL_TRANSACTIONS} ADD COLUMN IF NOT EXISTS {COL_REF} TEXT;""", # Ensure exists
            f"""ALTER TABLE {TBL_TRANSACTIONS} ADD COLUMN IF NOT EXISTS {COL_AMOUNT} NUMERIC(12, 2);""", # Ensure exists
            f"""ALTER TABLE {TBL_TRANSACTIONS} ADD COLUMN IF NOT EXISTS {COL_STATUS} VARCHAR(10);""", # Ensure exists (type fixed below)
            f"""ALTER TABLE {TBL_TRANSACTIONS} ADD COLUMN IF NOT EXISTS {COL_MEMO} VARCHAR(50);""", # Ensure exists (type fixed below)
            f"""ALTER TABLE {TBL_TRANSACTIONS} ADD COLUMN IF NOT EXISTS {COL_NOTES} TEXT;""", # Ensure exists
            f"""ALTER TABLE {TBL_TRANSACTIONS} ADD COLUMN IF NOT EXISTS transaction_type VARCHAR(10);""", # Ensure exists (type fixed below)
            f"""ALTER TABLE {TBL_TRANSACTIONS} ADD COLUMN IF NOT EXISTS payment_method VARCHAR(10);""", # Ensure exists (type fixed below)
            f"""ALTER TABLE {TBL_TRANSACTIONS} ADD COLUMN IF NOT EXISTS {COL_BILL_NO} VARCHAR(50);""", # Ensure exists
            f"""ALTER TABLE {TBL_TRANSACTIONS} ADD COLUMN IF NOT EXISTS {COL_INVOICE_NO} VARCHAR(50);""", # Ensure exists
            f"""ALTER TABLE {TBL_TRANSACTIONS} ADD COLUMN IF NOT EXISTS created_by_user_id INTEGER;""", # Ensure exists
            f"""ALTER TABLE {TBL_TRANSACTIONS} ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP;""", # Ensure exists
            f"""ALTER TABLE {TBL_TRANSACTIONS} ADD COLUMN IF NOT EXISTS updated_by_user_id INTEGER;""", # Ensure exists
            f"""ALTER TABLE {TBL_TRANSACTIONS} ADD COLUMN IF NOT EXISTS {COL_CREATED_AT} TIMESTAMP;""", # Ensure exists

            # --- 3. ALTER COLUMN TYPE for critical VARCHAR columns (Idempotent in effect) ---
            # These commands ensure the columns have at least the specified length.
            # Run AFTER ensuring the columns exist via ADD COLUMN IF NOT EXISTS.
            f"""ALTER TABLE {TBL_TRANSACTIONS} ALTER COLUMN {COL_PAYMENT_METHOD} TYPE VARCHAR(20);""", # For 'Internal Transfer Method' etc.
            f"""ALTER TABLE {TBL_TRANSACTIONS} ALTER COLUMN {COL_MEMO} TYPE VARCHAR(100);""", # To allow longer custom memos
            f"""ALTER TABLE {TBL_TRANSACTIONS} ALTER COLUMN {COL_STATUS} TYPE VARCHAR(20);""", # For 'Clearance', 'Returned' etc.
            f"""ALTER TABLE {TBL_TRANSACTIONS} ALTER COLUMN transaction_type TYPE VARCHAR(10);""", # For 'Transfer', 'Debit', 'Credit'

            # --- 4. ALTER Other Column Properties ---
            # Ensure check_no is NULLABLE
            f"""DO $$
            BEGIN
                IF EXISTS (
                    SELECT 1 FROM information_schema.columns
                    WHERE table_schema = current_schema() -- Use current_schema() for better portability
                      AND table_name = lower('{TBL_TRANSACTIONS}')
                      AND column_name = lower('{COL_CHECK_NO}')
                      AND is_nullable = 'NO'
                ) THEN
                    ALTER TABLE {TBL_TRANSACTIONS} ALTER COLUMN {COL_CHECK_NO} DROP NOT NULL;
                    RAISE NOTICE 'Altered {TBL_TRANSACTIONS}.{COL_CHECK_NO} to allow NULLs.';
                END IF;
            END $$;""",
            # Add check constraint back if it doesn't exist (after potential type change)
            # Note: Check constraints might need dropping and recreating if type changes drastically.
            # For VARCHAR widening, this is usually fine. For amount > 0:
            f"""ALTER TABLE {TBL_TRANSACTIONS} DROP CONSTRAINT IF EXISTS transactions_amount_check;""", # Drop old one if named like this
            f"""ALTER TABLE {TBL_TRANSACTIONS} ADD CONSTRAINT transactions_amount_check CHECK ({COL_AMOUNT} > 0);""",

            # --- 5. Create Indexes IF NOT EXISTS ---
            f"""CREATE UNIQUE INDEX IF NOT EXISTS idx_companies_name ON {TBL_COMPANIES} (name);""",
            f"""CREATE UNIQUE INDEX IF NOT EXISTS idx_banks_name ON banks (name);""",
            f"""CREATE UNIQUE INDEX IF NOT EXISTS idx_payees_name ON payees (name);""",
            f"""CREATE INDEX IF NOT EXISTS idx_payees_type ON payees (type);""",
            f"""CREATE UNIQUE INDEX IF NOT EXISTS idx_memos_name ON memos (name);""",
            f"""CREATE INDEX IF NOT EXISTS idx_transactions_date ON {TBL_TRANSACTIONS} ({COL_DATE});""",
            f"""CREATE INDEX IF NOT EXISTS idx_transactions_status ON {TBL_TRANSACTIONS} ({COL_STATUS});""",
            f"""CREATE INDEX IF NOT EXISTS idx_transactions_company_id ON {TBL_TRANSACTIONS} ({COL_COMPANY_ID});""",
            f"""CREATE INDEX IF NOT EXISTS idx_transactions_bank_name ON {TBL_TRANSACTIONS} ({COL_BANK_NAME});""",
            f"""CREATE INDEX IF NOT EXISTS idx_transactions_memo ON {TBL_TRANSACTIONS} ({COL_MEMO});""",
            f"""CREATE INDEX IF NOT EXISTS idx_transactions_type ON {TBL_TRANSACTIONS} (transaction_type);""",
            f"""CREATE INDEX IF NOT EXISTS idx_transactions_vendor ON {TBL_TRANSACTIONS} ({COL_VENDOR});""",
            f"""CREATE INDEX IF NOT EXISTS idx_transactions_bill_no ON {TBL_TRANSACTIONS} ({COL_BILL_NO});""",
            f"""CREATE INDEX IF NOT EXISTS idx_transactions_invoice_no ON {TBL_TRANSACTIONS} ({COL_INVOICE_NO});""",

            # --- 6. Add Foreign Key Constraints IF NOT EXISTS (Using DO $$ BEGIN for safety) ---
            # Transaction -> Company
            f"""DO $$
            BEGIN
                IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_transactions_company') THEN
                    ALTER TABLE {TBL_TRANSACTIONS} ADD CONSTRAINT fk_transactions_company
                    FOREIGN KEY ({COL_COMPANY_ID}) REFERENCES {TBL_COMPANIES}({COL_ID}) ON DELETE SET NULL;
                END IF;
            END $$;""",
            # Transaction -> User (Creator)
            f"""DO $$
            BEGIN
                IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_transactions_user_creator') THEN
                    ALTER TABLE {TBL_TRANSACTIONS} ADD CONSTRAINT fk_transactions_user_creator
                    FOREIGN KEY (created_by_user_id) REFERENCES users(user_id) ON DELETE SET NULL;
                END IF;
            END $$;""",
            # Transaction -> User (Updater)
            f"""DO $$
            BEGIN
                IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_transactions_user_updater') THEN
                    ALTER TABLE {TBL_TRANSACTIONS} ADD CONSTRAINT fk_transactions_user_updater
                    FOREIGN KEY (updated_by_user_id) REFERENCES users(user_id) ON DELETE SET NULL;
                END IF;
            END $$;""",

            # --- 7. Initialize Role Permissions ---
            # Ensure admin role has full access initially
            """INSERT INTO role_permissions (role_name, allowed_tabs)
               VALUES ('admin', 'ALL')
               ON CONFLICT (role_name) DO NOTHING;""",
            # Ensure 'user' role exists with default permissions
            """INSERT INTO role_permissions (role_name, allowed_tabs)
               VALUES ('user', 'home,add_transaction,report,bank_summary,memo_summary') -- Example default
               ON CONFLICT (role_name) DO NOTHING;"""
        ]

        # --- Execute Commands ---
        try:
            with conn.cursor() as cur:
                for cmd_idx, cmd in enumerate(commands):
                    try:
                        log_cmd = ' '.join(cmd.splitlines()).strip()[:80] + ('...' if len(cmd) > 80 else '')
                        cur.execute(cmd)
                        logging.info(f"Executed schema command ({cmd_idx+1}/{len(commands)}): {log_cmd}")
                    except psycopg2.Error as e:
                        logging.error(f"Failed schema command ({cmd_idx+1}): {log_cmd} Error: {e.pgcode} - {e.pgerror or e}")
                        conn.rollback() # Rollback the transaction on ANY error

                        # Determine if the error is critical enough to halt initialization
                        is_critical_command = False
                        cmd_upper = cmd.upper()
                        if "CREATE TABLE" in cmd_upper or \
                           "ADD CONSTRAINT" in cmd_upper or \
                           ("ALTER TABLE" in cmd_upper and "ADD COLUMN" in cmd_upper) or \
                           ("ALTER TABLE" in cmd_upper and "ALTER COLUMN" in cmd_upper):
                            is_critical_command = True

                        # Special handling for non-erroring DO block (e.g., check_no nullable)
                        if "DO $$" in cmd_upper and "DROP NOT NULL" in cmd_upper:
                             # A NOTICE might be raised, or an error if permissions issue.
                             # If it's a real error (e.pgcode exists), treat as potentially critical.
                            if hasattr(e, 'pgcode') and e.pgcode:
                                is_critical_command = True
                            else: # Likely just a notice, log it but don't halt unless specifically problematic
                                logging.warning(f"Notice or non-critical issue during check_no nullable block: {e.pgerror or e}")
                                # Continue to next command after rollback of this one

                        if is_critical_command:
                            initialization_ok = False
                            messagebox.showwarning(
                                "Schema Warning",
                                f"Failed critical step in DB initialization/update:\n{e.pgerror or e}\n\nCommand: {log_cmd}\n\nCheck logs.",
                                parent=self.root if 'self' in locals() and hasattr(self, 'root') else None
                            )
                            # Decide whether to break the loop or try subsequent commands
                            # break # Option: Stop entirely on critical failure
                        else:
                             logging.warning(f"Non-critical schema command failed (e.g., index create if exists): {log_cmd} Error: {e.pgerror or e}")
                        # Continue to the next command even if one fails (unless we 'break' above)

                # --- Final Commit/Log ---
                if initialization_ok:
                    conn.commit()
                    logging.info("Database schema initialization/update process completed successfully.")
                else:
                    # Rollback already happened on error, just log the failure state
                    logging.error("Database schema initialization/update failed due to one or more errors.")

        except psycopg2.Error as e:
            # Catch errors occurring outside the command loop (e.g., initial cursor creation)
            if conn and not conn.closed: # Check if conn exists and is not already closed due to severe error
                try:
                    conn.rollback()
                except psycopg2.Error as rb_err:
                    logging.error(f"Rollback failed after batch error: {rb_err}")
            logging.critical(f"Critical error during schema initialization batch: {e}", exc_info=True)
            messagebox.showerror("DB Init Error", f"Failed to initialize database schema: {e.pgerror or e}", parent = self.root if 'self' in locals() and hasattr(self, 'root') else None)
            initialization_ok = False
        except Exception as e:
            # Catch unexpected Python errors
            if conn and not conn.closed:
                try:
                    conn.rollback()
                except psycopg2.Error as rb_err:
                    logging.error(f"Rollback failed after unexpected error: {rb_err}")
            logging.critical(f"Unexpected error during schema initialization: {e}", exc_info=True)
            messagebox.showerror("DB Init Error", f"Unexpected error initializing schema: {e}", parent = self.root if 'self' in locals() and hasattr(self, 'root') else None)
            initialization_ok = False

        return initialization_ok




    # --- User Management Methods ---
    def add_user(self, username, password, role='user'):
        hashed_password = hash_password(password)
        if not hashed_password:
            logging.error("Cannot add user with empty password.")
            return None
        sql = "INSERT INTO users (username, password_hash, role) VALUES (%s, %s, %s) RETURNING user_id;"
        params = (username, hashed_password, role)
        result = self.execute_sql(sql, params, fetch=True)
        if result and isinstance(result, list) and len(result) > 0:
            logging.info(f"User '{username}' added with role '{role}'.")
            return result[0][0]
        return None

    def get_user_by_username(self, username):
        sql = """SELECT user_id, username, password_hash, role,
                        security_answer_hash_1, security_answer_hash_2
                 FROM users WHERE username = %s;"""
        result = self.execute_sql(sql, (username,), fetch=True)
        if result and len(result) == 1:
            return result[0]
        return None

    def get_users(self):
        sql = "SELECT user_id, username, role FROM users ORDER BY username;"
        result = self.execute_sql(sql, fetch=True)
        return result if result is not None else []

    def update_user_role(self, user_id, new_role):
        if new_role not in ['user', 'admin']:
            logging.error(f"Invalid role specified for update: {new_role}")
            return False
        sql = "UPDATE users SET role = %s WHERE user_id = %s;"
        return self.execute_sql(sql, (new_role, user_id))

    def delete_user(self, user_id):
        sql = "DELETE FROM users WHERE user_id = %s;"
        return self.execute_sql(sql, (user_id,))

    def update_user_password(self, user_id, new_hashed_password):
        if not new_hashed_password:
            logging.error("Attempted to update password with an empty hash.")
            return False
        sql = "UPDATE users SET password_hash = %s WHERE user_id = %s;"
        return self.execute_sql(sql, (new_hashed_password, user_id))

    def get_user_security_questions(self, user_id):
        sql = "SELECT security_question_1, security_question_2 FROM users WHERE user_id = %s;"
        result = self.execute_sql(sql, (user_id,), fetch=True)
        if result and len(result) == 1:
            return result[0]
        logging.warning(f"Could not retrieve security questions for user_id: {user_id}")
        return None, None

    def get_user_security_answer_hashes(self, user_id):
        sql = "SELECT security_answer_hash_1, security_answer_hash_2 FROM users WHERE user_id = %s;"
        result = self.execute_sql(sql, (user_id,), fetch=True)
        if result and len(result) == 1:
            return result[0]
        logging.warning(f"Could not retrieve security answer hashes for user_id: {user_id}")
        return None, None

    def update_user_security_info(self, user_id, q1, a1_hash, q2, a2_hash):
        q1 = q1 if q1 else None
        a1_hash = a1_hash if a1_hash else None
        q2 = q2 if q2 else None
        a2_hash = a2_hash if a2_hash else None
        if (q1 and not a1_hash) or (not q1 and a1_hash):
            logging.error(f"Security info update failed for user {user_id}: Question 1 and Answer 1 must both be set or both be empty.")
            return False
        if (q2 and not a2_hash) or (not q2 and a2_hash):
            logging.error(f"Security info update failed for user {user_id}: Question 2 and Answer 2 must both be set or both be empty.")
            return False

        sql = """
            UPDATE users SET
                security_question_1 = %s,
                security_answer_hash_1 = %s,
                security_question_2 = %s,
                security_answer_hash_2 = %s
            WHERE user_id = %s;
        """
        params = (q1, a1_hash, q2, a2_hash, user_id)
        success = self.execute_sql(sql, params)
        if success:
            logging.info(f"Security questions/answers updated for user_id: {user_id}")
        else:
            logging.error(f"Failed to update security info for user_id: {user_id}")
        return success

    # --- Role Permissions ---
    def get_allowed_tabs_for_role(self, role_name):
        sql = "SELECT allowed_tabs FROM role_permissions WHERE role_name = %s;"
        result = self.execute_sql(sql, (role_name,), fetch=True)
        if result and len(result) == 1:
            return result[0][0]
        logging.warning(f"No permissions found for role '{role_name}', returning None (implies no access).")
        return None

    def set_allowed_tabs_for_role(self, role_name, allowed_tabs_list):
        if role_name == 'admin':
             logging.warning("Attempted to change permissions for 'admin' role via set_allowed_tabs_for_role. This is prevented.")
             return False
        allowed_tabs_string = ",".join(sorted(list(set(allowed_tabs_list))))
        sql = """
            INSERT INTO role_permissions (role_name, allowed_tabs)
            VALUES (%s, %s)
            ON CONFLICT (role_name) DO UPDATE SET
                allowed_tabs = EXCLUDED.allowed_tabs;
        """
        params = (role_name, allowed_tabs_string)
        success = self.execute_sql(sql, params)
        if success:
            logging.info(f"Permissions updated for role '{role_name}': {allowed_tabs_string}")
        else:
            logging.error(f"Failed to update permissions for role '{role_name}'.")
        return success

    # --- Company Methods ---
    def add_company(self, name):
        sql = f"INSERT INTO {TBL_COMPANIES} (name) VALUES (%s) RETURNING {COL_ID};"
        result = self.execute_sql(sql, (name,), fetch=True)
        if result and isinstance(result, list) and len(result) > 0:
             return result[0][0]
        return None

    def get_companies(self):
        sql = f"SELECT {COL_ID}, name FROM {TBL_COMPANIES} ORDER BY name;"
        result = self.execute_sql(sql, fetch=True)
        return result if result is not None else []

    def delete_company(self, company_id):
        sql = f"DELETE FROM {TBL_COMPANIES} WHERE {COL_ID} = %s;"
        return self.execute_sql(sql, (company_id,))

    def update_company_name(self, company_id, new_name): # <<< ADDED
        """Updates the name of a specific company."""
        sql = f"UPDATE {TBL_COMPANIES} SET name = %s WHERE {COL_ID} = %s;"
        return self.execute_sql(sql, (new_name, company_id))

    # --- Bank Methods ---
    def add_bank(self, name):
        sql = "INSERT INTO banks (name) VALUES (%s) RETURNING bank_id;"
        result = self.execute_sql(sql, (name,), fetch=True)
        if result and isinstance(result, list) and len(result) > 0:
             return result[0][0]
        return None

    def get_banks(self):
        sql = "SELECT bank_id, name FROM banks ORDER BY name;"
        result = self.execute_sql(sql, fetch=True)
        return result if result is not None else []

    def delete_bank(self, bank_id):
        sql = "DELETE FROM banks WHERE bank_id = %s;"
        return self.execute_sql(sql, (bank_id,))

    def update_bank_name(self, bank_id, new_name): # <<< ADDED
        """Updates the name of a specific bank."""
        sql = "UPDATE banks SET name = %s WHERE bank_id = %s;"
        return self.execute_sql(sql, (new_name, bank_id))

    # --- Payee Methods ---
    def add_payee(self, name, payee_type):
        if payee_type not in ['Vendor', 'Customer']:
            logging.error(f"Invalid payee type: {payee_type}")
            return None
        sql = "INSERT INTO payees (name, type) VALUES (%s, %s) RETURNING payee_id;"
        params = (name, payee_type)
        result = self.execute_sql(sql, params, fetch=True)
        if result and isinstance(result, list) and len(result) > 0:
             return result[0][0]
        return None

    def get_payees(self, payee_type=None):
        sql = "SELECT payee_id, name, type FROM payees"
        params = []
        if payee_type:
            if payee_type in ['Vendor', 'Customer']:
                sql += " WHERE type = %s"
                params.append(payee_type)
            else:
                logging.warning(f"Invalid type '{payee_type}' requested in get_payees. Fetching all.")
        sql += " ORDER BY name;"
        result = self.execute_sql(sql, params=params if params else None, fetch=True)
        return result if result is not None else []

    def delete_payee(self, payee_id):
        sql = "DELETE FROM payees WHERE payee_id = %s;"
        return self.execute_sql(sql, (payee_id,))

    def update_payee_name(self, payee_id, new_name): # <<< ADDED
        """Updates the name of a specific payee."""
        sql = "UPDATE payees SET name = %s WHERE payee_id = %s;"
        return self.execute_sql(sql, (new_name, payee_id))

    # --- Transaction Methods ---
    def add_transaction(self, **data):
        """
        Adds a new transaction to the database.
        Expects keyword arguments for all transaction fields.
        """
        logging.debug(f"DatabaseManager.add_transaction called with data: {data}")

        # Define the SQL query for inserting a new transaction
        # Note: 'created_by_user_id' is the direct column name in the users table.
        # COL_VENDOR is used for vendor_or_customer_name.
        sql = f"""
            INSERT INTO {TBL_TRANSACTIONS} (
                {COL_COMPANY_ID}, {COL_BANK_NAME}, {COL_DATE}, {COL_CHECK_NO},
                {COL_VENDOR},  -- Maps to 'vendor_or_customer_name' from data
                {COL_REF}, {COL_AMOUNT}, {COL_STATUS}, {COL_MEMO}, {COL_NOTES},
                {COL_TRANSACTION_TYPE}, {COL_PAYMENT_METHOD},
                {COL_BILL_NO}, {COL_INVOICE_NO},
                created_by_user_id  -- Direct database column name
            ) VALUES (
                %s, %s, %s, %s,  -- company_id, bank_name, date, check_no
                %s,              -- vendor_or_customer_name
                %s, %s, %s, %s, %s,  -- reference, amount, status, memo, notes
                %s, %s,          -- transaction_type, payment_method
                %s, %s,          -- bill_no, invoice_no
                %s               -- created_by_user_id
            ) RETURNING {COL_ID};
        """

        # Prepare parameters in the correct order for the SQL query
        # .get() is used to safely access dictionary keys, defaulting to None if not found
        params = (
            data.get('company_id'),
            data.get('bank_name'),
            data.get('date'),
            data.get('check_no'),
            data.get('vendor_or_customer_name'), # This will be inserted into the COL_VENDOR column
            data.get('reference'),
            data.get('amount'),
            data.get('status'),
            data.get('memo'),
            data.get('notes'),
            data.get('transaction_type'),
            data.get('payment_method'),
            data.get('bill_no'),
            data.get('invoice_no'),
            data.get('created_by_user_id')
        )

        logging.debug(f"Executing SQL for add_transaction with params: {params}")
        result = self.execute_sql(sql, params, fetch=True)

        if result and isinstance(result, list) and len(result) > 0:
            new_id = result[0][0]
            logging.info(f"Transaction added successfully via DatabaseManager with ID: {new_id}")
            return new_id
        else:
            logging.error("Failed to add transaction or retrieve new ID from database.")
            # execute_sql would have likely shown an error message already if the SQL failed.
            return None

    def fetch_transactions(self, filter_status=None, filter_company_id=None,
                           filter_bank_name=None, filter_start_date=None,
                           filter_end_date=None, filter_memo=None,
                           filter_vendor_name=None, filter_customer_name=None, # These are for filtering
                           filter_transaction_type=None, filter_payment_method=None,
                           search_term=None):
        logging.info(f"DB fetch_transactions called with filters: Status='{filter_status}', CompID='{filter_company_id}', Bank='{filter_bank_name}', Start='{filter_start_date}', End='{filter_end_date}', Memo='{filter_memo}', Vendor='{filter_vendor_name}', Customer='{filter_customer_name}', Type='{filter_transaction_type}', Method='{filter_payment_method}', Search='{search_term}'")

        base_sql = f"""
            SELECT t.{COL_ID}, c.name AS {COL_COMPANY_NAME}, t.{COL_BANK_NAME}, t.{COL_DATE}, t.{COL_CHECK_NO},
                   t.{COL_VENDOR}, t.{COL_REF}, 
                   t.{COL_BILL_NO}, t.{COL_INVOICE_NO},
                   t.{COL_MEMO}, t.{COL_AMOUNT}, t.{COL_STATUS}, t.{COL_NOTES},
                   t.transaction_type, t.payment_method,
                   u_creator.username AS {COL_CREATED_BY}

            FROM {TBL_TRANSACTIONS} t
            LEFT JOIN {TBL_COMPANIES} c ON t.{COL_COMPANY_ID} = c.{COL_ID}
            LEFT JOIN users u_creator ON t.created_by_user_id = u_creator.user_id
            """
        params = []
        where_clauses = []

        if filter_status:
            if isinstance(filter_status, (list, tuple)):
                if filter_status: where_clauses.append(f"t.{COL_STATUS} = ANY(%s)"); params.append(list(filter_status))
            else: where_clauses.append(f"t.{COL_STATUS} = %s"); params.append(filter_status)
        if filter_company_id: where_clauses.append(f"t.{COL_COMPANY_ID} = %s"); params.append(filter_company_id)
        if filter_bank_name: where_clauses.append(f"t.{COL_BANK_NAME} = %s"); params.append(filter_bank_name)
        if filter_start_date: where_clauses.append(f"t.{COL_DATE} >= %s"); params.append(filter_start_date)
        if filter_end_date: where_clauses.append(f"t.{COL_DATE} <= %s"); params.append(filter_end_date)
        if filter_memo: where_clauses.append(f"t.{COL_MEMO} = %s"); params.append(filter_memo)
        
        # Filter by transaction_type first if provided, as it affects vendor/customer interpretation
        if filter_transaction_type:
            where_clauses.append(f"t.{COL_TRANSACTION_TYPE} = %s")
            params.append(filter_transaction_type)

        # Vendor/Customer filter logic - applies to t.COL_VENDOR
        # The SQL WHERE clause will operate on the single t.COL_VENDOR column.
        # The distinction is mainly for UI presentation and choosing the correct list of payees for the filter dropdown.
        if filter_vendor_name: # User selected a vendor from the "Vendor" filter dropdown
            where_clauses.append(f"t.{COL_VENDOR} = %s")
            params.append(filter_vendor_name)
            # Optionally, ensure it's a debit-like transaction if the filter implies it
            if not filter_transaction_type: # If type filter isn't already set
                 where_clauses.append(f"t.{COL_TRANSACTION_TYPE} IN ('{TYPE_DEBIT}', '{TYPE_TRANSFER}')") # Transfer out implies vendor
        
        if filter_customer_name: # User selected a customer from the "Customer" filter dropdown
            where_clauses.append(f"t.{COL_VENDOR} = %s")
            params.append(filter_customer_name)
            if not filter_transaction_type: # If type filter isn't already set
                 where_clauses.append(f"t.{COL_TRANSACTION_TYPE} IN ('{TYPE_CREDIT}', '{TYPE_TRANSFER}')") # Transfer in implies customer


        if filter_payment_method:
            where_clauses.append(f"t.{COL_PAYMENT_METHOD} = %s")
            params.append(filter_payment_method)

        if search_term:
            search_pattern_text = f"%{search_term}%"
            search_conditions = []
            search_columns_t = [COL_BANK_NAME, COL_CHECK_NO, COL_VENDOR, COL_REF, COL_MEMO, COL_NOTES, COL_BILL_NO, COL_INVOICE_NO]
            valid_search_cols_t = [col for col in search_columns_t if col]
            for col in valid_search_cols_t:
                search_conditions.append(f"t.{col} ILIKE %s"); params.append(search_pattern_text)
            search_conditions.append(f"c.name ILIKE %s"); params.append(search_pattern_text)
            try:
                search_amount = float(search_term.replace(',', '').replace('$', ''))
                search_conditions.append(f"t.{COL_AMOUNT} = %s"); params.append(search_amount)
            except ValueError: pass
            if search_conditions: where_clauses.append(f"({ ' OR '.join(search_conditions) })")

        if where_clauses:
            base_sql += " WHERE " + " AND ".join(where_clauses)
        base_sql += f" ORDER BY t.{COL_DATE} DESC, t.{COL_ID} DESC"

        logging.debug(f"Executing SQL for fetch_transactions:\n{base_sql}")
        logging.debug(f"SQL Params: {params}")
        data = self.execute_sql(base_sql, params=params if params else None, fetch=True)
        if data is None:
            return []

        formatted_data = []
        # SQL still returns 16 columns from DB:
        # ID, Comp, Bank, Date, Check, DB_Vendor, Ref, BillNo, InvNo, Memo, Amount, Status, Notes, Type, Method, Creator
        expected_db_cols = 16
        for row in data:
                if len(row) == expected_db_cols:
                    row_list = list(row)
                    t_id, comp_name, bank_name, date_obj, check_no, \
                    db_vendor_customer, ref, bill_no, invoice_no, memo, \
                    amount_val, status, notes, \
                    type_val, payment_method_val, creator_username = row_list

                    date_str = date_obj.strftime('%Y-%m-%d') if date_obj else 'N/A'
                    amount_str = f"{amount_val:,.2f}" if amount_val is not None else 'N/A'
                    amount_float = amount_val

                    # --- SPLIT vendor_customer based on transaction_type ---
                    ui_vendor_name = ""
                    ui_customer_name = ""

                    if type_val == TYPE_DEBIT:
                        ui_vendor_name = db_vendor_customer
                    elif type_val == TYPE_CREDIT:
                        ui_customer_name = db_vendor_customer
                    elif type_val == TYPE_TRANSFER:
                        # For transfers, the db_vendor_customer field often contains "Transfer to X" or "Transfer from Y"
                        # You might want to parse this or decide how to display it.
                        # For simplicity here, let's assume if it's a "Transfer to", it's like a vendor.
                        # If "Transfer from", it's like a customer. This is an assumption.
                        if db_vendor_customer:
                            if "transfer to" in str(db_vendor_customer).lower():
                                ui_vendor_name = db_vendor_customer # Or just the bank name part
                            elif "transfer from" in str(db_vendor_customer).lower():
                                ui_customer_name = db_vendor_customer # Or just the bank name part
                            else: # If it's just a generic name for a transfer, decide
                                # ui_vendor_name = db_vendor_customer # Example: put in vendor
                                pass # Or leave both blank if it doesn't fit neatly

                    # Construct the tuple for display in the Treeview (NEW TREE_COLUMNS_FULL order)
                    # (ID,Comp,Bank,Date,Check, UI_VENDOR, UI_CUSTOMER, Ref,Bill,Inv,Memo,Amt,Status,Type,Method,Creator)
                    # Now 17 elements due to splitting vendor/customer
                    display_tuple = (
                        t_id, comp_name, bank_name, date_str, check_no,
                        ui_vendor_name,    # <<< NEW
                        ui_customer_name,  # <<< NEW
                        ref, bill_no, invoice_no, memo,
                        amount_str, status,
                        type_val, payment_method_val,
                        creator_username
                    )
                    formatted_data.append((display_tuple, notes, amount_float, type_val, payment_method_val))
                else:
                    logging.warning(f"Skipping row with unexpected DB columns ({len(row)} expected {expected_db_cols}): {row}")
        return formatted_data   
    
    def get_transaction_details(self, transaction_id):
        # <<< MODIFIED SELECT list >>>
        sql = f"""
             SELECT t.{COL_ID}, t.{COL_COMPANY_ID}, c.name as {COL_COMPANY_NAME},
                    t.{COL_BANK_NAME}, t.{COL_DATE},
                    t.{COL_CHECK_NO}, t.{COL_VENDOR}, t.{COL_REF},
                    t.{COL_BILL_NO}, t.{COL_INVOICE_NO}, -- <<< ADDED
                    t.{COL_AMOUNT},
                    t.{COL_STATUS}, t.{COL_MEMO}, t.{COL_NOTES},
                    t.transaction_type, t.payment_method,
                    t.created_at, u_creator.username AS created_by_username,
                    t.updated_at, u_updater.username AS updated_by_username
             FROM {TBL_TRANSACTIONS} t
             LEFT JOIN {TBL_COMPANIES} c ON t.{COL_COMPANY_ID} = c.{COL_ID}
             LEFT JOIN users u_creator ON t.created_by_user_id = u_creator.user_id
             LEFT JOIN users u_updater ON t.updated_by_user_id = u_updater.user_id
             WHERE t.{COL_ID} = %s; """
        result = self.execute_sql(sql, (transaction_id,), fetch=True)
        if result and len(result) == 1:
            # Returns 20 elements now
            return result[0]
        else:
            logging.error(f"Could not retrieve details for transaction ID {transaction_id}. Result: {result}")
            return None

    def get_distinct_banks(self):
        banks_data = self.get_banks()
        return [name for bank_id, name in banks_data] if banks_data else []

    def update_transaction(self, transaction_id, company_id, bank_name, date, check_no,
                           vendor_or_customer_name, reference, amount, status, memo, notes,
                           transaction_type, payment_method,
                           bill_no, invoice_no, # <<< ADDED PARAMS
                           updated_by_user_id):
        # <<< MODIFIED SQL statement >>>
        sql = f"""
            UPDATE {TBL_TRANSACTIONS} SET
                {COL_COMPANY_ID} = %s, {COL_BANK_NAME} = %s, {COL_DATE} = %s, {COL_CHECK_NO} = %s,
                {COL_VENDOR} = %s, {COL_REF} = %s, {COL_AMOUNT} = %s, {COL_STATUS} = %s,
                {COL_MEMO} = %s, {COL_NOTES} = %s,
                transaction_type = %s, payment_method = %s,
                {COL_BILL_NO} = %s, {COL_INVOICE_NO} = %s, -- <<< ADDED COLS
                updated_at = CURRENT_TIMESTAMP,
                updated_by_user_id = %s
            WHERE {COL_ID} = %s; """
        # <<< MODIFIED params tuple >>>
        params = (company_id, bank_name, date, check_no, vendor_or_customer_name, reference,
                  amount, status, memo, notes, transaction_type, payment_method,
                  bill_no, invoice_no, # <<< ADDED PARAMS TO TUPLE
                  updated_by_user_id, transaction_id)
        return self.execute_sql(sql, params)

    def delete_transaction(self, transaction_id):
        """Deletes a transaction by ID."""
        sql = f"DELETE FROM {TBL_TRANSACTIONS} WHERE {COL_ID} = %s;"
        return self.execute_sql(sql, (transaction_id,))

    # <<< UPDATED: Bank Summary Query >>>
    # Inside DatabaseManager class:
    def get_bank_summary(self, filter_bank_name=None):
        """
        Fetches aggregated transaction data per bank.
        - Posted Balance: Excludes Pending, Void. Includes Clearance if it moves to a posted state.
        - Clearance: Net value of items specifically in 'Clearance' status.
        Optionally filters by a specific bank name.
        """
        logging.debug(f"Fetching bank summary. Filter Bank: {filter_bank_name}")
        params = []
        where_clause_parts = []

        # Exclude VOID status from all calculations in the summary
        where_clause_parts.append(f"status != '{STATUS_VOID}'")

        if filter_bank_name and filter_bank_name != FILTER_ALL_BANKS:
            where_clause_parts.append(f"{COL_BANK_NAME} = %s")
            params.append(filter_bank_name)

        where_clause = ""
        if where_clause_parts:
            where_clause = "WHERE " + " AND ".join(where_clause_parts)

        # Statuses considered "posted" for balance calculation (excluding Pending, Void)
        # For Transfers, 'Paid' means it left this bank, 'Received' means it came to this bank.
        posted_debit_statuses = [STATUS_PAID] # Applies to Debits and Transfer-out legs
        posted_credit_statuses = [STATUS_RECEIVED, STATUS_RETURNED] # Applies to Credits and Transfer-in legs
                                                            # STATUS_RETURNED is a debit-like credit.

        sql = f"""
            SELECT
                t.{COL_BANK_NAME},
                -- Total Credits (sum of actual Credits and Transfer-ins that are not Void)
                COALESCE(SUM(CASE
                                WHEN t.transaction_type = '{TYPE_CREDIT}' AND t.status != '{STATUS_VOID}' THEN t.{COL_AMOUNT}
                                WHEN t.transaction_type = '{TYPE_TRANSFER}' AND t.status = '{STATUS_RECEIVED}' THEN t.{COL_AMOUNT} -- Transfer IN
                                ELSE 0
                            END), 0) AS total_credits,
                -- Total Debits (sum of actual Debits and Transfer-outs that are not Void)
                COALESCE(SUM(CASE
                                WHEN t.transaction_type = '{TYPE_DEBIT}' AND t.status != '{STATUS_VOID}' THEN t.{COL_AMOUNT}
                                WHEN t.transaction_type = '{TYPE_TRANSFER}' AND t.status = '{STATUS_PAID}' THEN t.{COL_AMOUNT} -- Transfer OUT
                                ELSE 0
                            END), 0) AS total_debits,

                -- Posted Balance:
                COALESCE(SUM(CASE
                                -- Credits (Received, Returned)
                                WHEN t.transaction_type = '{TYPE_CREDIT}' AND t.status = ANY(%s) THEN
                                    CASE WHEN t.status = '{STATUS_RETURNED}' THEN -t.{COL_AMOUNT} ELSE t.{COL_AMOUNT} END
                                -- Debits (Paid)
                                WHEN t.transaction_type = '{TYPE_DEBIT}' AND t.status = ANY(%s) THEN -t.{COL_AMOUNT}
                                -- Transfers (Paid from this bank, Received to this bank)
                                WHEN t.transaction_type = '{TYPE_TRANSFER}' AND t.status = '{STATUS_RECEIVED}' THEN t.{COL_AMOUNT} -- Transfer IN to this bank
                                WHEN t.transaction_type = '{TYPE_TRANSFER}' AND t.status = '{STATUS_PAID}' THEN -t.{COL_AMOUNT} -- Transfer OUT from this bank
                                ELSE 0
                            END), 0) AS posted_balance,

                -- Net adjustment from items specifically marked as 'Clearance'
                COALESCE(SUM(CASE
                                WHEN t.status = '{STATUS_CLEARED}' THEN
                                    CASE
                                        -- For Debits, Clearance means money "returned" or "not actually gone out"
                                        WHEN t.transaction_type = '{TYPE_DEBIT}' THEN t.{COL_AMOUNT}
                                        -- For Credits, Clearance means money "not actually received"
                                        WHEN t.transaction_type = '{TYPE_CREDIT}' THEN -t.{COL_AMOUNT}
                                        -- For Transfers:
                                        -- If it was a "Transfer to X" (outflow), clearance is inflow (+)
                                        -- If it was a "Transfer from X" (inflow), clearance is outflow (-)
                                        WHEN t.transaction_type = '{TYPE_TRANSFER}' AND t.{COL_VENDOR} LIKE 'Transfer to %%' THEN t.{COL_AMOUNT} -- Was an outflow, now cleared (add back)
                                        WHEN t.transaction_type = '{TYPE_TRANSFER}' AND t.{COL_VENDOR} LIKE 'Transfer from %%' THEN -t.{COL_AMOUNT} -- Was an inflow, now cleared (remove)
                                        ELSE 0
                                    END
                                ELSE 0
                            END), 0) AS clearance_adjustment
            FROM {TBL_TRANSACTIONS} t
            {where_clause}
            GROUP BY t.{COL_BANK_NAME}
            ORDER BY t.{COL_BANK_NAME};
        """
        # Parameters for posted_balance CASE statement
        full_params = [posted_credit_statuses, posted_debit_statuses] + params

        result = self.execute_sql(sql, params=full_params, fetch=True)
        return result if result is not None else []

    def get_memo_summary(self):
        sql = f"""
            SELECT COALESCE({COL_MEMO}, '[No Memo]'), {COL_STATUS}, COUNT(*), SUM({COL_AMOUNT})
            FROM {TBL_TRANSACTIONS}
            GROUP BY {COL_MEMO}, {COL_STATUS}
            ORDER BY {COL_MEMO}, {COL_STATUS};
        """
        result = self.execute_sql(sql, fetch=True)
        return result if result is not None else []

    def update_transaction_status(self, transaction_id, new_status):
        """Updates the status for a single transaction ID (logs update)."""
        # Assume current user ID needs to be tracked for single updates too.
        # Fetching it here or passing it would be needed if tracking is desired.
        # For simplicity, let's assume single updates don't track updater for now.
        sql = f"""
            UPDATE {TBL_TRANSACTIONS} SET {COL_STATUS} = %s
            WHERE {COL_ID} = %s;
        """
        # If tracking needed: add updated_at=CURRENT_TIMESTAMP, updated_by_user_id=%s
        params = (new_status, transaction_id)
        return self.execute_sql(sql, params)

    def bulk_update_transaction_status(self, transaction_ids, new_status, updated_by_user_id): # <<< NEW
        """Updates the status for a list of transaction IDs."""
        if not transaction_ids:
            logging.warning("bulk_update_transaction_status called with empty ID list.")
            return False
        if not new_status or new_status not in ALL_STATUS_OPTIONS:
             logging.error(f"bulk_update_transaction_status called with invalid status: {new_status}")
             return False

        sql = f"""
            UPDATE {TBL_TRANSACTIONS}
            SET {COL_STATUS} = %s,
                updated_at = CURRENT_TIMESTAMP,
                updated_by_user_id = %s
            WHERE {COL_ID} = ANY(%s::int[]); -- Use ANY with array casting
        """
        params = (new_status, updated_by_user_id, transaction_ids)
        return self.execute_sql(sql, params) # Returns True on success, False on failure
    
    def add_memo(self, name):
        """Adds a new memo option to the memos table."""
        sql = "INSERT INTO memos (name) VALUES (%s) RETURNING memo_id;"
        result = self.execute_sql(sql, (name,), fetch=True)
        if result and isinstance(result, list) and len(result) > 0:
             return result[0][0]
        return None

    def get_memos(self):
        """Retrieves all memo options from the memos table."""
        sql = "SELECT memo_id, name FROM memos ORDER BY name;"
        result = self.execute_sql(sql, fetch=True)
        # Returns list of tuples [(memo_id, name), ...] or empty list
        return result if result is not None else []

    def update_memo_name(self, memo_id, new_name):
        """Updates the name of a specific memo."""
        # --- IMPORTANT: If storing name in transactions, need to update transactions too! ---
        conn = self.get_connection()
        if not conn: return False

        old_name_result = self.execute_sql("SELECT name FROM memos WHERE memo_id = %s", (memo_id,), fetch=True)
        if not old_name_result:
            logging.error(f"Cannot update memo: Memo ID {memo_id} not found.")
            return False
        old_name = old_name_result[0][0]

        if old_name == new_name:
            return True # No change needed

        success = False
        try:
            with conn.cursor() as cur:
                # 1. Update memos table
                logging.debug(f"Updating memo ID {memo_id} from '{old_name}' to '{new_name}'")
                cur.execute("UPDATE memos SET name = %s WHERE memo_id = %s;", (new_name, memo_id))

                # 2. Update transactions table (since we store name directly - Option 1)
                # If you chose Option 2 (memo_id FK), you skip this transaction update step.
                logging.debug(f"Updating transactions with old memo '{old_name}' to '{new_name}'")
                cur.execute(f"UPDATE {TBL_TRANSACTIONS} SET {COL_MEMO} = %s WHERE {COL_MEMO} = %s;", (new_name, old_name))
                updated_count = cur.rowcount
                logging.info(f"Updated {updated_count} transaction records for memo rename.")

                conn.commit()
                success = True
                logging.info(f"Memo rename committed successfully for ID {memo_id}.")
        except psycopg2.Error as e:
            logging.error(f"Error during memo rename transaction for ID {memo_id}: {e}", exc_info=True)
            if conn: conn.rollback(); logging.warning("Memo rename rolled back.")
            messagebox.showerror("Database Error", f"Failed to rename memo.\nError: {e.pgerror or e}")
            success = False
        except Exception as e:
             logging.error(f"Unexpected error during memo rename for ID {memo_id}: {e}", exc_info=True)
             if conn: conn.rollback(); logging.warning("Memo rename rolled back.")
             messagebox.showerror("Error", f"An unexpected error occurred during memo rename: {e}")
             success = False
        return success


    def delete_memo(self, memo_id):
        """Deletes a specific memo option."""
        # --- IMPORTANT: Handle transactions using this memo ---
        conn = self.get_connection()
        if not conn: return False

        memo_name_result = self.execute_sql("SELECT name FROM memos WHERE memo_id = %s", (memo_id,), fetch=True)
        if not memo_name_result:
            logging.warning(f"Cannot delete memo: Memo ID {memo_id} not found.")
            # Decide if this is an error or just means already deleted
            return True # Or False if you want to signal not found

        memo_name = memo_name_result[0][0]

        success = False
        try:
            with conn.cursor() as cur:
                 # Option 1 (Chosen): Clear memo in transactions
                 logging.debug(f"Clearing memo '{memo_name}' from transactions before deleting memo ID {memo_id}.")
                 cur.execute(f"UPDATE {TBL_TRANSACTIONS} SET {COL_MEMO} = NULL WHERE {COL_MEMO} = %s;", (memo_name,))
                 updated_count = cur.rowcount
                 logging.info(f"Cleared memo field for {updated_count} transaction records.")

                 # Option 2 (If using memo_id FK): The ON DELETE SET NULL handles this automatically
                 # Just delete from memos table

                 # Now delete from memos table
                 cur.execute("DELETE FROM memos WHERE memo_id = %s;", (memo_id,))

                 conn.commit()
                 success = True
                 logging.info(f"Memo deleted successfully: ID={memo_id}, Name='{memo_name}'.")

        except psycopg2.Error as e:
             logging.error(f"Error during memo delete transaction for ID {memo_id}: {e}", exc_info=True)
             if conn: conn.rollback(); logging.warning("Memo delete rolled back.")
             messagebox.showerror("Database Error", f"Failed to delete memo.\nError: {e.pgerror or e}")
             success = False
        except Exception as e:
             logging.error(f"Unexpected error during memo delete for ID {memo_id}: {e}", exc_info=True)
             if conn: conn.rollback(); logging.warning("Memo delete rolled back.")
             messagebox.showerror("Error", f"An unexpected error occurred during memo delete: {e}")
             success = False
        return success
    
    def check_transaction_exists(self, company_id, bank_name, date, amount, check_no=None, vendor_or_customer_name=None):
        """
        Checks if a transaction with similar key fields already exists.
        Returns True if a potential duplicate is found, False otherwise.
        """
        sql_parts = [
            f"{COL_COMPANY_ID} = %s",
            f"{COL_BANK_NAME} = %s",
            f"{COL_DATE} = %s",
            f"{COL_AMOUNT} = %s"
        ]
        params = [company_id, bank_name, date, amount]

        if check_no:
            sql_parts.append(f"{COL_CHECK_NO} = %s")
            params.append(check_no)
        else:
            # If check_no is None or empty, we look for records where check_no IS NULL.
            # This is important if you have transactions without check numbers.
            sql_parts.append(f"{COL_CHECK_NO} IS NULL")
            # No parameter to add for IS NULL

        if vendor_or_customer_name:
            sql_parts.append(f"{COL_VENDOR} = %s") # COL_VENDOR stores vendor/customer name
            params.append(vendor_or_customer_name)
        else:
            # If vendor/customer is not provided for check, we can make it optional or check for NULL
            # For now, let's assume if not provided, we don't filter by it, making the check slightly looser
            # OR, more strictly: sql_parts.append(f"{COL_VENDOR} IS NULL")
            pass # Not filtering by vendor if not provided for the check

        sql = f"SELECT {COL_ID} FROM {TBL_TRANSACTIONS} WHERE " + " AND ".join(sql_parts) + " LIMIT 1;"
        
        logging.debug(f"Executing duplicate check SQL: {sql} with params: {params}")
        result = self.execute_sql(sql, params=params, fetch=True)
        
        if result and len(result) > 0:
            logging.warning(f"Potential duplicate found for criteria: CompID={company_id}, Bank='{bank_name}', Date='{date}', Amt={amount}, Check='{check_no}', Vend/Cust='{vendor_or_customer_name}'. Existing ID: {result[0][0]}")
            return True # Found a transaction
        return False # No transaction found

    # --- END NEW Memo Methods ---


# --- Styling Setup Function ---
def setup_styling():
    style = ttk.Style()
    try:
        themes = style.theme_names()
        logging.debug(f"Available themes: {themes}")
        if 'clam' in themes: style.theme_use('clam')
        elif 'vista' in themes: style.theme_use('vista')
        elif 'aqua' in themes: style.theme_use('aqua')
        else: style.theme_use(themes[0])
        logging.info(f"Using theme: {style.theme_use()}")
    except tk.TclError as e:
        logging.warning(f"Could not set ttk theme, using default. Error: {e}")

    # <<< MODIFIED: Added radio_font_larger global >>>
    global default_font, text_font, header_font, title_font, default_font_bold, radio_font_larger
    try:
        default_font = tkFont.Font(family="Segoe UI", size=10)
        text_font = tkFont.Font(family="Segoe UI", size=10)
        header_font = tkFont.Font(family="Segoe UI Semibold", size=11)
        title_font = tkFont.Font(family="Segoe UI Semibold", size=18)
        default_font_bold = default_font.copy()
        default_font_bold.configure(weight='bold')
        # <<< NEW FONT for Radiobuttons >>>
        radio_font_larger = tkFont.Font(family="Segoe UI Semibold", size=11)
    except tk.TclError:
        logging.warning("Segoe UI font not found, using Tk default.")
        default_font = tkFont.nametofont("TkDefaultFont")
        text_font = tkFont.nametofont("TkTextFont")
        header_font = tkFont.nametofont("TkHeadingFont")
        title_font = tkFont.Font(family=default_font.actual("family"), size=18, weight="bold")
        default_font_bold = tkFont.nametofont("TkDefaultFont")
        try: default_font_bold.configure(weight='bold')
        except tk.TclError: pass
        # <<< Fallback Font >>>
        radio_font_larger = tkFont.Font(family=default_font.actual("family"), size=11, weight="bold") # Fallback

    # --- Base Styles ---
    style.configure('.', background=COLOR_PRIMARY_BG, foreground=COLOR_TEXT,
                    fieldbackground=COLOR_ENTRY_BG, font=default_font, borderwidth=0, focuscolor=COLOR_ACCENT)
    style.configure('TFrame', background=COLOR_PRIMARY_BG)
    style.configure('Card.TFrame', background=COLOR_CARD_BG, relief='flat', borderwidth=1, bordercolor=COLOR_BORDER)
    style.configure('TLabel', background=COLOR_PRIMARY_BG, foreground=COLOR_TEXT, font=default_font)
    style.configure('Card.TLabel', background=COLOR_CARD_BG, foreground=COLOR_TEXT, font=default_font)
    style.configure('Title.TLabel', background=COLOR_PRIMARY_BG, foreground=COLOR_ACCENT, font=title_font)
    style.configure('Header.TLabel', background=COLOR_CARD_BG, foreground=COLOR_ACCENT, font=header_font)
    style.configure('Error.TLabel', background=COLOR_CARD_BG, foreground=COLOR_VOID_ROW, font=default_font_bold)
    style.configure('TEntry', foreground=COLOR_ENTRY_FG, fieldbackground=COLOR_ENTRY_BG, insertcolor=COLOR_TEXT,
                    borderwidth=1, relief='solid', bordercolor=COLOR_BORDER, font=text_font)
    style.map('TEntry', bordercolor=[('focus', COLOR_ACCENT), ('invalid', COLOR_VOID_ROW)],
              fieldbackground=[('disabled', COLOR_SECONDARY_BG), ('invalid', COLOR_PENDING_ROW)])
    style.configure('TButton', background=COLOR_BUTTON_SECONDARY_BG, foreground=COLOR_BUTTON_SECONDARY_FG,
                    padding=(12, 7), font=default_font, borderwidth=0, relief='flat', anchor='center')
    style.map('TButton', background=[('active', COLOR_BUTTON_SECONDARY_HOVER), ('pressed', COLOR_BUTTON_SECONDARY_HOVER),
                                     ('disabled', COLOR_SECONDARY_BG)], foreground=[('disabled', COLOR_TEXT_SECONDARY)])
    style.configure('Accent.TButton', background=COLOR_BUTTON_PRIMARY_BG, foreground=COLOR_BUTTON_PRIMARY_FG, font=default_font_bold)
    style.map('Accent.TButton', background=[('active', COLOR_BUTTON_PRIMARY_HOVER), ('pressed', COLOR_BUTTON_PRIMARY_HOVER),
                                            ('disabled', COLOR_ACCENT_HOVER)], foreground=[('disabled', COLOR_BUTTON_SECONDARY_BG)])
    style.configure('Link.TButton', foreground=COLOR_ACCENT, background=COLOR_CARD_BG,
                    font=default_font, borderwidth=0, relief='flat', anchor='center',
                    padding=(0,0)) # Minimal padding
    style.map('Link.TButton',
              foreground=[('active', COLOR_ACCENT_HOVER), ('pressed', COLOR_ACCENT_HOVER)],
              background=[('active', COLOR_CARD_BG), ('pressed', COLOR_CARD_BG)]) # Keep background consistent
    link_font_underlined = default_font.copy()
    link_font_underlined.configure(underline=True)
    style.map('Link.TButton', font=[('active', link_font_underlined)])
    style.configure('TCombobox', foreground=COLOR_ENTRY_FG, fieldbackground=COLOR_ENTRY_BG, background=COLOR_ENTRY_BG,
                    arrowcolor=COLOR_TEXT, bordercolor=COLOR_BORDER, borderwidth=1, relief='solid', padding=(5, 5), font=text_font)
    style.map('TCombobox', bordercolor=[('focus', COLOR_ACCENT), ('invalid', COLOR_VOID_ROW)],
              fieldbackground=[('readonly', COLOR_ENTRY_BG), ('disabled', COLOR_SECONDARY_BG), ('invalid', COLOR_PENDING_ROW)],
              background=[('readonly', COLOR_ENTRY_BG), ('disabled', COLOR_SECONDARY_BG)],
              foreground=[('disabled', COLOR_TEXT_SECONDARY)], arrowcolor=[('disabled', COLOR_TEXT_SECONDARY)])
    style.configure('TNotebook', background=COLOR_PRIMARY_BG, borderwidth=0, tabmargins=[2, 5, 2, 0])
    style.configure('TNotebook.Tab', background=COLOR_PRIMARY_BG, foreground=COLOR_TEXT_SECONDARY,
                    padding=[15, 7], font=default_font, borderwidth=0, relief='flat')
    style.map('TNotebook.Tab', background=[('selected', COLOR_SECONDARY_BG)], foreground=[('selected', COLOR_ACCENT)],
              font=[('selected', default_font_bold)])
    style.configure('Treeview', background=COLOR_TREE_BG, foreground=COLOR_TREE_FG, fieldbackground=COLOR_TREE_BG,
                    rowheight=28, font=text_font, borderwidth=1, relief='solid', bordercolor=COLOR_BORDER)
    style.map('Treeview', background=[('selected', COLOR_ACCENT)], foreground=[('selected', COLOR_BUTTON_PRIMARY_FG)])
    style.configure('Treeview.Heading', background=COLOR_HEADER_BG, foreground=COLOR_HEADER_FG, font=header_font,
                    padding=(8, 8), relief='flat', borderwidth=0, anchor='w')
    style.map('Treeview.Heading', background=[('active', COLOR_SECONDARY_BG)], relief=[('active','groove')])
    style.configure("Vertical.TScrollbar", gripcount=0, background=COLOR_BUTTON_SECONDARY_BG, borderwidth=0,
                    troughcolor=COLOR_PRIMARY_BG, bordercolor=COLOR_BUTTON_SECONDARY_BG, arrowrelief='flat', relief='flat',
                    arrowcolor=COLOR_TEXT_SECONDARY, arrowsize=14)
    style.map("Vertical.TScrollbar", background=[('active', COLOR_BUTTON_SECONDARY_HOVER)],
              arrowcolor=[('pressed', COLOR_ACCENT), ('active', COLOR_TEXT)])
    style.configure("Horizontal.TScrollbar", gripcount=0, background=COLOR_BUTTON_SECONDARY_BG, borderwidth=0,
                    troughcolor=COLOR_PRIMARY_BG, bordercolor=COLOR_BUTTON_SECONDARY_BG, arrowrelief='flat', relief='flat',
                    arrowcolor=COLOR_TEXT_SECONDARY, arrowsize=14)
    style.map("Horizontal.TScrollbar", background=[('active', COLOR_BUTTON_SECONDARY_HOVER)],
              arrowcolor=[('pressed', COLOR_ACCENT), ('active', COLOR_TEXT)])
    style.configure('TCheckbutton', background=COLOR_CARD_BG, foreground=COLOR_TEXT, font=default_font, indicatorcolor=COLOR_ENTRY_BG)
    style.map('TCheckbutton',
              indicatorcolor=[('selected', COLOR_ACCENT), ('active', COLOR_ACCENT_HOVER)],
              background=[('active', COLOR_CARD_BG)])

    # --- Radiobutton Styles ---
    style.configure('TRadiobutton', background=COLOR_PRIMARY_BG, foreground=COLOR_TEXT, font=default_font) # Base style
    # <<< NEW Style for Larger Font >>>
    style.configure('Large.TRadiobutton', background=COLOR_PRIMARY_BG, foreground=COLOR_TEXT, font=radio_font_larger)
    # Optional: Add mapping for hover etc. if needed for the large style
    style.map('Large.TRadiobutton',
              background=[('active', COLOR_SECONDARY_BG)], # Example hover
              indicatorcolor=[('selected', COLOR_ACCENT), ('active', COLOR_ACCENT_HOVER)])


# --- Main Application Class ---
app = None # Define app globally

class BankSheetApp:
    # Inside BankSheetApp class
    # --- Define manageable tabs (used for UI and permissions) ---
    MANAGEABLE_TABS = {
        'home': 'Homepage',
        'bank_summary': 'Bank Summary',
        'add_transaction': 'Add Transaction',
        'report': 'Transaction Report',
        'memo_summary': 'Memo Summary',
        'management': 'Management (Companies/Banks/Payees)', # <<< Included
        # user_management is implicitly admin-only
    }

    def __init__(self, root):
        global app
        app = self
        self.root = root
        self.db_manager = DatabaseManager(load_config)
        self.current_user_id = None
        self.current_username = None
        self.current_user_role = None
        self.tab_frames = {}
        self.tab_texts = {}

        # --- ADDED FOR REPORT TREE SORTING ---
        self.report_tree_sort_column = None
        self.report_tree_sort_direction = 'asc' # Default: ascending
        self.report_tree_data_cache = []      # To store data for sorting
        self.report_tree_checked_db_ids = set() # To preserve checked items' DB IDs if CheckboxTreeview is used
        # --- END ADDED ---

        self.root.withdraw()
        print("DEBUG: BankSheetApp.__init__ - Root window withdrawn initially.")

        self.root.option_add('*tearOff', tk.FALSE)
        setup_styling()
        print("DEBUG: BankSheetApp.__init__ - Styling setup complete.")

        print("DEBUG: BankSheetApp.__init__ - Getting initial DB connection...")
        if not self.db_manager.get_connection():
            logging.critical("Initial DB connection failed. Cannot proceed.")
            print("FATAL ERROR: Could not connect to the database. Application cannot start.")
            if self.db_manager: self.db_manager.close_connection()
            if self.root:
                try: self.root.destroy()
                except tk.TclError: pass
            return

        print("DEBUG: BankSheetApp.__init__ - Initializing database schema...")
        if not self.db_manager.initialize_database():
            error_parent = tk.Toplevel()
            error_parent.withdraw()
            messagebox.showerror("Fatal Error", "Failed to initialize database schema. Application cannot start.", parent=error_parent)
            error_parent.destroy()
            logging.critical("Database schema initialization failed.")
            self.db_manager.close_connection()
            if self.root:
                try: self.root.destroy()
                except tk.TclError: pass
            return

        print("DEBUG: BankSheetApp.__init__ - Ensuring admin user exists...")
        self._ensure_admin_user()

        print("DEBUG: BankSheetApp.__init__ - Starting LoginDialog...")
        try:
            LoginDialog(self.root, self.db_manager, self._post_login_setup)
            print("DEBUG: BankSheetApp.__init__ - LoginDialog finished.")
        except Exception as login_dialog_ex:
            print(f"CRITICAL ERROR: Exception occurred during LoginDialog instantiation or wait: {login_dialog_ex}")
            logging.critical(f"CRITICAL ERROR during LoginDialog: {login_dialog_ex}", exc_info=True)
            error_parent = tk.Toplevel()
            error_parent.withdraw()
            messagebox.showerror("Critical Error", f"Failed to start login dialog:\n{login_dialog_ex}", parent=error_parent)
            error_parent.destroy()
            self.db_manager.close_connection()
            if hasattr(self, 'root') and self.root:
                try:
                    if self.root.winfo_exists(): self.root.destroy()
                except tk.TclError: pass
            return

        root_still_exists = False
        try:
            if self.root: root_still_exists = self.root.winfo_exists()
        except tk.TclError: root_still_exists = False

        if root_still_exists and self.current_user_id:
            print("DEBUG: BankSheetApp.__init__ - Login successful and root exists. Initialization complete.")
            pass # Initialization successful, continue.
        else:
            print("DEBUG: BankSheetApp.__init__ - Login failed/cancelled OR root was destroyed during setup. App will exit.")
            if self.db_manager: self.db_manager.close_connection()
            if root_still_exists and not self.current_user_id:
                print("DEBUG: BankSheetApp.__init__ - Destroying root because it exists but login failed.")
                try: self.root.destroy()
                except tk.TclError: pass

    def _ensure_admin_user(self):
        sql = "SELECT 1 FROM users WHERE role = 'admin' LIMIT 1;"
        result = self.db_manager.execute_sql(sql, fetch=True)
        if not result:
            logging.warning("No admin user found. Prompting to create one.")
            if messagebox.askyesno("Admin User Required", "No admin user found.\nWould you like to create one now?", parent=self.root):
                username = simpledialog.askstring("Create Admin", "Enter admin username:", parent=self.root)
                if username:
                    password = simpledialog.askstring("Create Admin", f"Enter password for '{username}':", show='*', parent=self.root)
                    if password:
                        if self.db_manager.add_user(username, password, role='admin'):
                            messagebox.showinfo("Admin Created", f"Admin user '{username}' created successfully.", parent=self.root)
                        else:
                            messagebox.showerror("Error", "Failed to create admin user (username might exist). Check logs.", parent=self.root)
                    else: messagebox.showwarning("Cancelled", "Password required. Admin not created.", parent=self.root)
                else: messagebox.showwarning("Cancelled", "Username required. Admin not created.", parent=self.root)
            else:
                messagebox.showwarning("Warning", "Admin user needed for full functionality.", parent=self.root)

    def _post_login_setup(self, user_info):
        if user_info:
            self.current_user_id, self.current_username, self.current_user_role = user_info
            logging.info(f"Proceeding with setup for user: {self.current_username} (Role: {self.current_user_role})")
            try:
                self.setup_ui()
                self.root.update_idletasks()
                self._apply_role_permissions() # Apply permissions *after* UI exists
                self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
                self.root.title(f"Bank Sheet - Logged in as: {self.current_username} ({self.current_user_role})")
                self.root.deiconify()
                self.root.lift()
                self.root.focus_force()
                self.initialize_data() # Populate data *after* UI is visible and permissions applied
            except Exception as e:
                print(f"CRITICAL ERROR in _post_login_setup's try block: {e}")
                logging.critical(f"CRITICAL ERROR during post-login UI setup: {e}", exc_info=True)
                try: messagebox.showerror("Fatal Setup Error", f"Failed to set up main window:\n{e}\nCheck logs.", parent=self.root if self.root.winfo_exists() else None)
                except Exception as msg_e: print(f"ERROR: Could not show error messagebox: {msg_e}")
                if hasattr(self, 'root') and self.root.winfo_exists(): self.root.destroy()
        else:
            logging.warning("Login failed or cancelled. Exiting application.")
            if hasattr(self, 'db_manager') and self.db_manager: self.db_manager.close_connection()
            if hasattr(self, 'root') and self.root.winfo_exists(): self.root.destroy()

    def setup_ui(self):
        # self.root.title("Bank Sheet") # Title set in _post_login_setup
        # self.root.geometry("1450x800") # Replaced by dynamic sizing
        # self.root.minsize(1250, 700)   # Replaced by dynamic minsize

        # Get screen dimensions
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()

        # Define desired initial size as a percentage of the screen
        # and ensure it's within reasonable min/max bounds.
        initial_width_pct = 0.90
        initial_height_pct = 0.85 # Slightly less height percentage

        # Define absolute min and max sizes for the application window
        # These values are examples; adjust them based on your UI's needs.
        # Min size should be what's absolutely necessary to see core UI.
        min_app_width = 1024
        min_app_height = 680 # Adjusted for 14-inch typical height (e.g., 768px)

        # Max size can prevent the app from being overly large on very high-res screens
        max_initial_width = 1800
        max_initial_height = 1000

        # Calculate initial width and height
        app_width = int(screen_width * initial_width_pct)
        app_height = int(screen_height * initial_height_pct)

        # Apply max constraints
        app_width = min(app_width, max_initial_width)
        app_height = min(app_height, max_initial_height)

        # Apply min constraints (ensure calculated size isn't smaller than min_app_width/height)
        app_width = max(app_width, min_app_width)
        app_height = max(app_height, min_app_height)
        
        # If the screen is smaller than our desired minimum, use the screen size
        # (minus a small margin if preferred) but not less than a hardcoded absolute minimum.
        hard_abs_min_width = 800 # Absolute smallest the window should ever be
        hard_abs_min_height = 550

        if screen_width < min_app_width:
            app_width = max(screen_width - 40, hard_abs_min_width) # Use screen width with a margin
        if screen_height < min_app_height:
            app_height = max(screen_height - 40, hard_abs_min_height) # Use screen height with a margin
            
        self.root.geometry(f"{app_width}x{app_height}")
        self.root.minsize(min_app_width, min_app_height) # Min resize limit
        
        self.root.configure(bg=COLOR_PRIMARY_BG)

        self._create_menu()
        self._create_notebook()

        # Create all tabs initially
        self._create_homepage_tab()
        self._create_bank_summary_tab()
        self._create_transaction_tab()
        self._create_report_tab()
        self._create_memo_summary_tab()
        self._create_management_tab()
        self._create_user_management_tab()

        # Set initial focus after UI is built
        self.root.after(100, lambda: self.company_combobox.focus_set() if hasattr(self, 'company_combobox') else None)
    
    def _create_menu(self):
        self.menubar = tk.Menu(self.root)
        self.root.config(menu=self.menubar)
        self.file_menu = tk.Menu(self.menubar, tearoff=0, background=COLOR_SECONDARY_BG, foreground=COLOR_TEXT,
                                 activebackground=COLOR_ACCENT, activeforeground=COLOR_BUTTON_PRIMARY_FG)
        self.menubar.add_cascade(label="File", menu=self.file_menu, underline=0)
        self.file_menu.add_command(label="Database Settings", command=self.show_settings_window, accelerator="Ctrl+S")
        self.file_menu.add_command(label="Export Full Report", command=self.export_to_excel, accelerator="Ctrl+E")
        self.file_menu.add_separator(background=COLOR_BORDER)
        self.file_menu.add_command(label="Exit", command=self.on_closing, accelerator="Ctrl+Q")

        view_menu = tk.Menu(self.menubar, tearoff=0, background=COLOR_SECONDARY_BG, foreground=COLOR_TEXT,
                            activebackground=COLOR_ACCENT, activeforeground=COLOR_BUTTON_PRIMARY_FG)
        self.menubar.add_cascade(label="View", menu=view_menu, underline=0)
        view_menu.add_command(label="Refresh All Data", command=self.refresh_all_views, accelerator="F5")

        self.root.bind_all("<Control-s>", lambda e: self.show_settings_window())
        self.root.bind_all("<Control-e>", lambda e: self.export_to_excel())
        self.root.bind_all("<Control-q>", lambda e: self.on_closing())
        self.root.bind_all("<F5>", lambda e: self.refresh_all_views())

    def _create_notebook(self):
        self.notebook = ttk.Notebook(self.root, padding="5 5 5 5", style='TNotebook')
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=15, pady=(10, 15))
        self.tab_frames = {} # Stores frame widgets
        self.tab_texts = {} # Stores display text

    def _create_homepage_tab(self):
        frame = ttk.Frame(self.notebook, padding="25 25 25 25")
        tab_key = 'home'
        self.tab_frames[tab_key] = frame
        tab_text = " Homepage "
        if not hasattr(self, 'tab_texts'): self.tab_texts = {}
        self.tab_texts[tab_key] = tab_text
        self.notebook.add(frame, text=tab_text) # Add initially, permissions hide later

        frame.rowconfigure(1, weight=1)
        frame.columnconfigure(0, weight=1)
        ttk.Label(frame, text="Bank Sheet Dashboard", style='Title.TLabel').grid(
            row=0, column=0, columnspan=2, pady=(0, 30), sticky='nw')

        pending_frame = ttk.Frame(frame, style='Card.TFrame', padding="20")
        pending_frame.grid(row=1, column=0, columnspan=2, sticky='nsew', pady=(0, 25))
        pending_frame.rowconfigure(1, weight=1)
        pending_frame.columnconfigure(0, weight=1)
        ttk.Label(pending_frame, text="Pending Transactions", style='Header.TLabel').grid(
            row=0, column=0, columnspan=2, sticky='nw', pady=(0, 15))

        self.pending_tree = ttk.Treeview(pending_frame, columns=TREE_COLUMNS_PENDING, show="headings", height=8, style='Treeview')
        self._configure_treeview_columns(self.pending_tree, TREE_COLUMNS_PENDING)
        pending_vsb = ttk.Scrollbar(pending_frame, orient="vertical", command=self.pending_tree.yview, style="Vertical.TScrollbar")
        pending_hsb = ttk.Scrollbar(pending_frame, orient="horizontal", command=self.pending_tree.xview, style="Horizontal.TScrollbar")
        self.pending_tree.configure(yscrollcommand=pending_vsb.set, xscrollcommand=pending_hsb.set)
        self.pending_tree.grid(row=1, column=0, sticky='nsew')
        pending_vsb.grid(row=1, column=1, sticky='ns')
        pending_hsb.grid(row=2, column=0, columnspan=2, sticky='ew', pady=(5,0))
        ttk.Button(pending_frame, text="Refresh", command=self.populate_pending_tree, width=12).grid(
            row=3, column=0, columnspan=2, pady=(15, 0), sticky='e')
        self.pending_context_menu = self._create_context_menu(self.pending_tree)
        self.pending_tree.bind("<Button-3>", lambda event: self._show_context_menu(event, self.pending_tree, self.pending_context_menu))
        self.pending_tree.bind("<Double-1>", self.edit_selected_transaction)

        actions_frame = ttk.Frame(frame, style='Card.TFrame', padding="20")
        actions_frame.grid(row=2, column=0, columnspan=2, sticky='nsew', pady=(0, 15))
        actions_frame.columnconfigure(0, weight=1); actions_frame.columnconfigure(1, weight=1)
        ttk.Label(actions_frame, text="Quick Actions", style='Header.TLabel').grid(row=0, column=0, columnspan=2, sticky='nw', pady=(0, 15))
        ttk.Button(actions_frame, text="Add New Transaction", command=self.go_to_add_transaction_tab, style='Accent.TButton').grid(row=1, column=0, padx=(0, 10), pady=5, sticky='ew', ipady=4)
        ttk.Button(actions_frame, text="View Full Report", command=self.go_to_report_tab).grid(row=1, column=1, padx=(10, 0), pady=5, sticky='ew', ipady=4)

    # <<< UPDATED Bank Summary Tab >>>
    def _create_bank_summary_tab(self):
        frame = ttk.Frame(self.notebook, padding="25 25 25 25")
        tab_key = 'bank_summary'
        self.tab_frames[tab_key] = frame
        tab_text = " Bank Summary "
        if not hasattr(self, 'tab_texts'): self.tab_texts = {}
        self.tab_texts[tab_key] = tab_text
        self.notebook.add(frame, text=tab_text) # Add initially

        frame.rowconfigure(2, weight=1) # Treeview is row 2
        frame.columnconfigure(0, weight=1)

        ttk.Label(frame, text="Bank Transaction Summary", style='Title.TLabel').grid(
            row=0, column=0, columnspan=2, pady=(0, 15), sticky='nw')

        # --- Filter Frame ---
        bank_filter_frame = ttk.Frame(frame, style='Card.TFrame', padding=(15, 10))
        bank_filter_frame.grid(row=1, column=0, sticky='new', pady=(0, 15))
        bank_filter_frame.columnconfigure(1, weight=1)
        ttk.Label(bank_filter_frame, text="Filter by Bank:", style='Card.TLabel').grid(row=0, column=0, sticky='w', padx=5, pady=5)
        self.bank_summary_filter_var = tk.StringVar()
        self.bank_summary_filter_combo = ttk.Combobox(bank_filter_frame, textvariable=self.bank_summary_filter_var, state='readonly', width=30, font=text_font)
        self.bank_summary_filter_combo.grid(row=0, column=1, sticky='ew', padx=5, pady=5)
        bank_filter_button_frame = ttk.Frame(bank_filter_frame, style='Card.TFrame')
        bank_filter_button_frame.grid(row=0, column=2, padx=(10, 0))
        ttk.Button(bank_filter_button_frame, text="Apply", command=self.populate_bank_summary_tree, style='Accent.TButton', width=8).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(bank_filter_button_frame, text="Clear", command=self.clear_bank_summary_filter, width=8).pack(side=tk.LEFT)

        # --- Summary Frame ---
        summary_frame = ttk.Frame(frame, style='Card.TFrame', padding=20)
        summary_frame.grid(row=2, column=0, sticky='nsew', pady=(0, 20)) # Treeview frame in row 2
        summary_frame.rowconfigure(0, weight=1)
        summary_frame.columnconfigure(0, weight=1)

        # Use UPDATED columns constant
        self.bank_summary_tree = ttk.Treeview(summary_frame, columns=TREE_COLUMNS_BANK_SUMMARY, show="headings", height=15, style='Treeview')

        # --- Configure Headings and Columns ---
        self.bank_summary_tree.heading("Bank Name", text="Bank Name", anchor=tk.W)
        self.bank_summary_tree.column("Bank Name", width=200, anchor=tk.W, stretch=tk.YES)
        self.bank_summary_tree.heading("Total Credits", text="Credits (+)", anchor=tk.E)
        self.bank_summary_tree.column("Total Credits", width=130, anchor=tk.E, stretch=tk.NO)
        self.bank_summary_tree.heading("Total Debits", text="Debits (-)", anchor=tk.E)
        self.bank_summary_tree.column("Total Debits", width=130, anchor=tk.E, stretch=tk.NO)
        self.bank_summary_tree.heading("Posted Balance", text="Posted Balance", anchor=tk.E)
        self.bank_summary_tree.column("Posted Balance", width=140, anchor=tk.E, stretch=tk.NO)

        # --- RENAMED: "Balance with Clearance" becomes "Difference" ---
        self.bank_summary_tree.heading("Difference", text="Difference", anchor=tk.E) # <<< TEXT CHANGED
        self.bank_summary_tree.column("Difference", width=160, anchor=tk.E, stretch=tk.NO) # <<< IDENTIFIER CHANGED

        # --- RENAMED: "Difference" becomes "Clearance" ---
        self.bank_summary_tree.heading("Clearance", text="Clearance", anchor=tk.E) # <<< TEXT CHANGED
        self.bank_summary_tree.column("Clearance", width=150, anchor=tk.E, stretch=tk.NO) # <<< IDENTIFIER CHANGED
        # --- END OF RENAMES ---
        # ... (Scrollbar setup) ...
        summary_vsb = ttk.Scrollbar(summary_frame, orient="vertical", command=self.bank_summary_tree.yview, style="Vertical.TScrollbar")
        summary_hsb = ttk.Scrollbar(summary_frame, orient="horizontal", command=self.bank_summary_tree.xview, style="Horizontal.TScrollbar")
        self.bank_summary_tree.configure(yscrollcommand=summary_vsb.set, xscrollcommand=summary_hsb.set)
        self.bank_summary_tree.grid(row=0, column=0, sticky='nsew')
        summary_vsb.grid(row=0, column=1, sticky='ns')
        summary_hsb.grid(row=1, column=0, columnspan=2, sticky='ew', pady=(5,0))

        # self._configure_tree_tags(self.bank_summary_tree) # Optional

        # Refresh button in row 3
        ttk.Button(frame, text="Refresh Summary", command=self.populate_bank_summary_tree, width=18).grid(
            row=3, column=0, pady=(10, 0), sticky='e')

    # --- Add filter clearing function ---
    def clear_bank_summary_filter(self):
        """Clears the bank summary filter and refreshes the view."""
        logging.debug("Clearing bank summary filter.")
        self.bank_summary_filter_var.set(FILTER_ALL_BANKS)
        try:
            if self.bank_summary_filter_combo['values']:
                self.bank_summary_filter_combo.current(0)
        except (tk.TclError, IndexError):
            pass
        self.populate_bank_summary_tree()

    def _create_transaction_tab(self):
        # Main frame for the tab, added to the notebook
        tab_frame = ttk.Frame(self.notebook, padding="5") # Reduced outer padding
        tab_key = 'add_transaction'
        self.tab_frames[tab_key] = tab_frame
        tab_text = " Add Transaction "
        if not hasattr(self, 'tab_texts'): self.tab_texts = {}
        self.tab_texts[tab_key] = tab_text
        self.notebook.add(tab_frame, text=tab_text)

        # Configure the main tab_frame to allow the canvas to expand
        tab_frame.rowconfigure(0, weight=1)
        tab_frame.columnconfigure(0, weight=1)

        # --- Create Canvas for Scrolling ---
        canvas = tk.Canvas(tab_frame, highlightthickness=0, bg=COLOR_PRIMARY_BG)
        canvas.grid(row=0, column=0, sticky='nsew')

        # --- Create Scrollbar for the Canvas ---
        scrollbar = ttk.Scrollbar(tab_frame, orient="vertical", command=canvas.yview, style="Vertical.TScrollbar")
        scrollbar.grid(row=0, column=1, sticky='ns')
        canvas.configure(yscrollcommand=scrollbar.set)

        # --- Create the Frame INSIDE the Canvas that will hold the actual form content ---
        # This is the frame that will be scrolled.
        # Use a standard ttk.Frame, not 'Card.TFrame' if you want the background to match the tab_frame
        scrollable_form_frame = ttk.Frame(canvas, padding="15 15 15 10") # Inner padding for content
        scrollable_form_frame.columnconfigure(1, weight=1) # For entry expansion

        # Add the scrollable_form_frame to the canvas
        canvas_frame_id = canvas.create_window((0, 0), window=scrollable_form_frame, anchor="nw")

        # --- Function to update scrollregion ---
        def on_frame_configure(event):
            canvas.configure(scrollregion=canvas.bbox("all"))

        # --- Function to handle mousewheel scrolling ---
        def on_mousewheel(event):
            # On Windows, event.delta is usually +/- 120. Divide by a factor for smoother scroll.
            # On Linux, event.num might be 4 (scroll up) or 5 (scroll down).
            if sys.platform == "win32":
                canvas.yview_scroll(int(-1 * (event.delta / 60)), "units")
            elif sys.platform == "darwin": # macOS
                 canvas.yview_scroll(int(-1 * (event.delta)), "units")
            else: # Linux
                if event.num == 4:
                    canvas.yview_scroll(-1, "units")
                elif event.num == 5:
                    canvas.yview_scroll(1, "units")
        
        scrollable_form_frame.bind("<Configure>", on_frame_configure)
        
        # Bind mousewheel to canvas, scrollable_form_frame, and its children for better UX
        canvas.bind_all("<MouseWheel>", on_mousewheel, add="+") # Bind globally to canvas
        # It might be necessary to also bind to the tab_frame if focus issues occur
        tab_frame.bind_all("<MouseWheel>", on_mousewheel, add="+")


        # Reconfigure canvas window size when canvas itself resizes
        def on_canvas_configure(event):
            canvas.itemconfig(canvas_frame_id, width=event.width)

        canvas.bind("<Configure>", on_canvas_configure)


        # --- NOW, ALL SUBSEQUENT WIDGETS ARE GRIDDED INTO scrollable_form_frame ---
        # Replace `frame` with `scrollable_form_frame` for all .grid() calls below

        pad_y_form = 6
        row_num = 0

        # Transaction Type Selection
        type_frame = ttk.Frame(scrollable_form_frame) # Grid into scrollable_form_frame
        type_frame.grid(row=row_num, column=0, columnspan=2, sticky=tk.W, padx=5, pady=(0, 10))
        ttk.Label(type_frame, text="Transaction Type:").pack(side=tk.LEFT, padx=(0, 10))
        self.transaction_type_var = tk.StringVar(value=TYPE_DEBIT)
        debit_rb = ttk.Radiobutton(type_frame, text=TYPE_DEBIT, variable=self.transaction_type_var,
                                   value=TYPE_DEBIT, command=self._update_transaction_form_layout,
                                   style='Large.TRadiobutton')
        debit_rb.pack(side=tk.LEFT, padx=5)
        credit_rb = ttk.Radiobutton(type_frame, text=TYPE_CREDIT, variable=self.transaction_type_var,
                                    value=TYPE_CREDIT, command=self._update_transaction_form_layout,
                                    style='Large.TRadiobutton')
        credit_rb.pack(side=tk.LEFT, padx=5)
        transfer_rb = ttk.Radiobutton(type_frame, text=TYPE_TRANSFER, variable=self.transaction_type_var,
                                     value=TYPE_TRANSFER, command=self._update_transaction_form_layout,
                                     style='Large.TRadiobutton')
        transfer_rb.pack(side=tk.LEFT, padx=5)
        row_num += 1

        # Payment Method
        self.payment_method_label = ttk.Label(scrollable_form_frame, text="Payment Method:")
        self.payment_method_label.grid(row=row_num, column=0, sticky=tk.W, padx=5, pady=pad_y_form)
        self.payment_method_var = tk.StringVar()
        self.payment_method_dropdown = ttk.Combobox(scrollable_form_frame, textvariable=self.payment_method_var, values=PAYMENT_METHODS, state="readonly", width=37, font=text_font)
        self.payment_method_dropdown.grid(row=row_num, column=1, sticky="ew", padx=10, pady=pad_y_form)
        self.payment_method_dropdown.bind("<<ComboboxSelected>>", self._update_check_no_state)
        row_num += 1

        # Company
        ttk.Label(scrollable_form_frame, text="Company:").grid(row=row_num, column=0, sticky=tk.W, padx=5, pady=pad_y_form)
        self.company_var = tk.StringVar()
        self.company_id_map = {}
        self.company_combobox = ttk.Combobox(scrollable_form_frame, textvariable=self.company_var, state="readonly", width=37, font=text_font)
        self.company_combobox.grid(row=row_num, column=1, sticky="ew", padx=10, pady=pad_y_form)
        self.company_combobox.bind("<<ComboboxSelected>>", self._validate_combobox)
        row_num += 1

        # Bank Name / From Bank
        self.bank_name_label = ttk.Label(scrollable_form_frame, text="Bank Name:")
        self.bank_name_label.grid(row=row_num, column=0, sticky=tk.W, padx=5, pady=pad_y_form)
        self.bank_name_var = tk.StringVar()
        self.bank_name_combobox = ttk.Combobox(scrollable_form_frame, textvariable=self.bank_name_var, width=37, font=text_font, state='readonly')
        self.bank_name_combobox.grid(row=row_num, column=1, sticky="ew", padx=10, pady=pad_y_form)
        self.bank_name_combobox.bind("<<ComboboxSelected>>", self._validate_combobox)
        row_num += 1

        # To Bank (for Transfer type)
        self.transfer_to_bank_label = ttk.Label(scrollable_form_frame, text="To Bank:")
        self.transfer_to_bank_label.grid(row=row_num, column=0, sticky=tk.W, padx=5, pady=pad_y_form)
        self.transfer_to_bank_var = tk.StringVar()
        self.transfer_to_bank_combo = ttk.Combobox(scrollable_form_frame, textvariable=self.transfer_to_bank_var, width=37, font=text_font, state='readonly')
        self.transfer_to_bank_combo.grid(row=row_num, column=1, sticky="ew", padx=10, pady=pad_y_form)
        self.transfer_to_bank_combo.bind("<<ComboboxSelected>>", self._validate_combobox)
        self.transfer_to_bank_widgets = (self.transfer_to_bank_label, self.transfer_to_bank_combo)
        row_num += 1

        # Date
        ttk.Label(scrollable_form_frame, text="Date:").grid(row=row_num, column=0, sticky=tk.W, padx=5, pady=pad_y_form)
        self.date_entry = DateEntry(scrollable_form_frame, width=20, background=COLOR_ENTRY_BG, foreground=COLOR_ENTRY_FG, borderwidth=1, bordercolor=COLOR_BORDER, date_pattern='yyyy-mm-dd', maxdate=datetime.now().date(), font=text_font, relief='solid', selectbackground=COLOR_ACCENT, headersbackground=COLOR_HEADER_BG, headersforeground=COLOR_HEADER_FG, weekendbackground=COLOR_ENTRY_BG, normalbackground=COLOR_ENTRY_BG, othermonthbackground=COLOR_SECONDARY_BG, disabledbackground=COLOR_SECONDARY_BG, disabledforeground=COLOR_TEXT_SECONDARY)
        self.date_entry.grid(row=row_num, column=1, sticky="ew", padx=10, pady=pad_y_form)
        row_num += 1

        # Check No
        self.check_no_label = ttk.Label(scrollable_form_frame, text="Check No:")
        self.check_no_label.grid(row=row_num, column=0, sticky=tk.W, padx=5, pady=pad_y_form)
        self.check_no_entry = ttk.Entry(scrollable_form_frame, width=40, font=text_font)
        self.check_no_entry.grid(row=row_num, column=1, sticky="ew", padx=10, pady=pad_y_form)
        self.check_no_entry.bind("<FocusOut>", lambda e: self._validate_entry(self.check_no_entry))
        self.check_no_widgets = (self.check_no_label, self.check_no_entry)
        row_num += 1

        # Vendor / Customer Name
        self.vendor_customer_label = ttk.Label(scrollable_form_frame, text="Vendor Name:")
        self.vendor_customer_label.grid(row=row_num, column=0, sticky=tk.W, padx=5, pady=pad_y_form)
        self.vendor_customer_var = tk.StringVar()
        self.vendor_customer_combobox = ttk.Combobox(scrollable_form_frame, textvariable=self.vendor_customer_var, width=37, font=text_font, state='readonly')
        self.vendor_customer_combobox.grid(row=row_num, column=1, sticky="ew", padx=10, pady=pad_y_form)
        self.vendor_customer_combobox.bind("<<ComboboxSelected>>", self._validate_combobox)
        self.vendor_customer_widgets = (self.vendor_customer_label, self.vendor_customer_combobox)
        row_num += 1

        # Reference
        ttk.Label(scrollable_form_frame, text="Reference:").grid(row=row_num, column=0, sticky=tk.W, padx=5, pady=pad_y_form)
        self.reference_entry = ttk.Entry(scrollable_form_frame, width=40, font=text_font)
        self.reference_entry.grid(row=row_num, column=1, sticky="ew", padx=10, pady=pad_y_form)
        row_num += 1

        # Bill No
        self.bill_no_label = ttk.Label(scrollable_form_frame, text="Bill No:")
        self.bill_no_label.grid(row=row_num, column=0, sticky=tk.W, padx=5, pady=pad_y_form)
        self.bill_no_entry = ttk.Entry(scrollable_form_frame, width=40, font=text_font)
        self.bill_no_entry.grid(row=row_num, column=1, sticky="ew", padx=10, pady=pad_y_form)
        self.bill_no_widgets = (self.bill_no_label, self.bill_no_entry)
        row_num += 1

        # Invoice No
        self.invoice_no_label = ttk.Label(scrollable_form_frame, text="Invoice No:")
        self.invoice_no_label.grid(row=row_num, column=0, sticky=tk.W, padx=5, pady=pad_y_form)
        self.invoice_no_entry = ttk.Entry(scrollable_form_frame, width=40, font=text_font)
        self.invoice_no_entry.grid(row=row_num, column=1, sticky="ew", padx=10, pady=pad_y_form)
        self.invoice_no_widgets = (self.invoice_no_label, self.invoice_no_entry)
        row_num += 1

        # Memo
        ttk.Label(scrollable_form_frame, text="Memo:").grid(row=row_num, column=0, sticky=tk.W, padx=5, pady=pad_y_form)
        self.memo_var = tk.StringVar()
        memo_state = "normal" if MEMO_OTHER else "readonly"
        self.memo_combobox = ttk.Combobox(scrollable_form_frame, textvariable=self.memo_var, state=memo_state, width=37, font=text_font)
        self.memo_combobox.grid(row=row_num, column=1, sticky="ew", padx=10, pady=pad_y_form)
        row_num += 1

        # Amount
        ttk.Label(scrollable_form_frame, text="Amount:").grid(row=row_num, column=0, sticky=tk.W, padx=5, pady=pad_y_form)
        self.amount_var = tk.StringVar()
        self.amount_entry = ttk.Entry(scrollable_form_frame, width=40, font=text_font, textvariable=self.amount_var)
        self.amount_entry.grid(row=row_num, column=1, sticky="ew", padx=10, pady=pad_y_form)
        self.amount_entry.bind("<FocusOut>", lambda e: self._validate_amount(True))
        self.amount_entry.bind("<KeyRelease>", lambda e: self._validate_amount(True))
        row_num += 1

        # Status
        self.status_label = ttk.Label(scrollable_form_frame, text="Status:")
        self.status_label.grid(row=row_num, column=0, sticky=tk.W, padx=5, pady=pad_y_form)
        self.status_var = tk.StringVar()
        self.status_dropdown = ttk.Combobox(scrollable_form_frame, textvariable=self.status_var, values=DEBIT_STATUS_OPTIONS, state="readonly", width=37, font=text_font)
        self.status_dropdown.grid(row=row_num, column=1, sticky="ew", padx=10, pady=pad_y_form)
        self.status_dropdown.bind("<<ComboboxSelected>>", self._validate_combobox)
        self.status_widgets = (self.status_label, self.status_dropdown)
        row_num += 1

        # Action Buttons
        button_frame_add = ttk.Frame(scrollable_form_frame)
        button_frame_add.grid(row=row_num, column=0, columnspan=2, pady=(15, 10), sticky=tk.EW)
        button_frame_add.columnconfigure(0, weight=1); button_frame_add.columnconfigure(1, weight=1)
        self.add_button = ttk.Button(button_frame_add, text="Add Transaction", command=self.add_transaction, style='Accent.TButton')
        self.add_button.grid(row=0, column=0, padx=(0,10), pady=5, ipady=4, sticky=tk.EW)
        self.clear_button = ttk.Button(button_frame_add, text="Clear Fields", command=self.clear_add_transaction_fields)
        self.clear_button.grid(row=0, column=1, padx=(10,0), pady=5, ipady=4, sticky=tk.EW)
        row_num += 1

        # Optional Notes Section
        notes_label_heading = ttk.Label(scrollable_form_frame, text="Optional Notes:") # Renamed to avoid conflict
        notes_label_heading.grid(row=row_num, column=0, columnspan=2, sticky=tk.W, padx=5, pady=(10, 2))
        row_num += 1

        notes_frame = ttk.Frame(scrollable_form_frame, style='Card.TFrame', padding=1)
        notes_frame.grid(row=row_num, column=0, columnspan=2, sticky='nsew', padx=5, pady=(0, 10))
        notes_frame.rowconfigure(0, weight=1); notes_frame.columnconfigure(0, weight=1)
        self.notes_text = tk.Text(notes_frame, height=4, width=40, wrap=tk.WORD, relief='flat',
                                  font=text_font, bg=COLOR_ENTRY_BG, fg=COLOR_ENTRY_FG,
                                  borderwidth=0, highlightthickness=0,
                                  selectbackground=COLOR_ACCENT, selectforeground=COLOR_BUTTON_PRIMARY_FG,
                                  insertbackground=COLOR_TEXT)
        self.notes_text.grid(row=0, column=0, sticky='nsew')
        notes_scrollbar_inner = ttk.Scrollbar(notes_frame, orient=tk.VERTICAL, command=self.notes_text.yview, style="Vertical.TScrollbar") # Renamed
        notes_scrollbar_inner.grid(row=0, column=1, sticky='ns')
        self.notes_text.configure(yscrollcommand=notes_scrollbar_inner.set)
        # scrollable_form_frame.rowconfigure(row_num, weight=0) # Keep notes from expanding infinitely
        row_num += 1

        # Import Button
        import_button_frame = ttk.Frame(scrollable_form_frame)
        import_button_frame.grid(row=row_num, column=0, columnspan=2, pady=(10, 5), sticky=tk.EW)
        import_button_frame.columnconfigure(0, weight=1)
        self.import_button = ttk.Button(import_button_frame, text="Import from Excel", command=self.import_from_excel, width=25)
        self.import_button.grid(row=0, column=0, pady=5, ipady=4, sticky=tk.EW)
        # No row_num increment after the last item


        # Initial layout update call
        self.root.after(10, self._update_transaction_form_layout)

    # --- Enhanced Layout Update Function ---
    def _update_transaction_form_layout(self):
        selected_type = self.transaction_type_var.get()
        logging.debug(f"Updating transaction form layout for type: {selected_type}")

    # <<< UPDATED Report Tab (for Bulk Status) >>>
    def _create_report_tab(self):
        frame = ttk.Frame(self.notebook, padding="15 15 15 15")
        tab_key = 'report'
        self.tab_frames[tab_key] = frame
        tab_text = " Transaction Report "
        if not hasattr(self, 'tab_texts'): self.tab_texts = {}
        self.tab_texts[tab_key] = tab_text
        self.notebook.add(frame, text=tab_text)

        frame.columnconfigure(0, weight=1)
        frame.rowconfigure(1, weight=1)

        # --- Filter Frame ---
        filter_frame = ttk.Frame(frame, style='Card.TFrame', padding=(15, 15, 15, 10))
        filter_frame.grid(row=0, column=0, sticky='new', pady=(0, 15))
        filter_frame.columnconfigure((1, 3, 5, 7), weight=1)
        ff_row = 0; ff_pady = (3, 4); ff_padx = 5

        ttk.Label(filter_frame, text="Company:", style='Card.TLabel').grid(row=ff_row, column=0, sticky='w', padx=ff_padx, pady=ff_pady)
        self.filter_company_var = tk.StringVar()
        self.filter_company_combo = ttk.Combobox(filter_frame, textvariable=self.filter_company_var, state='readonly', width=20, font=text_font)
        self.filter_company_combo.grid(row=ff_row, column=1, sticky='ew', padx=ff_padx, pady=ff_pady)

        ttk.Label(filter_frame, text="Bank:", style='Card.TLabel').grid(row=ff_row, column=2, sticky='w', padx=ff_padx, pady=ff_pady)
        self.filter_bank_var = tk.StringVar()
        self.filter_bank_combo = ttk.Combobox(filter_frame, textvariable=self.filter_bank_var, state='readonly', width=20, font=text_font)
        self.filter_bank_combo.grid(row=ff_row, column=3, sticky='ew', padx=ff_padx, pady=ff_pady)

        ttk.Label(filter_frame, text="Type:", style='Card.TLabel').grid(row=ff_row, column=4, sticky='w', padx=ff_padx, pady=ff_pady)
        self.filter_type_var = tk.StringVar()
        self.filter_type_combo = ttk.Combobox(filter_frame, textvariable=self.filter_type_var, state='readonly', width=12, font=text_font)
        self.filter_type_combo['values'] = [FILTER_ALL_TYPES] + TRANSACTION_TYPES
        self.filter_type_combo.grid(row=ff_row, column=5, sticky='ew', padx=ff_padx, pady=ff_pady)

        ttk.Label(filter_frame, text="Method:", style='Card.TLabel').grid(row=ff_row, column=6, sticky='w', padx=ff_padx, pady=ff_pady)
        self.filter_method_var = tk.StringVar()
        self.filter_method_combo = ttk.Combobox(filter_frame, textvariable=self.filter_method_var, state='readonly', width=15, font=text_font)
        self.filter_method_combo.grid(row=ff_row, column=7, sticky='ew', padx=ff_padx, pady=ff_pady)
        ff_row += 1

        ttk.Label(filter_frame, text="Vendor:", style='Card.TLabel').grid(row=ff_row, column=0, sticky='w', padx=ff_padx, pady=ff_pady)
        self.filter_vendor_var = tk.StringVar()
        self.filter_vendor_combo = ttk.Combobox(filter_frame, textvariable=self.filter_vendor_var, state='readonly', width=20, font=text_font)
        self.filter_vendor_combo.grid(row=ff_row, column=1, sticky='ew', padx=ff_padx, pady=ff_pady)

        ttk.Label(filter_frame, text="Customer:", style='Card.TLabel').grid(row=ff_row, column=2, sticky='w', padx=ff_padx, pady=ff_pady)
        self.filter_customer_var = tk.StringVar()
        self.filter_customer_combo = ttk.Combobox(filter_frame, textvariable=self.filter_customer_var, state='readonly', width=20, font=text_font)
        self.filter_customer_combo.grid(row=ff_row, column=3, sticky='ew', padx=ff_padx, pady=ff_pady)

        ttk.Label(filter_frame, text="Status:", style='Card.TLabel').grid(row=ff_row, column=4, sticky='w', padx=ff_padx, pady=ff_pady)
        self.filter_status_var = tk.StringVar()
        self.filter_status_combo = ttk.Combobox(filter_frame, textvariable=self.filter_status_var, state='readonly', width=12, font=text_font)
        self.filter_status_combo.grid(row=ff_row, column=5, sticky='ew', padx=ff_padx, pady=ff_pady)

        ttk.Label(filter_frame, text="Memo:", style='Card.TLabel').grid(row=ff_row, column=6, sticky='w', padx=ff_padx, pady=ff_pady)
        self.filter_memo_var = tk.StringVar()
        self.filter_memo_combo = ttk.Combobox(filter_frame, textvariable=self.filter_memo_var, state='readonly', width=15, font=text_font)
        self.filter_memo_combo.grid(row=ff_row, column=7, sticky='ew', padx=ff_padx, pady=ff_pady)
        ff_row += 1

        ttk.Label(filter_frame, text="Start Date:", style='Card.TLabel').grid(row=ff_row, column=0, sticky='w', padx=ff_padx, pady=ff_pady)
        self.filter_start_date = DateEntry(filter_frame, width=12, font=text_font, date_pattern='yyyy-mm-dd', background=COLOR_ENTRY_BG, foreground=COLOR_ENTRY_FG, borderwidth=1, bordercolor=COLOR_BORDER, relief='solid', selectbackground=COLOR_ACCENT, headersbackground=COLOR_HEADER_BG, headersforeground=COLOR_HEADER_FG, weekendbackground=COLOR_ENTRY_BG, normalbackground=COLOR_ENTRY_BG, othermonthbackground=COLOR_SECONDARY_BG)
        self.filter_start_date.grid(row=ff_row, column=1, sticky='ew', padx=ff_padx, pady=ff_pady); self.filter_start_date.delete(0, tk.END)

        ttk.Label(filter_frame, text="End Date:", style='Card.TLabel').grid(row=ff_row, column=2, sticky='w', padx=ff_padx, pady=ff_pady)
        self.filter_end_date = DateEntry(filter_frame, width=12, font=text_font, date_pattern='yyyy-mm-dd', background=COLOR_ENTRY_BG, foreground=COLOR_ENTRY_FG, borderwidth=1, bordercolor=COLOR_BORDER, relief='solid', selectbackground=COLOR_ACCENT, headersbackground=COLOR_HEADER_BG, headersforeground=COLOR_HEADER_FG, weekendbackground=COLOR_ENTRY_BG, normalbackground=COLOR_ENTRY_BG, othermonthbackground=COLOR_SECONDARY_BG)
        self.filter_end_date.grid(row=ff_row, column=3, sticky='ew', padx=ff_padx, pady=ff_pady); self.filter_end_date.delete(0, tk.END)

        ttk.Label(filter_frame, text="Search:", style='Card.TLabel').grid(row=ff_row, column=4, sticky='w', padx=ff_padx, pady=ff_pady)
        self.search_var = tk.StringVar()
        self.search_entry = ttk.Entry(filter_frame, textvariable=self.search_var, width=40, font=text_font)
        self.search_entry.grid(row=ff_row, column=5, columnspan=3, sticky='ew', padx=ff_padx, pady=ff_pady)
        self.search_entry.bind("<Return>", lambda e: self.apply_report_filters())
        ff_row += 1

        filter_button_frame = ttk.Frame(filter_frame, style='Card.TFrame')
        filter_button_frame.grid(row=ff_row, column=0, columnspan=8, sticky='e', pady=(8, 0), padx=(0, ff_padx))
        self.apply_filter_button = ttk.Button(filter_button_frame, text="Apply Filters / Search", command=self.apply_report_filters, style='Accent.TButton', width=20)
        self.apply_filter_button.pack(side=tk.RIGHT, padx=(8, 0))
        self.clear_filter_button = ttk.Button(filter_button_frame, text="Clear Filters & Search", command=self.clear_report_filters, width=20)
        self.clear_filter_button.pack(side=tk.RIGHT)

        # --- Report Treeview ---
        tree_frame = ttk.Frame(frame)
        tree_frame.grid(row=1, column=0, sticky='nsew')
        tree_frame.columnconfigure(0, weight=1); tree_frame.rowconfigure(0, weight=1)
        self.report_tree = CheckboxTreeview(tree_frame, columns=TREE_COLUMNS_FULL, show="tree headings", height=15)
        self.report_tree.column("#0", width=40, stretch=tk.NO, anchor=tk.CENTER)
        self.report_tree.heading("#0", text="")
        self._configure_treeview_columns(self.report_tree, TREE_COLUMNS_FULL) # This will apply new headers
        vsb = ttk.Scrollbar(tree_frame, orient="vertical", command=self.report_tree.yview, style="Vertical.TScrollbar")
        hsb = ttk.Scrollbar(tree_frame, orient="horizontal", command=self.report_tree.xview, style="Horizontal.TScrollbar")
        self.report_tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        self.report_tree.grid(row=0, column=0, sticky='nsew')
        vsb.grid(row=0, column=1, sticky='ns')
        hsb.grid(row=1, column=0, columnspan=2, sticky='ew', pady=(5,0))
        self.report_context_menu = self._create_context_menu_report_bulk()
        self.report_tree.bind("<Button-3>", lambda event: self._show_context_menu(event, self.report_tree, self.report_context_menu))
        self.report_tree.bind("<Double-1>", self.edit_selected_transaction)

        # Bulk Action Frame
        bulk_action_frame = ttk.Frame(frame)
        bulk_action_frame.grid(row=2, column=0, sticky='ew', pady=(10, 5), padx=5)
        bulk_action_frame.columnconfigure(2, weight=1)
        ttk.Label(bulk_action_frame, text="With Selected:").pack(side=tk.LEFT, padx=(0, 5))
        self.bulk_status_var = tk.StringVar()
        self.bulk_status_combo = ttk.Combobox(bulk_action_frame, textvariable=self.bulk_status_var, values=ALL_STATUS_OPTIONS, state='readonly', width=15, font=text_font)
        self.bulk_status_combo.pack(side=tk.LEFT, padx=5)
        if ALL_STATUS_OPTIONS: self.bulk_status_combo.current(0)
        bulk_change_button = ttk.Button(bulk_action_frame, text="Change Status", command=self.bulk_change_status, width=18)
        bulk_change_button.pack(side=tk.LEFT, padx=5)

        bottom_button_frame = ttk.Frame(frame)
        bottom_button_frame.grid(row=3, column=0, pady=(15, 5), sticky=tk.E)
        ttk.Button(bottom_button_frame, text="Export Current View", command=self.export_to_excel).pack(side=tk.RIGHT, padx=(10, 0))
        ttk.Button(bottom_button_frame, text="Refresh (Clear Filters)", command=self.clear_report_filters).pack(side=tk.RIGHT)

        # Call auto-size after data is loaded (e.g., in populate_report_tree or apply_report_filters)
        # self.root.after(100, self._auto_size_report_tree_columns) # Example initial call if needed

    def _create_memo_summary_tab(self):
        frame = ttk.Frame(self.notebook, padding="25 25 25 25")
        tab_key = 'memo_summary'
        self.tab_frames[tab_key] = frame
        tab_text = " Memo Summary "
        if not hasattr(self, 'tab_texts'): self.tab_texts = {}
        self.tab_texts[tab_key] = tab_text
        self.notebook.add(frame, text=tab_text) # Add initially

        frame.rowconfigure(1, weight=1); frame.columnconfigure(0, weight=1)
        ttk.Label(frame, text="Memo Transaction Summary", style='Title.TLabel').grid(row=0, column=0, columnspan=2, pady=(0, 20), sticky='nw')
        summary_frame = ttk.Frame(frame, style='Card.TFrame', padding=20)
        summary_frame.grid(row=1, column=0, sticky='nsew', pady=(0, 20))
        summary_frame.rowconfigure(0, weight=1); summary_frame.columnconfigure(0, weight=1)
        self.memo_summary_tree = ttk.Treeview(summary_frame, columns=TREE_COLUMNS_MEMO_SUMMARY, show="headings", height=15, style='Treeview')
        self.memo_summary_tree.heading("Memo", text="Memo", anchor=tk.W); self.memo_summary_tree.column("Memo", width=250, anchor=tk.W, stretch=tk.YES)
        self.memo_summary_tree.heading("Status", text="Status", anchor=tk.CENTER); self.memo_summary_tree.column("Status", width=100, anchor=tk.CENTER, stretch=tk.NO)
        self.memo_summary_tree.heading("Count", text="Count", anchor=tk.CENTER); self.memo_summary_tree.column("Count", width=80, anchor=tk.CENTER, stretch=tk.NO)
        self.memo_summary_tree.heading("Total Amount", text="Total Amount", anchor=tk.E); self.memo_summary_tree.column("Total Amount", width=150, anchor=tk.E, stretch=tk.NO)
        summary_vsb = ttk.Scrollbar(summary_frame, orient="vertical", command=self.memo_summary_tree.yview, style="Vertical.TScrollbar")
        summary_hsb = ttk.Scrollbar(summary_frame, orient="horizontal", command=self.memo_summary_tree.xview, style="Horizontal.TScrollbar")
        self.memo_summary_tree.configure(yscrollcommand=summary_vsb.set, xscrollcommand=summary_hsb.set)
        self.memo_summary_tree.grid(row=0, column=0, sticky='nsew')
        summary_vsb.grid(row=0, column=1, sticky='ns'); summary_hsb.grid(row=1, column=0, columnspan=2, sticky='ew', pady=(5,0))
        self._configure_tree_tags(self.memo_summary_tree)
        ttk.Button(frame, text="Refresh Summary", command=self.populate_memo_summary_tree, width=18).grid(row=2, column=0, pady=(10, 0), sticky='e')

    # <<< UPDATED Management Tab >>>
    def _create_management_tab(self):
        frame = ttk.Frame(self.notebook, padding="20")
        tab_key = 'management'
        self.tab_frames[tab_key] = frame
        tab_text = " Management "
        if not hasattr(self, 'tab_texts'): self.tab_texts = {}
        self.tab_texts[tab_key] = tab_text
        self.notebook.add(frame, text=tab_text, state='hidden') # Start hidden

        frame.columnconfigure(0, weight=1); frame.columnconfigure(1, weight=0)
        frame.rowconfigure(0, weight=1)

        # --- Left Panel (List View) ---
        left_panel = ttk.Frame(frame, style='Card.TFrame', padding=15)
        left_panel.grid(row=0, column=0, sticky='nsew', padx=(0, 10))
        left_panel.rowconfigure(2, weight=1); left_panel.columnconfigure(0, weight=1)
        ttk.Label(left_panel, text="View Items", style='Header.TLabel').grid(row=0, column=0, columnspan=2, sticky='nw', pady=(0, 10))
        list_type_frame = ttk.Frame(left_panel, style='Card.TFrame')
        list_type_frame.grid(row=1, column=0, columnspan=2, sticky='ew', pady=(0, 10))
        list_type_frame.columnconfigure(1, weight=1)
        ttk.Label(list_type_frame, text="Show:", style='Card.TLabel').grid(row=0, column=0, padx=(0, 5), sticky='w')
        self.mgmt_list_type_var = tk.StringVar(value="Companies")
        self.mgmt_list_type_combo = ttk.Combobox(list_type_frame, textvariable=self.mgmt_list_type_var,
                                                 values=["Companies", "Banks", "Vendors", "Customers", "Memos"], # <<< Added Memo
                                                 state='readonly', font=text_font)
        self.mgmt_list_type_combo.grid(row=0, column=1, sticky='ew')
        self.mgmt_list_type_combo.bind("<<ComboboxSelected>>", self.populate_management_list)
        self.mgmt_list_tree = ttk.Treeview(left_panel, show="headings", height=15, style='Treeview')
        mgmt_vsb = ttk.Scrollbar(left_panel, orient="vertical", command=self.mgmt_list_tree.yview, style="Vertical.TScrollbar")
        mgmt_hsb = ttk.Scrollbar(left_panel, orient="horizontal", command=self.mgmt_list_tree.xview, style="Horizontal.TScrollbar")
        self.mgmt_list_tree.configure(yscrollcommand=mgmt_vsb.set, xscrollcommand=mgmt_hsb.set)
        self.mgmt_list_tree.grid(row=2, column=0, sticky='nsew')
        mgmt_vsb.grid(row=2, column=1, sticky='ns'); mgmt_hsb.grid(row=3, column=0, columnspan=2, sticky='ew', pady=(5,0))
        # Context Menu for Management Tree
        self.mgmt_context_menu = tk.Menu(self.root, tearoff=0, background=COLOR_SECONDARY_BG, foreground=COLOR_TEXT,
                                         activebackground=COLOR_ACCENT, activeforeground=COLOR_BUTTON_PRIMARY_FG)
        self.mgmt_context_menu.add_command(label="Edit Selected Item", command=self.edit_selected_mgmt_item) # <<< ADDED
        self.mgmt_context_menu.add_command(label="Delete Selected Item", command=self.delete_selected_mgmt_item)
        self.mgmt_list_tree.bind("<Button-3>", self.show_mgmt_context_menu) # Show menu function updated below
        ttk.Button(left_panel, text="Refresh List", command=self.populate_management_list, width=15).grid(row=4, column=0, columnspan=2, pady=(15, 0), sticky='e')

        # --- Right Panel (Add New Item) ---
        right_panel = ttk.Frame(frame, style='Card.TFrame', padding=15)
        right_panel.grid(row=0, column=1, sticky='nsew', padx=(10, 0))
        right_panel.columnconfigure(0, weight=1)
        ttk.Label(right_panel, text="Add New Item", style='Header.TLabel').grid(row=0, column=0, sticky='nw', pady=(0, 15))
        ttk.Label(right_panel, text="Type:", style='Card.TLabel').grid(row=1, column=0, sticky='nw', pady=(5,2))
        self.mgmt_add_type_var = tk.StringVar(value="Company")
        self.mgmt_add_type_combo = ttk.Combobox(right_panel, textvariable=self.mgmt_add_type_var,
                                                values=["Company", "Bank", "Vendor", "Customer", "Memo"], # <<< Added Memo
                                                state='readonly', width=30, font=text_font)
        self.mgmt_add_type_combo.grid(row=2, column=0, sticky='ew', pady=(0, 10))
        ttk.Label(right_panel, text="Name:", style='Card.TLabel').grid(row=3, column=0, sticky='nw', pady=(5,2))
        self.mgmt_new_name_entry = ttk.Entry(right_panel, width=30, font=text_font)
        self.mgmt_new_name_entry.grid(row=4, column=0, sticky='ew', pady=(0, 15))
        self.mgmt_new_name_entry.bind("<Return>", lambda e: self.add_mgmt_item())
        ttk.Button(right_panel, text="Add Item", command=self.add_mgmt_item, style='Accent.TButton').grid(row=5, column=0, sticky='ew', pady=(10,0), ipady=4)

        self.root.after(200, self.populate_management_list)

    # <<< UPDATED User Management Tab (for Permission UI) >>>
    def _create_user_management_tab(self):
        frame = ttk.Frame(self.notebook, padding="30")
        tab_key = 'user_management'
        self.tab_frames[tab_key] = frame
        tab_text = " User Management "
        if not hasattr(self, 'tab_texts'): self.tab_texts = {}
        self.tab_texts[tab_key] = tab_text
        self.notebook.add(frame, text=tab_text, state='hidden') # Start hidden

        frame.columnconfigure(0, weight=1); frame.columnconfigure(1, weight=1)
        frame.rowconfigure(0, weight=1)

        # --- User List Frame (Column 0) ---
        list_frame = ttk.Frame(frame, style='Card.TFrame', padding=20)
        list_frame.grid(row=0, column=0, sticky='nsew', padx=(0, 10))
        list_frame.rowconfigure(1, weight=1); list_frame.columnconfigure(0, weight=1)
        ttk.Label(list_frame, text="Existing Users", style='Header.TLabel').grid(row=0, column=0, columnspan=2, sticky='nw', pady=(0, 15))
        self.users_tree = ttk.Treeview(list_frame, columns=TREE_COLUMNS_USERS, show="headings", height=15, style='Treeview')
        self.users_tree.heading("user_id", text="ID"); self.users_tree.heading("username", text="Username"); self.users_tree.heading("role", text="Role")
        self.users_tree.column("user_id", width=60, anchor=tk.CENTER, stretch=tk.NO)
        self.users_tree.column("username", width=180, anchor=tk.W, stretch=tk.YES)
        self.users_tree.column("role", width=100, anchor=tk.CENTER, stretch=tk.NO)
        users_vsb = ttk.Scrollbar(list_frame, orient="vertical", command=self.users_tree.yview, style="Vertical.TScrollbar")
        self.users_tree.configure(yscrollcommand=users_vsb.set)
        self.users_tree.grid(row=1, column=0, sticky='nsew'); users_vsb.grid(row=1, column=1, sticky='ns')
        self.user_context_menu = tk.Menu(self.root, tearoff=0, background=COLOR_SECONDARY_BG, foreground=COLOR_TEXT, activebackground=COLOR_ACCENT, activeforeground=COLOR_BUTTON_PRIMARY_FG)
        role_menu = tk.Menu(self.user_context_menu, tearoff=0, background=COLOR_SECONDARY_BG, foreground=COLOR_TEXT, activebackground=COLOR_ACCENT, activeforeground=COLOR_BUTTON_PRIMARY_FG)
        self.user_context_menu.add_cascade(label="Change Role To", menu=role_menu)
        role_menu.add_command(label="admin", command=lambda: self.change_selected_user_role('admin')); role_menu.add_command(label="user", command=lambda: self.change_selected_user_role('user'))
        self.user_context_menu.add_separator(background=COLOR_BORDER)
        self.user_context_menu.add_command(label="Reset Password", command=self.reset_selected_user_password)
        self.user_context_menu.add_separator(background=COLOR_BORDER)
        self.user_context_menu.add_command(label="Set Security Questions", command=self.show_set_security_questions_dialog)
        self.user_context_menu.add_separator(background=COLOR_BORDER)
        self.user_context_menu.add_command(label="Delete User", command=self.delete_selected_user)
        self.users_tree.bind("<Button-3>", self.show_user_context_menu)
        ttk.Button(list_frame, text="Refresh List", command=self.populate_users_tree, width=15).grid(row=2, column=0, columnspan=2, pady=(15, 0), sticky='e')

        # --- Right Panel (Column 1) ---
        right_panel = ttk.Frame(frame)
        right_panel.grid(row=0, column=1, sticky='nsew', padx=(10, 0))
        right_panel.columnconfigure(0, weight=1)
        right_panel.rowconfigure(0, weight=0); right_panel.rowconfigure(1, weight=1) # Add User fixed, Perms expand

        # --- Add User Frame (Inside Right Panel, Row 0) ---
        add_frame = ttk.Frame(right_panel, style='Card.TFrame', padding=20)
        add_frame.grid(row=0, column=0, sticky='new', pady=(0, 20))
        add_frame.columnconfigure(0, weight=1)
        ttk.Label(add_frame, text="Add New User", style='Header.TLabel').grid(row=0, column=0, columnspan=2, sticky='nw', pady=(0, 15))
        ttk.Label(add_frame, text="Username:", style='Card.TLabel').grid(row=1, column=0, sticky='nw', pady=(5,2))
        self.new_username_entry = ttk.Entry(add_frame, width=30, font=text_font)
        self.new_username_entry.grid(row=2, column=0, columnspan=2, sticky='ew', pady=(0, 10))
        ttk.Label(add_frame, text="Password:", style='Card.TLabel').grid(row=3, column=0, sticky='nw', pady=(5,2))
        self.new_password_entry = ttk.Entry(add_frame, width=30, font=text_font, show='*')
        self.new_password_entry.grid(row=4, column=0, columnspan=2, sticky='ew', pady=(0, 10))
        ttk.Label(add_frame, text="Confirm Password:", style='Card.TLabel').grid(row=5, column=0, sticky='nw', pady=(5,2))
        self.confirm_password_entry = ttk.Entry(add_frame, width=30, font=text_font, show='*')
        self.confirm_password_entry.grid(row=6, column=0, columnspan=2, sticky='ew', pady=(0, 15))
        ttk.Label(add_frame, text="Role:", style='Card.TLabel').grid(row=7, column=0, sticky='nw', pady=(5,2))
        self.new_user_role_var = tk.StringVar(value='user')
        role_frame = ttk.Frame(add_frame, style='Card.TFrame')
        role_frame.grid(row=8, column=0, columnspan=2, sticky='ew', pady=(0, 15))
        ttk.Radiobutton(role_frame, text="User", variable=self.new_user_role_var, value='user').pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(role_frame, text="Admin", variable=self.new_user_role_var, value='admin').pack(side=tk.LEFT, padx=5)
        self.add_user_button = ttk.Button(add_frame, text="Add User", command=self.add_new_user, style='Accent.TButton')
        self.add_user_button.grid(row=9, column=0, columnspan=2, sticky='ew', pady=(10,0), ipady=4)

        # --- User Role Permissions Frame (Inside Right Panel, Row 1) ---
        permissions_frame = ttk.Frame(right_panel, style='Card.TFrame', padding=20)
        permissions_frame.grid(row=1, column=0, sticky='nsew')
        permissions_frame.columnconfigure(0, weight=1); permissions_frame.rowconfigure(1, weight=1)
        ttk.Label(permissions_frame, text="User Role Tab Access", style='Header.TLabel').grid(row=0, column=0, columnspan=2, sticky='nw', pady=(0, 15))
        perm_canvas = tk.Canvas(permissions_frame, bg=COLOR_CARD_BG, highlightthickness=0, borderwidth=0)
        perm_scrollbar = ttk.Scrollbar(permissions_frame, orient="vertical", command=perm_canvas.yview, style="Vertical.TScrollbar")
        self.perm_checkbox_frame = ttk.Frame(perm_canvas, style='Card.TFrame')
        self.perm_checkbox_window_id = perm_canvas.create_window((0, 0), window=self.perm_checkbox_frame, anchor="nw")
        self.perm_checkbox_frame.bind("<Configure>", lambda e: perm_canvas.configure(scrollregion=perm_canvas.bbox("all")))
        perm_canvas.configure(yscrollcommand=perm_scrollbar.set)
        perm_canvas.grid(row=1, column=0, sticky='nsew', pady=(0, 15)); perm_scrollbar.grid(row=1, column=1, sticky='ns', pady=(0,15))
        perm_canvas.bind('<Configure>', lambda e: perm_canvas.itemconfigure(self.perm_checkbox_window_id, width=e.width))

        self.perm_tab_vars = {}
        row_idx = 0
        for tab_key, tab_name in self.MANAGEABLE_TABS.items():
            # <<< Allow configuration of 'management' tab >>>
            if tab_key not in ['user_management']:
                var = tk.BooleanVar()
                cb = ttk.Checkbutton(self.perm_checkbox_frame, text=tab_name, variable=var, style='TCheckbutton')
                cb.grid(row=row_idx, column=0, sticky='nw', padx=5, pady=3)
                self.perm_tab_vars[tab_key] = var
                row_idx += 1

        self.save_perms_button = ttk.Button(permissions_frame, text="Save User Permissions", command=self._save_user_role_permissions, style='Accent.TButton')
        self.save_perms_button.grid(row=2, column=0, columnspan=2, sticky='ew', pady=(10, 0), ipady=4)

        if self.current_user_role == 'admin':
            self.root.after(300, self._load_user_role_permissions_ui)
        else:
             permissions_frame.grid_remove()

    # --- Helper to configure Treeview tags ---
    def _configure_tree_tags(self, treeview):
        status_tags = [
            STATUS_PENDING.lower(), STATUS_PAID.lower(), STATUS_VOID.lower(),
            STATUS_RECEIVED.lower(), STATUS_RETURNED.lower(), STATUS_CLEARED.lower(), # <<< Added cleared
            'nodata', 'default'
        ]
        tag_colors = {
            STATUS_PENDING.lower(): (COLOR_PENDING_ROW, COLOR_ROW_TEXT),
            STATUS_PAID.lower(): (COLOR_PAID_ROW, COLOR_ROW_TEXT),
            STATUS_VOID.lower(): (COLOR_VOID_ROW, COLOR_ROW_TEXT),
            STATUS_RECEIVED.lower(): (COLOR_PAID_ROW, COLOR_ROW_TEXT),
            STATUS_RETURNED.lower(): (COLOR_VOID_ROW, COLOR_ROW_TEXT),
            STATUS_CLEARED.lower(): (COLOR_CLEARED_ROW, COLOR_ROW_TEXT), # <<< Added cleared
            'nodata': (COLOR_TREE_BG, COLOR_TEXT_SECONDARY),
            'default': (COLOR_TREE_BG, COLOR_TREE_FG)
        }
        for tag in status_tags:
            bg, fg = tag_colors.get(tag, (COLOR_TREE_BG, COLOR_TREE_FG))
            try:
                font_to_use = text_font if 'text_font' in globals() else default_font
                treeview.tag_configure(tag, background=bg, foreground=fg, font=font_to_use)
            except tk.TclError as e:
                 logging.warning(f"Could not configure tag '{tag}' on {treeview}: {e}")

# Inside BankSheetApp class
    def _configure_treeview_columns(self, treeview, column_defs):
        col_configs = {
            COL_ID: {"width": 50, "anchor": tk.CENTER, "stretch": tk.NO},
            COL_COMPANY_NAME: {"width": 140, "anchor": tk.W, "stretch": tk.YES},
            COL_BANK_NAME: {"width": 120, "anchor": tk.W, "stretch": tk.YES},
            COL_DATE: {"width": 100, "anchor": tk.CENTER, "stretch": tk.NO},
            COL_CHECK_NO: {"width": 90, "anchor": tk.CENTER, "stretch": tk.NO},
            COL_UI_VENDOR_NAME: {"width": 150, "anchor": tk.W, "stretch": tk.YES},
            COL_UI_CUSTOMER_NAME: {"width": 150, "anchor": tk.W, "stretch": tk.YES},
            COL_REF: {"width": 150, "anchor": tk.W, "stretch": tk.YES},
            COL_BILL_NO: {"width": 90, "anchor": tk.W, "stretch": tk.NO},
            COL_INVOICE_NO: {"width": 90, "anchor": tk.W, "stretch": tk.NO},
            COL_MEMO: {"width": 130, "anchor": tk.W, "stretch": tk.YES},
            COL_AMOUNT: {"width": 110, "anchor": tk.E, "stretch": tk.NO},
            COL_STATUS: {"width": 80, "anchor": tk.CENTER, "stretch": tk.NO},
            COL_TRANSACTION_TYPE: {"width": 80, "anchor": tk.CENTER, "stretch": tk.NO},
            COL_PAYMENT_METHOD: {"width": 100, "anchor": tk.W, "stretch": tk.NO},
            COL_CREATED_BY: {"width": 100, "anchor": tk.CENTER, "stretch": tk.NO},
            "name": {"width": 250, "anchor": tk.W, "stretch": tk.YES}
        }
        heading_overrides = {
            COL_ID: "ID",
            COL_COMPANY_NAME: "Company", # Make sure all have explicit heading text
            COL_BANK_NAME: "Bank Name",
            COL_DATE: "Date",
            COL_CHECK_NO: "Check No",
            COL_UI_VENDOR_NAME: "Vendor",
            COL_UI_CUSTOMER_NAME: "Customer",
            COL_REF: "Reference",
            COL_BILL_NO: "Bill #",
            COL_INVOICE_NO: "Invoice #",
            COL_MEMO: "Memo",
            COL_AMOUNT: "Amount",
            COL_STATUS: "Status",
            COL_TRANSACTION_TYPE: "Type",
            COL_PAYMENT_METHOD: "Method",
            COL_CREATED_BY: "Created By",
            "name": "Name" # for management tab
        }

        if isinstance(treeview, CheckboxTreeview) and "#0" not in treeview['columns']:
             try:
                 treeview.column("#0", width=40, stretch=tk.NO, anchor=tk.CENTER)
                 treeview.heading("#0", text="")
             except tk.TclError:
                 logging.warning("Could not configure #0 column for CheckboxTreeview.")

        for col_id in column_defs:
             if col_id == "#0": continue

             base_heading_text = heading_overrides.get(col_id, col_id.replace('_ui','').replace('_', ' ').title())
             # Special case for pending tree creator column if needed, but general override is better
             # if treeview != getattr(self, 'report_tree', None) and col_id == COL_CREATED_BY:
             #     base_heading_text = "Created By"

             config = col_configs.get(col_id, {})
             width = config.get("width", 120)
             anchor = config.get("anchor", tk.W)
             stretch = config.get("stretch", tk.YES)

             if col_id in treeview['columns']:
                 try:
                     sort_command = None
                     # Assign sort command only to the report_tree
                     if treeview == getattr(self, 'report_tree', None):
                         # Use a wrapper or functools.partial if lambda gives issues.
                         # The direct lambda c=col_id should work, but let's be explicit.
                         def create_sort_command(column_identifier):
                             return lambda: self._sort_report_tree_by_column(column_identifier)
                         sort_command = create_sort_command(col_id)

                     if sort_command:
                        treeview.heading(col_id, text=base_heading_text, anchor=anchor, command=sort_command)
                     else:
                        treeview.heading(col_id, text=base_heading_text, anchor=anchor) # No command for other trees
                     treeview.column(col_id, width=width, anchor=anchor, stretch=stretch)

                 except tk.TclError as e:
                     # Check if the error is specifically about the -command option
                     if "-command" in str(e).lower() and "value" in str(e).lower() and "missing" in str(e).lower():
                         logging.error(f"Error configuring treeview heading '{col_id}' command: {e}. This means the sort_command was not accepted.")
                         # Fallback: configure without command if it fails
                         treeview.heading(col_id, text=base_heading_text, anchor=anchor)
                     else:
                         logging.error(f"Error configuring treeview column/heading '{col_id}': {e}")
             else:
                  logging.warning(f"Column identifier '{col_id}' defined in column_defs but not found in Treeview columns: {treeview['columns']}")


# Inside BankSheetApp class
    def _get_db_id_from_tree_item(self, treeview, iid):
        """Safely retrieves the database ID (first value) from a treeview item."""
        if not iid:
            return None
        try:
            item_data = treeview.item(iid)
            if item_data and 'values' in item_data and item_data['values']:
                return int(item_data['values'][0])
        except (ValueError, TypeError, IndexError, KeyError):
            logging.error(f"Could not extract DB ID from treeview item '{iid}'. Data: {item_data}", exc_info=True)
        return None

# Inside BankSheetApp class
    def _sort_report_tree_by_column(self, col_id):
        """Handles column header click for sorting the report_tree."""
        if not hasattr(self, 'report_tree'):
            return

        logging.debug(f"Report tree sort requested for column: {col_id}")

        if self.report_tree_sort_column == col_id:
            # Toggle direction if same column is clicked
            self.report_tree_sort_direction = 'desc' if self.report_tree_sort_direction == 'asc' else 'asc'
        else:
            # New column, default to ascending
            self.report_tree_sort_column = col_id
            self.report_tree_sort_direction = 'asc'

        # Update column header texts with sort indicators
        for c_id in TREE_COLUMNS_FULL:
            if c_id == "#0": continue
            base_text = self.report_tree.heading(c_id, "text").replace(" ▲", "").replace(" ▼", "")
            if c_id == self.report_tree_sort_column:
                indicator = " ▲" if self.report_tree_sort_direction == 'asc' else " ▼"
                self.report_tree.heading(c_id, text=base_text + indicator)
            else:
                self.report_tree.heading(c_id, text=base_text)

        self._perform_report_tree_sort()
        # Re-populate the tree with the sorted data from cache
        self._populate_treeview_data(self.report_tree, self.report_tree_data_cache, TREE_COLUMNS_FULL)
        logging.info(f"Report tree sorted by '{self.report_tree_sort_column}' ({self.report_tree_sort_direction}).")

    def _perform_report_tree_sort(self):
        """Sorts the self.report_tree_data_cache based on current sort settings."""
        if not self.report_tree_sort_column or not self.report_tree_data_cache:
            if not self.report_tree_data_cache:
                 logging.debug("_perform_report_tree_sort: No data in cache to sort.")
            return

        try:
            # The sort column ID (e.g., COL_DATE) needs to map to an index in the display_tuple
            col_idx_in_display_tuple = TREE_COLUMNS_FULL.index(self.report_tree_sort_column)
        except ValueError:
            logging.error(f"Sort column '{self.report_tree_sort_column}' not found in TREE_COLUMNS_FULL definition.")
            return

        logging.debug(f"Performing sort on cache. Column: '{self.report_tree_sort_column}' (index {col_idx_in_display_tuple}), Direction: '{self.report_tree_sort_direction}'")

        def sort_key_func(cached_row_data):
            # cached_row_data is: (display_tuple, notes, amount_float, type_val, payment_method_val)
            display_tuple_values = cached_row_data[0]

            # Handle cases where display_tuple_values might not have enough elements (e.g. 'nodata' row was in cache)
            if col_idx_in_display_tuple >= len(display_tuple_values):
                return "" # or a value that sorts to the end/beginning

            value_to_sort_str = display_tuple_values[col_idx_in_display_tuple]

            if self.report_tree_sort_column == COL_ID:
                try: return int(value_to_sort_str)
                except (ValueError, TypeError): return 0 # Sort non-numeric IDs as 0
            elif self.report_tree_sort_column == COL_DATE:
                try: return datetime.strptime(value_to_sort_str, '%Y-%m-%d').date()
                except (ValueError, TypeError): return datetime.min.date() # Sort invalid dates to the beginning
            elif self.report_tree_sort_column == COL_AMOUNT:
                # Use the pre-parsed amount_float which is cached_row_data[2]
                return cached_row_data[2] if cached_row_data[2] is not None else 0.0
            elif self.report_tree_sort_column == COL_CHECK_NO: # Treat check_no as numeric if possible
                try: return int(value_to_sort_str)
                except (ValueError, TypeError): return float('-inf') # Sort non-numeric check numbers before numeric ones
            # For all other columns, treat as case-insensitive strings
            return str(value_to_sort_str).lower() if value_to_sort_str is not None else ""

        try:
            self.report_tree_data_cache.sort(
                key=sort_key_func,
                reverse=(self.report_tree_sort_direction == 'desc')
            )
            logging.debug(f"Cache sorted. First item (display_tuple): {self.report_tree_data_cache[0][0] if self.report_tree_data_cache else 'N/A'}")
        except Exception as e:
            logging.error(f"Error during report_tree_data_cache sort: {e}", exc_info=True)

    def _create_context_menu(self, treeview_widget):
        menu = tk.Menu(self.root, tearoff=0, background=COLOR_SECONDARY_BG, foreground=COLOR_TEXT,
                       activebackground=COLOR_ACCENT, activeforeground=COLOR_BUTTON_PRIMARY_FG, relief='solid', borderwidth=1)
        menu.add_command(label="Edit Transaction", command=lambda: self.edit_selected_transaction(treeview_widget))
        # <<< REMOVED Delete option >>>
        # menu.add_command(label="Delete Transaction", command=lambda: self.delete_selected_transaction(treeview_widget))
        menu.add_separator(background=COLOR_BORDER)
        status_menu = tk.Menu(menu, tearoff=0, background=COLOR_SECONDARY_BG, foreground=COLOR_TEXT,
                              activebackground=COLOR_ACCENT, activeforeground=COLOR_BUTTON_PRIMARY_FG)
        menu.add_cascade(label="Change Status To", menu=status_menu)
        # Use ALL_STATUS_OPTIONS which now excludes Pending/Cleared from Credit
        for status in ALL_STATUS_OPTIONS:
             status_menu.add_command(label=status, command=lambda s=status, tw=treeview_widget: self.change_selected_status(tw, s))
        return menu

    def _create_context_menu_report_bulk(self): # For Report Tab
        menu = tk.Menu(self.root, tearoff=0, background=COLOR_SECONDARY_BG, foreground=COLOR_TEXT,
                       activebackground=COLOR_ACCENT, activeforeground=COLOR_BUTTON_PRIMARY_FG, relief='solid', borderwidth=1)
        menu.add_command(label="Edit Transaction", command=lambda: self.edit_selected_transaction(self.report_tree))
        # <<< REMOVED Delete option >>>
        # menu.add_command(label="Delete Transaction", command=lambda: self.delete_selected_transaction(self.report_tree))
        return menu

    def _show_context_menu(self, event, treeview_widget, context_menu):
        iid = treeview_widget.identify_row(event.y)
        if iid:
            if 'nodata' not in treeview_widget.item(iid, 'tags'):
                treeview_widget.selection_set(iid)
                treeview_widget.focus(iid)
                context_menu.post(event.x_root, event.y_root)

    # --- Data Population and Refresh ---
    def initialize_data(self):
        self.refresh_all_views()

    def refresh_all_views(self):
        logging.info("Refreshing all application views...")
        self.populate_company_dropdown()
        self.populate_filter_comboboxes() # Includes bank filters
        self.apply_report_filters() # Populates report tree
        self.populate_pending_tree()
        self.populate_bank_summary_tree() # <<< UPDATED
        self.populate_memo_summary_tree()
        self.populate_bank_dropdown() # Add Trans bank dropdown
        self.populate_payee_dropdowns() # Add Trans payee dropdown
        self.populate_management_list() # <<< UPDATED (handles memo)
        if self.current_user_role == 'admin':
            self.populate_users_tree()
            self._load_user_role_permissions_ui() # Reload perm checkboxes if admin
        logging.info("All views refreshed.")

    def populate_company_dropdown(self):
        logging.debug("Populating company dropdown...")
        companies = self.db_manager.get_companies()
        self.company_id_map.clear()
        company_names = [name for id, name in companies] if companies else []
        if companies:
            for comp_id, comp_name in companies: self.company_id_map[comp_name] = comp_id
            logging.debug(f"Loaded {len(company_names)} companies into dropdown map.")
        else: logging.warning("No companies found in database for dropdown.")

        current_selection = self.company_var.get()
        self.company_combobox['values'] = company_names

        if company_names:
            if current_selection in company_names: self.company_var.set(current_selection)
            else: self.company_combobox.current(0); self.company_var.set(company_names[0])
            self.company_combobox.configure(state='readonly')
            self._set_widget_valid(self.company_combobox)
        else:
            self.company_var.set(""); self.company_combobox.configure(state='disabled'); self._set_widget_invalid(self.company_combobox)
        logging.debug("Company dropdown populated.")

    def populate_filter_comboboxes(self):
        logging.debug("Populating filter comboboxes...")
        # Company Filter (Report Tab)
        companies = self.db_manager.get_companies()
        company_filter_names = [FILTER_ALL_COMPANIES] + [name for id, name in companies]
        current_comp_filter = self.filter_company_var.get()
        self.filter_company_combo['values'] = company_filter_names
        if current_comp_filter in company_filter_names: self.filter_company_var.set(current_comp_filter)
        elif company_filter_names: self.filter_company_combo.current(0)
        else: self.filter_company_var.set("")

        # Bank Filter (Report Tab AND Bank Summary Tab)
        banks = self.db_manager.get_distinct_banks()
        bank_filter_names = [FILTER_ALL_BANKS] + banks
        # Report Tab Bank Filter
        current_bank_filter_report = self.filter_bank_var.get()
        self.filter_bank_combo['values'] = bank_filter_names
        if current_bank_filter_report in bank_filter_names: self.filter_bank_var.set(current_bank_filter_report)
        elif bank_filter_names: self.filter_bank_combo.current(0)
        else: self.filter_bank_var.set("")
        # Bank Summary Tab Bank Filter
        current_bank_filter_summary = self.bank_summary_filter_var.get()
        self.bank_summary_filter_combo['values'] = bank_filter_names
        if current_bank_filter_summary in bank_filter_names: self.bank_summary_filter_var.set(current_bank_filter_summary)
        elif bank_filter_names: self.bank_summary_filter_combo.current(0)
        else: self.bank_summary_filter_var.set("")

        # Status Filter (Uses ALL_STATUS_OPTIONS now)
        status_filter_options = [FILTER_ALL_STATUSES] + ALL_STATUS_OPTIONS
        current_status_filter = self.filter_status_var.get()
        self.filter_status_combo['values'] = status_filter_options
        if current_status_filter in status_filter_options: self.filter_status_var.set(current_status_filter)
        elif status_filter_options: self.filter_status_combo.current(0)
        else: self.filter_status_var.set("")

        # Memo Filter (Dynamic)
        memos_data = self.db_manager.get_memos()
        memo_names = [name for m_id, name in memos_data] if memos_data else []
        memo_filter_options = [FILTER_ALL_MEMOS] + sorted(memo_names)
        current_memo_filter = self.filter_memo_var.get()
        self.filter_memo_combo['values'] = memo_filter_options
        if current_memo_filter in memo_filter_options: self.filter_memo_var.set(current_memo_filter)
        elif memo_filter_options: self.filter_memo_combo.current(0)
        else: self.filter_memo_var.set("")

        # <<< NEW: Vendor Filter >>>
        vendors_data = self.db_manager.get_payees(payee_type='Vendor')
        vendor_names = [name for p_id, name, p_type in vendors_data] if vendors_data else []
        vendor_filter_options = [FILTER_ALL_VENDORS] + sorted(vendor_names)
        current_vendor_filter = self.filter_vendor_var.get()
        self.filter_vendor_combo['values'] = vendor_filter_options
        if current_vendor_filter in vendor_filter_options: self.filter_vendor_var.set(current_vendor_filter)
        elif vendor_filter_options: self.filter_vendor_combo.current(0)
        else: self.filter_vendor_var.set("")

        # <<< NEW: Customer Filter >>>
        customers_data = self.db_manager.get_payees(payee_type='Customer')
        customer_names = [name for p_id, name, p_type in customers_data] if customers_data else []
        customer_filter_options = [FILTER_ALL_CUSTOMERS] + sorted(customer_names)
        current_customer_filter = self.filter_customer_var.get()
        self.filter_customer_combo['values'] = customer_filter_options
        if current_customer_filter in customer_filter_options: self.filter_customer_var.set(current_customer_filter)
        elif customer_filter_options: self.filter_customer_combo.current(0)
        else: self.filter_customer_var.set("")

        # <<< NEW: Type Filter >>>
        # Values already set in _create_report_tab, just set default
        current_type_filter = self.filter_type_var.get()
        if not current_type_filter: # Set default if empty
            self.filter_type_combo.current(0) # Index 0 is "All Types"

        # <<< NEW: Method Filter >>>
        method_filter_options = [FILTER_ALL_METHODS] + PAYMENT_METHODS
        current_method_filter = self.filter_method_var.get()
        self.filter_method_combo['values'] = method_filter_options
        if current_method_filter in method_filter_options: self.filter_method_var.set(current_method_filter)
        elif method_filter_options: self.filter_method_combo.current(0)
        else: self.filter_method_var.set("")

        logging.debug("Filter comboboxes populated.")

    def populate_add_trans_bank_dropdowns(self):
        """Populates the Bank Name/From Bank AND the To Bank dropdowns on the Add Transaction tab."""
        logging.debug("Populating Add Transaction/Transfer bank dropdowns...")
        banks_data = self.db_manager.get_banks()
        bank_names = [name for bank_id, name in banks_data] if banks_data else []

        # --- Populate "Bank Name" / "From Bank" dropdown ---
        if hasattr(self, 'bank_name_combobox') and hasattr(self, 'bank_name_var'):
            current_main_bank = self.bank_name_var.get()
            self.bank_name_combobox['values'] = bank_names
            if bank_names:
                if current_main_bank in bank_names:
                    self.bank_name_var.set(current_main_bank)
                else:
                    if not current_main_bank and bank_names:
                        self.bank_name_combobox.current(0)
                        self.bank_name_var.set(bank_names[0])
                    elif current_main_bank not in bank_names:
                         self.bank_name_var.set("")
                self.bank_name_combobox.config(state='readonly')
                self._set_widget_valid(self.bank_name_combobox)
            else:
                self.bank_name_var.set("")
                self.bank_name_combobox.config(state='disabled')
                self._set_widget_invalid(self.bank_name_combobox)
        else:
            logging.warning("Main bank combobox or var not found for population in Add Transaction tab.")

        # --- Populate "To Bank" dropdown (for Transfers) ---
        if hasattr(self, 'transfer_to_bank_combo') and hasattr(self, 'transfer_to_bank_var'):
            current_to_bank = self.transfer_to_bank_var.get()
            self.transfer_to_bank_combo['values'] = bank_names
            if bank_names:
                if current_to_bank in bank_names:
                    self.transfer_to_bank_var.set(current_to_bank)
                else:
                    if not current_to_bank and bank_names:
                        self.transfer_to_bank_combo.current(0)
                        self.transfer_to_bank_var.set(bank_names[0])
                    elif current_to_bank not in bank_names:
                        self.transfer_to_bank_var.set("")
                self.transfer_to_bank_combo.config(state='readonly')
                self._set_widget_valid(self.transfer_to_bank_combo)
            else:
                self.transfer_to_bank_var.set("")
                self.transfer_to_bank_combo.config(state='disabled')
                self._set_widget_invalid(self.transfer_to_bank_combo)
        else:
            logging.warning("Transfer 'To Bank' combobox or var not found for population.")

        logging.debug(f"Add Transaction bank dropdowns populated with {len(bank_names)} banks.")
        
        # --- MODIFIED HERE: Pass widget directly ---
        if hasattr(self, 'bank_name_combobox'):
            self._validate_combobox(self.bank_name_combobox)
        if hasattr(self, 'transfer_to_bank_combo'):
            self._validate_combobox(self.transfer_to_bank_combo)

    def populate_payee_dropdowns(self):
        logging.debug("Triggering payee dropdown update via form layout.")
        self._update_transaction_form_layout()

    # Inside BankSheetApp class
    def populate_report_tree(self, filters=None):
        logging.debug(f"Populating full report treeview with filters: {filters}")
        filter_args = filters if filters else {}

        # Preserve checked items before fetching new data
        if isinstance(self.report_tree, CheckboxTreeview):
            current_tree_checked_iids = self.report_tree.get_checked()
            for iid in current_tree_checked_iids:
                db_id = self._get_db_id_from_tree_item(self.report_tree, iid)
                if db_id is not None:
                    self.report_tree_checked_db_ids.add(db_id)
            logging.debug(f"Preserved checked DB IDs (before fetch): {self.report_tree_checked_db_ids}")


        # Fetch new data from DB and store in cache
        self.report_tree_data_cache = self.db_manager.fetch_transactions(**filter_args)
        logging.debug(f"Fetched {len(self.report_tree_data_cache)} items into cache.")

        # If a sort column is active, sort the newly fetched data
        if self.report_tree_sort_column:
            logging.debug(f"Applying active sort: {self.report_tree_sort_column} {self.report_tree_sort_direction}")
            self._perform_report_tree_sort() # This sorts self.report_tree_data_cache
        else:
            logging.debug("No active sort column, displaying data as fetched.")

        # Populate the treeview with data from the (potentially sorted) cache
        self._populate_treeview_data(self.report_tree, self.report_tree_data_cache, TREE_COLUMNS_FULL)
        self._auto_size_report_tree_columns()


    def populate_pending_tree(self):
        logging.debug("Populating pending report treeview...")
        data = self.db_manager.fetch_transactions(filter_status=STATUS_PENDING)
        self._populate_treeview_data(self.pending_tree, data, TREE_COLUMNS_PENDING)
        logging.debug(f"Pending tree populated with {len(data)} items.")

    # <<< UPDATED Bank Summary Population >>>
    def populate_bank_summary_tree(self):
        logging.debug("Populating bank summary treeview...")
        for item in self.bank_summary_tree.get_children():
            self.bank_summary_tree.delete(item)

        selected_bank = self.bank_summary_filter_var.get()
        logging.debug(f"Bank summary filter selected: '{selected_bank}'")
        # Pass the filter name correctly
        summary_data = self.db_manager.get_bank_summary(
            filter_bank_name=selected_bank if selected_bank != FILTER_ALL_BANKS else None
        )


        if not summary_data:
            # Adjusted length for the updated columns
            nodata_values = ["No summary data available.", "", "", "", "", ""]
            try: self.bank_summary_tree.insert("", tk.END, values=tuple(nodata_values), tags=('nodata',))
            except Exception as e: logging.error(f"Error inserting 'no data' row into bank summary tree: {e}")
            return

        # Process new data structure: (bank_name, total_credits, total_debits, posted_balance, clearance_adjustment)
        for bank_name, total_credits, total_debits, posted_balance, clearance_adjustment in summary_data:
            credits_str = f"{total_credits:,.2f}" if total_credits is not None else "0.00"
            debits_str = f"{total_debits:,.2f}" if total_debits is not None else "0.00"
            # --- Use posted_balance ---
            posted_balance_str = f"{posted_balance:,.2f}" if posted_balance is not None else "0.00"
            # Balance with clearance is now based on posted_balance
            balance_with_clearance = posted_balance + clearance_adjustment
            # --- END OF UPDATE ---
            bal_w_clear_str = f"{balance_with_clearance:,.2f}" if balance_with_clearance is not None else "0.00"
            diff_str = f"{clearance_adjustment:,.2f}" if clearance_adjustment is not None else "0.00"

            # Tuple matches UPDATED TREE_COLUMNS_BANK_SUMMARY order
            display_values = (bank_name, credits_str, debits_str, posted_balance_str, bal_w_clear_str, diff_str)

            try: self.bank_summary_tree.insert("", tk.END, values=display_values)
            except Exception as e: logging.error(f"Error inserting row into bank summary tree: {display_values} - {e}", exc_info=True)

        logging.debug(f"Bank summary tree populated with {len(summary_data)} aggregation rows.")
        
    def populate_memo_summary_tree(self):
        logging.debug("Populating memo summary treeview...")
        for item in self.memo_summary_tree.get_children(): self.memo_summary_tree.delete(item)
        summary_data = self.db_manager.get_memo_summary()
        if not summary_data:
            nodata_values = ["No summary data available.", "", "", ""]
            try: self.memo_summary_tree.insert("", tk.END, values=tuple(nodata_values), tags=('nodata',))
            except Exception as e: logging.error(f"Error inserting 'no data' row into memo summary tree: {e}")
            return
        self._configure_tree_tags(self.memo_summary_tree)
        for memo, status, count, total_amount in summary_data:
            amount_str = f"{total_amount:,.2f}" if total_amount is not None else "N/A"
            display_values = (memo, status, count, amount_str)
            # Use ALL_STATUS_OPTIONS for tag check
            status_tag = str(status).lower() if status and str(status).lower() in [s.lower() for s in ALL_STATUS_OPTIONS] else 'default'
            try: self.memo_summary_tree.insert("", tk.END, values=display_values, tags=(status_tag,))
            except Exception as e: logging.error(f"Error inserting row into memo summary tree: {display_values} - {e}", exc_info=True)
        logging.debug(f"Memo summary tree populated with {len(summary_data)} aggregation rows.")

    # <<< UPDATED Management List Population (Handles Memo) >>>
    def populate_management_list(self, event=None):
        selected_type = self.mgmt_list_type_var.get()
        logging.info(f"Populating management list for type: {selected_type}")
        for item in self.mgmt_list_tree.get_children(): self.mgmt_list_tree.delete(item)
        try:
            self.mgmt_list_tree["displaycolumns"] = ()
            self.mgmt_list_tree["columns"] = ()
        except Exception as e: logging.error(f"Error clearing Treeview columns: {e}", exc_info=True)

        data = []; columns = (); column_configs = {}
        if selected_type == "Companies":
            data = self.db_manager.get_companies(); columns = ("id", "name")
            column_configs = {"id": {"text": "ID", "width": 60}, "name": {"text": "Company Name", "width": 250, "stretch": tk.YES}}
        elif selected_type == "Banks":
            data = self.db_manager.get_banks(); columns = ("id", "name")
            column_configs = {"id": {"text": "ID", "width": 60}, "name": {"text": "Bank Name", "width": 250, "stretch": tk.YES}}
        elif selected_type == "Vendors":
            data_raw = self.db_manager.get_payees(payee_type='Vendor')
            data = [(row[0], row[1]) for row in data_raw] if data_raw else []; columns = ("id", "name")
            column_configs = {"id": {"text": "ID", "width": 60}, "name": {"text": "Vendor Name", "width": 250, "stretch": tk.YES}}
        elif selected_type == "Customers":
            data_raw = self.db_manager.get_payees(payee_type='Customer')
            data = [(row[0], row[1]) for row in data_raw] if data_raw else []; columns = ("id", "name")
            column_configs = {"id": {"text": "ID", "width": 60}, "name": {"text": "Customer Name", "width": 250, "stretch": tk.YES}}
        elif selected_type == "Memos": # <<< Changed from "Memo"
            data = self.db_manager.get_memos() # <<< Use new DB method
            columns = ("id", "name") # <<< Use id and name
            column_configs = {"id": {"text": "ID", "width": 60}, "name": {"text": "Memo Name", "width": 250, "stretch": tk.YES}}

        try: # Configure columns
            self.mgmt_list_tree["columns"] = columns
            self.mgmt_list_tree["displaycolumns"] = columns
            for col in columns:
                config = column_configs.get(col, {})
                text = config.get("text", col.title()); width = config.get("width", 100)
                anchor = config.get("anchor", tk.W); stretch = config.get("stretch", tk.YES)
                self.mgmt_list_tree.heading(col, text=text, anchor=anchor)
                self.mgmt_list_tree.column(col, width=width, anchor=anchor, stretch=stretch)
        except Exception as e:
            logging.error(f"Error configuring Treeview columns or headings: {e}", exc_info=True)
            messagebox.showerror("UI Error", f"Failed to set up list columns: {e}")
            return

        if data: # Populate data
            for row_values in data:
                 # --- REMOVED OLD MEMO HANDLING ---
                # if selected_type == "Memo" and isinstance(row_values, str):
                #    self.mgmt_list_tree.insert("", tk.END, values=(row_values,)) # Insert string as tuple
                # --- END REMOVED ---
                if isinstance(row_values, (list, tuple)) and len(row_values) == len(columns):
                    self.mgmt_list_tree.insert("", tk.END, values=row_values)
                else:
                    logging.warning(f"Skipping invalid data row for {selected_type}: Expected {len(columns)} values, got {row_values}")
            logging.debug(f"Displayed {len(data)} {selected_type} in management treeview.")

# Inside BankSheetApp class

    def _auto_size_report_tree_columns(self):
        """Automatically sizes columns in the report_tree based on content and header."""
        if not hasattr(self, 'report_tree'):
            return
        tree = self.report_tree
        min_col_width = 60  # Minimum width for any column
        max_col_width = 300 # Maximum width for any column (except Notes perhaps)
        padding = 10        # Extra padding

        columns_to_size = [col for col in tree["columns"] if col != "#0"]
        if isinstance(tree, CheckboxTreeview): # If #0 column exists for checkboxes
            try:
                tree.column("#0", width=40, stretch=tk.NO, anchor=tk.CENTER) # Fixed width for checkbox
            except tk.TclError: pass

        for col_id in columns_to_size:
            try:
                # Measure header width
                header_text = tree.heading(col_id)["text"]
                header_font_obj = tkFont.Font(font=tree.heading(col_id).get("font", default_font))
                header_width = header_font_obj.measure(header_text) + padding

                # Measure content width
                max_content_width = 0
                content_font_obj = tkFont.Font(font=tree.item(tree.get_children("")[0] if tree.get_children("") else "", "font") if tree.get_children("") else default_font)

                for item_iid in tree.get_children(""): # Iterate over top-level items
                    item_values = tree.item(item_iid, "values")
                    if item_values:
                        try:
                            col_index = tree["columns"].index(col_id)
                            cell_value = str(item_values[col_index])
                            content_width = content_font_obj.measure(cell_value)
                            if content_width > max_content_width:
                                max_content_width = content_width
                        except (IndexError, ValueError):
                            # This can happen if column_defs are out of sync with actual data columns
                            # logging.warning(f"Index error for column {col_id} when auto-sizing.")
                            pass # Silently continue, might be due to 'nodata' row or mismatched columns

                final_width = max(header_width, max_content_width + padding)
                final_width = max(final_width, min_col_width) # Apply minimum
                final_width = min(final_width, max_col_width) # Apply maximum

                # Special handling for notes or very long columns if needed
                if col_id == COL_NOTES and final_width > 200:
                    final_width = 200 # Cap notes column specifically

                tree.column(col_id, width=final_width)
                # logging.debug(f"Auto-sized column '{col_id}': Header='{header_text}', Width={final_width}")
            except tk.TclError as e:
                logging.warning(f"TclError auto-sizing column '{col_id}': {e}")
            except Exception as e:
                logging.error(f"Unexpected error auto-sizing column '{col_id}': {e}", exc_info=True)
        logging.info("Report tree columns auto-sized.")

# Inside BankSheetApp class
    def _populate_treeview_data(self, treeview, data, column_defs):
        if treeview == getattr(self, 'report_tree', None) and isinstance(treeview, CheckboxTreeview):
            temp_checked_ids_before_clear = set()
            for iid in treeview.get_checked():
                db_id = self._get_db_id_from_tree_item(treeview, iid)
                if db_id is not None:
                    temp_checked_ids_before_clear.add(db_id)
            self.report_tree_checked_db_ids.update(temp_checked_ids_before_clear)
            logging.debug(f"Checked DB IDs before populating {treeview}: {self.report_tree_checked_db_ids}")

        for item in treeview.get_children(): treeview.delete(item)
        self._configure_tree_tags(treeview)

        if not data:
            num_cols = len(column_defs)
            nodata_values = [""] * num_cols
            msg = "No transactions found."
            col_index_for_msg = 1 if num_cols > 1 else 0
            if COL_UI_VENDOR_NAME in column_defs: col_index_for_msg = column_defs.index(COL_UI_VENDOR_NAME)
            elif COL_DATE in column_defs: col_index_for_msg = column_defs.index(COL_DATE)

            filters_active = False
            # Corrected list of all filter constants for the check
            all_filter_defaults = [
                FILTER_ALL_COMPANIES, FILTER_ALL_BANKS, FILTER_ALL_STATUSES,
                FILTER_ALL_MEMOS, FILTER_ALL_VENDORS, FILTER_ALL_CUSTOMERS,
                FILTER_ALL_TYPES, FILTER_ALL_METHODS
            ]
            if hasattr(self, 'search_var') and (self.search_var.get() or any(
                getattr(self, fvar, tk.StringVar()).get() not in all_filter_defaults
                for fvar in ['filter_company_var', 'filter_bank_var', 'filter_status_var', 'filter_memo_var',
                             'filter_vendor_var', 'filter_customer_var', 'filter_type_var', 'filter_method_var']
                if hasattr(self, fvar) and getattr(self, fvar) is not None # ensure the var itself exists
            ) or (hasattr(self, 'filter_start_date') and self.filter_start_date.get()) or \
               (hasattr(self, 'filter_end_date') and self.filter_end_date.get())):
                filters_active = True

            if filters_active: msg = "No transactions match current filters/search."
            if 0 <= col_index_for_msg < num_cols: nodata_values[col_index_for_msg] = msg
            elif nodata_values: nodata_values[0] = msg

            try: treeview.insert("", tk.END, values=tuple(nodata_values), tags=('nodata',))
            except Exception as e: logging.error(f"Error inserting 'no data' row into {treeview}: {e}")
            return

        expected_display_cols = len(column_defs)
        try: status_col_display_index = column_defs.index(COL_STATUS)
        except ValueError: status_col_display_index = -1

        newly_inserted_iids_map = {}

        for row_data_full in data:
            display_values = row_data_full[0]

            if len(display_values) != expected_display_cols:
                 logging.warning(f"Display tuple length mismatch for {treeview}: Expected {expected_display_cols}, got {len(display_values)}. Row: {display_values[:3]}...")
                 continue

            status_tag = 'default'
            if status_col_display_index != -1 and 0 <= status_col_display_index < len(display_values):
                 status_value_raw = display_values[status_col_display_index]
                 if status_value_raw:
                     status_value = str(status_value_raw).lower()
                     all_statuses_lower = [s.lower() for s in ALL_STATUS_OPTIONS]
                     if status_value in all_statuses_lower: status_tag = status_value
            try:
                db_id = int(display_values[0])
                item_iid = treeview.insert("", tk.END, values=display_values, tags=(status_tag,))
                newly_inserted_iids_map[db_id] = item_iid
            except Exception as e:
                logging.error(f"Error inserting row into {treeview}: {display_values[:3]}... - {e}", exc_info=True)

        if treeview == getattr(self, 'report_tree', None) and isinstance(treeview, CheckboxTreeview):
            items_re_checked = 0
            for db_id_to_check in self.report_tree_checked_db_ids:
                if db_id_to_check in newly_inserted_iids_map:
                    iid_to_check = newly_inserted_iids_map[db_id_to_check]
                    try:
                        treeview.check_item(iid_to_check)
                        items_re_checked +=1
                    except Exception as e:
                        logging.warning(f"Could not re-check item with IID '{iid_to_check}' (DB ID {db_id_to_check}): {e}")
            logging.debug(f"Re-applied checks to {items_re_checked} items in report tree.")
            

    # --- Filtering and Search ---
    def apply_report_filters(self):
        logging.debug("--- Applying report filters / search ---")
        filters = {}
        # Company, Bank, Dates, Status, Memo (existing logic)
        comp_name = self.filter_company_var.get(); comp_id = self.company_id_map.get(comp_name)
        if comp_name != FILTER_ALL_COMPANIES and comp_id: filters['filter_company_id'] = comp_id

        bank_name = self.filter_bank_var.get()
        if bank_name != FILTER_ALL_BANKS: filters['filter_bank_name'] = bank_name

        try: start_date = self.filter_start_date.get_date(); filters['filter_start_date'] = start_date
        except ValueError: pass # Ignore if date entry is empty/invalid

        try: end_date = self.filter_end_date.get_date(); filters['filter_end_date'] = end_date
        except ValueError: pass # Ignore if date entry is empty/invalid

        status = self.filter_status_var.get()
        if status != FILTER_ALL_STATUSES: filters['filter_status'] = status

        memo = self.filter_memo_var.get()
        if memo != FILTER_ALL_MEMOS: filters['filter_memo'] = memo

        # <<< MODIFIED: Read from Vendor/Customer Comboboxes >>>
        vendor = self.filter_vendor_var.get()
        if vendor != FILTER_ALL_VENDORS: filters['filter_vendor_name'] = vendor # Pass vendor name

        customer = self.filter_customer_var.get()
        if customer != FILTER_ALL_CUSTOMERS: filters['filter_customer_name'] = customer # Pass customer name

        # <<< NEW: Read Type and Method Filters >>>
        trans_type = self.filter_type_var.get()
        if trans_type != FILTER_ALL_TYPES: filters['filter_transaction_type'] = trans_type

        method = self.filter_method_var.get()
        if method != FILTER_ALL_METHODS: filters['filter_payment_method'] = method

        # Search Term
        search_term = self.search_var.get().strip()
        if search_term: filters['search_term'] = search_term

        logging.info(f"Filters & Search passed to populate_report_tree: {filters}")
        self.populate_report_tree(filters=filters)
        logging.debug("--- Finished applying report filters / search ---")

# Inside BankSheetApp class
    def clear_report_filters(self):
        logging.debug("--- Clearing report filters & search ---")
        # Clear existing filters
        self.filter_company_var.set(FILTER_ALL_COMPANIES)
        self.filter_bank_var.set(FILTER_ALL_BANKS)
        self.filter_status_var.set(FILTER_ALL_STATUSES)
        self.filter_memo_var.set(FILTER_ALL_MEMOS)
        self.search_var.set("")
        self.filter_start_date.delete(0, tk.END)
        self.filter_end_date.delete(0, tk.END)

        self.filter_vendor_var.set(FILTER_ALL_VENDORS)
        self.filter_customer_var.set(FILTER_ALL_CUSTOMERS)
        self.filter_type_var.set(FILTER_ALL_TYPES)
        self.filter_method_var.set(FILTER_ALL_METHODS)

        try:
            if hasattr(self, 'filter_company_combo') and self.filter_company_combo['values']: self.filter_company_combo.current(0)
            if hasattr(self, 'filter_bank_combo') and self.filter_bank_combo['values']: self.filter_bank_combo.current(0)
            # ... (rest of combobox resets)
            if hasattr(self, 'filter_status_combo') and self.filter_status_combo['values']: self.filter_status_combo.current(0)
            if hasattr(self, 'filter_memo_combo') and self.filter_memo_combo['values']: self.filter_memo_combo.current(0)
            if hasattr(self, 'filter_vendor_combo') and self.filter_vendor_combo['values']: self.filter_vendor_combo.current(0)
            if hasattr(self, 'filter_customer_combo') and self.filter_customer_combo['values']: self.filter_customer_combo.current(0)
            if hasattr(self, 'filter_type_combo') and self.filter_type_combo['values']: self.filter_type_combo.current(0)
            if hasattr(self, 'filter_method_combo') and self.filter_method_combo['values']: self.filter_method_combo.current(0)
        except (tk.TclError, IndexError):
            logging.warning("Error resetting combobox current index during filter clear.")

        # --- ADDED: Reset sort state and header indicators ---
        if hasattr(self, 'report_tree'):
            for c_id in TREE_COLUMNS_FULL:
                if c_id == "#0": continue
                try:
                    base_text = self.report_tree.heading(c_id, "text").replace(" ▲", "").replace(" ▼", "")
                    self.report_tree.heading(c_id, text=base_text)
                except tk.TclError: # Could happen if report_tree not fully initialized
                    pass
        self.report_tree_sort_column = None
        self.report_tree_sort_direction = 'asc'
        self.report_tree_data_cache = [] # Clear cache on filter clear
        self.report_tree_checked_db_ids.clear() # Clear checked items on filter clear
        if hasattr(self, 'report_tree') and isinstance(self.report_tree, CheckboxTreeview):
            try:
                self.report_tree.uncheck_all() # Visually uncheck
            except Exception as e:
                logging.warning(f"Error unchecking all items in report tree: {e}")
        # --- END ADDED ---

        self.apply_report_filters() # Re-apply to show all data
        logging.debug("--- Finished clearing report filters & search ---")

    # --- Transaction Actions ---
    def add_transaction(self):
        # ... (logging and initial setup) ...
        logging.debug("Attempting to add transaction...")
        errors = []; validated_data = {}
        selected_type = self.transaction_type_var.get()
        selected_payment_method = self.payment_method_var.get()
        validated_data['transaction_type'] = selected_type

        is_debit = (selected_type == TYPE_DEBIT)
        is_credit = (selected_type == TYPE_CREDIT)
        is_transfer = (selected_type == TYPE_TRANSFER)

        current_pm_options_add = []
        if is_transfer: current_pm_options_add = TRANSFER_PAYMENT_METHODS
        else: current_pm_options_add = [m for m in PAYMENT_METHODS if m != METHOD_TRANSFER]
        if not selected_payment_method or selected_payment_method not in current_pm_options_add:
            errors.append(f"Payment Method required (one of: {', '.join(current_pm_options_add)})."); self._set_widget_invalid(self.payment_method_dropdown)
        else: validated_data['payment_method'] = selected_payment_method; self._set_widget_valid(self.payment_method_dropdown)

        # ... (Company, Bank, To Bank, Date, Vendor/Cust, CheckNo, Bill/Inv, Memo, Amount validation - no changes here) ...
        company_name = self.company_var.get(); company_id = self.company_id_map.get(company_name)
        if not company_name or company_id is None: errors.append("Company is required."); self._set_widget_invalid(self.company_combobox)
        else: validated_data['company_id'] = company_id; self._set_widget_valid(self.company_combobox)
        bank_name_val = self.bank_name_var.get()
        if not bank_name_val:
            label_text = "From Bank" if is_transfer else "Bank Name"
            errors.append(f"{label_text} is required."); self._set_widget_invalid(self.bank_name_combobox)
        else: validated_data['bank_name'] = bank_name_val; self._set_widget_valid(self.bank_name_combobox)
        if is_transfer:
            to_bank_val = self.transfer_to_bank_var.get()
            if not to_bank_val: errors.append("To Bank is required for transfers."); self._set_widget_invalid(self.transfer_to_bank_combo)
            elif to_bank_val == bank_name_val:
                errors.append("'From Bank' and 'To Bank' cannot be the same."); self._set_widget_invalid(self.transfer_to_bank_combo); self._set_widget_invalid(self.bank_name_combobox)
            else: validated_data['transfer_to_bank_name'] = to_bank_val; self._set_widget_valid(self.transfer_to_bank_combo)
        try: validated_data['date'] = self.date_entry.get_date()
        except Exception: errors.append("Invalid date format.")
        if is_debit or is_credit:
            vendor_customer_val = self.vendor_customer_var.get()
            payee_label_text = "Customer Name" if is_credit else "Vendor Name"
            if not vendor_customer_val: errors.append(f"{payee_label_text} is required."); self._set_widget_invalid(self.vendor_customer_combobox)
            else: validated_data['vendor_or_customer_name'] = vendor_customer_val; self._set_widget_valid(self.vendor_customer_combobox)
        else: validated_data['vendor_or_customer_name'] = None
        check_no_val = self.check_no_entry.get().strip()
        is_check_no_required_add = (is_debit or is_transfer) and selected_payment_method == METHOD_CHECK
        if is_check_no_required_add and not check_no_val: errors.append("Check No. required for this method."); self._set_widget_invalid(self.check_no_entry)
        elif check_no_val: validated_data['check_no'] = check_no_val; self._set_widget_valid(self.check_no_entry)
        else: validated_data['check_no'] = None; self._set_widget_valid(self.check_no_entry)
        if is_debit:
            bill_no_val = self.bill_no_entry.get().strip()
            validated_data['bill_no'] = bill_no_val if bill_no_val else None; validated_data['invoice_no'] = None; self._set_widget_valid(self.bill_no_entry)
        elif is_credit:
            invoice_no_val = self.invoice_no_entry.get().strip()
            validated_data['invoice_no'] = invoice_no_val if invoice_no_val else None; validated_data['bill_no'] = None; self._set_widget_valid(self.invoice_no_entry)
        else: validated_data['bill_no'] = None; validated_data['invoice_no'] = None
        memo_value = self.memo_var.get().strip(); final_memo_value = None
        if not memo_value: errors.append("Memo is required."); self._set_widget_invalid(self.memo_combobox)
        elif memo_value == MEMO_OTHER:
            custom_memo = simpledialog.askstring("Custom Memo", "Enter custom memo:", parent=self.tab_frames['add_transaction'])
            if custom_memo is None: errors.append("Custom memo selection cancelled."); self._set_widget_invalid(self.memo_combobox)
            elif not custom_memo.strip(): errors.append("Custom memo cannot be empty."); self._set_widget_invalid(self.memo_combobox)
            else: final_memo_value = custom_memo.strip(); self._set_widget_valid(self.memo_combobox)
        else: final_memo_value = memo_value; self._set_widget_valid(self.memo_combobox)
        validated_data['memo'] = final_memo_value
        amount_val = self._validate_amount(check_only=False)
        if amount_val is None:
            if not self.amount_var.get().strip(): errors.append("Amount is required.")
            else: errors.append("Amount is invalid.")
            self._set_widget_invalid(self.amount_entry)
        else: validated_data['amount'] = amount_val; self._set_widget_valid(self.amount_entry)


        # Status (Only for Debit/Credit) - MODIFIED
        if is_debit or is_credit:
            status_val_add = self.status_var.get()
            allowed_statuses_add = []
            if is_credit:
                allowed_statuses_add = CREDIT_STATUS_OPTIONS
            elif is_debit:
                if selected_payment_method == METHOD_CHECK:
                    allowed_statuses_add = [STATUS_PAID, STATUS_VOID, STATUS_PENDING, STATUS_CLEARED]
                else:
                    allowed_statuses_add = [STATUS_PAID, STATUS_VOID]

            if not status_val_add or status_val_add not in allowed_statuses_add:
                errors.append(f"Status is required (one of: {', '.join(allowed_statuses_add)})."); self._set_widget_invalid(self.status_dropdown)
            else: validated_data['status'] = status_val_add; self._set_widget_valid(self.status_dropdown)

        notes_text = self.notes_text.get("1.0", tk.END).strip()
        validated_data['notes'] = notes_text if notes_text else None
        validated_data['reference'] = self.reference_entry.get().strip() or None
        self._set_widget_valid(self.reference_entry)

        if errors:
            # ... (Error display and re-validation - no changes) ...
            for combo_attr_name in ['company_combobox', 'bank_name_combobox', 'transfer_to_bank_combo', 'payment_method_dropdown', 'vendor_customer_combobox', 'status_dropdown', 'memo_combobox']:
                if hasattr(self, combo_attr_name): self._validate_combobox(getattr(self, combo_attr_name))
            if hasattr(self, 'amount_entry'): self._validate_amount(check_only=True)
            if hasattr(self, 'check_no_entry'): self._validate_entry(self.check_no_entry)
            if hasattr(self, 'bill_no_entry'): self._validate_entry(self.bill_no_entry)
            if hasattr(self, 'invoice_no_entry'): self._validate_entry(self.invoice_no_entry)
            messagebox.showerror("Input Error", "Correct errors:\n\n- " + "\n- ".join(errors), parent=self.tab_frames['add_transaction'])
            logging.warning(f"Add transaction validation failed: {errors}")
            return

        # ... (DB insertion logic - no changes) ...
        validated_data['created_by_user_id'] = self.current_user_id
        logging.info(f"Adding {validated_data.get('transaction_type', 'Unknown Type')} by User ID: {self.current_user_id}...")
        try:
            if is_transfer:
                logging.debug(f"Transfer validated_data: {validated_data}")
                from_bank = validated_data['bank_name']; to_bank = validated_data['transfer_to_bank_name']
                debit_leg_data = validated_data.copy(); debit_leg_data['bank_name'] = from_bank; debit_leg_data['status'] = DEFAULT_TRANSFER_DEBIT_STATUS; debit_leg_data['vendor_or_customer_name'] = f"Transfer to {to_bank}"; del debit_leg_data['transfer_to_bank_name']
                credit_leg_data = validated_data.copy(); credit_leg_data['bank_name'] = to_bank; credit_leg_data['status'] = DEFAULT_TRANSFER_CREDIT_STATUS; credit_leg_data['vendor_or_customer_name'] = f"Transfer from {from_bank}"; del credit_leg_data['transfer_to_bank_name']
                conn = self.db_manager.get_connection()
                if not conn: messagebox.showerror("DB Error", "Cannot connect for transfer.", parent=self.tab_frames['add_transaction']); return
                debit_id = None; credit_id = None; transfer_success = False
                try:
                    with conn.cursor() as cur:
                        logging.info(f"Debit leg: {debit_leg_data}"); debit_id = self.db_manager.add_transaction(**debit_leg_data)
                        if not debit_id: raise Exception("Failed debit leg.")
                        logging.info(f"Credit leg: {credit_leg_data}"); credit_id = self.db_manager.add_transaction(**credit_leg_data)
                        if not credit_id: raise Exception("Failed credit leg.")
                        transfer_success = True; logging.info(f"Transfer OK: Debit ID {debit_id}, Credit ID {credit_id}")
                except Exception as transfer_e: logging.error(f"Transfer error: {transfer_e}", exc_info=True); messagebox.showerror("Transfer Error", f"Failed: {transfer_e}", parent=self.tab_frames['add_transaction']);
                if transfer_success: messagebox.showinfo("Success", "Transfer recorded.", parent=self.tab_frames['add_transaction']); self.clear_add_transaction_fields(); self.refresh_all_views();
                if hasattr(self, 'payment_method_dropdown'): self.payment_method_dropdown.focus_set()
            else:
                new_trans_id = self.db_manager.add_transaction(**validated_data)
                if new_trans_id: messagebox.showinfo("Success", "Transaction added.", parent=self.tab_frames['add_transaction']); logging.info(f"Added ID: {new_trans_id}"); self.clear_add_transaction_fields(); self.refresh_all_views();
                if hasattr(self, 'payment_method_dropdown'): self.payment_method_dropdown.focus_set()
        except Exception as e: logging.error(f"Error adding transaction: {e}", exc_info=True); messagebox.showerror("Error", f"Error adding: {e}", parent=self.tab_frames['add_transaction'])

    
    
    def clear_add_transaction_fields(self):
        logging.debug("Clearing Add Transaction fields.")
        self.transaction_type_var.set(TYPE_DEBIT) # Default back to Debit
        if hasattr(self, 'payment_method_var'): self.payment_method_var.set(METHOD_CHECK)
        if hasattr(self, 'company_combobox') and self.company_combobox.cget('values'):
            try: self.company_combobox.current(0); self.company_var.set(self.company_combobox['values'][0])
            except (tk.TclError, IndexError): self.company_var.set("")
        else: self.company_var.set("")
        if hasattr(self, 'date_entry'): self.date_entry.set_date(datetime.now())
        if hasattr(self, 'bank_name_var'): self.bank_name_var.set("")
        if hasattr(self, 'check_no_entry'): self.check_no_entry.delete(0, tk.END)
        if hasattr(self, 'vendor_customer_var'): self.vendor_customer_var.set("") # Cleared
        if hasattr(self, 'reference_entry'): self.reference_entry.delete(0, tk.END)
        # <<< MODIFIED: Clear new fields >>>
        if hasattr(self, 'bill_no_entry'): self.bill_no_entry.delete(0, tk.END)
        if hasattr(self, 'invoice_no_entry'): self.invoice_no_entry.delete(0, tk.END)
        if hasattr(self, 'memo_combobox'): self.populate_memo_dropdown() # Reset memo dropdown state/value
        if hasattr(self, 'amount_var'): self.amount_var.set("")
        if hasattr(self, 'status_var'): self.status_var.set("") # Clear status var before layout update sets default
        if hasattr(self, 'notes_text'): self.notes_text.delete("1.0", tk.END)

        # Call layout update AFTER clearing vars to set correct dropdowns/defaults
        if hasattr(self, '_update_transaction_form_layout'): self._update_transaction_form_layout()

        # Reset visual validation state for all relevant widgets
        widgets_to_reset = [getattr(self, w, None) for w in [
            'company_combobox', 'bank_name_combobox', 'check_no_entry',
            'vendor_customer_combobox', 'amount_entry', 'status_dropdown',
            'memo_combobox', 'payment_method_dropdown',
            'bill_no_entry', 'invoice_no_entry' # Include new ones
            ]]
        for widget in widgets_to_reset:
            if widget: self._set_widget_valid(widget)

        # Ensure check entry state is correct after layout update
        if hasattr(self, '_update_check_no_state'): self._update_check_no_state()

        # Set focus
        if hasattr(self, 'payment_method_dropdown'): self.payment_method_dropdown.focus_set()
        elif hasattr(self, 'company_combobox'): self.company_combobox.focus_set()


    def _validate_amount(self, check_only=False):
        amount_str = self.amount_var.get(); valid = False; amount_float = None
        parent_win = self.tab_frames.get('add_transaction', self.root)
        try:
            cleaned = amount_str.replace('$', '').replace(',', '').strip()
            if cleaned:
                 amount_float = float(cleaned)
                 if amount_float > 0: valid = True
                 else:
                     if not check_only: messagebox.showerror("Input Error", "Amount must be positive.", parent=parent_win)
            else:
                 if not check_only: messagebox.showerror("Input Error", "Amount cannot be empty.", parent=parent_win)
        except ValueError:
            if not check_only and amount_str: messagebox.showerror("Input Error", f"Invalid amount format: '{amount_str}'.", parent=parent_win)
        if valid: self._set_widget_valid(self.amount_entry); return amount_float
        else:
            if amount_str and not valid: self._set_widget_invalid(self.amount_entry)
            else: self._set_widget_valid(self.amount_entry)
            if not check_only and not valid and amount_str: self.amount_entry.focus_set()
            return None

    def _validate_entry(self, entry_widget):
        if not entry_widget.get().strip(): self._set_widget_invalid(entry_widget); return False
        else: self._set_widget_valid(entry_widget); return True

    def _validate_combobox(self, event=None):
         widget = event.widget if event else None
         if isinstance(widget, ttk.Combobox):
             if not widget.get(): self._set_widget_invalid(widget); return False
             else: self._set_widget_valid(widget); return True
         return False # Not a combobox event

    def _set_widget_invalid(self, widget):
        try: widget.state(['invalid'])
        except tk.TclError: logging.warning(f"Widget {widget} doesn't support 'invalid' state.")

    def _set_widget_valid(self, widget):
        try: widget.state(['!invalid'])
        except tk.TclError: pass

    def get_selected_transaction_id(self, treeview):
        selection = treeview.focus()
        if selection:
            item_data = treeview.item(selection)
            if 'nodata' in item_data.get('tags', []): return None
            if item_data and 'values' in item_data and item_data['values']:
                try: return int(item_data['values'][0])
                except (ValueError, TypeError, IndexError): logging.error(f"Invalid ID in treeview: {item_data['values']}")
        return None

    def edit_selected_transaction(self, event_or_treeview):
        treeview = event_or_treeview.widget if isinstance(event_or_treeview, tk.Event) else event_or_treeview
        selected_id = self.get_selected_transaction_id(treeview)
        if not selected_id: messagebox.showinfo("Edit Transaction", "Select transaction.", parent=self.root); return
        logging.info(f"Edit requested for transaction ID: {selected_id}")
        transaction_details = self.db_manager.get_transaction_details(selected_id)
        if transaction_details: self.show_edit_window(selected_id, transaction_details)
        else: messagebox.showerror("Error", f"Could not retrieve data for ID {selected_id}.", parent=self.root)

    def show_edit_window(self, transaction_id, data):
        try:
            t_id, comp_id, comp_name, bank_name_db, date_obj, check_no, \
            vendor_customer_db, ref, bill_no_db, invoice_no_db, \
            amount_val, status_db, memo_db_value, notes_db_value, \
            type_db, payment_method_db, created_at_ts, created_by_user, \
            updated_at_ts, updated_by_user = data
        except (ValueError, TypeError) as e:
            logging.error(f"Error unpacking edit data ({len(data)} elements expected 20): {data} - {e}")
            messagebox.showerror("Error", "Load error: Could not unpack/load transaction data for editing.")
            return

        edit_window = tk.Toplevel(self.root)
        edit_window.title(f"Edit {type_db} Transaction ID: {t_id}")
        # ... (rest of window setup) ...
        edit_window.transient(self.root); edit_window.grab_set(); edit_window.resizable(True, True)
        edit_window.configure(bg=COLOR_PRIMARY_BG); edit_window.minsize(550, 650)

        main_edit_frame = ttk.Frame(edit_window, padding="15")
        main_edit_frame.pack(expand=True, fill="both")
        main_edit_frame.rowconfigure(1, weight=0); main_edit_frame.rowconfigure(2, weight=1)
        main_edit_frame.columnconfigure(0, weight=1)

        user_info_frame = ttk.Frame(main_edit_frame, style='Card.TFrame', padding=5)
        user_info_frame.grid(row=0, column=0, sticky='new', pady=(0, 10))
        user_info_frame.columnconfigure(1, weight=1); user_info_frame.columnconfigure(3, weight=1)
        created_at_str = created_at_ts.strftime('%Y-%m-%d %H:%M') if created_at_ts else 'N/A'
        updated_at_str = updated_at_ts.strftime('%Y-%m-%d %H:%M') if updated_at_ts else 'N/A'
        created_by_str = created_by_user if created_by_user else 'N/A'
        updated_by_str = updated_by_user if updated_by_user else 'N/A'
        ttk.Label(user_info_frame, text="Created:", style='Card.TLabel').grid(row=0, column=0, sticky='w', padx=5, pady=2)
        ttk.Label(user_info_frame, text=f"{created_at_str} by {created_by_str}", style='Card.TLabel').grid(row=0, column=1, sticky='w', padx=5, pady=2)
        ttk.Label(user_info_frame, text="Updated:", style='Card.TLabel').grid(row=0, column=2, sticky='w', padx=5, pady=2)
        ttk.Label(user_info_frame, text=f"{updated_at_str} by {updated_by_str}", style='Card.TLabel').grid(row=0, column=3, sticky='w', padx=5, pady=2)

        form_frame = ttk.Frame(main_edit_frame, style='Card.TFrame', padding=(15, 15, 15, 5))
        form_frame.grid(row=1, column=0, sticky='nsew', pady=(0, 15))
        form_frame.columnconfigure(1, weight=1)

        pad_y_form = 6; row_num = 0; current_custom_memo = None

        ttk.Label(form_frame, text="Transaction Type:", style='Card.TLabel').grid(row=row_num, column=0, sticky=tk.W, padx=5, pady=pad_y_form)
        ttk.Label(form_frame, text=type_db, style='Card.TLabel', font=default_font_bold).grid(row=row_num, column=1, sticky=tk.W, padx=10, pady=pad_y_form)
        row_num += 1

        edit_payment_method_label = ttk.Label(form_frame, text="Payment Method:", style='Card.TLabel')
        edit_payment_method_label.grid(row=row_num, column=0, sticky=tk.W, padx=5, pady=pad_y_form)
        edit_payment_method_var = tk.StringVar()
        if type_db == TYPE_TRANSFER: editable_payment_methods_edit = TRANSFER_PAYMENT_METHODS
        else: editable_payment_methods_edit = [m for m in PAYMENT_METHODS if m != METHOD_TRANSFER]
        edit_payment_method_combo = ttk.Combobox(form_frame, textvariable=edit_payment_method_var, values=editable_payment_methods_edit, state="readonly", width=37, font=text_font)
        edit_payment_method_combo.grid(row=row_num, column=1, sticky="ew", padx=10, pady=pad_y_form)
        if payment_method_db in editable_payment_methods_edit: edit_payment_method_var.set(payment_method_db)
        elif editable_payment_methods_edit: edit_payment_method_var.set(editable_payment_methods_edit[0])
        else: edit_payment_method_var.set("")
        row_num += 1

        ttk.Label(form_frame, text="Company:", style='Card.TLabel').grid(row=row_num, column=0, sticky=tk.W, padx=5, pady=pad_y_form)
        edit_company_var = tk.StringVar(value=comp_name if comp_name else "")
        edit_company_id_map = {}
        edit_company_combo = ttk.Combobox(form_frame, textvariable=edit_company_var, state="readonly", width=37, font=text_font)
        edit_company_combo.grid(row=row_num, column=1, sticky="ew", padx=10, pady=pad_y_form)
        edit_companies = self.db_manager.get_companies()
        edit_company_names = [name for id, name in edit_companies] if edit_companies else []
        edit_company_id_map = {name: id for id, name in edit_companies} if edit_companies else {}
        edit_company_combo['values'] = edit_company_names
        if comp_name in edit_company_names: edit_company_var.set(comp_name)
        elif edit_company_names: edit_company_var.set(edit_company_names[0]);
        else: edit_company_var.set(""); edit_company_combo.configure(state='disabled')
        row_num += 1
        bank_label_text = "Bank Name:"
        if type_db == TYPE_TRANSFER:
            if vendor_customer_db and vendor_customer_db.startswith("Transfer to"): bank_label_text = "From Bank:"
            elif vendor_customer_db and vendor_customer_db.startswith("Transfer from"): bank_label_text = "To Bank:"
        ttk.Label(form_frame, text=bank_label_text, style='Card.TLabel').grid(row=row_num, column=0, sticky=tk.W, padx=5, pady=pad_y_form)
        edit_bank_name_var = tk.StringVar(value=bank_name_db if bank_name_db else "")
        edit_bank_name_combo = ttk.Combobox(form_frame, textvariable=edit_bank_name_var, width=37, font=text_font, state='readonly')
        edit_bank_name_combo.grid(row=row_num, column=1, sticky="ew", padx=10, pady=pad_y_form)
        edit_banks_data = self.db_manager.get_banks()
        edit_bank_names = [name for b_id, name in edit_banks_data] if edit_banks_data else []
        edit_bank_name_combo['values'] = edit_bank_names
        if bank_name_db in edit_bank_names: edit_bank_name_var.set(bank_name_db)
        elif edit_bank_names: edit_bank_name_var.set(edit_bank_names[0]);
        else: edit_bank_name_var.set(""); edit_bank_name_combo.configure(state='disabled')
        row_num += 1
        ttk.Label(form_frame, text="Date:", style='Card.TLabel').grid(row=row_num, column=0, sticky=tk.W, padx=5, pady=pad_y_form)
        edit_date_entry = DateEntry(form_frame, width=20, font=text_font, date_pattern='yyyy-mm-dd', background=COLOR_ENTRY_BG, foreground=COLOR_ENTRY_FG, borderwidth=1, bordercolor=COLOR_BORDER, maxdate=datetime.now().date(), relief='solid', selectbackground=COLOR_ACCENT, headersbackground=COLOR_HEADER_BG, headersforeground=COLOR_HEADER_FG, weekendbackground=COLOR_ENTRY_BG, normalbackground=COLOR_ENTRY_BG, othermonthbackground=COLOR_SECONDARY_BG)
        edit_date_entry.grid(row=row_num, column=1, sticky="ew", padx=10, pady=pad_y_form)
        if date_obj: edit_date_entry.set_date(date_obj)
        else: edit_date_entry.delete(0, tk.END)
        row_num += 1
        edit_check_no_label = ttk.Label(form_frame, text="Check No:", style='Card.TLabel')
        edit_check_no_label.grid(row=row_num, column=0, sticky=tk.W, padx=5, pady=pad_y_form)
        edit_check_no_var = tk.StringVar(value=check_no if check_no else "")
        edit_check_no_entry = ttk.Entry(form_frame, textvariable=edit_check_no_var, width=40, font=text_font)
        edit_check_no_entry.grid(row=row_num, column=1, sticky="ew", padx=10, pady=pad_y_form)
        edit_check_no_widgets = (edit_check_no_label, edit_check_no_entry)
        row_num += 1
        edit_vendor_customer_label = ttk.Label(form_frame, text="Vendor/Customer:", style='Card.TLabel')
        edit_vendor_customer_label.grid(row=row_num, column=0, sticky=tk.W, padx=5, pady=pad_y_form)
        edit_vendor_customer_var = tk.StringVar(value=vendor_customer_db if vendor_customer_db else "")
        edit_vendor_customer_combo = ttk.Combobox(form_frame, textvariable=edit_vendor_customer_var, width=37, font=text_font, state='readonly')
        edit_vendor_customer_combo.grid(row=row_num, column=1, sticky="ew", padx=10, pady=pad_y_form)
        edit_vendor_customer_widgets = (edit_vendor_customer_label, edit_vendor_customer_combo)
        row_num += 1
        if type_db != TYPE_TRANSFER:
            vendor_customer_label_text = "Customer Name:" if type_db == TYPE_CREDIT else "Vendor Name:"
            edit_vendor_customer_label.configure(text=vendor_customer_label_text)
            payee_type_needed_edit = 'Customer' if type_db == TYPE_CREDIT else 'Vendor'
            edit_payees_data = self.db_manager.get_payees(payee_type=payee_type_needed_edit)
            edit_payee_names = [name for p_id, name, p_type in edit_payees_data] if edit_payees_data else []
            edit_vendor_customer_combo['values'] = edit_payee_names
            if vendor_customer_db in edit_payee_names: edit_vendor_customer_var.set(vendor_customer_db)
            elif edit_payee_names: edit_vendor_customer_var.set(edit_payee_names[0])
            else: edit_vendor_customer_var.set(""); edit_vendor_customer_combo.configure(state='disabled')
        else:
            for w in edit_vendor_customer_widgets: w.grid_remove()
        ttk.Label(form_frame, text="Reference:", style='Card.TLabel').grid(row=row_num, column=0, sticky=tk.W, padx=5, pady=pad_y_form)
        edit_ref_var = tk.StringVar(value=ref if ref is not None else "")
        edit_ref_entry = ttk.Entry(form_frame, textvariable=edit_ref_var, width=40, font=text_font)
        edit_ref_entry.grid(row=row_num, column=1, sticky="ew", padx=10, pady=pad_y_form)
        row_num += 1
        edit_bill_no_label = ttk.Label(form_frame, text="Bill No:", style='Card.TLabel')
        edit_bill_no_label.grid(row=row_num, column=0, sticky=tk.W, padx=5, pady=pad_y_form)
        edit_bill_no_var = tk.StringVar(value=bill_no_db if bill_no_db else "")
        edit_bill_no_entry = ttk.Entry(form_frame, textvariable=edit_bill_no_var, width=40, font=text_font)
        edit_bill_no_entry.grid(row=row_num, column=1, sticky="ew", padx=10, pady=pad_y_form)
        edit_bill_no_widgets = (edit_bill_no_label, edit_bill_no_entry)
        row_num += 1
        edit_invoice_no_label = ttk.Label(form_frame, text="Invoice No:", style='Card.TLabel')
        edit_invoice_no_label.grid(row=row_num, column=0, sticky=tk.W, padx=5, pady=pad_y_form)
        edit_invoice_no_var = tk.StringVar(value=invoice_no_db if invoice_no_db else "")
        edit_invoice_no_entry = ttk.Entry(form_frame, textvariable=edit_invoice_no_var, width=40, font=text_font)
        edit_invoice_no_entry.grid(row=row_num, column=1, sticky="ew", padx=10, pady=pad_y_form)
        edit_invoice_no_widgets = (edit_invoice_no_label, edit_invoice_no_entry)
        row_num += 1
        if type_db == TYPE_DEBIT:
            for w in edit_invoice_no_widgets: w.grid_remove()
        elif type_db == TYPE_CREDIT:
            for w in edit_bill_no_widgets: w.grid_remove()
        elif type_db == TYPE_TRANSFER:
            for w in edit_bill_no_widgets: w.grid_remove()
            for w in edit_invoice_no_widgets: w.grid_remove()
        ttk.Label(form_frame, text="Memo:", style='Card.TLabel').grid(row=row_num, column=0, sticky=tk.W, padx=5, pady=pad_y_form)
        edit_memo_var = tk.StringVar()
        memos_data_edit = self.db_manager.get_memos(); memo_names_edit = sorted([name for m_id, name in memos_data_edit]) if memos_data_edit else []
        dynamic_memo_options = memo_names_edit[:]; memo_state_edit = "readonly"
        if MEMO_OTHER:
            if MEMO_OTHER not in dynamic_memo_options: dynamic_memo_options.append(MEMO_OTHER)
            memo_state_edit = "normal"
        edit_memo_combo = ttk.Combobox(form_frame, textvariable=edit_memo_var, values=dynamic_memo_options, state=memo_state_edit, width=37, font=text_font)
        edit_memo_combo.grid(row=row_num, column=1, sticky="ew", padx=10, pady=pad_y_form)
        row_num += 1; current_custom_memo = None
        if memo_db_value in memo_names_edit: edit_memo_var.set(memo_db_value)
        elif MEMO_OTHER and memo_db_value is not None and memo_db_value.strip() and memo_db_value not in memo_names_edit:
            edit_memo_var.set(MEMO_OTHER); current_custom_memo = memo_db_value
        else:
            if DEFAULT_MEMO and DEFAULT_MEMO in dynamic_memo_options: edit_memo_var.set(DEFAULT_MEMO)
            elif dynamic_memo_options:
                first_option = dynamic_memo_options[0]
                if first_option == MEMO_OTHER and len(dynamic_memo_options) > 1: edit_memo_var.set(dynamic_memo_options[1])
                else: edit_memo_var.set(first_option)
            else: edit_memo_var.set("")
        ttk.Label(form_frame, text="Amount:", style='Card.TLabel').grid(row=row_num, column=0, sticky=tk.W, padx=5, pady=pad_y_form)
        edit_amount_var = tk.StringVar(value=f"{amount_val:.2f}" if amount_val is not None else "")
        edit_amount_entry = ttk.Entry(form_frame, textvariable=edit_amount_var, width=40, font=text_font)
        edit_amount_entry.grid(row=row_num, column=1, sticky="ew", padx=10, pady=pad_y_form)
        row_num += 1


        # --- Status Dropdown (Edit Window) - MODIFIED ---
        ttk.Label(form_frame, text="Status:", style='Card.TLabel').grid(row=row_num, column=0, sticky=tk.W, padx=5, pady=pad_y_form)
        edit_status_var = tk.StringVar()
        status_options_edit_win = []

        if type_db == TYPE_CREDIT:
            status_options_edit_win = CREDIT_STATUS_OPTIONS # Includes Void
        elif type_db == TYPE_DEBIT:
            current_payment_method_in_edit = edit_payment_method_var.get() # Use current PM in edit form
            if current_payment_method_in_edit == METHOD_CHECK:
                status_options_edit_win = [STATUS_PAID, STATUS_VOID, STATUS_PENDING, STATUS_CLEARED]
            else: # For other debit methods
                status_options_edit_win = [STATUS_PAID, STATUS_VOID]
        elif type_db == TYPE_TRANSFER:
            status_options_edit_win = list(set([status_db, STATUS_VOID, STATUS_CLEARED]))


        edit_status_combo = ttk.Combobox(form_frame, textvariable=edit_status_var, values=sorted(list(set(status_options_edit_win))), state="readonly", width=37, font=text_font)
        edit_status_combo.grid(row=row_num, column=1, sticky="ew", padx=10, pady=pad_y_form)

        if status_db in status_options_edit_win:
            edit_status_var.set(status_db)
        elif status_options_edit_win:
            edit_status_var.set(status_options_edit_win[0])
            logging.warning(f"Edit window: DB Status '{status_db}' not in dynamic options for type '{type_db}' and method '{edit_payment_method_var.get()}', defaulting to '{status_options_edit_win[0]}'.")
        else:
            edit_status_var.set("")
        row_num += 1


        def update_edit_fields_on_pm_change(event=None):
            # 1. Update Check No field state
            is_check_enabled_edit = (type_db == TYPE_DEBIT or type_db == TYPE_TRANSFER) and \
                                    edit_payment_method_var.get() == METHOD_CHECK
            new_check_state_edit = 'normal' if is_check_enabled_edit else 'disabled'
            label_color_edit = COLOR_TEXT if is_check_enabled_edit else COLOR_TEXT_SECONDARY
            if hasattr(edit_check_no_entry, 'configure'):
                 edit_check_no_entry.configure(state=new_check_state_edit)
            if hasattr(edit_check_no_label, 'configure'):
                 edit_check_no_label.configure(foreground=label_color_edit)
            if not is_check_enabled_edit:
                 edit_check_no_var.set("")

            # 2. Update Status dropdown for Debit transactions
            if type_db == TYPE_DEBIT:
                current_pm_edit = edit_payment_method_var.get()
                debit_status_options_edit_pm_change = []
                default_debit_status_edit_pm_change = ""

                # <<< MODIFIED DEBIT STATUS LOGIC within PM change handler >>>
                if current_pm_edit == METHOD_CHECK:
                    debit_status_options_edit_pm_change = [STATUS_PAID, STATUS_VOID, STATUS_PENDING, STATUS_CLEARED]
                    default_debit_status_edit_pm_change = STATUS_PENDING # Or Paid
                else: # Other debit methods
                    debit_status_options_edit_pm_change = [STATUS_PAID, STATUS_VOID]
                    default_debit_status_edit_pm_change = STATUS_PAID

                # Preserve original status if it's still valid or was Paid with Check
                # This is important if user toggles payment method
                # original_status_for_debit_in_pm_change = status_db # The status when the window opened
                # if original_status_for_debit_in_pm_change not in debit_status_options_edit_pm_change:
                    # If the original status is no longer directly an option (e.g. was "Paid", PM changed to "Check")
                    # we might want to default to "Pending" for Check, or keep "Paid" if it makes sense
                    # For simplicity, we'll just default to the new list's default.
                    # If `status_db` (original status) should be an option even if PM changes, add it:
                    #   debit_status_options_edit_pm_change.append(status_db)
                    #   debit_status_options_edit_pm_change = sorted(list(set(debit_status_options_edit_pm_change)))
                    # pass

                edit_status_combo.configure(values=sorted(list(set(debit_status_options_edit_pm_change))))
                current_selected_status_in_pm_change = edit_status_var.get()

                if current_selected_status_in_pm_change not in debit_status_options_edit_pm_change or not current_selected_status_in_pm_change:
                    # If current status in dropdown is no longer valid for the new PM, reset it
                    # Or if the original status (status_db) is still valid, try to set it
                    if status_db in debit_status_options_edit_pm_change:
                         edit_status_var.set(status_db)
                    else:
                         edit_status_var.set(default_debit_status_edit_pm_change)
                logging.debug(f"Edit window: Debit status options updated for PM '{current_pm_edit}': {debit_status_options_edit_pm_change}")


        edit_payment_method_combo.bind("<<ComboboxSelected>>", update_edit_fields_on_pm_change)
        update_edit_fields_on_pm_change() # Initial call

        if type_db == TYPE_CREDIT:
            for w in edit_check_no_widgets: w.grid_remove()

        # ... (Notes, Save/Cancel buttons, window geometry - no changes here) ...
        notes_frame_edit = ttk.Frame(main_edit_frame, style='Card.TFrame', padding=5)
        notes_frame_edit.grid(row=2, column=0, sticky='nsew', pady=(0, 10))
        notes_frame_edit.rowconfigure(1, weight=1); notes_frame_edit.columnconfigure(0, weight=1)
        ttk.Label(notes_frame_edit, text="Notes:", style='Card.TLabel').grid(row=0, column=0, columnspan=2, sticky=tk.W, pady=(0, 3))
        edit_notes_text = tk.Text(notes_frame_edit, height=6, width=50, wrap=tk.WORD, relief='flat', font=text_font, bg=COLOR_ENTRY_BG, fg=COLOR_ENTRY_FG, borderwidth=0, highlightthickness=0, selectbackground=COLOR_ACCENT, selectforeground=COLOR_BUTTON_PRIMARY_FG, insertbackground=COLOR_TEXT)
        edit_notes_text.grid(row=1, column=0, sticky='nsew', padx=(1,0), pady=1)
        if notes_db_value: edit_notes_text.insert("1.0", notes_db_value)
        edit_notes_scrollbar = ttk.Scrollbar(notes_frame_edit, orient=tk.VERTICAL, command=edit_notes_text.yview, style="Vertical.TScrollbar")
        edit_notes_scrollbar.grid(row=1, column=1, sticky='ns', pady=1, padx=(0,1))
        edit_notes_text.configure(yscrollcommand=edit_notes_scrollbar.set)
        button_frame_edit = ttk.Frame(main_edit_frame)
        button_frame_edit.grid(row=3, column=0, sticky=tk.E, pady=(10, 0))

        def save_changes():
            logging.debug(f"Save Changes called for ID {t_id}")
            errors = []; new_data = {}
            new_data['transaction_type'] = type_db
            new_payment_method = edit_payment_method_var.get()
            current_pm_options_edit_save = []
            if type_db == TYPE_TRANSFER: current_pm_options_edit_save = TRANSFER_PAYMENT_METHODS
            else: current_pm_options_edit_save = [m for m in PAYMENT_METHODS if m != METHOD_TRANSFER]
            if not new_payment_method or new_payment_method not in current_pm_options_edit_save:
                errors.append(f"Payment Method required (must be one of: {', '.join(current_pm_options_edit_save)}).")
            else: new_data['payment_method'] = new_payment_method
            new_comp_name = edit_company_var.get(); new_comp_id = edit_company_id_map.get(new_comp_name)
            if not new_comp_name or new_comp_id is None: errors.append("Company required.")
            else: new_data['company_id'] = new_comp_id
            new_bank_name = edit_bank_name_var.get()
            if not new_bank_name: errors.append("Bank Name required.")
            elif new_bank_name not in edit_bank_names: errors.append(f"Invalid Bank Name: '{new_bank_name}'.")
            else: new_data['bank_name'] = new_bank_name
            try: new_data['date'] = edit_date_entry.get_date()
            except Exception: errors.append("Invalid date.")
            new_check_no_save = edit_check_no_var.get().strip()
            is_check_no_required_edit_save = (type_db == TYPE_DEBIT or type_db == TYPE_TRANSFER) and new_payment_method == METHOD_CHECK
            if is_check_no_required_edit_save and not new_check_no_save: errors.append(f"Check No required for {type_db} with Check method.")
            elif new_check_no_save: new_data['check_no'] = new_check_no_save
            else: new_data['check_no'] = None
            if type_db == TYPE_CREDIT: new_data['check_no'] = None
            if type_db == TYPE_TRANSFER:
                new_data['vendor_or_customer_name'] = vendor_customer_db; new_data['bill_no'] = bill_no_db; new_data['invoice_no'] = invoice_no_db
            else:
                new_vendor_customer = edit_vendor_customer_var.get()
                vc_label = "Customer Name" if type_db == TYPE_CREDIT else "Vendor Name"
                if not new_vendor_customer: errors.append(f"{vc_label} selection required.")
                else: new_data['vendor_or_customer_name'] = new_vendor_customer
                new_bill_no_ui = edit_bill_no_var.get().strip(); new_invoice_no_ui = edit_invoice_no_var.get().strip()
                if type_db == TYPE_DEBIT: new_data['bill_no'] = new_bill_no_ui if new_bill_no_ui else None; new_data['invoice_no'] = None
                elif type_db == TYPE_CREDIT: new_data['invoice_no'] = new_invoice_no_ui if new_invoice_no_ui else None; new_data['bill_no'] = None
            new_data['reference'] = edit_ref_var.get().strip() or None
            selected_category_edit_save = edit_memo_var.get(); final_memo_value_edit_save = None
            if not selected_category_edit_save: errors.append("Memo selection required.")
            elif MEMO_OTHER and selected_category_edit_save == MEMO_OTHER:
                if current_custom_memo: final_memo_value_edit_save = current_custom_memo
                else:
                     custom_memo_edit_save = simpledialog.askstring("Custom Memo Required", "Enter custom memo:", parent=edit_window)
                     if custom_memo_edit_save is None: errors.append("Custom memo required or select predefined."); final_memo_value_edit_save = None
                     elif not custom_memo_edit_save.strip(): errors.append("Custom memo cannot be empty."); final_memo_value_edit_save = None
                     else: final_memo_value_edit_save = custom_memo_edit_save.strip()
            else: final_memo_value_edit_save = selected_category_edit_save
            new_data['memo'] = final_memo_value_edit_save
            try:
                cleaned_save = edit_amount_var.get().replace('$', '').replace(',', '').strip()
                if not cleaned_save: errors.append("Amount is required."); new_amount_save = None
                else:
                    new_amount_save = float(cleaned_save)
                    if new_amount_save <= 0: errors.append("Amount must be positive."); new_amount_save = None
                    else: new_data['amount'] = new_amount_save
            except ValueError: errors.append("Invalid amount format."); new_amount_save = None

            new_status_save = edit_status_var.get()
            valid_statuses_for_save_edit = []
            if type_db == TYPE_CREDIT: valid_statuses_for_save_edit = CREDIT_STATUS_OPTIONS
            elif type_db == TYPE_DEBIT:
                if new_payment_method == METHOD_CHECK:
                    valid_statuses_for_save_edit = [STATUS_PAID, STATUS_VOID, STATUS_PENDING, STATUS_CLEARED]
                else: valid_statuses_for_save_edit = [STATUS_PAID, STATUS_VOID]
            elif type_db == TYPE_TRANSFER: valid_statuses_for_save_edit = list(set([status_db, STATUS_VOID, STATUS_CLEARED]))
            if not new_status_save or new_status_save not in valid_statuses_for_save_edit:
                errors.append(f"Status required (one of: {', '.join(valid_statuses_for_save_edit)} for {type_db} with method {new_payment_method}).")
            else: new_data['status'] = new_status_save
            new_notes_save = edit_notes_text.get("1.0", tk.END).strip()
            new_data['notes'] = new_notes_save if new_notes_save else None
            if errors: messagebox.showerror("Input Error", "Correct errors:\n\n- " + "\n- ".join(errors), parent=edit_window); return
            logging.info(f"Attempting update for ID {t_id} by User ID {self.current_user_id} with data: {new_data}")
            try:
                if self.db_manager.update_transaction(transaction_id=t_id, updated_by_user_id=self.current_user_id, **new_data):
                    messagebox.showinfo("Success", f"Transaction ID {t_id} updated.", parent=edit_window); logging.info(f"ID {t_id} updated.")
                    edit_window.destroy(); self.refresh_all_views()
            except Exception as e: logging.error(f"Error update_transaction: {e}", exc_info=True); messagebox.showerror("Error", f"Error saving:\n{e}", parent=edit_window)
        save_button = ttk.Button(button_frame_edit, text="Save Changes", command=save_changes, style='Accent.TButton', width=15); save_button.pack(side=tk.RIGHT, padx=(10, 0))
        cancel_button = ttk.Button(button_frame_edit, text="Cancel", command=edit_window.destroy, width=10); cancel_button.pack(side=tk.RIGHT)
        edit_window.update_idletasks(); root_x=self.root.winfo_rootx(); root_y=self.root.winfo_rooty(); root_w=self.root.winfo_width(); root_h=self.root.winfo_height(); win_w=edit_window.winfo_reqwidth(); win_h=edit_window.winfo_reqheight(); x=root_x+(root_w//2)-(win_w//2); y=root_y+(root_h//2)-(win_h//2); min_w_edit=550; min_h_edit=650; final_w_edit = max(win_w, min_w_edit); final_h_edit = max(win_h, min_h_edit); edit_window.geometry(f"{final_w_edit}x{final_h_edit}+{x}+{y}"); edit_window.minsize(min_w_edit, min_h_edit); edit_window.protocol("WM_DELETE_WINDOW", edit_window.destroy); edit_window.wait_window()


        # --- Bulk Status Change Action ---
    # --- In BankSheetApp class ---

    def bulk_change_status(self):
        """Changes the status for all checked transactions in the report tree."""
        logging.debug("--- Starting Bulk Status Change ---")
        if self.current_user_role != 'admin': # Keep admin check
            messagebox.showwarning("Permission Denied", "Only admin users can perform bulk status changes.", parent=self.root)
            logging.warning("Non-admin attempted bulk status change.")
            return

        target_status = self.bulk_status_var.get()
        if not target_status or target_status not in ALL_STATUS_OPTIONS:
            messagebox.showerror("Input Error", "Please select a valid target status.", parent=self.root)
            logging.warning(f"Bulk status change failed: Invalid target status '{target_status}'.")
            return

        try:
            if not isinstance(self.report_tree, CheckboxTreeview):
                messagebox.showerror("Error", "Bulk selection feature not implemented.\n(Requires CheckboxTreeview integration).", parent=self.root)
                logging.error("Bulk status change attempted but CheckboxTreeview is not in use.")
                return

            checked_iids = self.report_tree.get_checked()
            logging.debug(f"Raw checked iids from treeview: {checked_iids}")

            if not checked_iids:
                messagebox.showinfo("No Selection", "No transactions selected (checked).", parent=self.root)
                logging.debug("Bulk status change: No items checked.")
                return

            transaction_ids_to_update = []
            selected_details_for_bulk = {} # Store {db_id: (type, payment_method, current_status)}
            skipped_nodata = 0
            fetch_errors = False

            for iid in checked_iids:
                try:
                    item_data = self.report_tree.item(iid)
                    if 'nodata' in item_data.get('tags', []):
                        skipped_nodata += 1; continue

                    db_id = int(item_data['values'][0])
                    # Fetch details needed for validation (type, payment_method, current_status)
                    # Treeview columns: ID, Comp, Bank, Date, Check, UI_VENDOR, UI_CUSTOMER, Ref,Bill,Inv,Memo,Amt,Status,Type,Method,Creator
                    # Indices:          0,   1,    2,    3,    4,      5,         6,           7,  8,   9,  10,  11,  12,    13,  14,    15
                    try:
                        tree_values = item_data['values']
                        trans_type_from_tree = tree_values[13] # COL_TRANSACTION_TYPE index
                        payment_method_from_tree = tree_values[14] # COL_PAYMENT_METHOD index
                        current_status_from_tree = tree_values[12] # COL_STATUS index
                        selected_details_for_bulk[db_id] = (trans_type_from_tree, payment_method_from_tree, current_status_from_tree)
                        transaction_ids_to_update.append(db_id)
                    except (IndexError, TypeError) as e_tree_val:
                        logging.error(f"Could not get type/method/status from tree for ID {db_id} for bulk change: {e_tree_val}. Item values: {item_data.get('values')}")
                        fetch_errors = True # Treat as a fetch error if we can't get required info
                        # Optionally, you could fall back to a full DB fetch here if needed
                        # full_db_details = self.db_manager.get_transaction_details(db_id)
                        # if full_db_details:
                        #     selected_details_for_bulk[db_id] = (full_db_details[14], full_db_details[15], full_db_details[11]) # type, method, status
                        #     transaction_ids_to_update.append(db_id)
                        # else:
                        #    logging.error(f"DB fetch also failed for ID {db_id} during bulk change prep.")
                        #    fetch_errors = True
                except (IndexError, ValueError, TypeError, KeyError) as e:
                    logging.error(f"Error extracting DB ID for iid '{iid}': {e} - Item Data: {item_data}", exc_info=True)
                    messagebox.showerror("Internal Error", f"Could not process selected item (iid: {iid}).\nCheck logs.", parent=self.root)
                    return

            if fetch_errors:
                 messagebox.showerror("Error", "Could not retrieve necessary details for all selected transactions to validate status change. Aborting.", parent=self.root)
                 return

            if skipped_nodata > 0: logging.warning(f"Skipped {skipped_nodata} 'nodata' items during bulk update.")

            if not transaction_ids_to_update:
                 messagebox.showinfo("No Selection", "No valid transactions selected (after processing checks).", parent=self.root)
                 logging.debug("Bulk status change: No valid transaction IDs found after mapping.")
                 return

            # --- Validation before confirmation ---
            validation_passed = True
            invalid_updates = []

            for tid in transaction_ids_to_update:
                details = selected_details_for_bulk.get(tid)
                if not details:
                    logging.error(f"Missing details for transaction ID {tid} during bulk validation. Should not happen.")
                    validation_passed = False; invalid_updates.append(f"ID {tid}: Internal error - missing details."); continue

                trans_type, payment_method, current_status_val = details
                allowed_statuses_for_this_transaction = []

                if trans_type == TYPE_CREDIT:
                    allowed_statuses_for_this_transaction = CREDIT_STATUS_OPTIONS # Includes Void
                elif trans_type == TYPE_DEBIT:
                    if payment_method == METHOD_CHECK:
                        # For checks, allow changing to any of these
                        allowed_statuses_for_this_transaction = [STATUS_PAID, STATUS_VOID, STATUS_PENDING, STATUS_CLEARED]
                    else: # Other debit methods
                        allowed_statuses_for_this_transaction = [STATUS_PAID, STATUS_VOID]
                elif trans_type == TYPE_TRANSFER:
                    # For transfer legs, usually only to Void or Clearance from its current state
                    allowed_statuses_for_this_transaction = list(set([current_status_val, STATUS_VOID, STATUS_CLEARED]))

                if not allowed_statuses_for_this_transaction: # Should not happen if logic above is complete
                     validation_passed = False
                     invalid_updates.append(f"ID {tid} ({trans_type}, {payment_method}): No valid target statuses defined.")
                     logging.warning(f"Bulk status change: No allowed statuses determined for ID {tid} ({trans_type}, {payment_method}).")
                     continue

                if target_status not in allowed_statuses_for_this_transaction:
                    validation_passed = False
                    invalid_updates.append(f"ID {tid} ({trans_type}, {payment_method}) -> Status '{target_status}' (Not allowed. Valid: {', '.join(allowed_statuses_for_this_transaction)})")

            if not validation_passed:
                error_msg_lines = [f"Cannot apply status '{target_status}' to all selected items due to type/method constraints."]
                error_msg_lines.append("\nInvalid changes requested:")
                for inv_upd in invalid_updates[:5]: # Show first 5 detailed errors
                    error_msg_lines.append(f"- {inv_upd}")
                if len(invalid_updates) > 5:
                    error_msg_lines.append(f"...and {len(invalid_updates) - 5} more.")
                final_error_msg = "\n".join(error_msg_lines)
                messagebox.showerror("Validation Error", final_error_msg, parent=self.root)
                logging.warning(f"Bulk status change validation failed. Target: '{target_status}'. Invalid updates: {invalid_updates}")
                return
            # --- End Validation ---

            logging.debug(f"Mapped Database Transaction IDs to update: {transaction_ids_to_update}")

            item_count = len(transaction_ids_to_update)
            if messagebox.askyesno("Confirm Bulk Change",
                                   f"Change status to '{target_status}' for {item_count} selected transaction(s)?",
                                   icon='warning', parent=self.root):

                logging.info(f"Admin '{self.current_username}' initiating bulk status change to '{target_status}' for IDs: {transaction_ids_to_update}")

                success = self.db_manager.bulk_update_transaction_status(
                    transaction_ids=transaction_ids_to_update,
                    new_status=target_status,
                    updated_by_user_id=self.current_user_id
                )

                if success:
                    messagebox.showinfo("Success", f"Status updated to '{target_status}' for {item_count} transaction(s).", parent=self.root)
                    logging.info(f"Bulk status update successful for {item_count} items.")
                    self.refresh_all_views()
                    try:
                        if isinstance(self.report_tree, CheckboxTreeview): self.report_tree.uncheck_all()
                    except Exception as uncheck_e: logging.warning(f"Could not uncheck items after bulk update: {uncheck_e}")
                else:
                    logging.error("Bulk status update failed (DBManager reported error).")
            else:
                logging.debug("Bulk status change cancelled by user.")

        except AttributeError as ae:
            messagebox.showerror("Error", f"Checkbox functionality error: {ae}.\nPlease ensure 'ttkwidgets' is installed correctly.", parent=self.root)
            logging.error(f"AttributeError during bulk status change (likely CheckboxTreeview issue): {ae}", exc_info=True)
        except Exception as e:
             messagebox.showerror("Error", f"An unexpected error occurred during bulk status change:\n{e}", parent=self.root)
             logging.error(f"Unexpected error during bulk status change: {e}", exc_info=True)

        logging.debug("--- Finished Bulk Status Change Attempt ---")  
        
    def add_mgmt_item(self):
        if self.current_user_role != 'admin':
            messagebox.showwarning("Permission Denied", "Only admin users can add items.", parent=self.tab_frames.get('management', self.root)) # Use .get
            return
        item_type = self.mgmt_add_type_var.get() # This will be "Company", "Bank", "Vendor", "Customer", or "Memo" (Singular)
        item_name = self.mgmt_new_name_entry.get().strip()

        if not item_name:
            messagebox.showerror("Input Error", "Item Name cannot be empty.", parent=self.tab_frames.get('management', self.root))
            self.mgmt_new_name_entry.focus_set()
            return

        new_id = None; success = False; db_call_info = ""
        try:
            if item_type == "Company": db_call_info = f"add_company('{item_name}')"; new_id = self.db_manager.add_company(item_name)
            elif item_type == "Bank": db_call_info = f"add_bank('{item_name}')"; new_id = self.db_manager.add_bank(item_name)
            elif item_type == "Vendor": db_call_info = f"add_payee('{item_name}', 'Vendor')"; new_id = self.db_manager.add_payee(item_name, 'Vendor')
            elif item_type == "Customer": db_call_info = f"add_payee('{item_name}', 'Customer')"; new_id = self.db_manager.add_payee(item_name, 'Customer')
            elif item_type == "Memo": # Use singular from dropdown
                db_call_info = f"add_memo('{item_name}')"; new_id = self.db_manager.add_memo(item_name)
            else:
                messagebox.showerror("Error", f"Invalid item type selected: {item_type}", parent=self.tab_frames.get('management', self.root))
                logging.error(f"add_mgmt_item called with unexpected item type: {item_type}")
                return

            success = new_id is not None

            if success:
                messagebox.showinfo("Success", f"{item_type} '{item_name}' added.", parent=self.tab_frames.get('management', self.root))
                logging.info(f"{item_type} added: ID={new_id}, Name='{item_name}' by User='{self.current_username}'")
                self.mgmt_new_name_entry.delete(0, tk.END)
                self.populate_management_list() # Refresh the tree view in the management tab

                # Refresh relevant dropdowns throughout the application
                if item_type == "Company":
                    self.populate_company_dropdown()
                    self.populate_filter_comboboxes()
                elif item_type == "Bank":
                    # --- MODIFIED HERE ---
                    self.populate_add_trans_bank_dropdowns() # Corrected method name
                    self.populate_filter_comboboxes()
                elif item_type in ["Vendor", "Customer"]:
                    self.populate_payee_dropdowns()
                elif item_type == "Memo":
                    self.populate_memo_dropdown()
                    self.populate_filter_comboboxes()

                self.mgmt_new_name_entry.focus_set()
            # else: DBManager shows error

        except Exception as e:
             logging.error(f"Error during add_mgmt_item ({db_call_info}): {e}", exc_info=True)
             messagebox.showerror("Error", f"An unexpected error occurred while adding {item_type}: {e}", parent=self.tab_frames.get('management', self.root))

    def get_selected_mgmt_item_id(self):
        selection = self.mgmt_list_tree.focus()
        if selection:
            item_data = self.mgmt_list_tree.item(selection)
            if 'nodata' not in item_data.get('tags', []) and item_data['values']:
                # ID is only present for non-Memo types
                current_view_type = self.mgmt_list_type_var.get()
                if current_view_type != "Memo":
                    try: return int(item_data['values'][0]) # ID is first column
                    except (ValueError, TypeError, IndexError): logging.error(f"Invalid ID in management treeview: {item_data['values']}")
        return None

    # <<< UPDATED Management Context Menu (Disable actions for Memo) >>>
    def show_mgmt_context_menu(self, event):
        iid = self.mgmt_list_tree.identify_row(event.y)
        if iid:
            item_data = self.mgmt_list_tree.item(iid)
            if 'nodata' not in item_data.get('tags', []):
                self.mgmt_list_tree.selection_set(iid); self.mgmt_list_tree.focus(iid)
                if self.current_user_role == 'admin':
                    current_view_type = self.mgmt_list_type_var.get()
                    can_delete_edit = current_view_type not in ["Memo"]
                    try:
                        self.mgmt_context_menu.entryconfigure("Delete Selected Item", state=tk.NORMAL if can_delete_edit else tk.DISABLED)
                        self.mgmt_context_menu.entryconfigure("Edit Selected Item", state=tk.NORMAL if can_delete_edit else tk.DISABLED)
                    except tk.TclError as e: logging.warning(f"Error configuring mgmt context menu state: {e}")
                    self.mgmt_context_menu.post(event.x_root, event.y_root)
                else: logging.debug("Non-admin right-clicked mgmt list.")

    # <<< UPDATED Delete Management Item (Prevents Memo) >>>
    def delete_selected_mgmt_item(self):
        if self.current_user_role != 'admin':
            messagebox.showwarning("Permission Denied", "Only admin users can delete.", parent=self.tab_frames.get('management', self.root)) # Use .get
            return

        # --- ADDED: Get the current view type ---
        item_type_view = self.mgmt_list_type_var.get() # e.g., "Companies", "Banks", "Vendors", "Customers", "Memos"
        # --- END ADDED ---

        selected_id = self.get_selected_mgmt_item_id()
        if not selected_id:
            # --- UPDATED Message to include Memo ---
            messagebox.showinfo("Delete Item", "Select an item (Company, Bank, Vendor, Customer, or Memo) from the list to delete.", parent=self.tab_frames.get('management', self.root))
            # --- END UPDATED Message ---
            return

        # --- ADDED: Get item name for confirmation ---
        try:
            focused_item_iid = self.mgmt_list_tree.focus()
            if not focused_item_iid:
                 messagebox.showerror("Error", "Could not identify selected item.", parent=self.tab_frames.get('management', self.root))
                 logging.error("Failed to get focused item iid for delete.")
                 return
            item_data = self.mgmt_list_tree.item(focused_item_iid)
            # Assuming 'name' is always the second column (index 1)
            item_name = item_data['values'][1]
        except (IndexError, KeyError, TypeError) as e:
            messagebox.showerror("Error", f"Could not get name for the selected item.\nDetails: {e}", parent=self.tab_frames.get('management', self.root))
            logging.error(f"Failed get name for ID {selected_id} during delete: {e}")
            return
        # --- END ADDED ---

        item_type_db = None
        # Use item_type_view (which we just defined)
        if item_type_view == "Companies": item_type_db = "Company"
        elif item_type_view == "Banks": item_type_db = "Bank"
        elif item_type_view == "Vendors": item_type_db = "Vendor"
        elif item_type_view == "Customers": item_type_db = "Customer"
        elif item_type_view == "Memos": item_type_db = "Memo"

        if not item_type_db:
            messagebox.showerror("Error", "Cannot determine item type for deletion.", parent=self.tab_frames.get('management', self.root))
            logging.error(f"Could not map view type '{item_type_view}' to db type for delete.")
            return

        # Update warning message for Memo deletion
        warning_msg = ""
        if item_type_db == "Memo":
            warning_msg = "\n\nWarning: This will clear the memo field for any transactions currently using it."

        # Use item_name in the confirmation
        if messagebox.askyesno("Confirm Delete", f"Delete {item_type_db} '{item_name}' (ID: {selected_id})?{warning_msg}", icon='warning', parent=self.tab_frames.get('management', self.root)):
            logging.warning(f"Admin '{self.current_username}' attempting delete {item_type_db} ID: {selected_id}, Name: '{item_name}'") # Log name too
            success = False
            db_call_info = ""
            try:
                if item_type_db == "Company": db_call_info = f"delete_company({selected_id})"; success = self.db_manager.delete_company(selected_id)
                elif item_type_db == "Bank": db_call_info = f"delete_bank({selected_id})"; success = self.db_manager.delete_bank(selected_id)
                elif item_type_db in ["Vendor", "Customer"]: db_call_info = f"delete_payee({selected_id})"; success = self.db_manager.delete_payee(selected_id)
                elif item_type_db == "Memo":
                     db_call_info = f"delete_memo({selected_id})"; success = self.db_manager.delete_memo(selected_id)

                if success:
                    messagebox.showinfo("Deleted", f"{item_type_db} '{item_name}' deleted.", parent=self.tab_frames.get('management', self.root))
                    logging.info(f"{item_type_db} ID {selected_id} ('{item_name}') deleted.")
                    self.populate_management_list()
                    # Refresh relevant dropdowns
                    if item_type_db == "Company": self.populate_company_dropdown(); self.populate_filter_comboboxes()
                    if item_type_db == "Bank": self.populate_bank_dropdown(); self.populate_filter_comboboxes()
                    if item_type_db in ["Vendor", "Customer"]: self.populate_payee_dropdowns()
                    if item_type_db == "Memo": self.populate_memo_dropdown(); self.populate_filter_comboboxes()
                # else: DB manager shows FK violation etc.
            except Exception as e:
                logging.error(f"Error during delete ({db_call_info}): {e}", exc_info=True)
                messagebox.showerror("Error", f"Unexpected error deleting {item_type_db}: {e}", parent=self.tab_frames.get('management', self.root))
    def edit_selected_mgmt_item(self):
        """Handles editing the name of the selected item (Company, Bank, Payee, Memo)."""
        if self.current_user_role != 'admin':
            messagebox.showwarning("Permission Denied", "Only admin users can edit items.", parent=self.tab_frames.get('management', self.root))
            logging.warning(f"Non-admin user '{self.current_username}' attempted to edit a management item.")
            return

        item_type_view = self.mgmt_list_type_var.get() # e.g., "Companies", "Banks", "Vendors", "Customers", "Memos"

        selected_id = self.get_selected_mgmt_item_id()
        if not selected_id:
            messagebox.showinfo("Edit Item", "Select an item (Company, Bank, Vendor, Customer, or Memo) from the list to edit its name.", parent=self.tab_frames.get('management', self.root))
            return

        # Get the current name from the selected Treeview item
        try:
            focused_item_iid = self.mgmt_list_tree.focus()
            if not focused_item_iid:
                 messagebox.showerror("Error", "Could not identify selected item.", parent=self.tab_frames.get('management', self.root))
                 logging.error("Failed to get focused item iid for edit.")
                 return
            item_data = self.mgmt_list_tree.item(focused_item_iid)
            # Assuming 'name' is always the second column (index 1) after 'id' (index 0) for all types
            current_name = item_data['values'][1]
        except (IndexError, KeyError, TypeError) as e:
            messagebox.showerror("Error", f"Could not get current name for the selected item.\nDetails: {e}", parent=self.tab_frames.get('management', self.root))
            logging.error(f"Failed get name for ID {selected_id} during edit: {e}")
            return

        # Determine the singular name for the prompt (e.g., "Memo" from "Memos")
        type_singular = item_type_view[:-1] if item_type_view.endswith('s') else item_type_view

        # Prompt user for the new name
        new_name = simpledialog.askstring(
            f"Edit {type_singular} Name",
            f"Enter the new name for '{current_name}' (ID: {selected_id}):",
            initialvalue=current_name,
            parent=self.tab_frames.get('management', self.root)
        )

        # --- Validation ---
        if new_name is None:
            logging.debug(f"Edit cancelled by user for {type_singular} ID {selected_id}.")
            return # User cancelled the dialog

        new_name = new_name.strip()

        if not new_name:
            messagebox.showerror("Input Error", "Name cannot be empty.", parent=self.tab_frames.get('management', self.root))
            return

        if new_name == current_name:
            messagebox.showinfo("No Change", "The name was not changed.", parent=self.tab_frames.get('management', self.root))
            return
        # --- End Validation ---


        # Determine the correct update function from the DatabaseManager
        update_func = None
        if item_type_view == "Companies":
            update_func = self.db_manager.update_company_name
        elif item_type_view == "Banks":
            update_func = self.db_manager.update_bank_name
        elif item_type_view in ["Vendors", "Customers"]:
            update_func = self.db_manager.update_payee_name
        elif item_type_view == "Memos": # Handle editing Memos
            update_func = self.db_manager.update_memo_name # Use the specific memo update method

        if update_func:
            logging.info(f"Admin '{self.current_username}' attempting to rename {type_singular} ID {selected_id} from '{current_name}' to '{new_name}'")
            try:
                # Call the appropriate update function
                if update_func(selected_id, new_name):
                    messagebox.showinfo("Success", f"{type_singular} name updated successfully.", parent=self.tab_frames.get('management', self.root))
                    logging.info(f"{type_singular} ID {selected_id} renamed to '{new_name}'.")

                    # Refresh the list view where the change was made
                    self.populate_management_list()

                    # Refresh relevant dropdowns throughout the application
                    if item_type_view == "Companies":
                        self.populate_company_dropdown()
                        self.populate_filter_comboboxes()
                    elif item_type_view == "Banks":
                        self.populate_bank_dropdown()
                        self.populate_filter_comboboxes()
                    elif item_type_view in ["Vendors", "Customers"]:
                        self.populate_payee_dropdowns() # Updates Add Transaction tab based on type
                    elif item_type_view == "Memos":
                        self.populate_memo_dropdown() # Updates Add Transaction tab
                        self.populate_filter_comboboxes() # Updates Report tab filter

                # else: If update_func returned False, the DatabaseManager should have shown an error (e.g., unique constraint)

            except Exception as e:
                # Catch unexpected errors during the database call
                logging.error(f"Unexpected error during {type_singular} name update (ID: {selected_id}): {e}", exc_info=True)
                messagebox.showerror("Error", f"An unexpected error occurred while updating the {type_singular} name:\n{e}", parent=self.tab_frames.get('management', self.root))
        else:
            # This case should ideally not happen if item_type_view is always valid
            logging.error(f"No update function defined for management item type: {item_type_view}")
            messagebox.showerror("Internal Error", f"Cannot edit item type '{item_type_view}'. Update logic is missing.", parent=self.tab_frames.get('management', self.root))

# --- End of edit_selected_mgmt_item function ---

    # --- User Management Handlers ---
    def populate_users_tree(self):
        logging.debug("Populating users list treeview...")
        for item in self.users_tree.get_children(): self.users_tree.delete(item)
        users = self.db_manager.get_users()
        if users:
             for user_id, username, role in users: self.users_tree.insert("", tk.END, values=(user_id, username, role))
             logging.debug(f"Displayed {len(users)} users.")
        else: self.users_tree.insert("", tk.END, values=("", "No users found.", ""), tags=('nodata',)); logging.debug("No users found.")

    def add_new_user(self):
        username = self.new_username_entry.get().strip(); password = self.new_password_entry.get()
        confirm_password = self.confirm_password_entry.get(); role = self.new_user_role_var.get()
        errors = [];
        if not username or len(username) < 3: errors.append("Username required (min 3 chars).")
        if not password or len(password) < 6: errors.append("Password required (min 6 chars).")
        if password != confirm_password: errors.append("Passwords do not match.")
        if role not in ['user', 'admin']: errors.append("Invalid role.")
        if errors: messagebox.showerror("Input Error", "Errors:\n- " + "\n- ".join(errors), parent=self.tab_frames['user_management']); return
        new_id = self.db_manager.add_user(username, password, role)
        if new_id:
             messagebox.showinfo("Success", f"User '{username}' ({role}) added.", parent=self.tab_frames['user_management']); logging.info(f"User added: ID={new_id} by Admin='{self.current_username}'")
             self.new_username_entry.delete(0, tk.END); self.new_password_entry.delete(0, tk.END); self.confirm_password_entry.delete(0, tk.END); self.new_user_role_var.set('user')
             self.populate_users_tree(); self.new_username_entry.focus_set()
        # else: DBManager shows unique error

    def get_selected_user_id(self):
        selection = self.users_tree.focus()
        if selection:
            item_data = self.users_tree.item(selection)
            if 'nodata' not in item_data.get('tags', []) and item_data['values']:
                try: return int(item_data['values'][0])
                except (ValueError, TypeError, IndexError): pass
        return None

    def show_user_context_menu(self, event):
        iid = self.users_tree.identify_row(event.y)
        if iid:
            item_data = self.users_tree.item(iid)
            if 'nodata' not in item_data.get('tags', []):
                self.users_tree.selection_set(iid); self.users_tree.focus(iid)
                selected_user_id = self.get_selected_user_id(); is_self = (selected_user_id == self.current_user_id)
                try:
                    self.user_context_menu.entryconfigure("Change Role To", state=tk.DISABLED if is_self else tk.NORMAL)
                    self.user_context_menu.entryconfigure("Delete User", state=tk.DISABLED if is_self else tk.NORMAL)
                    self.user_context_menu.entryconfigure("Reset Password", state=tk.DISABLED if is_self else tk.NORMAL)
                    self.user_context_menu.entryconfigure("Set Security Questions", state=tk.NORMAL) # Allow for self
                except tk.TclError: pass
                self.user_context_menu.post(event.x_root, event.y_root)

    def show_set_security_questions_dialog(self):
        selected_user_id = self.get_selected_user_id()
        if not selected_user_id: messagebox.showinfo("Set Security Questions", "Select a user.", parent=self.tab_frames['user_management']); return
        item_data = self.users_tree.item(self.users_tree.focus()); username = item_data['values'][1]
        q1, q2 = self.db_manager.get_user_security_questions(selected_user_id)
        SecurityQuestionsDialog(self.root, self.db_manager, selected_user_id, username, q1, q2)

    def change_selected_user_role(self, new_role):
        selected_user_id = self.get_selected_user_id()
        if not selected_user_id: messagebox.showinfo("Change Role", "Select a user.", parent=self.tab_frames['user_management']); return
        if selected_user_id == self.current_user_id: messagebox.showwarning("Change Role", "Cannot change own role.", parent=self.tab_frames['user_management']); return
        item_data = self.users_tree.item(self.users_tree.focus()); username = item_data['values'][1]; current_role = item_data['values'][2]
        if current_role == new_role: messagebox.showinfo("Change Role", f"User '{username}' already role '{new_role}'.", parent=self.tab_frames['user_management']); return
        if messagebox.askyesno("Confirm Role Change", f"Change role for '{username}'\nFrom: '{current_role}'\nTo:     '{new_role}'?", parent=self.tab_frames['user_management']):
            logging.info(f"Admin '{self.current_username}' attempting role change for ID {selected_user_id} to '{new_role}'")
            if self.db_manager.update_user_role(selected_user_id, new_role):
                 messagebox.showinfo("Success", f"Role for '{username}' updated to '{new_role}'.", parent=self.tab_frames['user_management']); logging.info(f"Role updated for ID {selected_user_id}."); self.populate_users_tree()
            else: messagebox.showerror("Error", "Failed to update role. Check logs.", parent=self.tab_frames['user_management'])

    def reset_selected_user_password(self):
        selected_user_id = self.get_selected_user_id()
        if not selected_user_id: messagebox.showinfo("Reset Password", "Select a user.", parent=self.tab_frames['user_management']); return
        if selected_user_id == self.current_user_id: messagebox.showwarning("Reset Password", "Cannot reset own password here.", parent=self.tab_frames['user_management']); return
        item_data = self.users_tree.item(self.users_tree.focus()); username = item_data['values'][1]
        if not messagebox.askyesno("Confirm Reset", f"Reset password for user '{username}'?", parent=self.tab_frames['user_management']): return
        new_password = simpledialog.askstring("New Password", f"Enter new password for '{username}':", show='*', parent=self.tab_frames['user_management'])
        if not new_password: messagebox.showwarning("Cancelled", "Password empty. Reset cancelled.", parent=self.tab_frames['user_management']); return
        if len(new_password) < 6: messagebox.showwarning("Input Error", "Password min 6 chars. Reset cancelled.", parent=self.tab_frames['user_management']); return
        confirm_password = simpledialog.askstring("Confirm Password", f"Confirm new password for '{username}':", show='*', parent=self.tab_frames['user_management'])
        if new_password != confirm_password: messagebox.showerror("Error", "Passwords do not match. Reset cancelled.", parent=self.tab_frames['user_management']); return
        new_hashed_password = hash_password(new_password)
        if not new_hashed_password: messagebox.showerror("Error", "Failed to hash password. Reset cancelled.", parent=self.tab_frames['user_management']); logging.error(f"Failed hash password for ID {selected_user_id}"); return
        logging.info(f"Admin '{self.current_username}' attempting password reset for ID {selected_user_id}")
        if self.db_manager.update_user_password(selected_user_id, new_hashed_password):
            messagebox.showinfo("Success", f"Password for '{username}' reset.", parent=self.tab_frames['user_management']); logging.info(f"Password reset successful for ID {selected_user_id}.")
        else: messagebox.showerror("Database Error", "Failed to update password. Check logs.", parent=self.tab_frames['user_management']); logging.error(f"DB update failed password reset for ID {selected_user_id}.")

    def delete_selected_user(self):
        selected_user_id = self.get_selected_user_id()
        if not selected_user_id:
            messagebox.showinfo("Delete User", "Select a user first.", parent=self.tab_frames['user_management'])
            return
        if selected_user_id == self.current_user_id:
            messagebox.showwarning("Delete User", "Cannot delete yourself.", parent=self.tab_frames['user_management'])
            return

        # Ensure item_data is valid before accessing values
        item_data = self.users_tree.item(self.users_tree.focus())
        try:
            username = item_data['values'][1]
            role = item_data['values'][2]
        except (IndexError, KeyError, TypeError):
            messagebox.showerror("Error", "Could not retrieve user details for deletion confirmation.", parent=self.tab_frames['user_management'])
            logging.error(f"Failed to get user details for ID {selected_user_id} during delete confirmation.")
            return

        if messagebox.askyesno("Confirm Delete", f"Delete user '{username}' (Role: {role})?\n\nThis cannot be undone.\nTransactions created/updated by this user will have their user reference cleared.", icon='warning', parent=self.tab_frames['user_management']):
            logging.warning(f"Admin '{self.current_username}' attempting delete user ID: {selected_user_id}, Username: '{username}'")
            if self.db_manager.delete_user(selected_user_id):
                messagebox.showinfo("Deleted", f"User '{username}' deleted.", parent=self.tab_frames['user_management'])
                logging.info(f"User ID {selected_user_id} deleted.")
                self.populate_users_tree() # Refresh list
            else:
                # DB Manager might show a more specific error (like FK constraint if not SET NULL)
                # This is a fallback message.
                messagebox.showerror("Error", "Failed to delete user. Check logs.", parent=self.tab_frames['user_management'])
                logging.error(f"Failed to delete user ID {selected_user_id}.")

    def _load_user_role_permissions_ui(self):
        """Loads current 'user' role permissions from DB and sets checkboxes."""
        if self.current_user_role != 'admin':
            logging.warning("_load_user_role_permissions_ui called by non-admin. Skipping.")
            return

        logging.debug("Loading 'user' role permissions into UI checkboxes.")
        allowed_tabs_str = self.db_manager.get_allowed_tabs_for_role('user')
        allowed_tabs = set(allowed_tabs_str.split(',')) if allowed_tabs_str else set()

        for tab_key, var in self.perm_tab_vars.items():
            var.set(tab_key in allowed_tabs) # Set True if key is in allowed, False otherwise
        logging.debug(f"Loaded user role permissions from DB: {allowed_tabs}")

    def _save_user_role_permissions(self):
        """Saves the selected tab permissions for the 'user' role to the DB."""
        if self.current_user_role != 'admin':
            messagebox.showerror("Permission Denied", "Only administrators can save role permissions.", parent=self.root)
            logging.warning("_save_user_role_permissions called by non-admin.")
            return

        logging.info("Saving 'user' role tab permissions.")
        allowed_tabs_list = [tab_key for tab_key, var in self.perm_tab_vars.items() if var.get()]

        if self.db_manager.set_allowed_tabs_for_role('user', allowed_tabs_list):
            messagebox.showinfo("Permissions Saved", "Tab access permissions for the 'user' role have been updated.",
                                parent=self.tab_frames.get('user_management', self.root))
            # No need to re-apply permissions immediately for the admin saving them.
            # Changes will take effect for 'user' role on their next login.
        else:
            messagebox.showerror("Error", "Failed to save permissions to the database. Check logs.",
                                 parent=self.tab_frames.get('user_management', self.root))

    # --- Permission Application ---
    def _apply_role_permissions(self):
        """Hides or shows UI elements based on role and DB permissions."""
        is_admin = (self.current_user_role == 'admin')
        logging.info(f"--- APPLYING PERMISSIONS --- Role: {self.current_user_role}, Is Admin: {is_admin}")

        target_visible_tabs = set()
        allowed_tabs_str = self.db_manager.get_allowed_tabs_for_role(self.current_user_role)
        logging.debug(f"Raw allowed_tabs_str for role '{self.current_user_role}': '{allowed_tabs_str}'")

        all_possible_ui_tabs = set(self.tab_frames.keys())
        admin_only_tabs = {'user_management'}

        if is_admin and allowed_tabs_str == 'ALL':
            target_visible_tabs = all_possible_ui_tabs
            logging.debug(f"Admin role with 'ALL'. Target tabs: {target_visible_tabs}")
        elif allowed_tabs_str:
            target_visible_tabs = set(allowed_tabs_str.split(','))
            logging.debug(f"Fetched permissions for '{self.current_user_role}'. Initial target: {target_visible_tabs}")
            if not is_admin:
                target_visible_tabs -= admin_only_tabs
                logging.debug(f"After admin-only removal, final target for '{self.current_user_role}': {target_visible_tabs}")
        else:
            logging.warning(f"No permissions in DB for role '{self.current_user_role}'. No tabs targeted.")
            target_visible_tabs = set()

        # --- Tab Management Logic (Revised for clarity) ---
        logging.debug(f"Managing notebook tabs. Target visible: {target_visible_tabs}")
        currently_managed_tabs = {}
        try:
            managed_tab_ids = self.notebook.tabs()
            for tab_id in managed_tab_ids:
                 frame_widget = self.notebook.nametowidget(tab_id)
                 # Find the key associated with this frame
                 for key, frame in self.tab_frames.items():
                     if frame == frame_widget:
                         currently_managed_tabs[key] = frame
                         break
            logging.debug(f"Currently managed tabs in notebook: {list(currently_managed_tabs.keys())}")
        except Exception as e:
            logging.error(f"Error getting currently managed tabs: {e}")

        for tab_key, tab_frame in self.tab_frames.items():
            tab_text = self.tab_texts.get(tab_key, f" {tab_key.title()} ")
            should_be_visible = tab_key in target_visible_tabs
            is_currently_visible = tab_key in currently_managed_tabs

            if should_be_visible and not is_currently_visible:
                try:
                    self.notebook.add(tab_frame, text=tab_text, state='normal')
                    logging.info(f"Tab '{tab_key}' ADDED for role '{self.current_user_role}'.")
                except tk.TclError as add_err:
                    logging.error(f"Error adding tab '{tab_key}': {add_err}")
            elif not should_be_visible and is_currently_visible:
                try:
                    self.notebook.forget(tab_frame)
                    logging.info(f"Tab '{tab_key}' FORGOTTEN for role '{self.current_user_role}'.")
                except tk.TclError as forget_err:
                    logging.error(f"Error forgetting tab '{tab_key}': {forget_err}")
            # Optional: Ensure state is 'normal' if it should be visible and is already visible
            elif should_be_visible and is_currently_visible:
                 try:
                    current_state = self.notebook.tab(tab_frame, "state")
                    if current_state != 'normal':
                        self.notebook.tab(tab_frame, state='normal')
                        logging.debug(f"Tab '{tab_key}' state forced to NORMAL.")
                 except tk.TclError: pass # Ignore error if tab is somehow unmanageable temporarily
        # --- End Tab Management Logic ---


        # --- Menu Item / Context Menu / Button State Management ---
        if hasattr(self, 'file_menu'):
            try: self.file_menu.entryconfigure("Database Settings", state=tk.NORMAL if is_admin else tk.DISABLED)
            except tk.TclError: pass

        # <<< MODIFIED: Removed "Delete Transaction" from the list >>>
        destructive_labels = ["Delete Selected Item", "Delete User"]
        menus_to_check = [
            getattr(self, name, None) for name in
            ['report_context_menu', 'pending_context_menu', 'mgmt_context_menu', 'user_context_menu']
            if getattr(self, name, None) is not None
        ]

        admin_state = tk.NORMAL if is_admin else tk.DISABLED
        for menu in menus_to_check:
            if menu:
                # Iterate safely through menu items
                num_items = menu.index(tk.END)
                if num_items is None: num_items = -1 # Handle empty menu case

                for i in range(num_items + 1):
                    try:
                        entry_type = menu.type(i)
                        if entry_type not in ('command', 'checkbutton', 'radiobutton', 'cascade'):
                            continue # Skip separators etc.

                        label = menu.entrycget(i, "label")
                        current_state = admin_state # Default

                        # Special handling (same as before, just ensuring it doesn't crash on missing items)
                        if menu == self.mgmt_context_menu and label in ["Edit Selected Item", "Delete Selected Item"]:
                           current_view_type = self.mgmt_list_type_var.get() if hasattr(self, 'mgmt_list_type_var') else ""
                           if current_view_type == "Memos": current_state = tk.DISABLED

                        elif menu == self.user_context_menu:
                             selected_id = self.get_selected_user_id()
                             is_self = (selected_id == self.current_user_id) if selected_id else False
                             if label in ["Change Role To", "Delete User", "Reset Password"] and is_self: current_state = tk.DISABLED
                             elif label == "Set Security Questions": current_state = tk.NORMAL # Allow for self even if not admin
                             elif not is_admin and label != "Set Security Questions": current_state = tk.DISABLED # Non-admins can only set own Qs

                        elif label in destructive_labels and not is_admin:
                             current_state = tk.DISABLED

                        menu.entryconfigure(i, state=current_state)

                    except tk.TclError as e:
                        # Log error if it's not just about an invalid index (which can happen if menu changes)
                        if "bad menu entry index" not in str(e):
                             logging.warning(f"TclError configuring menu item index {i} in {menu}: {e}")
                    except Exception as e:
                        logging.error(f"Error configuring context menu item index {i} in {menu}: {e}", exc_info=True)

        # --- Rest of the permission logic (unchanged) ---
        user_mgmt_state = tk.NORMAL if is_admin else tk.DISABLED
        if hasattr(self, 'add_user_button'): self.add_user_button.configure(state=user_mgmt_state)
        if hasattr(self, 'save_perms_button'): self.save_perms_button.configure(state=user_mgmt_state)

        perm_frame = None
        if hasattr(self, 'perm_checkbox_frame'):
            try:
                 widget_path = str(self.perm_checkbox_frame)
                 if self.root.tk.call('winfo', 'exists', widget_path):
                    perm_frame_parent = self.perm_checkbox_frame.master
                    if self.root.tk.call('winfo', 'exists', str(perm_frame_parent)):
                        perm_frame = perm_frame_parent.master
            except Exception as e: logging.error(f"Error finding perm_frame parent: {e}")

        if isinstance(perm_frame, ttk.Frame):
             try:
                 if self.root.tk.call('winfo', 'exists', str(perm_frame)):
                    if not is_admin:
                        if perm_frame.winfo_viewable(): perm_frame.grid_remove(); logging.debug("Permissions frame hidden.")
                    elif not perm_frame.winfo_viewable(): perm_frame.grid(); logging.debug("Permissions frame shown.")
             except Exception as e: logging.error(f"Error managing permissions frame visibility: {e}")
        elif is_admin: logging.warning("Could not find valid permissions_frame parent widget.")

        logging.info("--- Finished applying role permissions ---")

        # Specific buttons in User Management
        user_mgmt_state = tk.NORMAL if is_admin else tk.DISABLED
        if hasattr(self, 'add_user_button'): self.add_user_button.configure(state=user_mgmt_state)
        if hasattr(self, 'save_perms_button'): self.save_perms_button.configure(state=user_mgmt_state)

        # Permissions Frame Visibility (User Management Tab)
        perm_frame = None
        # Find the parent frame containing the checkboxes (usually right_panel -> permissions_frame)
        if hasattr(self, 'perm_checkbox_frame'):
            try:
                 # Check if the widget path is valid before accessing master
                 widget_path = str(self.perm_checkbox_frame)
                 if self.root.tk.call('winfo', 'exists', widget_path):
                    perm_frame_parent = self.perm_checkbox_frame.master # Canvas
                    if self.root.tk.call('winfo', 'exists', str(perm_frame_parent)):
                        perm_frame = perm_frame_parent.master # permissions_frame
            except Exception as e:
                logging.error(f"Error finding perm_frame parent: {e}")

        if isinstance(perm_frame, ttk.Frame):
             try:
                 if self.root.tk.call('winfo', 'exists', str(perm_frame)): # Check existence before managing grid
                    if not is_admin:
                        if perm_frame.winfo_viewable():
                             perm_frame.grid_remove(); logging.debug("Permissions frame hidden.")
                    # Ensure visible if admin (might have been hidden by non-admin login)
                    elif not perm_frame.winfo_viewable():
                        perm_frame.grid(); logging.debug("Permissions frame shown.")
             except Exception as e: logging.error(f"Error managing permissions frame visibility: {e}")
        elif is_admin: logging.warning("Could not find valid permissions_frame parent widget.")


        logging.info("--- Finished applying role permissions ---")

    # --- Navigation & UI Helpers ---
    def _get_tab_index(self, tab_key):
        frame = self.tab_frames.get(tab_key)
        if frame:
            try: return self.notebook.index(frame)
            except tk.TclError: logging.error(f"Tab frame '{tab_key}' not found in notebook."); return None
        logging.error(f"Tab frame key '{tab_key}' not found in self.tab_frames.")
        return None

    def go_to_add_transaction_tab(self):
        idx = self._get_tab_index('add_transaction')
        if idx is not None:
            self.notebook.select(idx)
            if hasattr(self, 'payment_method_dropdown'): self.payment_method_dropdown.focus_set()
            elif hasattr(self, 'company_combobox'): self.company_combobox.focus_set()

    def go_to_report_tab(self):
        idx = self._get_tab_index('report')
        if idx is not None: self.notebook.select(idx)

    def go_to_management_tab(self): # Renamed from go_to_companies_tab
         idx = self._get_tab_index('management')
         if idx is not None: self.notebook.select(idx)

    def _update_check_no_state(self, event=None):
        payment_method = self.payment_method_var.get()
        transaction_type = self.transaction_type_var.get()

        is_enabled = (transaction_type == TYPE_DEBIT or transaction_type == TYPE_TRANSFER) and \
                     payment_method == METHOD_CHECK
        is_required = is_enabled

        new_state = 'normal' if is_enabled else 'disabled'
        label_color = COLOR_TEXT if is_enabled else COLOR_TEXT_SECONDARY

        if hasattr(self, 'check_no_entry') and hasattr(self, 'check_no_label'):
            self.check_no_entry.configure(state=new_state)
            self.check_no_label.configure(foreground=label_color)
            if not is_enabled:
                self.check_no_entry.delete(0, tk.END)
            if is_required and not self.check_no_entry.get().strip():
                pass
            else:
                self._set_widget_valid(self.check_no_entry)

        logging.debug(f"Check No state updated: {new_state} (Required: {is_required}) for Type: {transaction_type}, Method: {payment_method}")

        # Update status dropdown for Debit when payment method changes
        if transaction_type == TYPE_DEBIT and hasattr(self, 'status_dropdown') and hasattr(self, 'status_var'):
            current_debit_status = self.status_var.get()
            new_debit_status_options = []
            default_debit_status = ""

            # <<< MODIFIED DEBIT STATUS LOGIC >>>
            if payment_method == METHOD_CHECK:
                new_debit_status_options = [STATUS_PAID, STATUS_VOID, STATUS_PENDING, STATUS_CLEARED]
                default_debit_status = STATUS_PENDING # Or Paid, depending on common workflow
            else: # For other debit methods
                new_debit_status_options = [STATUS_PAID, STATUS_VOID]
                default_debit_status = STATUS_PAID

            self.status_dropdown.configure(values=sorted(list(set(new_debit_status_options))))
            if current_debit_status not in new_debit_status_options or not current_debit_status:
                self.status_var.set(default_debit_status)
            logging.debug(f"Debit status dropdown updated for payment method '{payment_method}': Options={new_debit_status_options}, Default='{default_debit_status}'")


    def _update_transaction_form_layout(self):
        selected_type = self.transaction_type_var.get()
        selected_payment_method = self.payment_method_var.get()
        logging.debug(f"Updating transaction form layout for type: {selected_type}, method: {selected_payment_method}")

        # ... (manage_grid helper and other visibility/label updates remain the same) ...
        def manage_grid(widget_tuple_on_self, show=True):
            if not widget_tuple_on_self or not isinstance(widget_tuple_on_self, tuple):
                 logging.warning(f"manage_grid: Invalid widget tuple passed: {widget_tuple_on_self}")
                 return
            for widget in widget_tuple_on_self:
                try:
                    if show:
                        if not widget.winfo_manager() or not widget.winfo_ismapped():
                            widget.grid()
                    else:
                        if widget.winfo_manager() and widget.winfo_ismapped():
                            widget.grid_remove()
                except tk.TclError as e: logging.error(f"TclError managing grid for widget {widget}: {e}")
                except AttributeError: logging.error(f"AttributeError: Widget {widget} might be None or not a widget.")

        is_debit = (selected_type == TYPE_DEBIT)
        is_credit = (selected_type == TYPE_CREDIT)
        is_transfer = (selected_type == TYPE_TRANSFER)

        manage_grid(self.transfer_to_bank_widgets, show=is_transfer)
        manage_grid(self.vendor_customer_widgets, show=(is_debit or is_credit))
        manage_grid(self.bill_no_widgets, show=is_debit)
        manage_grid(self.invoice_no_widgets, show=is_credit)
        manage_grid(self.check_no_widgets, show=(is_debit or is_credit or is_transfer))
        manage_grid(self.status_widgets, show=(is_debit or is_credit))

        if is_transfer:
            self.bank_name_label.configure(text="From Bank:")
            self.add_button.configure(text="Record Transfer")
        else:
            self.bank_name_label.configure(text="Bank Name:")
            self.add_button.configure(text="Add Transaction")
            payee_label = "Customer Name:" if is_credit else "Vendor Name:"
            if hasattr(self, 'vendor_customer_label'):
                self.vendor_customer_label.configure(text=payee_label)

        if (is_debit or is_credit) and hasattr(self, 'vendor_customer_combobox'):
            payee_type_needed = 'Customer' if is_credit else 'Vendor'
            payees_data = self.db_manager.get_payees(payee_type=payee_type_needed)
            payee_names = [name for payee_id, name, p_type in payees_data] if payees_data else []
            current_vc = self.vendor_customer_var.get()
            self.vendor_customer_combobox['values'] = payee_names
            if current_vc not in payee_names:
                self.vendor_customer_var.set("")
        elif is_transfer and hasattr(self, 'vendor_customer_var'):
            self.vendor_customer_var.set("")

        if hasattr(self, 'payment_method_dropdown') and hasattr(self, 'payment_method_var'):
            current_pm = self.payment_method_var.get()
            if is_transfer:
                self.payment_method_dropdown.configure(values=TRANSFER_PAYMENT_METHODS)
                if current_pm not in TRANSFER_PAYMENT_METHODS or not current_pm:
                     default_transfer_pm = METHOD_EFT if METHOD_EFT in TRANSFER_PAYMENT_METHODS else (TRANSFER_PAYMENT_METHODS[0] if TRANSFER_PAYMENT_METHODS else "")
                     self.payment_method_var.set(default_transfer_pm)
            else:
                debit_credit_payment_methods = [m for m in PAYMENT_METHODS if m != METHOD_TRANSFER]
                self.payment_method_dropdown.configure(values=debit_credit_payment_methods)
                if current_pm not in debit_credit_payment_methods or not current_pm or current_pm == METHOD_TRANSFER:
                     default_dc_pm = METHOD_CHECK if METHOD_CHECK in debit_credit_payment_methods else (debit_credit_payment_methods[0] if debit_credit_payment_methods else "")
                     self.payment_method_var.set(default_dc_pm)

        # --- Update Status Dropdown (if Debit/Credit) ---
        if (is_debit or is_credit) and hasattr(self, 'status_dropdown') and hasattr(self, 'status_var'):
            current_status_val = self.status_var.get()
            status_options_for_type = []
            default_status_for_type = ""

            if is_credit:
                status_options_for_type = CREDIT_STATUS_OPTIONS
                default_status_for_type = STATUS_RECEIVED
            elif is_debit:
                # <<< MODIFIED DEBIT STATUS LOGIC >>>
                if selected_payment_method == METHOD_CHECK:
                    # For Checks, all these are valid. Paid is for immediate payment.
                    status_options_for_type = [STATUS_PAID, STATUS_VOID, STATUS_PENDING, STATUS_CLEARED]
                    default_status_for_type = STATUS_PENDING # Or STATUS_PAID if that's more common
                else: # For other debit methods (Cash, EFT, etc.)
                    status_options_for_type = [STATUS_PAID, STATUS_VOID]
                    default_status_for_type = STATUS_PAID

            self.status_dropdown.configure(values=sorted(list(set(status_options_for_type)))) # Ensure unique and sorted
            if current_status_val not in status_options_for_type or not current_status_val:
                 self.status_var.set(default_status_for_type)

        self._update_check_no_state()

        widgets_to_reset_valid_names = [
            'company_combobox', 'bank_name_combobox', 'transfer_to_bank_combo',
            'payment_method_dropdown', 'vendor_customer_combobox',
            'amount_entry', 'status_dropdown', 'memo_combobox',
            'check_no_entry', 'bill_no_entry', 'invoice_no_entry'
        ]
        for widget_name_str in widgets_to_reset_valid_names:
            if hasattr(self, widget_name_str):
                widget_obj = getattr(self, widget_name_str)
                if widget_obj:
                    self._set_widget_valid(widget_obj)


    # --- Excel Import/Export ---
    def import_from_excel(self):
        logging.info("Initiating Excel import process.")
        filepath = filedialog.askopenfilename(
            title="Select Excel File",
            filetypes=[("Excel files", "*.xlsx"), ("All files", "*.*")],
            parent=self.root
        )
        if not filepath:
            logging.info("Excel import cancelled.")
            return

        logging.info(f"Attempting import from: {filepath}")
        try:
            df = pd.read_excel(filepath, engine='openpyxl')
            logging.info(f"Read Excel file. Found {len(df)} rows.")

            # --- Column mapping and header validation (remains the same) ---
            column_map = {
                'company_name': ['company', 'company name'],
                'bank_name': ['bank', 'bank name'],
                'date': ['date', 'transaction date'],
                'check_no': ['check no', 'check #', 'check number', 'chk no'],
                'vendor_name': ['vendor', 'vendor name', 'payee', 'vendor / customer'],
                'reference': ['reference', 'ref', 'description'],
                'amount': ['amount', 'value', 'debit', 'credit'],
                'status': ['status', 'state'],
                'memo': ['memo', 'category'],
                'notes': ['notes', 'note', 'details'],
                'transaction_type': ['transaction type', 'type'],
                'payment_method': ['payment method', 'method', 'pmt method'],
                'bill_no': ['bill no', 'bill #', 'bill number'],
                'invoice_no': ['invoice no', 'invoice #', 'invoice number']
            }
            required_excel_cols_for_internal_keys = {
                'company_name', 'bank_name', 'date', 'amount', 'status', 'vendor_name'
            }
            df.columns = df.columns.str.strip().str.lower()
            actual_excel_columns_lc = set(df.columns)
            mapped_excel_cols_to_internal = {}
            found_internal_keys_from_excel = set()
            missing_required_headers_for_keys = []
            for internal_key, potential_excel_headers in column_map.items():
                header_found_for_key = False
                for excel_header_variant_lc in potential_excel_headers:
                    if excel_header_variant_lc in actual_excel_columns_lc:
                        mapped_excel_cols_to_internal[excel_header_variant_lc] = internal_key
                        found_internal_keys_from_excel.add(internal_key)
                        header_found_for_key = True
                        break
                if not header_found_for_key and internal_key in required_excel_cols_for_internal_keys:
                    missing_required_headers_for_keys.append(
                        f"'{internal_key}' (expected one of: {', '.join(potential_excel_headers)})"
                    )
            if missing_required_headers_for_keys:
                err_msg = (
                    "Import failed. Missing required column headers in Excel for internal fields:\n- " +
                    "\n- ".join(missing_required_headers_for_keys) +
                    "\n\nPlease ensure your Excel file has these columns."
                )
                messagebox.showerror("Import Error - Missing Column Headers", err_msg, parent=self.root)
                logging.error(f"Import failed: Missing column headers for keys: {missing_required_headers_for_keys}")
                return
            logging.info(f"Successfully mapped Excel columns to internal keys: {found_internal_keys_from_excel}")
            # --- End column mapping ---

            self.populate_company_dropdown()

            added_count = 0
            skipped_count = 0
            duplicate_count = 0 # <<< NEW counter
            error_details = []

            for index, row_from_excel in df.iterrows():
                row_num_excel = index + 2
                row_errors = []
                processed_row_data = {}

                for excel_header_lc, internal_key in mapped_excel_cols_to_internal.items():
                    raw_value = row_from_excel.get(excel_header_lc)
                    if pd.isna(raw_value) or (isinstance(raw_value, str) and not raw_value.strip()):
                        processed_row_data[internal_key] = None
                    elif isinstance(raw_value, str):
                        processed_row_data[internal_key] = raw_value.strip()
                    else:
                        processed_row_data[internal_key] = raw_value
                
                logging.debug(f"Row {row_num_excel} raw mapped data: {processed_row_data}")
                final_data_for_db = {}

                # --- Field-specific Validation and Transformation (same as before, but ensure values are ready for duplicate check) ---
                company_name_val = processed_row_data.get('company_name')
                company_id_for_check = None # Use this for the duplicate check
                if not company_name_val:
                    if 'company_name' in required_excel_cols_for_internal_keys: row_errors.append("Company Name missing.")
                else:
                    company_id_for_check = self.company_id_map.get(company_name_val)
                    if company_id_for_check is None:
                        row_errors.append(f"Company '{company_name_val}' not found in application setup.")
                final_data_for_db['company_id'] = company_id_for_check

                bank_name_for_check = processed_row_data.get('bank_name')
                if not bank_name_for_check and 'bank_name' in required_excel_cols_for_internal_keys:
                    row_errors.append("Bank Name missing.")
                final_data_for_db['bank_name'] = bank_name_for_check

                date_val = processed_row_data.get('date')
                date_for_check = None
                if date_val is None:
                    if 'date' in required_excel_cols_for_internal_keys: row_errors.append("Date missing.")
                else:
                    try: date_for_check = pd.to_datetime(date_val).date()
                    except (ValueError, TypeError, AttributeError): row_errors.append(f"Invalid date format: '{date_val}'.")
                final_data_for_db['date'] = date_for_check

                check_no_raw = processed_row_data.get('check_no')
                check_no_for_check = None
                if check_no_raw is not None:
                    if isinstance(check_no_raw, float) and check_no_raw.is_integer():
                        check_no_for_check = str(int(check_no_raw))
                    else: check_no_for_check = str(check_no_raw).strip()
                final_data_for_db['check_no'] = check_no_for_check

                vendor_name_for_check = processed_row_data.get('vendor_name')
                if not vendor_name_for_check and 'vendor_name' in required_excel_cols_for_internal_keys:
                    row_errors.append("Vendor/Customer Name missing.")
                final_data_for_db['vendor_or_customer_name'] = vendor_name_for_check

                amount_raw = processed_row_data.get('amount')
                amount_for_check = None
                if amount_raw is None:
                    if 'amount' in required_excel_cols_for_internal_keys: row_errors.append("Amount missing.")
                else:
                    try:
                        cleaned_amount_str = str(amount_raw).replace('$', '').replace(',', '').strip()
                        if not cleaned_amount_str:
                             if 'amount' in required_excel_cols_for_internal_keys: row_errors.append("Amount missing (empty after cleaning).")
                        else:
                            amount_for_check = float(cleaned_amount_str)
                            if amount_for_check <= 0:
                                row_errors.append("Amount must be a positive value.")
                                amount_for_check = None
                    except (ValueError, TypeError): row_errors.append(f"Invalid amount format: '{amount_raw}'.")
                final_data_for_db['amount'] = amount_for_check

                # Status (not used in duplicate check directly, but validated)
                status_raw = processed_row_data.get('status')
                normalized_status = None
                if status_raw is None:
                    if 'status' in required_excel_cols_for_internal_keys: row_errors.append("Status missing.")
                else:
                    normalized_status = str(status_raw).strip().title()
                    if normalized_status not in ALL_STATUS_OPTIONS:
                        row_errors.append(f"Invalid Status: '{status_raw}'. Valid: {', '.join(ALL_STATUS_OPTIONS)}.")
                        normalized_status = None
                final_data_for_db['status'] = normalized_status
                
                # ... (rest of the field validations: transaction_type, payment_method, bill_no, invoice_no, etc. remain the same)
                tt_from_excel = processed_row_data.get('transaction_type')
                pm_from_excel = processed_row_data.get('payment_method')
                imported_transaction_type = None
                imported_payment_method = None
                if tt_from_excel:
                    tt_candidate = str(tt_from_excel).strip().title()
                    if tt_candidate in TRANSACTION_TYPES: imported_transaction_type = tt_candidate
                    else: row_errors.append(f"Invalid Transaction Type from Excel: '{tt_from_excel}'. Valid: {', '.join(TRANSACTION_TYPES)}.")
                if pm_from_excel:
                    pm_input_normalized = str(pm_from_excel).strip().lower()
                    found_method = None
                    for valid_method_from_list in PAYMENT_METHODS:
                        if valid_method_from_list.lower() == pm_input_normalized: found_method = valid_method_from_list; break
                    if found_method: imported_payment_method = found_method
                    else: row_errors.append(f"Invalid Payment Method from Excel: '{pm_from_excel}'. Valid: {', '.join(PAYMENT_METHODS)}.")
                if not imported_transaction_type and normalized_status:
                    if normalized_status in CREDIT_STATUS_OPTIONS and normalized_status not in DEBIT_STATUS_OPTIONS: imported_transaction_type = TYPE_CREDIT
                    elif normalized_status in DEBIT_STATUS_OPTIONS: imported_transaction_type = TYPE_DEBIT
                if not imported_payment_method and imported_transaction_type:
                    if imported_transaction_type == TYPE_DEBIT: imported_payment_method = METHOD_CHECK
                    elif imported_transaction_type == TYPE_CREDIT: imported_payment_method = METHOD_EFT
                    elif imported_transaction_type == TYPE_TRANSFER: imported_payment_method = METHOD_EFT
                if not imported_transaction_type: row_errors.append("Transaction Type could not be determined.")
                if not imported_payment_method: row_errors.append("Payment Method could not be determined.")
                final_data_for_db['transaction_type'] = imported_transaction_type
                final_data_for_db['payment_method'] = imported_payment_method
                if imported_transaction_type in [TYPE_DEBIT, TYPE_TRANSFER] and \
                   imported_payment_method == METHOD_CHECK and not check_no_for_check: # Use check_no_for_check
                    row_errors.append(f"Check No. is required for {imported_transaction_type} with {METHOD_CHECK} payment.")
                bill_no_val = processed_row_data.get('bill_no'); invoice_no_val = processed_row_data.get('invoice_no')
                final_data_for_db['bill_no'] = None; final_data_for_db['invoice_no'] = None
                if imported_transaction_type == TYPE_DEBIT: final_data_for_db['bill_no'] = str(bill_no_val).strip() if bill_no_val else None
                elif imported_transaction_type == TYPE_CREDIT: final_data_for_db['invoice_no'] = str(invoice_no_val).strip() if invoice_no_val else None
                final_data_for_db['reference'] = processed_row_data.get('reference')
                final_data_for_db['memo'] = processed_row_data.get('memo')
                final_data_for_db['notes'] = processed_row_data.get('notes')
                final_data_for_db['created_by_user_id'] = self.current_user_id
                # --- End Field Validation ---

                if row_errors:
                    skipped_count += 1
                    error_details.append(f"Row {row_num_excel}: Skipped (Validation) - {'; '.join(row_errors)}")
                    logging.warning(f"Skipping Excel row {row_num_excel} due to validation errors: {row_errors}")
                    continue

                # --- DUPLICATE CHECK ---
                if self.db_manager.check_transaction_exists(
                    company_id=company_id_for_check,
                    bank_name=bank_name_for_check,
                    date=date_for_check,
                    amount=amount_for_check,
                    check_no=check_no_for_check, # Pass the string or None
                    vendor_or_customer_name=vendor_name_for_check
                ):
                    duplicate_count += 1
                    error_details.append(f"Row {row_num_excel}: Skipped (Potential Duplicate Found)")
                    logging.warning(f"Skipping Excel row {row_num_excel} as potential duplicate found.")
                    continue
                # --- END DUPLICATE CHECK ---

                try:
                    logging.debug(f"Attempting to add transaction from Excel (Row {row_num_excel}): {final_data_for_db}")
                    new_id = self.db_manager.add_transaction(**final_data_for_db)
                    if new_id:
                        added_count += 1
                    else:
                        skipped_count += 1
                        err_msg = f"Row {row_num_excel}: Database add failed (check previous errors or logs)."
                        if not any(err_msg in detail for detail in error_details[-3:]):
                            error_details.append(err_msg)
                        logging.error(f"DB insert failed for Excel row {row_num_excel}, or was handled by DB manager.")
                except psycopg2.Error as db_err:
                    skipped_count += 1
                    pg_err_msg = f"{db_err.pgcode}: {db_err.pgerror}" if hasattr(db_err, 'pgcode') else str(db_err)
                    err = f"Row {row_num_excel}: DB Error - {pg_err_msg}"
                    error_details.append(err)
                    logging.error(f"Database error processing Excel row {row_num_excel}: {pg_err_msg}", exc_info=True)
                except Exception as e:
                    skipped_count += 1
                    err = f"Row {row_num_excel}: Unexpected error during DB add - {e}"
                    error_details.append(err)
                    logging.error(f"Unexpected error processing Excel row {row_num_excel} for DB add: {e}", exc_info=True)

            # --- Import Summary ---
            summary_msg = (
                f"Import complete.\n\n"
                f"Successfully Added: {added_count}\n"
                f"Skipped (Duplicates): {duplicate_count}\n" # <<< NEW
                f"Skipped (Other Errors): {skipped_count}"    # Renamed
            )
            if error_details:
                display_errors = error_details[:15]
                summary_msg += "\n\nSkipped Row Details (first " + str(len(display_errors)) + " shown):\n" + "\n".join(display_errors)
                if len(error_details) > 15:
                    summary_msg += f"\n...and {len(error_details) - 15} more errors/skipped rows (see '{log_file}' for full details)."
                
                log_msg_full_errors = f"Import completed. Added: {added_count}, Duplicates: {duplicate_count}, Other Skipped: {skipped_count}.\nFull Error List:\n" + "\n".join(error_details)
                logging.warning(log_msg_full_errors) # Log with new counts
                messagebox.showwarning("Import Complete with Issues", summary_msg, parent=self.root)
            else:
                logging.info(f"Import successful. Added: {added_count}, Duplicates: {duplicate_count}, Other Skipped: {skipped_count}.")
                messagebox.showinfo("Import Successful", summary_msg, parent=self.root)

            if added_count > 0:
                self.refresh_all_views()

        # --- Exception handling (remains the same) ---
        except FileNotFoundError:
            messagebox.showerror("Import Error", f"File not found:\n{filepath}", parent=self.root)
            logging.error(f"Import failed: File not found {filepath}")
        except ImportError as imp_err:
            if 'pandas' in str(imp_err).lower(): err_lib = 'pandas'
            elif 'openpyxl' in str(imp_err).lower(): err_lib = 'openpyxl'
            else: err_lib = 'a required library'
            messagebox.showerror("Import Error", f"Required library '{err_lib}' is missing.\nPlease install it (e.g., pip install {err_lib})", parent=self.root)
            logging.error(f"Excel import failed: {err_lib} missing.", exc_info=True)
        except Exception as e:
            messagebox.showerror("Import Error", f"An unexpected error occurred during import:\n{e}\n\nCheck '{log_file}' for details.", parent=self.root)
            logging.error(f"Unexpected Excel import error from {filepath}: {e}", exc_info=True)

# Inside BankSheetApp class
    def export_to_excel(self):
        logging.info("Starting Excel export of current view...")
        current_filters = {}
        # ... (filter preparation remains the same, it will correctly filter the single DB COL_VENDOR) ...
        comp_name = self.filter_company_var.get(); comp_id = self.company_id_map.get(comp_name)
        if comp_name != FILTER_ALL_COMPANIES and comp_id: current_filters['filter_company_id'] = comp_id
        bank_name = self.filter_bank_var.get()
        if bank_name != FILTER_ALL_BANKS: current_filters['filter_bank_name'] = bank_name
        try: start_date = self.filter_start_date.get_date(); current_filters['filter_start_date'] = start_date
        except ValueError: pass
        try: end_date = self.filter_end_date.get_date(); current_filters['filter_end_date'] = end_date
        except ValueError: pass
        status = self.filter_status_var.get()
        if status != FILTER_ALL_STATUSES: current_filters['filter_status'] = status
        memo = self.filter_memo_var.get()
        if memo != FILTER_ALL_MEMOS: current_filters['filter_memo'] = memo
        
        # Filter values
        vendor_filter_val = self.filter_vendor_var.get()
        customer_filter_val = self.filter_customer_var.get()

        if vendor_filter_val != FILTER_ALL_VENDORS:
            current_filters['filter_vendor_name'] = vendor_filter_val
        if customer_filter_val != FILTER_ALL_CUSTOMERS:
            current_filters['filter_customer_name'] = customer_filter_val

        trans_type_filter = self.filter_type_var.get()
        if trans_type_filter != FILTER_ALL_TYPES: current_filters['filter_transaction_type'] = trans_type_filter
        method_filter = self.filter_method_var.get()
        if method_filter != FILTER_ALL_METHODS: current_filters['filter_payment_method'] = method_filter
        search_term = self.search_var.get().strip()
        if search_term: current_filters['search_term'] = search_term


        logging.info(f"Exporting data with filters/search: {current_filters}")
        data_for_export = self.db_manager.fetch_transactions(**current_filters) # This now returns the split vendor/customer in display_tuple

        if not data_for_export:
            messagebox.showinfo("Export Info", "No data in current view to export.", parent=self.root)
            logging.info("Excel export: no data.")
            return

        df_data = []
        # data_for_export item: (display_tuple, notes, amount_float, original_type_val, original_payment_method_val)
        # display_tuple (17 elements): (ID,Comp,Bank,Date,Check, UI_VENDOR, UI_CUSTOMER, Ref,Bill,Inv,Memo,Amt,Status,Type,Method,Creator)

        # <<< UPDATED COLUMNS LIST FOR EXCEL (16 columns) >>>
        columns_excel = [ # Use a different name to avoid confusion with treeview columns
            "ID", "Company", "Bank Name", "Date", "Check No",
            "Vendor", "Customer", # <<< SEPARATE COLUMNS
            "Reference", "Bill No", "Invoice No", # <<< ADDED BILL/INVOICE NO
            "Memo", "Notes", "Amount", "Status",
            "Transaction Type", "Payment Method",
            "Created By"
        ]

        for row_tuple_from_db in data_for_export:
            display_tuple = row_tuple_from_db[0] # This is the 17-element tuple
            notes = row_tuple_from_db[1]

            # Construct the row for the DataFrame based on the `columns_excel`
            df_row = (
                display_tuple[0],   # ID
                display_tuple[1],   # Company
                display_tuple[2],   # Bank Name
                display_tuple[3],   # Date
                display_tuple[4],   # Check No
                display_tuple[5],   # UI_VENDOR_NAME
                display_tuple[6],   # UI_CUSTOMER_NAME
                display_tuple[7],   # Reference
                display_tuple[8],   # Bill No
                display_tuple[9],   # Invoice No
                display_tuple[10],  # Memo
                notes,              # Notes (from row_tuple_from_db[1])
                display_tuple[11],  # Amount (as string, like "1,234.50")
                display_tuple[12],  # Status
                display_tuple[13],  # Transaction Type
                display_tuple[14],  # Payment Method
                display_tuple[15]   # Created By
            )
            df_data.append(df_row)

        try:
            df = pd.DataFrame(df_data, columns=columns_excel) # Use columns_excel

            # Attempt to convert Amount column to numeric for Excel if it's string
            if "Amount" in df.columns:
                try:
                    # Remove commas before converting, handle potential errors
                    df["Amount"] = df["Amount"].astype(str).str.replace(',', '', regex=False)
                    df["Amount"] = pd.to_numeric(df["Amount"], errors='coerce')
                except Exception as e:
                    logging.warning(f"Could not convert 'Amount' column to numeric for Excel export: {e}")


            search_suffix = f"_search_{search_term.replace(' ','_')}" if search_term else ""
            default_filename = f"Bank_Sheet_Report_{datetime.now().strftime('%Y%m%d_%H%M')}{search_suffix}.xlsx"
            filepath = filedialog.asksaveasfilename(
                defaultextension=".xlsx",
                filetypes=[("Excel files", "*.xlsx"), ("All files", "*.*")],
                title="Save Report As",
                initialfile=default_filename,
                parent=self.root
            )
            if not filepath:
                logging.info("Excel export cancelled.")
                return

            try:
                writer = pd.ExcelWriter(filepath, engine='openpyxl', 
                                        date_format='YYYY-MM-DD', 
                                        datetime_format='YYYY-MM-DD')
                df.to_excel(writer, index=False, sheet_name='Report View')
                workbook = writer.book
                worksheet = writer.sheets['Report View']

                for idx, col_name_excel in enumerate(df.columns): # Use df.columns which are from columns_excel
                    series = df[col_name_excel]
                    max_content_len = 0
                    try: max_content_len = series.astype(str).map(len).max()
                    except TypeError: pass
                    if pd.isna(max_content_len): max_content_len = 0
                    
                    header_len = len(str(series.name)) if series.name else 0
                    max_len = max(max_content_len, header_len) + 2 # Use series.name for header length
                    
                    col_letter = chr(65 + idx)
                    if col_name_excel == "Notes" and max_len > 60:
                        max_len = 60
                        worksheet.column_dimensions[col_letter].width = max_len
                        from openpyxl.styles import Alignment
                        for cell in worksheet[col_letter]:
                            if cell.row > 1: cell.alignment = (cell.alignment or Alignment()).copy(wrapText=True)
                    else:
                        worksheet.column_dimensions[col_letter].width = max_len
                
                try: # Apply currency format to Amount column
                    amount_col_index_excel = columns_excel.index("Amount")
                    currency_format = '_($* #,##0.00_);_($* (#,##0.00);_($* "-"??_);_(@_)'
                    amount_col_letter_excel = chr(65 + amount_col_index_excel)
                    for cell in worksheet[amount_col_letter_excel]:
                        if cell.row > 1: cell.number_format = currency_format
                except ValueError: logging.warning("Amount column not found for Excel currency formatting.")
                
                writer.close() # Use close() for modern pandas/openpyxl
                messagebox.showinfo("Export Successful", f"Report exported to:\n{filepath}", parent=self.root)
                logging.info(f"Report exported to Excel: {filepath}")
            except ImportError:
                logging.error("Export format failed: 'openpyxl' missing. Exporting without advanced formatting.")
                df.to_excel(filepath, index=False) # Fallback to basic export
                messagebox.showinfo("Export Successful (Basic)", f"Report exported (no formatting):\n{filepath}", parent=self.root)
            except Exception as e_write:
                messagebox.showerror("Export Error", f"Error writing Excel file: {e_write}", parent=self.root)
                logging.error(f"Error writing Excel file {filepath}: {e_write}", exc_info=True)
        except ImportError:
            messagebox.showerror("Import Error", "Required 'pandas' or 'openpyxl' library missing.\nPlease install: pip install pandas openpyxl", parent=self.root)
            logging.error("Export failed: pandas or openpyxl library is missing.", exc_info=True)
        except Exception as e:
            messagebox.showerror("Export Error", f"An unexpected error occurred during export preparation:\n{e}", parent=self.root)
            logging.error(f"Error preparing report for Excel: {e}", exc_info=True)

    # --- Settings ---
    def show_settings_window(self):
        # No changes needed here, kept for completeness
        settings_window = tk.Toplevel(self.root); settings_window.title("Database Settings"); settings_window.transient(self.root); settings_window.grab_set(); settings_window.resizable(False, False); settings_window.configure(bg=COLOR_PRIMARY_BG)
        current_config = self.db_manager.config if self.db_manager and self.db_manager.config else load_config()
        settings_frame = ttk.Frame(settings_window, padding="25", style='Card.TFrame'); settings_frame.grid(row=0, column=0, sticky="nsew", padx=20, pady=20); settings_frame.columnconfigure(1, weight=1)
        labels = ["Host:", "Port:", "Database Name:", "User:", "Password:"]; entries = {}; row_num = 0
        for label_text in labels: lbl = ttk.Label(settings_frame, text=label_text, style='Card.TLabel'); lbl.grid(row=row_num, column=0, sticky=tk.W, pady=6, padx=(0,10)); entry = ttk.Entry(settings_frame, width=38, font=text_font, show=("*" if label_text == "Password:" else None)); entry.grid(row=row_num, column=1, sticky="ew", pady=6); entries[label_text.replace(":", "")] = entry; row_num += 1
        entries["Host"].insert(0, current_config.get('host', DEFAULT_DB_HOST)); entries["Port"].insert(0, current_config.get('port', str(DEFAULT_DB_PORT))); entries["Database Name"].insert(0, current_config.get('name', DEFAULT_DB_NAME)); entries["User"].insert(0, current_config.get('user', DEFAULT_DB_USER)); pwd = current_config.get('password', ''); entries["Password"].insert(0, pwd if pwd is not None else "")
        button_frame = ttk.Frame(settings_frame, style='Card.TFrame'); button_frame.grid(row=row_num, column=0, columnspan=2, pady=(25, 5), sticky=tk.E)
        validation_label = ttk.Label(settings_frame, text="", style='Error.TLabel', wraplength=350); validation_label.grid(row=row_num+1, column=0, columnspan=2, pady=(5, 0), sticky='ew')
        def save_settings_action():
            validation_label.configure(text=""); host = entries["Host"].get().strip(); port_str = entries["Port"].get().strip(); name = entries["Database Name"].get().strip(); user = entries["User"].get().strip(); password = entries["Password"].get()
            errors = []; port = None
            if not host: errors.append("Host empty."); 
            if not name: errors.append("Database Name empty."); 
            if not user: errors.append("User empty.")
            if not port_str: errors.append("Port empty.")
            else: 
                try: port = int(port_str); assert 0 < port < 65536; 
                except (ValueError, AssertionError): errors.append("Invalid Port (1-65535).")
            if errors: validation_label.configure(text="Errors:\n- " + "\n- ".join(errors)); return
            new_db_config = {"host": host, "port": port, "name": name, "user": user, "password": password if password else None} # Store empty pass as None
            if save_config(new_db_config): self.db_manager.config = new_db_config; self.db_manager.close_connection(); messagebox.showinfo("Settings Saved", "Settings saved.\nReconnect on next operation.", parent=settings_window); logging.info("DB settings saved, connection reset."); settings_window.destroy()
        save_button = ttk.Button(button_frame, text="Save Settings", command=save_settings_action, style='Accent.TButton', width=15); save_button.pack(side=tk.RIGHT, padx=(10, 0))
        cancel_button = ttk.Button(button_frame, text="Cancel", command=settings_window.destroy, width=10); cancel_button.pack(side=tk.RIGHT)
        settings_window.update_idletasks(); root_x=self.root.winfo_rootx(); root_y=self.root.winfo_rooty(); root_w=self.root.winfo_width(); root_h=self.root.winfo_height(); win_w=settings_window.winfo_width(); win_h=settings_window.winfo_height(); x=root_x+(root_w//2)-(win_w//2); y=root_y+(root_h//2)-(win_h//2); settings_window.geometry(f"+{x}+{y}"); settings_window.protocol("WM_DELETE_WINDOW", settings_window.destroy); settings_window.wait_window()

    # --- Application Lifecycle ---
    def on_closing(self):
        logging.info("--- Bank Sheet Application Closing ---")
        if messagebox.askokcancel("Quit", "Exit Bank Sheet?", icon='question', parent=self.root):
            self.db_manager.close_connection()
            self.root.destroy()
            logging.info("--- Application Exit Confirmed ---")
        else:
             logging.info("--- Application Exit Cancelled ---")

    def run(self):
        # Login/setup happens in __init__
        if self.current_user_id:
            logging.info("--- Starting Tkinter Main Loop ---")
            self.root.mainloop()
        else:
            logging.warning("--- Application not starting main loop (login failed/cancelled/error) ---")

    # Kept for potential future use if custom input needed again
    def _validate_combobox(self, event_or_widget=None): # Renamed parameter for clarity
         widget = None
         if isinstance(event_or_widget, tk.Event): # If it's an event object
             widget = event_or_widget.widget
         elif isinstance(event_or_widget, ttk.Combobox): # If it's a Combobox widget itself
             widget = event_or_widget
         # Add a check if you pass the dictionary {'widget': ...} still by mistake for other calls
         elif isinstance(event_or_widget, dict) and 'widget' in event_or_widget and isinstance(event_or_widget['widget'], ttk.Combobox):
             widget = event_or_widget['widget']
             logging.warning("_validate_combobox called with a dictionary, please pass the widget directly or an event object.")


         if widget: # Proceed only if we have a valid widget
             if not widget.get():
                 self._set_widget_invalid(widget)
                 return False
             else:
                 self._set_widget_valid(widget)
                 return True
         else:
            # logging.debug(f"_validate_combobox called with invalid argument: {event_or_widget}")
            pass # Or log a warning if event_or_widget was not None but couldn't resolve to a widget
         return False

    def populate_memo_dropdown(self):
        """Populates the memo dropdown on the Add Transaction tab."""
        logging.debug("Populating Add Transaction memo dropdown...")
        if not hasattr(self, 'memo_combobox'):
            logging.warning("Memo combobox not found for population.")
            return

        memos_data = self.db_manager.get_memos()
        memo_names = sorted([name for m_id, name in memos_data]) if memos_data else []

        # Optionally add "Other" if you still want custom entry
        full_memo_options = memo_names
        if MEMO_OTHER: # Check if MEMO_OTHER constant exists and is truthy
            if MEMO_OTHER not in full_memo_options:
                full_memo_options.append(MEMO_OTHER)

        current_selection = self.memo_var.get()
        self.memo_combobox['values'] = full_memo_options

        if current_selection in full_memo_options:
            self.memo_var.set(current_selection)
        # Set a default if desired (maybe the first item, or handle no memos)
        elif full_memo_options:
            # Decide on default: first item? Or keep blank? Or use DEFAULT_MEMO if it exists in list?
            if DEFAULT_MEMO and DEFAULT_MEMO in full_memo_options:
                self.memo_var.set(DEFAULT_MEMO)
            else:
                self.memo_combobox.current(0) # Set to first available memo
                # self.memo_var.set("") # Alternative: Keep blank initially
        else:
            self.memo_var.set("") # No memos available

        # Adjust state based on whether 'Other' is the only option or not
        if MEMO_OTHER and len(full_memo_options) == 1 and full_memo_options[0] == MEMO_OTHER:
            self.memo_combobox.configure(state="readonly") # Force 'Other' if it's the only one
            self.memo_var.set(MEMO_OTHER)
        elif MEMO_OTHER:
            self.memo_combobox.configure(state="normal") # Allow typing if Other exists alongside DB items
        else:
            self.memo_combobox.configure(state="readonly") # Readonly if no Other option

        logging.debug("Add Transaction memo dropdown populated.")

     # --- Data Population and Refresh ---
    def refresh_all_views(self):
        logging.info("Refreshing all application views...")
        self.populate_company_dropdown()
        self.populate_filter_comboboxes()
        self.apply_report_filters() # Populates report tree
        self.populate_pending_tree()
        self.populate_bank_summary_tree()
        self.populate_memo_summary_tree()
        
        # --- MODIFIED HERE ---
        self.populate_add_trans_bank_dropdowns() # Call the specific method for Add Transaction tab banks
        
        self.populate_payee_dropdowns() # Add Trans payee dropdown
        self.populate_memo_dropdown() # Add Trans memo dropdown
        self.populate_management_list()
        if self.current_user_role == 'admin':
            self.populate_users_tree()
            self._load_user_role_permissions_ui()
        # Ensure initial layout is correct after refresh
        self.root.after(50, self._update_transaction_form_layout) # This will handle correct display based on transaction type
        logging.info("All views refreshed.")



# --- Main Execution ---
if __name__ == "__main__":
    root = tk.Tk()
    root.withdraw() # Hide initially
    app = None
    try:
        # App __init__ handles DB init, login, UI setup, permission, initial data load
        app = BankSheetApp(root)

        root_exists_final = False
        try: root_exists_final = root.winfo_exists()
        except tk.TclError: root_exists_final = False

        # Only run if app created, login succeeded, and root still exists
        if app and app.current_user_id and root_exists_final:
             app.run() # Contains the mainloop
             logging.info("--- Bank Sheet Application Exited Normally ---")
        else:
             logging.warning("--- Bank Sheet Application did not run main loop ---")
             if root_exists_final:
                 try: root.destroy() # Ensure cleanup if loop didn't run
                 except tk.TclError: pass
    except Exception as e:
         logging.critical(f"--- Unhandled Exception in Main Block: {e} ---", exc_info=True)
         try: messagebox.showerror("Fatal Error", f"Critical error:\n{e}\nCheck 'bank_sheet.log'.")
         except tk.TclError: print(f"FATAL ERROR (Tkinter unavailable): {e}")
         if app and hasattr(app, 'db_manager') and app.db_manager: app.db_manager.close_connection()
         if 'root' in locals() and isinstance(root, tk.Tk):
             try:
                 if root.winfo_exists(): root.destroy()
             except tk.TclError: pass
         sys.exit(1)