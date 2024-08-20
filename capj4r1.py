import hashlib
import os
import random
import string
import tkinter as tk
from tkinter import filedialog, ttk, BooleanVar, Menu, Toplevel, Checkbutton, messagebox
import threading
import webbrowser
from concurrent.futures import ThreadPoolExecutor
import json

# Configuration file path
CONFIG_FILE = "user_settings.json"

# Buffer size for reading large files (64KB)
BUFFER_SIZE = 65536

# Thread pool for concurrent file processing
executor = ThreadPoolExecutor(max_workers=4)

# Minimum donation value
MIN_DONATION = 5

# Function to set the window icon
def apply_window_icon(window):
    # Get the absolute path of the icon
    icon_path = os.path.join(os.path.dirname(__file__), "capj4r1.ico")
    window.iconbitmap(icon_path)

# Load user settings from file
def load_settings():
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, "r") as file:
            return json.load(file)
    return {}

# Save user settings to file
def save_settings():
    settings = {
        "dark_mode": dark_mode.get(),
        "hide_file_path": hide_file_path.get(),
        "hide_md5": hide_md5.get(),
        "hide_sha1": hide_sha1.get(),
        "hide_sha256": hide_sha256.get(),
        "hide_sha512": hide_sha512.get()
    }
    with open(CONFIG_FILE, "w") as file:
        json.dump(settings, file)

# Hash calculation functions
def calculate_md5(file_path):
    if hide_md5.get():
        return None  # Return None if MD5 is hidden
    md5_hash = hashlib.md5()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            md5_hash.update(byte_block)
    return md5_hash.hexdigest()

def calculate_sha1(file_path):
    if hide_sha1.get():
        return None  # Return None if SHA-1 is hidden
    sha1_hash = hashlib.sha1()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha1_hash.update(byte_block)
    return sha1_hash.hexdigest()

def calculate_sha256(file_path):
    if hide_sha256.get():
        return None  # Return None if SHA-256 is hidden
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def calculate_sha512(file_path):
    if hide_sha512.get():
        return None  # Return None if SHA-512 is hidden
    sha512_hash = hashlib.sha512()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha512_hash.update(byte_block)
    return sha512_hash.hexdigest()

# File modification function
def modify_file(file_path):
    with open(file_path, "a") as f:
        random_string = ''.join(random.choices(string.ascii_letters + string.digits, k=16))
        f.write(random_string)

# Apply dark mode to a window
def apply_dark_mode_to_window(window):
    if dark_mode.get():
        window.configure(bg="#36393f")
        for widget in window.winfo_children():
            if isinstance(widget, tk.Label):
                widget.config(bg="#36393f", fg="white")
            elif isinstance(widget, tk.Button):
                widget.config(bg="#2f3136", fg="white")
            elif isinstance(widget, tk.Entry):
                widget.config(bg="#2f3136", fg="white", insertbackground="white")
            elif isinstance(widget, ttk.Combobox):
                style.configure("TCombobox", fieldbackground="#2f3136", foreground="white")
            elif isinstance(widget, ttk.Progressbar):
                style.configure("TProgressbar", troughcolor="#2f3136", background="white")
            elif isinstance(widget, ttk.Label):  # ttk.Label uses style configuration
                style.configure("TLabel", background="#36393f", foreground="white")
    else:
        window.configure(bg="SystemButtonFace")
        for widget in window.winfo_children():
            if isinstance(widget, tk.Label):
                widget.config(bg="SystemButtonFace", fg="black")
            elif isinstance(widget, tk.Button):
                widget.config(bg="SystemButtonFace", fg="black")
            elif isinstance(widget, tk.Entry):
                widget.config(bg="SystemButtonFace", fg="black", insertbackground="black")
            elif isinstance(widget, ttk.Combobox):
                style.configure("TCombobox", fieldbackground="SystemButtonFace", foreground="black")
            elif isinstance(widget, ttk.Progressbar):
                style.configure("TProgressbar", troughcolor="SystemButtonFace", background="black")
            elif isinstance(widget, ttk.Label):  # ttk.Label uses style configuration
                style.configure("TLabel", background="SystemButtonFace", foreground="black")

# PayPal Donation logic (updated to handle dynamic amounts and currency)
def donate(amount, currency):
    if float(amount) < MIN_DONATION:
        messagebox.showerror("Invalid Amount", f"Minimum donation amount is {MIN_DONATION} {currency}.")
        return

    paypal_url = f"https://www.paypal.com/cgi-bin/webscr?cmd=_donations&business=travizvander@proton.me&currency_code={currency}&amount={amount}"
    webbrowser.open(paypal_url)  # Opens the PayPal donation link in the default browser

# Open donation popup
def open_donation_popup():
    def update_note():
        note_label.config(text=f"Minimum {MIN_DONATION} {currency_var.get()}")

    def validate_donation():
        amount = amount_entry.get()
        currency = currency_var.get()

        try:
            if float(amount) < MIN_DONATION:
                raise ValueError
        except ValueError:
            messagebox.showerror("Invalid Amount", f"Please enter a valid amount (minimum {MIN_DONATION} {currency}).")
            return

        donate(amount, currency)

    donation_popup = Toplevel(root)
    donation_popup.title("Support Us")
    donation_popup.geometry("350x400")  # Adjusted for content size
    apply_window_icon(donation_popup)  # Apply the icon to the donation popup

    # Donation label
    label = tk.Label(donation_popup, text="Buy me a coffee!", font=("Arial", 14))
    label.pack(pady=10)

    # Coffee Image (local file reference)
    coffee_image = tk.PhotoImage(file="coffee.png")  # Replace with the local path to the coffee image
    coffee_label = tk.Label(donation_popup, image=coffee_image)
    coffee_label.image = coffee_image  # Keep a reference to avoid garbage collection
    coffee_label.pack(pady=10)

    # Entry for the donation amount
    amount_label = tk.Label(donation_popup, text="Enter amount:")
    amount_label.pack(pady=5)

    amount_entry = tk.Entry(donation_popup)
    amount_entry.pack(pady=5)

    # Currency selection dropdown
    currency_label = tk.Label(donation_popup, text="Select currency:")
    currency_label.pack(pady=5)

    currency_var = tk.StringVar(value="USD")
    currency_dropdown = ttk.Combobox(donation_popup, textvariable=currency_var, values=["USD", "MYR"], state="readonly")
    currency_dropdown.pack(pady=5)
    currency_dropdown.bind("<<ComboboxSelected>>", lambda e: update_note())

    # Minimum amount note
    note_label = tk.Label(donation_popup, text=f"Minimum {MIN_DONATION} {currency_var.get()}.", fg="gray", font=("Arial", 9))
    note_label.pack(pady=5)

    # Donate button
    donate_button = tk.Button(donation_popup, text="Donate", command=validate_donation)
    donate_button.pack(pady=10)

    # Apply dark mode to the donation window
    apply_dark_mode_to_window(donation_popup)

    donation_popup.transient(root)  # Set the donation window to be modal
    donation_popup.grab_set()  # Ensure all focus is on this window

# File import processing in a separate thread
def process_file_import(file_paths, spinner_popup):
    existing_files = [table.item(row)["values"][0] for row in table.get_children()]
    
    def add_file(file_path):
        if file_path not in existing_files:
            old_md5 = calculate_md5(file_path)
            old_sha1 = calculate_sha1(file_path)
            old_sha256 = calculate_sha256(file_path)
            old_sha512 = calculate_sha512(file_path)
            table.insert("", "end", values=(
                file_path,
                old_md5 if old_md5 is not None else "",  # If hash is hidden, insert empty string
                old_sha1 if old_sha1 is not None else "",
                old_sha256 if old_sha256 is not None else "",
                old_sha512 if old_sha512 is not None else "",
                "", "", "", "", "Pending"
            ))

    # Use a thread pool to process multiple files concurrently
    with ThreadPoolExecutor() as executor:
        list(executor.map(add_file, file_paths))

    update_file_names()  # Update file names based on the current setting
    update_totals()
    root.after(100, lambda: close_spinner(spinner_popup))

# Add files to the table and avoid duplicates (starts a thread)
def add_files():
    file_paths = filedialog.askopenfilenames(title="Select Files")
    if file_paths:
        spinner_popup = show_spinner("Importing files, please wait...")
        threading.Thread(target=process_file_import, args=(file_paths, spinner_popup)).start()

# Process folder selection to include all files in the folder and subfolders
def process_folder_import(folders, spinner_popup):
    file_paths = []
    for folder in folders:
        for root_dir, _, files in os.walk(folder):
            for file in files:
                file_paths.append(os.path.join(root_dir, file))

    process_file_import(file_paths, spinner_popup)

# Add folders and their files to the table
def add_folders():
    folder = filedialog.askdirectory(mustexist=True, title="Select Folder", parent=root)
    if folder:
        spinner_popup = show_spinner("Importing folders, please wait...")
        threading.Thread(target=process_folder_import, args=([folder], spinner_popup)).start()

# Hash modification processing in a separate thread
def process_hash_change(spinner_popup):
    def modify_and_update(row):
        file_path = table.item(row)["values"][0]

        # Only update hash if not hidden
        old_md5 = table.item(row)["values"][1] if table.item(row)["values"][5] == "" else table.item(row)["values"][5]
        old_sha1 = table.item(row)["values"][2] if table.item(row)["values"][6] == "" else table.item(row)["values"][6]
        old_sha256 = table.item(row)["values"][3] if table.item(row)["values"][7] == "" else table.item(row)["values"][7]
        old_sha512 = table.item(row)["values"][4] if table.item(row)["values"][8] == "" else table.item(row)["values"][8]

        # Modify the file
        modify_file(file_path)

        # Update only non-hidden hashes
        new_md5 = calculate_md5(file_path) if not hide_md5.get() else old_md5
        new_sha1 = calculate_sha1(file_path) if not hide_sha1.get() else old_sha1
        new_sha256 = calculate_sha256(file_path) if not hide_sha256.get() else old_sha256
        new_sha512 = calculate_sha512(file_path) if not hide_sha512.get() else old_sha512

        # Update the table with the new hashes and status
        table.item(row, values=(
            file_path,
            old_md5, old_sha1, old_sha256, old_sha512,
            new_md5, new_sha1, new_sha256, new_sha512,
            "Modified"
        ))

    # Use a thread pool to process multiple rows concurrently
    rows = table.get_children()
    with ThreadPoolExecutor() as executor:
        list(executor.map(modify_and_update, rows))

    update_totals()
    root.after(100, lambda: close_spinner(spinner_popup))

# Update hash for selected files without modifying hidden hashes (starts a thread)
def update_hashes_for_selected_files():
    spinner_popup = show_spinner("Changing hashes, please wait...")
    threading.Thread(target=process_hash_change, args=(spinner_popup,)).start()

# Show spinner animation
def show_spinner(message):
    spinner_popup = Toplevel(root)
    spinner_popup.title("Loading")
    spinner_popup.geometry("300x100")
    spinner_popup.resizable(False, False)
    apply_window_icon(spinner_popup)  # Apply the icon to the spinner window

    # Apply dark mode to the spinner window
    apply_dark_mode_to_window(spinner_popup)

    label = ttk.Label(spinner_popup, text=message)
    label.pack(pady=10)

    progress_bar = ttk.Progressbar(spinner_popup, mode="indeterminate")
    progress_bar.pack(pady=10, padx=20)
    progress_bar.start()

    return spinner_popup

# Close spinner
def close_spinner(spinner_popup):
    spinner_popup.destroy()

# Update file names based on whether to hide file paths
def update_file_names():
    for row in table.get_children():
        file_path = table.item(row)["values"][0]
        display_name = os.path.basename(file_path) if hide_file_path.get() else file_path
        table.set(row, column="File Name", value=display_name)

# Remove selected files from the table
def remove_selected_files():
    selected_items = table.selection()
    for item in selected_items:
        table.delete(item)
    update_totals()

# Remove all files from the table
def remove_all_files():
    for row in table.get_children():
        table.delete(row)
    update_totals()

# Sort table by file name
sort_order = True
def sort_by_filename():
    global sort_order
    data = [(table.set(k, 'File Name'), k) for k in table.get_children('')]
    data.sort(reverse=sort_order)
    for index, (val, k) in enumerate(data):
        table.move(k, '', index)
    sort_order = not sort_order
    update_sort_arrow()

# Update sort arrow in File Name column header
def update_sort_arrow():
    arrow = "▲" if sort_order else "▼"
    table.heading("File Name", text=f"File Name {arrow}")

# Update total count display
def update_totals():
    total_items = len(table.get_children())
    item_count_label.config(text=f"Item Count: {total_items}")
    total_count_label.config(text=f"Total Count: {total_items}")

# Dark mode toggle
def toggle_dark_mode():
    if dark_mode.get():
        root.configure(bg="#36393f")
        style.configure("dark.Treeview", background="#2f3136", foreground="white", fieldbackground="#2f3136", rowheight=25)
        style.map("dark.Treeview", 
                  background=[('selected', '#44475a')],
                  foreground=[('selected', 'white')],
                  highlightthickness=[('hover', 1)],
                  highlightbackground=[('hover', '#44475a')])
        style.configure("dark.Treeview.Heading", background="#202225", foreground="white")
        table.configure(style="dark.Treeview")
        style.configure("TButton", background="#2f3136", foreground="white")
        style.configure("TLabel", background="#36393f", foreground="white")
        item_count_label.config(bg="#36393f", fg="white")
        total_count_label.config(bg="#36393f", fg="white")
        credit_label.config(bg="#36393f", fg="lightgray")
        button_frame.config(bg="#36393f")
        label_frame.config(bg="#36393f")
        file_menu.config(bg="#2f3136", fg="white")
        settings_menu.config(bg="#2f3136", fg="white")
    else:
        root.configure(bg="SystemButtonFace")
        style.configure("Treeview", background="white", foreground="black", fieldbackground="white", rowheight=25)
        style.configure("Treeview.Heading", background="SystemButtonFace", foreground="black")
        table.configure(style="Treeview")
        style.configure("TButton", background="SystemButtonFace", foreground="black")
        style.configure("TLabel", background="SystemButtonFace", foreground="black")
        item_count_label.config(bg="SystemButtonFace", fg="black")
        total_count_label.config(bg="SystemButtonFace", fg="black")
        credit_label.config(bg="SystemButtonFace", fg="gray")
        button_frame.config(bg="SystemButtonFace")
        label_frame.config(bg="SystemButtonFace")
        file_menu.config(bg="SystemButtonFace", fg="black")
        settings_menu.config(bg="SystemButtonFace", fg="black")
    save_settings()  # Save the user settings when toggling dark mode

# Update column visibility based on the user's settings
def update_column_visibility():
    table["displaycolumns"] = [col for col, hide in zip(all_columns, 
        [False, hide_md5.get(), hide_sha1.get(), hide_sha256.get(), hide_sha512.get(),
         hide_md5.get(), hide_sha1.get(), hide_sha256.get(), hide_sha512.get(), False]) if not hide]
    save_settings()  # Save user settings after column visibility change

# Hash menu to hide specific hash functions
def open_settings():
    settings_window = Toplevel(root)
    settings_window.title("Settings")
    settings_window.geometry("400x300")
    apply_window_icon(settings_window)  # Apply the icon to the settings window

    # Apply dark mode to settings window
    apply_dark_mode_to_window(settings_window)

    left_frame = tk.Frame(settings_window)
    left_frame.pack(side=tk.LEFT, fill=tk.Y)
    
    right_frame = tk.Frame(settings_window)
    right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)
    
    general_button = tk.Button(left_frame, text="General", command=lambda: show_general(right_frame))
    general_button.pack(fill=tk.X)

    hash_button = tk.Button(left_frame, text="Hash", command=lambda: show_hash_settings(right_frame))
    hash_button.pack(fill=tk.X)

    show_general(right_frame)

# General settings menu
def show_general(frame):
    for widget in frame.winfo_children():
        widget.destroy()
    
    dark_mode_check = Checkbutton(frame, text="Enable Dark Mode", variable=dark_mode, command=toggle_dark_mode)
    dark_mode_check.pack(anchor="w")
    
    hide_file_path_check = Checkbutton(frame, text="Hide File Path (Show File Name Only) [BUGGY]", variable=hide_file_path, command=update_file_names)
    hide_file_path_check.pack(anchor="w")

# Hash settings menu (to hide hash options)
def show_hash_settings(frame):
    for widget in frame.winfo_children():
        widget.destroy()
    
    hide_md5_check = Checkbutton(frame, text="Hide MD5", variable=hide_md5, command=update_column_visibility)
    hide_md5_check.pack(anchor="w")

    hide_sha1_check = Checkbutton(frame, text="Hide SHA-1", variable=hide_sha1, command=update_column_visibility)
    hide_sha1_check.pack(anchor="w")

    hide_sha256_check = Checkbutton(frame, text="Hide SHA-256", variable=hide_sha256, command=update_column_visibility)
    hide_sha256_check.pack(anchor="w")

    hide_sha512_check = Checkbutton(frame, text="Hide SHA-512", variable=hide_sha512, command=update_column_visibility)
    hide_sha512_check.pack(anchor="w")

# GUI setup
root = tk.Tk()
root.title("CAP J4-R1 V1.0")
root.geometry("1200x600")
apply_window_icon(root)  # Apply the icon to the main window

# Allow resizing of the root window
root.columnconfigure(0, weight=1)
root.rowconfigure(0, weight=1)

# Variables for settings
dark_mode = BooleanVar(value=False)
hide_file_path = BooleanVar(value=False)
hide_md5 = BooleanVar(value=False)
hide_sha1 = BooleanVar(value=False)
hide_sha256 = BooleanVar(value=False)
hide_sha512 = BooleanVar(value=False)

# Apply style configurations (initialize style here before using it)
style = ttk.Style()
style.theme_use("clam")

# Load settings
loaded_settings = load_settings()
dark_mode.set(loaded_settings.get("dark_mode", False))
hide_file_path.set(loaded_settings.get("hide_file_path", False))
hide_md5.set(loaded_settings.get("hide_md5", False))
hide_sha1.set(loaded_settings.get("hide_sha1", False))
hide_sha256.set(loaded_settings.get("hide_sha256", False))
hide_sha512.set(loaded_settings.get("hide_sha512", False))

# Table (Treeview)
all_columns = ("File Name", "Old MD5", "Old SHA-1", "Old SHA-256", "Old SHA-512", 
               "New MD5", "New SHA-1", "New SHA-256", "New SHA-512", "Status")
table_frame = tk.Frame(root)
table_frame.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)

# Enable resizing of table
table_frame.columnconfigure(0, weight=1)
table_frame.rowconfigure(0, weight=1)

table = ttk.Treeview(table_frame, columns=all_columns, show="headings", height=15)
for col in all_columns:
    table.heading(col, text=col)
    table.column(col, anchor="w", minwidth=100, width=150)

# Adding File Name sorting functionality
table.heading("File Name", text="File Name", command=sort_by_filename)
table.grid(row=0, column=0, sticky="nsew")

# Add vertical scrollbar to the table
scrollbar = ttk.Scrollbar(table_frame, orient=tk.VERTICAL, command=table.yview)
scrollbar.grid(row=0, column=1, sticky='ns')
table.configure(yscrollcommand=scrollbar.set)

# Buttons
button_frame = tk.Frame(root)
button_frame.grid(row=1, column=0, sticky="ew", padx=10, pady=10)

add_files_button = tk.Button(button_frame, text="Add Files", command=add_files)
add_files_button.pack(side=tk.LEFT, padx=10)

add_folders_button = tk.Button(button_frame, text="Add Folders", command=add_folders)
add_folders_button.pack(side=tk.LEFT, padx=10)

start_hash_change_button = tk.Button(button_frame, text="Start Change Hashes", command=update_hashes_for_selected_files)
start_hash_change_button.pack(side=tk.LEFT, padx=10)

remove_selected_button = tk.Button(button_frame, text="Remove Selected Files", command=remove_selected_files)
remove_selected_button.pack(side=tk.LEFT, padx=10)

remove_all_button = tk.Button(button_frame, text="Remove All Files", command=remove_all_files)
remove_all_button.pack(side=tk.LEFT, padx=10)

# Labels for count
label_frame = tk.Frame(root)
label_frame.grid(row=2, column=0, sticky="ew", padx=10, pady=10)

item_count_label = tk.Label(label_frame, text="Item Count: 0")
item_count_label.pack(side=tk.LEFT)

total_count_label = tk.Label(label_frame, text="Total Count: 0")
total_count_label.pack(side=tk.LEFT)

# Credit Label under total count
credit_label = tk.Label(root, text="Used for modifying file hashes for educational purposes.\nTool by @TraviZ", font=("Arial", 10), fg="gray")
credit_label.grid(row=3, column=0, padx=10, pady=10)

# Menu bar
menu_bar = Menu(root)
root.config(menu=menu_bar)

# File menu
file_menu = Menu(menu_bar, tearoff=0)
menu_bar.add_cascade(label="File", menu=file_menu)
file_menu.add_command(label="Open...", command=add_files)
file_menu.add_command(label="Open Folders...", command=add_folders)
file_menu.add_separator()
file_menu.add_command(label="Exit", command=root.quit)

# Settings menu
settings_menu = Menu(menu_bar, tearoff=0)
menu_bar.add_cascade(label="Settings", menu=settings_menu)

# General submenu under Settings
settings_menu.add_command(label="General", command=open_settings)

# Donation button next to Settings
menu_bar.add_command(label="Donate", command=open_donation_popup)

# Hash submenu under Settings
hash_menu = Menu(settings_menu, tearoff=0)
settings_menu.add_cascade(label="Hash", menu=hash_menu)
hash_menu.add_checkbutton(label="Hide MD5", variable=hide_md5, command=update_column_visibility)
hash_menu.add_checkbutton(label="Hide SHA-1", variable=hide_sha1, command=update_column_visibility)
hash_menu.add_checkbutton(label="Hide SHA-256", variable=hide_sha256, command=update_column_visibility)
hash_menu.add_checkbutton(label="Hide SHA-512", variable=hide_sha512, command=update_column_visibility)

# Update column visibility initially
update_column_visibility()

# Apply dark mode if it's enabled on startup (after the table is created and menus are defined)
if dark_mode.get():
    toggle_dark_mode()

root.mainloop()
