import tkinter as tk
from tkinter import ttk
from src.pgp.consts.consts import SYMMETRIC_ENCRYPTION_ALGORITHMS, SIGNING_ALGORITHMS
from src.pgp.user.user import User


def send_msg_tab_gen(notebook, user: User, logout_callback):
    send_msg_tab = ttk.Frame(notebook)
    notebook.add(send_msg_tab, text="Send Message")

    # Message
    message_label = ttk.Label(send_msg_tab, text="Message:")
    message_label.grid(row=0, column=0, padx=12, pady=4, sticky=tk.W)
    message_text = tk.Text(send_msg_tab, height=5, width=30)
    message_text.grid(row=0, column=1, padx=12, pady=4, sticky="we")

    # From Email
    from_email_label = ttk.Label(send_msg_tab, text="From Email:")
    from_email_label.grid(row=1, column=0, padx=12, pady=4, sticky=tk.W)
    from_email_entry = ttk.Combobox(send_msg_tab, values=["Email 1", "Email 2"])
    from_email_entry.grid(row=1, column=1, padx=12, pady=4)

    # To Email
    to_email_label = ttk.Label(send_msg_tab, text="To Email:")
    to_email_label.grid(row=2, column=0, padx=12, pady=4, sticky=tk.W)
    to_email_entry = ttk.Entry(send_msg_tab)
    to_email_entry.grid(row=2, column=1, padx=12, pady=4)

    # Public Key
    public_key_label = ttk.Label(send_msg_tab, text="Public Key:")
    public_key_label.grid(row=3, column=0, padx=12, pady=4, sticky=tk.W)
    public_key_combo = ttk.Combobox(send_msg_tab, values=["Public Key 1", "Public Key 2"])
    public_key_combo.grid(row=3, column=1, padx=12, pady=4)

    # Compress
    compress_label = ttk.Label(send_msg_tab, text="Compress:")
    compress_label.grid(row=4, column=0, padx=12, pady=4, sticky=tk.W)
    compress_var = tk.BooleanVar()
    compress_var.set(True)  # Set checkbox to True by default
    compress_checkbox = ttk.Checkbutton(send_msg_tab, variable=compress_var)
    compress_checkbox.grid(row=4, column=1, padx=12, pady=4)

    # Convert to Radix-64
    radix64_label = ttk.Label(send_msg_tab, text="Convert to Radix-64:")
    radix64_label.grid(row=5, column=0, padx=12, pady=4, sticky=tk.W)
    radix64_var = tk.BooleanVar()
    radix64_checkbox = ttk.Checkbutton(send_msg_tab, variable=radix64_var)
    radix64_checkbox.grid(row=5, column=1, padx=12, pady=4)

    # Destination Folder
    dest_folder_label = ttk.Label(send_msg_tab, text="Destination Folder:")
    dest_folder_label.grid(row=6, column=0, padx=12, pady=4, sticky=tk.W)
    dest_folder_entry = ttk.Entry(send_msg_tab)
    dest_folder_entry.grid(row=6, column=1, padx=12, pady=4)

    # Send Message button
    send_msg_btn = ttk.Button(send_msg_tab, text="Send Message")
    send_msg_btn.grid(row=7, column=0, columnspan=2, padx=10, pady=10)

    # Logout
    logout_separator = ttk.Separator(send_msg_tab, orient="horizontal")
    logout_separator.grid(row=8, column=0, columnspan=12, padx=0, pady=10, sticky="we")
    username_label = ttk.Label(send_msg_tab, text=f"Current user: {user.user_name}")
    username_label.grid(row=9, column=0, padx=12, pady=4, sticky=tk.W)
    logout_btn = ttk.Button(send_msg_tab, text="Logout", command=logout_callback)
    logout_btn.grid(row=9, column=1, columnspan=1, padx=10, pady=10)