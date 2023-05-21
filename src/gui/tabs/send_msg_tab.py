import random
import tkinter as tk
from tkinter import filedialog
from tkinter import ttk

from src.pgp.consts.consts import SYMMETRIC_ENCRYPTION_ALGORITHMS, SIGNING_ALGORITHMS, Algorithm
from src.pgp.message.message import PGPMessage
from src.pgp.user.user import User


def select_directory(directory_label: ttk.Label):
    directory = filedialog.askdirectory()
    if directory:
        directory_label.config(text=directory)
    else:
        directory_label.config(text="No directory selected")


def send_message(user: User,
                 message_text: tk.Text,
                 to_email_combobox: ttk.Combobox,
                 from_email_combobox: ttk.Combobox,
                 symmetric_algo_combobox: ttk.Combobox,
                 signature_algo_combobox: ttk.Combobox,
                 compress_var: tk.BooleanVar,
                 convert_var: tk.BooleanVar,
                 password_text: tk.Text,
                 directory_label: ttk.Label):
    message = message_text.get("1.0", tk.END)
    to_email = to_email_combobox.get()
    from_email = from_email_combobox.get()
    directory = directory_label["text"]
    password = password_text.get("1.0", tk.END)
    symmetric_algo = symmetric_algo_combobox.get()
    signature_algo = signature_algo_combobox.get()
    compress = compress_var.get()
    convert = convert_var.get()
    pgp_message: PGPMessage = user.sender.prepare_message(message=message,
                                                          sender_mail=from_email,
                                                          receiver_mail=to_email,
                                                          symmetric_encryption_algorithm=Algorithm(symmetric_algo),
                                                          password=password,
                                                          compress=compress,
                                                          convert=convert,
                                                          )
    user.sender.send_message(message=pgp_message,
                             message_path=f"{directory}/{to_email}_{from_email}_{random.randint(0, 10000)}.pgp")


def send_msg_tab_gen(notebook, user: User, logout_callback):


    send_msg_tab = ttk.Frame(notebook)
    notebook.add(send_msg_tab, text="Send Message")

    # Message
    message_label = ttk.Label(send_msg_tab, text="Message:")
    message_label.grid(row=0, column=0, padx=12, pady=4, sticky=tk.W)
    message_text = tk.Text(send_msg_tab, height=5, width=30)
    message_text.grid(row=0, column=1, padx=12, pady=4, sticky="we")

    # Email
    to_email_label = ttk.Label(send_msg_tab, text="To Email:")
    to_email_label.grid(row=1, column=0, padx=12, pady=4, sticky=tk.W)
    to_email_entry = ttk.Entry(send_msg_tab)
    to_email_entry.grid(row=1, column=1, padx=12, pady=4)

    # Symmetric Algorithm
    symmetric_algo_label = ttk.Label(send_msg_tab, text="Symmetric Algorithm:")
    symmetric_algo_label.grid(row=3, column=0, padx=12, pady=4, sticky=tk.W)
    symmetric_algo_combo = ttk.Combobox(send_msg_tab,
                                        values=[algorithm.value for algorithm in SYMMETRIC_ENCRYPTION_ALGORITHMS])
    symmetric_algo_combo.grid(row=3, column=1, padx=12, pady=4)
    symmetric_algo_combo.config(state=tk.DISABLED)

    # Public Key
    public_key_label = ttk.Label(send_msg_tab, text="Public Key:")
    public_key_label.grid(row=4, column=0, padx=12, pady=4, sticky=tk.W)
    public_key_combo = ttk.Combobox(send_msg_tab, values=["Public Key 1", "Public Key 2"])
    public_key_combo.grid(row=4, column=1, padx=12, pady=4)


    # Signature Type
    signature_type_label = ttk.Label(send_msg_tab, text="Signature Type:")
    signature_type_label.grid(row=6, column=0, padx=12, pady=4, sticky=tk.W)
    signature_type_combo = ttk.Combobox(send_msg_tab, values=[algorithm.value for algorithm in SIGNING_ALGORITHMS])
    signature_type_combo.grid(row=6, column=1, padx=12, pady=4)
    signature_type_combo.config(state=tk.DISABLED)


    # Symmetric Algorithm
    symmetric_algo_label = ttk.Label(send_msg_tab, text="Symmetric Algorithm:")
    symmetric_algo_label.grid(row=4, column=0, padx=12, pady=4, sticky=tk.W)
    symmetric_algo_combo = ttk.Combobox(send_msg_tab,
                                        values=[algorithm.value for algorithm in SYMMETRIC_ENCRYPTION_ALGORITHMS])
    symmetric_algo_combo.grid(row=4, column=1, padx=12, pady=4)

    # Signature Type
    signature_type_label = ttk.Label(send_msg_tab, text="Signature Type:")
    signature_type_label.grid(row=6, column=0, padx=12, pady=4, sticky=tk.W)
    signature_type_combo = ttk.Combobox(send_msg_tab, values=[algorithm.value for algorithm in SIGNING_ALGORITHMS])
    signature_type_combo.grid(row=6, column=1, padx=12, pady=4)

    # Compress
    compress_label = ttk.Label(send_msg_tab, text="Compress:")
    compress_label.grid(row=7, column=0, padx=12, pady=4, sticky=tk.W)
    compress_var = tk.BooleanVar()
    compress_checkbox = ttk.Checkbutton(send_msg_tab, variable=compress_var)
    compress_checkbox.grid(row=7, column=1, padx=12, pady=4)

    # Convert to Radix-64
    radix64_label = ttk.Label(send_msg_tab, text="Convert to Radix-64:")
    radix64_label.grid(row=8, column=0, padx=12, pady=4, sticky=tk.W)
    radix64_var = tk.BooleanVar()
    radix64_checkbox = ttk.Checkbutton(send_msg_tab, variable=radix64_var)
    radix64_checkbox.grid(row=8, column=1, padx=12, pady=4)


    # Destination Folder
    dest_folder_label = ttk.Label(send_msg_tab, text="Destination Folder:")
    dest_folder_label.grid(row=9, column=0, padx=12, pady=4, sticky=tk.W)
    dest_folder_entry = ttk.Entry(send_msg_tab)
    dest_folder_entry.grid(row=9, column=1, padx=12, pady=4)

    # Send Message button
    send_msg_btn = ttk.Button(send_msg_tab, text="Send Message")
    send_msg_btn.grid(row=10, column=0, columnspan=2, padx=10, pady=10)


    # Logout
    logout_separator = ttk.Separator(send_msg_tab, orient="horizontal")
    logout_separator.grid(row=8, column=0, columnspan=12, padx=0, pady=10, sticky="we")
    username_label = ttk.Label(send_msg_tab, text=f"Current user: {user.user_name}")
    username_label.grid(row=9, column=0, padx=12, pady=4, sticky=tk.W)
    logout_btn = ttk.Button(send_msg_tab, text="Logout", command=logout_callback)
    logout_btn.grid(row=9, column=1, columnspan=1, padx=10, pady=10)

    # Directory Label
    directory_label = ttk.Label(send_msg_tab, text="No directory selected")
    directory_label.grid(row=9, column=1, padx=12, pady=4, sticky=tk.W)

    # Select Directory Button
    select_directory_button = ttk.Button(send_msg_tab, text="Select Directory",
                                         command=lambda: select_directory(directory_label))
    select_directory_button.grid(row=9, column=0, padx=12, pady=4, sticky=tk.W)

    # Send Message button
    send_msg_btn = ttk.Button(send_msg_tab, text="Send Message")
    send_msg_btn.grid(row=11, column=0, columnspan=2, padx=10, pady=10)

