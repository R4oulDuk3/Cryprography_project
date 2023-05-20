import tkinter as tk
from tkinter import ttk
from src.pgp.consts.consts import SYMMETRIC_ENCRYPTION_ALGORITHMS, SIGNING_ALGORITHMS


def send_msg_tab_gen(notebook, username):
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

    # Encrypt Message
    encrypt_label = ttk.Label(send_msg_tab, text="Encrypt Message:")
    encrypt_label.grid(row=2, column=0, padx=12, pady=4, sticky=tk.W)
    encrypt_var = tk.BooleanVar(value=False)
    encrypt_checkbox = ttk.Checkbutton(send_msg_tab, variable=encrypt_var,
                                       command=lambda: toggle_encrypt_field(encrypt_var, symmetric_algo_combo))
    encrypt_checkbox.grid(row=2, column=1, padx=12, pady=4)

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

    # Sign Message
    sign_label = ttk.Label(send_msg_tab, text="Sign Message:")
    sign_label.grid(row=5, column=0, padx=12, pady=4, sticky=tk.W)
    sign_var = tk.BooleanVar(value=False)
    sign_checkbox = ttk.Checkbutton(send_msg_tab, variable=sign_var,
                                    command=lambda: toggle_sign_field(sign_var, signature_type_combo))
    sign_checkbox.grid(row=5, column=1, padx=12, pady=4)

    # Signature Type
    signature_type_label = ttk.Label(send_msg_tab, text="Signature Type:")
    signature_type_label.grid(row=6, column=0, padx=12, pady=4, sticky=tk.W)
    signature_type_combo = ttk.Combobox(send_msg_tab, values=[algorithm.value for algorithm in SIGNING_ALGORITHMS])
    signature_type_combo.grid(row=6, column=1, padx=12, pady=4)
    signature_type_combo.config(state=tk.DISABLED)

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

def toggle_encrypt_field(checkbox_var, combo):
    if checkbox_var.get():
        combo.config(state=tk.NORMAL)
    else:
        combo.set("")
        combo.config(state=tk.DISABLED)

def toggle_sign_field(checkbox_var, combo):
    if checkbox_var.get():
        combo.config(state=tk.NORMAL)
    else:
        combo.set("")
        combo.config(state=tk.DISABLED)