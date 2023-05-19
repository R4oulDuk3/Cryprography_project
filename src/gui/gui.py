import tkinter as tk
from tkinter import ttk, filedialog
from tkinter.font import Font
from src.pgp.consts.consts import KEY_SIZES, ASYMMETRIC_ENCRYPTION_ALGORITHMS, SIGNING_ALGORITHMS, \
    SYMMETRIC_ENCRYPTION_ALGORITHMS


def gui_start():
    window = tk.Tk()
    window.title("PGP - Log in")
    window.geometry("450x400")

    def login_window_btn():
        window.destroy()
        show_main_window()

    header_font = Font(size=20, weight="bold")
    header_label = ttk.Label(window, text="Pretty Good Privacy", font=header_font)
    header_label.pack(pady=20)

    login_window = ttk.Frame(window)
    login_window.pack(padx=50, pady=20)

    username_label = ttk.Label(login_window, text="Username:")
    username_label.pack(padx=10, pady=10)

    username_entry = ttk.Entry(login_window)
    username_entry.pack(padx=10, pady=10)

    continue_button = ttk.Button(login_window, text="Continue", command=login_window_btn)
    continue_button.pack(padx=10, pady=10)

    window.mainloop()


def show_main_window():
    window = tk.Tk()
    window.title("PGP - Zastita podataka")
    window.geometry("900x800")

    tabs = ttk.Notebook(window)
    keyg_tab_gen(tabs)
    keyoverview_tab_gen(tabs)
    send_msg_tab_gen(tabs)
    receive_msg_tab_gen(tabs)

    tabs.pack()
    window.mainloop()


def keyg_tab_gen(notebook):
    key_gen_tab = ttk.Frame(notebook)
    notebook.add(key_gen_tab, text="Key Generation")

    generate_label = ttk.Label(key_gen_tab, text="Generate a new key pair:")
    generate_label.grid(row=0, column=0, columnspan=2, padx=10, pady=10)

    # Email
    email_label = ttk.Label(key_gen_tab, text="Email:")
    email_label.grid(row=1, column=0, padx=12, pady=4, sticky=tk.W)
    email_entry = ttk.Entry(key_gen_tab)
    email_entry.grid(row=1, column=1, padx=12, pady=4)
    email_entry.config(width=23)

    # Algorithm
    asym_algo_label = ttk.Label(key_gen_tab, text="Asymmetric algorithm")
    asym_algo_label.grid(row=2, column=0, padx=12, pady=4, sticky=tk.W)
    asym_algo_combo = ttk.Combobox(key_gen_tab, values=[algorithm.value for algorithm in ASYMMETRIC_ENCRYPTION_ALGORITHMS])
    asym_algo_combo.grid(row=2, column=1, padx=12, pady=4)
    asym_algo_combo.current(0)
    asym_algo_combo.bind("<<ComboboxSelected>>", lambda event: update_signature_label(asym_algo_combo))

    # Signature
    signature_type_label = ttk.Label(key_gen_tab, text="Signature type:")
    signature_type_label.grid(row=3, column=0, padx=12, pady=4, sticky=tk.W)
    global signature_label
    signature_label = ttk.Label(key_gen_tab, text="")
    signature_label.grid(row=3, column=1, padx=12, pady=4, sticky=tk.W)
    update_signature_label(asym_algo_combo)

    # Key Size
    key_size_label = ttk.Label(key_gen_tab, text="Key Size:")
    key_size_label.grid(row=4, column=0, padx=12, pady=4, sticky=tk.W)
    key_size_combo = ttk.Combobox(key_gen_tab, values=KEY_SIZES)
    key_size_combo.grid(row=4, column=1, padx=12, pady=4)
    key_size_combo.current(0)

    # Password
    ttk.Label(key_gen_tab, text="Password:").grid(row=5, column=0, padx=12, pady=4, sticky=tk.W)
    password_entry = ttk.Entry(key_gen_tab, show="*")
    password_entry.grid(row=5, column=1, padx=12, pady=4)
    password_entry.config(width=23)
    ttk.Label(key_gen_tab).grid(row=6)

    # Generate Keys button
    generate_btn = ttk.Button(key_gen_tab, text="Generate Keys")
    generate_btn.grid(row=7, column=0, columnspan=2, padx=10, pady=10)

    # Separator
    separator = ttk.Separator(key_gen_tab, orient="horizontal")
    separator.grid(row=8, column=0, columnspan=6, padx=0, pady=10, sticky="we")

    # Import Keys Label
    import_keys_label = ttk.Label(key_gen_tab, text="Import keys:")
    import_keys_label.grid(row=9, column=0, columnspan=2, padx=10, pady=10)

    def browse_private_key():
        file_path = filedialog.askopenfilename(filetypes=[("Key Files", "*.pem")])
        private_key_entry.delete(0, tk.END)
        private_key_entry.insert(tk.END, file_path)

    def browse_public_key():
        file_path = filedialog.askopenfilename(filetypes=[("Key Files", "*.pem")])
        public_key_entry.delete(0, tk.END)
        public_key_entry.insert(tk.END, file_path)

    # Private Key Label and Entry
    private_key_label = ttk.Label(key_gen_tab, text="Private Key:")
    private_key_label.grid(row=10, column=0, padx=12, pady=4, sticky=tk.W)
    private_key_entry = ttk.Entry(key_gen_tab)
    private_key_entry.grid(row=10, column=1, padx=12, pady=4)
    private_key_entry.config(width=23)
    browse_private_key_button = ttk.Button(key_gen_tab, text="Browse", command=browse_private_key)
    browse_private_key_button.grid(row=10, column=2, padx=4, pady=4)

    # Public Key Label and Entry
    public_key_label = ttk.Label(key_gen_tab, text="Public Key:")
    public_key_label.grid(row=11, column=0, padx=12, pady=4, sticky=tk.W)
    public_key_entry = ttk.Entry(key_gen_tab)
    public_key_entry.grid(row=11, column=1, padx=12, pady=4)
    public_key_entry.config(width=23)
    browse_public_key_button = ttk.Button(key_gen_tab, text="Browse", command=browse_public_key)
    browse_public_key_button.grid(row=11, column=2, padx=4, pady=4)

    # Import Keys button
    import_keys_button = ttk.Button(key_gen_tab, text="Import")
    import_keys_button.grid(row=12, column=0, columnspan=2, padx=10, pady=10)


def update_signature_label(asym_algo_combo):
    selected_asym_algo = ASYMMETRIC_ENCRYPTION_ALGORITHMS(asym_algo_combo.get())
    if selected_asym_algo == ASYMMETRIC_ENCRYPTION_ALGORITHMS.RSA:
        signature_label.config(text="RSA Signature")
    elif selected_asym_algo == ASYMMETRIC_ENCRYPTION_ALGORITHMS.ELGAMAL:
        signature_label.config(text="DSA Signature")


def keyoverview_tab_gen(notebook):
    keyoverview_tab = ttk.Frame(notebook)
    notebook.add(keyoverview_tab, text="Key Overview")


def send_msg_tab_gen(notebook):
    send_msg_tab = ttk.Frame(notebook)
    notebook.add(send_msg_tab, text="Send Message")

    # Message
    message_label = ttk.Label(send_msg_tab, text="Message:")
    message_label.grid(row=0, column=0, padx=12, pady=4, sticky=tk.W)
    message_text = tk.Text(send_msg_tab, height=5, width=30)
    message_text.grid(row=0, column=1, padx=12, pady=4, sticky="we")

    # Email
    email_label = ttk.Label(send_msg_tab, text="Email:")
    email_label.grid(row=1, column=0, padx=12, pady=4, sticky=tk.W)
    email_entry = ttk.Entry(send_msg_tab)
    email_entry.grid(row=1, column=1, padx=12, pady=4)

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
    symmetric_algo_combo = ttk.Combobox(send_msg_tab, values=[algorithm.value for algorithm in SYMMETRIC_ENCRYPTION_ALGORITHMS])
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


def receive_msg_tab_gen(notebook):
    receive_msg_tab = ttk.Frame(notebook)
    notebook.add(receive_msg_tab, text="Receive message")

    def browse_receive_message():
        file_path = filedialog.askopenfilename(filetypes=[("Key Files", "*.pem")])
        receive_msg_entry.delete(0, tk.END)
        receive_msg_entry.insert(tk.END, file_path)

    # Message path
    receive_msg_label = ttk.Label(receive_msg_tab, text="Message path:")
    receive_msg_label.grid(row=1, column=0, padx=12, pady=4, sticky=tk.W)
    receive_msg_entry = ttk.Entry(receive_msg_tab)
    receive_msg_entry.grid(row=1, column=1, padx=12, pady=4)
    receive_msg_entry.config(width=23)
    browse_private_key_button = ttk.Button(receive_msg_tab, text="Browse", command=browse_receive_message)
    browse_private_key_button.grid(row=1, column=2, padx=4, pady=4)

    # Open message to be received
    receive_msg_btn = ttk.Button(receive_msg_tab, text="Open")
    receive_msg_btn.grid(row=2, column=0, columnspan=2, padx=10, pady=10)


if __name__ == "__main__":
    gui_start()
