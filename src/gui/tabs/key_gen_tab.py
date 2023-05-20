import tkinter as tk
from tkinter import ttk, filedialog
from src.pgp.consts.consts import KEY_SIZES, ASYMMETRIC_ENCRYPTION_ALGORITHMS


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
    asym_algo_combo = ttk.Combobox(key_gen_tab,
                                   values=[algorithm.value for algorithm in ASYMMETRIC_ENCRYPTION_ALGORITHMS])
    asym_algo_combo.grid(row=2, column=1, padx=12, pady=4)
    asym_algo_combo.current(0)
    asym_algo_combo.bind("<<ComboboxSelected>>", lambda event: update_signature_label(asym_algo_combo, signature_label))

    # Signature
    signature_type_label = ttk.Label(key_gen_tab, text="Signature type:")
    signature_type_label.grid(row=3, column=0, padx=12, pady=4, sticky=tk.W)
    signature_label = ttk.Label(key_gen_tab, text="")
    signature_label.grid(row=3, column=1, padx=12, pady=4, sticky=tk.W)
    update_signature_label(asym_algo_combo, signature_label)

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
    separator.grid(row=8, column=0, columnspan=12, padx=0, pady=10, sticky="we")

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

def update_signature_label(asym_algo_combo, signature_label):
    selected_asym_algo = asym_algo_combo.get()
    if selected_asym_algo == 'RSA':
        signature_label.config(text="RSA Signature")
    elif selected_asym_algo == 'ElGamal':
        signature_label.config(text="DSA Signature")