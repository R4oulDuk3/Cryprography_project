import tkinter as tk
from tkinter import ttk, filedialog
from src.gui.tabs.initial_login_tab import gui_start
from src.pgp.consts.consts import KEY_SIZES, ASYMMETRIC_ENCRYPTION_ALGORITHMS, AlgorithmType, Algorithm
from src.pgp.user.user import User


def generate_keypair_callback(user: User, generate_result_label: ttk.Label, email: str, key_type: str, asym_algo: str,
                              key_size: int, password: str):
    if email == "":
        generate_result_label.config(text="Email input box is empty.")
        return
    elif password == "":
        generate_result_label.config(text="Password input box is empty.")
        return
    try:
        asym_algo = Algorithm.RSA if asym_algo == "RSA" else Algorithm.ELGAMAL if asym_algo == "ElGamal" else None
        key_type = AlgorithmType.ASYMMETRIC_ENCRYPTION if key_type == "Encryption" \
            else AlgorithmType.SIGNING if key_type == "Signature" else None
        user.key_manager.generate_key_pair(
            algorithm=asym_algo,
            key_size=key_size,
            password=password,
            email=email,
            algorithm_type=key_type
        )
        generate_result_label.config(text="Keys generated successfully!")
    except Exception as e:
        print(f"Error while generating keys: {e}")
        generate_result_label.config(text=f"Error while generating keys: {e}")


def keyg_tab_gen(notebook, user, logout_callback):
    def update_signature_label(asym_algo_combo, signature_label):
        selected_asym_algo = asym_algo_combo.get()
        if selected_asym_algo == 'RSA':
            signature_label.config(text="RSA Signature")
        elif selected_asym_algo == 'ElGamal':
            signature_label.config(text="DSA Signature")

    def browse_private_key():
        file_path = filedialog.askopenfilename(filetypes=[("Key Files", "*.pem")])
        private_key_entry.delete(0, tk.END)
        private_key_entry.insert(tk.END, file_path)

    def browse_public_key():
        file_path = filedialog.askopenfilename(filetypes=[("Key Files", "*.pem")])
        public_key_entry.delete(0, tk.END)
        public_key_entry.insert(tk.END, file_path)

    def generate_keys_callback():
        generate_result_label.config(text="Keys generated successfully!")

    def import_keys_callback():
        import_keys_result_label.config(text="Keys imported successfully!")

    key_gen_tab = ttk.Frame(notebook)
    notebook.add(key_gen_tab, text="Key Generation")

    # Generate a new key pair label
    generate_label = ttk.Label(key_gen_tab, text="Generate a new key pair:")
    generate_label.grid(row=0, column=0, columnspan=2, padx=10, pady=10)

    # Email label and entry
    email_label = ttk.Label(key_gen_tab, text="Email:")
    email_label.grid(row=1, column=0, padx=12, pady=4, sticky=tk.W)
    email_entry = ttk.Entry(key_gen_tab)
    email_entry.grid(row=1, column=1, padx=12, pady=4)
    email_entry.config(width=23)

    # Key Type label and combo box
    key_type_label = ttk.Label(key_gen_tab, text="Key Type:")
    key_type_label.grid(row=2, column=0, padx=12, pady=4, sticky=tk.W)
    key_type_combo = ttk.Combobox(key_gen_tab, values=["Encryption", "Signature"], state="readonly")
    key_type_combo.grid(row=2, column=1, padx=12, pady=4)
    key_type_combo.current(0)

    # Algorithm label and combo box
    asym_algo_label = ttk.Label(key_gen_tab, text="Asymmetric algorithm")
    asym_algo_label.grid(row=3, column=0, padx=12, pady=4, sticky=tk.W)
    asym_algo_combo = ttk.Combobox(
        key_gen_tab,
        values=[algorithm.value for algorithm in ASYMMETRIC_ENCRYPTION_ALGORITHMS],
        state="readonly"
    )
    asym_algo_combo.grid(row=3, column=1, padx=12, pady=4)
    asym_algo_combo.current(0)
    asym_algo_combo.bind("<<ComboboxSelected>>", lambda event: update_signature_label(asym_algo_combo, signature_label))

    # Signature label
    signature_type_label = ttk.Label(key_gen_tab, text="Signature type:")
    signature_type_label.grid(row=4, column=0, padx=12, pady=4, sticky=tk.W)
    signature_label = ttk.Label(key_gen_tab, text="")
    signature_label.grid(row=4, column=1, padx=12, pady=4, sticky=tk.W)
    update_signature_label(asym_algo_combo, signature_label)

    # Key Size label and combo box
    key_size_label = ttk.Label(key_gen_tab, text="Key Size:")
    key_size_label.grid(row=5, column=0, padx=12, pady=4, sticky=tk.W)
    key_size_combo = ttk.Combobox(key_gen_tab, values=KEY_SIZES, state="readonly")
    key_size_combo.grid(row=5, column=1, padx=12, pady=4)
    key_size_combo.current(0)

    # Password label and entry
    ttk.Label(key_gen_tab, text="Password:").grid(row=6, column=0, padx=12, pady=4, sticky=tk.W)
    password_entry = ttk.Entry(key_gen_tab, show="*")
    password_entry.grid(row=6, column=1, padx=12, pady=4)
    password_entry.config(width=23)
    ttk.Label(key_gen_tab).grid(row=7)

    # Generate Keys button
    generate_btn = ttk.Button(key_gen_tab, text="Generate Keys")
    generate_btn.grid(row=8, column=0, columnspan=2, padx=10, pady=10)
    generate_btn.bind(
        "<Button-1>", lambda event: generate_keypair_callback(
            user,
            generate_result_label,
            email=email_entry.get(),
            key_type=key_type_combo.get(),
            asym_algo=asym_algo_combo.get(),
            key_size=int(key_size_combo.get()),
            password=password_entry.get()
        )
    )

    # Generate result label
    generate_result_label = ttk.Label(key_gen_tab, text="")
    generate_result_label.grid(row=9, column=0, columnspan=2)

    # Import keys label
    import_keys_label = ttk.Label(key_gen_tab, text="Import keys:")
    import_keys_label.grid(row=10, column=0, columnspan=2, padx=10, pady=10)

    # Private Key
    private_key_label = ttk.Label(key_gen_tab, text="Private Key:")
    private_key_label.grid(row=11, column=0, padx=12, pady=4, sticky=tk.W)
    private_key_entry = ttk.Entry(key_gen_tab)
    private_key_entry.grid(row=11, column=1, padx=12, pady=4)
    private_key_entry.config(width=23)

    # Browse button
    browse_private_key_button = ttk.Button(key_gen_tab, text="Browse", command=browse_private_key)
    browse_private_key_button.grid(row=11, column=2, padx=4, pady=4)

    # Public Key
    public_key_label = ttk.Label(key_gen_tab, text="Public Key:")
    public_key_label.grid(row=12, column=0, padx=12, pady=4, sticky=tk.W)
    public_key_entry = ttk.Entry(key_gen_tab)
    public_key_entry.grid(row=12, column=1, padx=12, pady=4)
    public_key_entry.config(width=23)

    # Browse button
    browse_public_key_button = ttk.Button(key_gen_tab, text="Browse", command=browse_public_key)
    browse_public_key_button.grid(row=12, column=2, padx=4, pady=4)

    # Import Keys button
    import_keys_button = ttk.Button(key_gen_tab, text="Import", command=import_keys_callback)
    import_keys_button.grid(row=13, column=0, columnspan=2, padx=10, pady=10)

    # Import keys result label
    import_keys_result_label = ttk.Label(key_gen_tab, text="")
    import_keys_result_label.grid(row=14, column=0, columnspan=2)

    # Logout
    logout_separator = ttk.Separator(key_gen_tab, orient="horizontal")
    logout_separator.grid(row=15, column=0, columnspan=12, padx=0, pady=10, sticky="we")
    username_label = ttk.Label(key_gen_tab, text=f"Current user: {user.user_name}")
    username_label.grid(row=16, column=0, padx=12, pady=4, sticky=tk.W)
    logout_btn = ttk.Button(key_gen_tab, text="Logout", command=logout_callback)
    logout_btn.grid(row=17, column=0, padx=12, pady=4, sticky=tk.W)
