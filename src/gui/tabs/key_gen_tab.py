import tkinter as tk
from tkinter import ttk, filedialog
from src.gui.tabs.initial_login_tab import gui_start
from src.pgp.consts.consts import KEY_SIZES, ASYMMETRIC_ENCRYPTION_ALGORITHMS, AlgorithmType, Algorithm
from src.pgp.key.key import KeyPair
from src.pgp.key.key_serializer import KeySerializer, conclude_pem_algorithm
from src.pgp.key.manager import KeyManager
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


def import_keys_callback(user: User, import_keys_result_label: ttk.Label, path_private: str, path_public: str,
                         email: str, password: str, key_type: str):
    try:
        key_manager = KeyManager(user.user_name)
        key_type = AlgorithmType.ASYMMETRIC_ENCRYPTION if key_type == "Encryption" \
            else AlgorithmType.SIGNING if key_type == "Signature" else None
        key_manager.import_key_pair_from_pem(
            public_key_pem_path=path_public,
            private_key_pem_path=path_private,
            email=email,
            password=password,
            algorithm_type=key_type
        )
        import_keys_result_label.config(text="Successfully loaded keys!")
    except Exception as e:
        print(f"Error while exporting message: {e}")
        import_keys_result_label.config(text=f"Error while importing key: {e}")


def export_keys_callback(user: User, export_keys_result_label: ttk.Label, path: str,
                         password: str, email: str, key_type: str):
    try:
        algorithm_type = AlgorithmType.ASYMMETRIC_ENCRYPTION if key_type == "Encryption" \
            else AlgorithmType.SIGNING if key_type == "Signature" else None
        key_manager = KeyManager(user.user_name)
        key_pair = key_manager.get_key_pair_by_user_mail(email, password, algorithm_type=algorithm_type)
        key_serializer = KeySerializer()
        key_serializer.export_private_key_to_pem(
            key_pair=key_pair,
            private_key_pem_path=path+"/private_key_"+user.user_name+"_"+key_type+".pem"
        )
        key_serializer.export_public_key_to_pem(
            key_pair=key_pair,
            public_key_pem_path=path+"/public_key_"+user.user_name+"_"+key_type+".pem"
        )
        export_keys_result_label.config(text="Successfully exported public and private keys!")
    except Exception as e:
        print(f"Error while exporting keys: {e}")
        export_keys_result_label.config(text=f"Error while exporting keys: {e}")


def keyg_tab_gen(notebook, user, logout_callback):
    def update_signature_label(asym_algo_combo, signature_label):
        selected_asym_algo = asym_algo_combo.get()
        if selected_asym_algo == 'RSA':
            signature_label.config(text="RSA Signature")
        elif selected_asym_algo == 'ElGamal':
            signature_label.config(text="DSA Signature")

    def browse_import_private_key():
        file_path = filedialog.askopenfilename(filetypes=[("Key Files", "*.pem")])
        import_private_key_entry.delete(0, tk.END)
        if file_path:
            import_private_key_entry.insert(tk.END, file_path)
            import_keys_result_label.config(text="")
        else:
            import_keys_result_label.config(text="No .pem file selected.")

    def browse_import_public_key():
        file_path = filedialog.askopenfilename(filetypes=[("Key Files", "*.pem")])
        import_public_key_entry.delete(0, tk.END)
        if file_path:
            import_public_key_entry.insert(tk.END, file_path)
            import_keys_result_label.config(text="")
        else:
            import_keys_result_label.config(text="No .pem file selected.")

    def browse_export_key():
        directory = filedialog.askdirectory()
        export_key_entry.delete(0, tk.END)
        if directory:
            export_key_entry.insert(tk.END, directory)
            export_keys_result_label.config(text="")
        else:
            export_keys_result_label.config(text="No export folder selected.")

    def generate_keys_callback():
        generate_result_label.config(text="Keys generated successfully!")

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

    # Generate result label
    generate_result_label = ttk.Label(key_gen_tab, text="")
    generate_result_label.grid(row=8, column=0, columnspan=2)

    # Generate Keys button
    generate_btn = ttk.Button(key_gen_tab, text="Generate Keys")
    generate_btn.grid(row=9, column=0, columnspan=2, padx=10, pady=10)
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

    # Separator
    separator1 = ttk.Separator(key_gen_tab, orient="horizontal")
    separator1.grid(row=10, column=0, columnspan=3, padx=10, pady=10, sticky="we")

    # Import keys label
    import_keys_label = ttk.Label(key_gen_tab, text="Import keys:")
    import_keys_label.grid(row=11, column=0, columnspan=2, padx=10, pady=10)

    # Key Entry for Import Public Key
    import_public_key_label = ttk.Label(key_gen_tab, text="Public key:")
    import_public_key_label.grid(row=12, column=0, padx=12, pady=4, sticky=tk.W)
    import_public_key_entry = ttk.Entry(key_gen_tab)
    import_public_key_entry.grid(row=12, column=1, padx=12, pady=4)
    import_public_key_entry.config(width=23)

    # Browse button for Import Public Key
    browse_import_public_key_button = ttk.Button(key_gen_tab, text="Browse", command=browse_import_public_key)
    browse_import_public_key_button.grid(row=12, column=2, padx=4, pady=4)

    # Key Entry for Import Private Key
    import_private_key_label = ttk.Label(key_gen_tab, text="Private key:")
    import_private_key_label.grid(row=13, column=0, padx=12, pady=4, sticky=tk.W)
    import_private_key_entry = ttk.Entry(key_gen_tab)
    import_private_key_entry.grid(row=13, column=1, padx=12, pady=4)
    import_private_key_entry.config(width=23)

    # Browse button for Import Private Key
    browse_import_private_key_button = ttk.Button(key_gen_tab, text="Browse", command=browse_import_private_key)
    browse_import_private_key_button.grid(row=13, column=2, padx=4, pady=4)

    # Email label for Import
    import_keys_email_label = ttk.Label(key_gen_tab, text="Email:")
    import_keys_email_label.grid(row=14, column=0, padx=12, pady=4, sticky=tk.W)

    # Email entry for Import
    import_keys_email_entry = ttk.Entry(key_gen_tab)
    import_keys_email_entry.grid(row=14, column=1, padx=12, pady=4)
    import_keys_email_entry.config(width=23)

    # Password label for Import
    import_keys_password_label = ttk.Label(key_gen_tab, text="Password:")
    import_keys_password_label.grid(row=15, column=0, padx=12, pady=4, sticky=tk.W)

    # Password entry for Import
    import_keys_password_entry = ttk.Entry(key_gen_tab, show="*")
    import_keys_password_entry.grid(row=15, column=1, padx=12, pady=4)
    import_keys_password_entry.config(width=23)

    # Key type label for Import
    import_key_type_label = ttk.Label(key_gen_tab, text="Key type:")
    import_key_type_label.grid(row=16, column=0, padx=12, pady=4, sticky=tk.W)

    # Key type combobox for Import
    import_key_type_combo = ttk.Combobox(key_gen_tab, values=["Encryption", "Signature"], state="readonly")
    import_key_type_combo.grid(row=16, column=1, padx=12, pady=4)
    import_key_type_combo.config(width=21)
    import_key_type_combo.set("Encryption")

    # Import keys result label
    import_keys_result_label = ttk.Label(key_gen_tab, text="")
    import_keys_result_label.grid(row=17, column=0, columnspan=2)

    # Import Keys button
    import_keys_button = ttk.Button(key_gen_tab, text="Import")
    import_keys_button.grid(row=18, column=0, columnspan=2, padx=10, pady=10)
    import_keys_button.bind(
        "<Button-1>", lambda event: import_keys_callback(
            user,
            import_keys_result_label,
            path_public=import_public_key_entry.get(),
            path_private=import_private_key_entry.get(),
            email=import_keys_email_entry.get(),
            password=import_keys_password_entry.get(),
            key_type=import_key_type_combo.get()
        )
    )

    # Separator
    separator2 = ttk.Separator(key_gen_tab, orient="horizontal")
    separator2.grid(row=19, column=0, columnspan=3, padx=10, pady=10, sticky="we")

    # Export keys label
    export_keys_label = ttk.Label(key_gen_tab, text="Export keys:")
    export_keys_label.grid(row=20, column=0, columnspan=2, padx=10, pady=10)

    # Key Entry for Export
    export_key_label = ttk.Label(key_gen_tab, text="Export location:")
    export_key_label.grid(row=21, column=0, padx=12, pady=4, sticky=tk.W)
    export_key_entry = ttk.Entry(key_gen_tab)
    export_key_entry.grid(row=21, column=1, padx=12, pady=4)
    export_key_entry.config(width=23)

    # Browse button for Export
    browse_export_key_button = ttk.Button(key_gen_tab, text="Browse", command=browse_export_key)
    browse_export_key_button.grid(row=21, column=2, padx=4, pady=4)

    # Password label for Export
    export_password_label = ttk.Label(key_gen_tab, text="Password:")
    export_password_label.grid(row=22, column=0, padx=12, pady=4, sticky=tk.W)

    # Password entry for Export
    export_password_entry = ttk.Entry(key_gen_tab, show="*")
    export_password_entry.grid(row=22, column=1, padx=12, pady=4)
    export_password_entry.config(width=23)

    # Key selection label for Export
    export_email_selection_label = ttk.Label(key_gen_tab, text="Email:")
    export_email_selection_label.grid(row=23, column=0, padx=12, pady=4, sticky=tk.W)

    # Key selection combobox for Export
    export_email_selection_combo = ttk.Combobox(
        key_gen_tab,
        values=list(user.key_manager.get_private_keyring_dictionary().keys()),
        state="readonly"
    )
    export_email_selection_combo.grid(row=23, column=1, padx=12, pady=4)
    export_email_selection_combo.config(width=21)

    # Key type label for Export
    export_key_type_label = ttk.Label(key_gen_tab, text="Key type:")
    export_key_type_label.grid(row=24, column=0, padx=12, pady=4, sticky=tk.W)

    # Key type combobox for Export
    export_key_type_combo = ttk.Combobox(key_gen_tab, values=["Encryption", "Signature"], state="readonly")
    export_key_type_combo.grid(row=24, column=1, padx=12, pady=4)
    export_key_type_combo.config(width=21)
    export_key_type_combo.set("Encryption")

    # Export keys result label
    export_keys_result_label = ttk.Label(key_gen_tab, text="")
    export_keys_result_label.grid(row=25, column=0, columnspan=2)

    # Export Keys button
    export_keys_button = ttk.Button(key_gen_tab, text="Export")
    export_keys_button.grid(row=26, column=0, columnspan=2, padx=10, pady=10)
    export_keys_button.bind(
        "<Button-1>", lambda event: export_keys_callback(
            user,
            export_keys_result_label,
            path=export_key_entry.get(),
            password=export_password_entry.get(),
            email=export_email_selection_combo.get(),
            key_type=export_key_type_combo.get()
        )
    )

    # Logout
    logout_separator = ttk.Separator(key_gen_tab, orient="horizontal")
    logout_separator.grid(row=27, column=0, columnspan=3, padx=10, pady=10, sticky="we")
    username_label = ttk.Label(key_gen_tab, text=f"Current user: {user.user_name}")
    username_label.grid(row=28, column=0, padx=12, pady=4, sticky=tk.W)
    logout_btn = ttk.Button(key_gen_tab, text="Logout", command=logout_callback)
    logout_btn.grid(row=29, column=0, padx=12, pady=4, sticky=tk.W)
