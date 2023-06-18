import tkinter as tk
from tkinter import ttk, filedialog
from tkinter.font import Font
from datetime import datetime
from src.pgp.consts.consts import KEY_SIZES, ASYMMETRIC_ENCRYPTION_ALGORITHMS, AlgorithmType, Algorithm
from src.pgp.key.key_serializer import KeySerializer, conclude_asymmetric_algorithm_from_pem
from src.pgp.key.manager import KeyManager
from src.pgp.user.user import User
import traceback


def generate_keypair_callback(user: User, generate_result_label: ttk.Label, email: str, key_type: str, asym_algo: str,
                              key_size: int, password: str, export_email_selection_combo: ttk.Combobox,
                              delete_email_selection_combo: ttk.Combobox):
    if email == "":
        generate_result_label.config(text="Email input box is empty.", foreground="black")
        return
    elif password == "":
        generate_result_label.config(text="Password input box is empty.", foreground="black")
        return
    try:
        key_type = AlgorithmType.ASYMMETRIC_ENCRYPTION if key_type == "Encryption" \
            else AlgorithmType.SIGNING if key_type == "Signature" else None

        kg_algorithm = None
        if asym_algo == "RSA":
            kg_algorithm = Algorithm.RSA
        elif asym_algo == "ElGamal":
            if key_type == AlgorithmType.SIGNING:
                kg_algorithm = Algorithm.DSA
            elif key_type == AlgorithmType.ASYMMETRIC_ENCRYPTION:
                kg_algorithm = Algorithm.ELGAMAL
            else:
                kg_algorithm = None
        user.key_manager.generate_key_pair(
            algorithm=kg_algorithm,
            key_size=key_size,
            password=password,
            email=email,
            algorithm_type=key_type
        )
        generated_key_type = "Encryption" if key_type == AlgorithmType.ASYMMETRIC_ENCRYPTION else "Signature"
        generated_key_algorithm = None
        if kg_algorithm == Algorithm.RSA:
            generated_key_algorithm = "RSA"
        elif kg_algorithm == Algorithm.DSA:
            generated_key_algorithm = "DSA"
        elif kg_algorithm == Algorithm.ELGAMAL:
            generated_key_algorithm = "ElGamal"
        timestamp = datetime.now().strftime("%H:%M:%S")
        generate_result_label.config(
            text=f"Successfully generated {generated_key_type} keys with {generated_key_algorithm} algorithm. TS({timestamp})!",
            foreground="green"
        )
        update_email_list(user, export_email_selection_combo, delete_email_selection_combo)
    except Exception as e:
        print(f"Error while generating keys: {e}")
        generate_result_label.config(text=f"Error while generating keys: {e}", foreground="red")


def update_email_list(user, export_email_selection_combo: ttk.Combobox, delete_email_selection_combo: ttk.Combobox):
    emails = user.key_manager.get_all_private_keyring_mails()
    export_email_selection_combo['values'] = emails
    delete_email_selection_combo['values'] = emails


def import_keys_callback(user: User, import_keys_result_label: ttk.Label, path_private: str, path_public: str,
                         email: str, password: str, key_type: str, export_email_selection_combo: ttk.Combobox,
                         delete_email_selection_combo: ttk.Combobox):
    if path_private == "" or path_public == "":
        import_keys_result_label.config(text="No location selected!", foreground="black")
        return
    try:
        key_manager = user.key_manager
        key_type = AlgorithmType.ASYMMETRIC_ENCRYPTION if key_type == "Encryption" \
            else AlgorithmType.SIGNING if key_type == "Signature" else None
        key_manager.import_key_pair_from_pem(
            public_key_pem_path=path_public,
            private_key_pem_path=path_private,
            email=email,
            password=password,
            algorithm_type=key_type
        )
        update_email_list(user, export_email_selection_combo, delete_email_selection_combo)
        generated_key_type = "Encryption" if key_type == AlgorithmType.ASYMMETRIC_ENCRYPTION else "Signature"
        import_keys_result_label.config(
            text=f"Successfully imported {generated_key_type} keys for email: {email}!",
            foreground="green"
        )
    except Exception as e:
        print(f"Error while exporting message: {e}")
        import_keys_result_label.config(text=f"Error while importing key: {e}", foreground="red")


def export_keys_callback(user: User, export_keys_result_label: ttk.Label, path: str,
                         password: str, email: str, key_type: str):
    if path == "":
        export_keys_result_label.config(text="No location selected!", foreground="black")
        return
    try:
        algorithm_type = AlgorithmType.ASYMMETRIC_ENCRYPTION if key_type == "Encryption" \
            else AlgorithmType.SIGNING if key_type == "Signature" else None
        key_manager = KeyManager(user.user_name)
        key_pair = key_manager.get_key_pair_by_user_mail(email, password, algorithm_type=algorithm_type)
        key_serializer = KeySerializer()
        key_serializer.export_private_key_to_pem(
            key_pair=key_pair,
            private_key_pem_path=path + "/private_key_" + user.user_name + "_" + key_type + "_" + email + ".pem"
        )
        key_serializer.export_public_key_to_pem(
            key_pair=key_pair,
            public_key_pem_path=path + "/public_key_" + user.user_name + "_" + key_type + "_" + email + ".pem"
        )
        export_keys_result_label.config(
            text=f"Successfully exported public and private keys for {user.user_name} ({email})!", foreground="green")
    except Exception as e:
        print(f"Error while exporting keys: {e}")
        export_keys_result_label.config(text=f"Error while exporting keys: {e}", foreground="red")


def delete_keys_callback(user: User, delete_keys_result_label: ttk.Label, delete_email_selection_combo: ttk.Combobox,
                         export_email_selection_combo: ttk.Combobox,
                         password: str, email: str, key_type: str):
    try:
        user.key_manager.delete_key_pair_by_user_email(email=email,
                                                       password=password,
                                                       algorithm_type=AlgorithmType(key_type))
        update_email_list(user, export_email_selection_combo, delete_email_selection_combo)
        print(f"Successfully deleted key [{key_type}] for {user.user_name} ({email})!")
        delete_keys_result_label.config(text=
                                        f"Successfully deleted key [{key_type}] for {user.user_name} ({email})!",
                                        foreground="green")

    except Exception as e:
        print(f"Error while deleting keys: {e}")
        delete_keys_result_label.config(text=f"Error while deleting keys: {e}", foreground="red")
        traceback.print_exc()


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
            import_keys_result_label.config(text="No .pem file selected.", foreground="black")

    def browse_import_public_key():
        file_path = filedialog.askopenfilename(filetypes=[("Key Files", "*.pem")])
        import_public_key_entry.delete(0, tk.END)
        if file_path:
            import_public_key_entry.insert(tk.END, file_path)
            import_keys_result_label.config(text="")
        else:
            import_keys_result_label.config(text="No .pem file selected.", foreground="black")

    def browse_export_key():
        directory = filedialog.askdirectory()
        export_key_entry.delete(0, tk.END)
        if directory:
            export_key_entry.insert(tk.END, directory)
            export_keys_result_label.config(text="")
        else:
            export_keys_result_label.config(text="No export folder selected.", foreground="black")

    key_gen_tab = ttk.Frame(notebook)
    notebook.add(key_gen_tab, text="Key Generation")

    canvas = tk.Canvas(key_gen_tab)
    scrollbar = ttk.Scrollbar(key_gen_tab, orient="vertical", command=canvas.yview)
    scrollable_frame = ttk.Frame(canvas)

    # GENERATE NEW KEY PAIR
    header_font = Font(size=15, weight="bold")
    generate_label = ttk.Label(scrollable_frame, text="Generate a new key pair:", font=header_font)
    generate_label.grid(row=0, column=0, columnspan=2, padx=10, pady=10)

    email_label = ttk.Label(scrollable_frame, text="Email:")
    email_label.grid(row=1, column=0, padx=12, pady=4, sticky=tk.W)
    email_entry = ttk.Entry(scrollable_frame)
    email_entry.grid(row=1, column=1, padx=12, pady=4)
    email_entry.config(width=23)

    key_type_label = ttk.Label(scrollable_frame, text="Key Type:")
    key_type_label.grid(row=2, column=0, padx=12, pady=4, sticky=tk.W)
    key_type_combo = ttk.Combobox(scrollable_frame, values=["Encryption", "Signature"], state="readonly")
    key_type_combo.grid(row=2, column=1, padx=12, pady=4)
    key_type_combo.current(0)

    asym_algo_label = ttk.Label(scrollable_frame, text="Asymmetric algorithm")
    asym_algo_label.grid(row=3, column=0, padx=12, pady=4, sticky=tk.W)
    asym_algo_combo = ttk.Combobox(
        scrollable_frame,
        values=[algorithm.value for algorithm in ASYMMETRIC_ENCRYPTION_ALGORITHMS],
        state="readonly"
    )
    asym_algo_combo.grid(row=3, column=1, padx=12, pady=4)
    asym_algo_combo.current(0)
    asym_algo_combo.bind("<<ComboboxSelected>>", lambda event: update_signature_label(asym_algo_combo, signature_label))

    signature_type_label = ttk.Label(scrollable_frame, text="Signature type:")
    signature_type_label.grid(row=4, column=0, padx=12, pady=4, sticky=tk.W)
    signature_label = ttk.Label(scrollable_frame, text="")
    signature_label.grid(row=4, column=1, padx=12, pady=4, sticky=tk.W)
    update_signature_label(asym_algo_combo, signature_label)

    key_size_label = ttk.Label(scrollable_frame, text="Key Size:")
    key_size_label.grid(row=5, column=0, padx=12, pady=4, sticky=tk.W)
    key_size_combo = ttk.Combobox(scrollable_frame, values=KEY_SIZES, state="readonly")
    key_size_combo.grid(row=5, column=1, padx=12, pady=4)
    key_size_combo.current(0)

    generate_key_pair_password_label = ttk.Label(scrollable_frame, text="Password:")
    generate_key_pair_password_label.grid(row=6, column=0, padx=12, pady=4, sticky=tk.W)
    password_entry = ttk.Entry(scrollable_frame, show="*")
    password_entry.grid(row=6, column=1, padx=12, pady=4)
    password_entry.config(width=23)

    generate_result_label = ttk.Label(scrollable_frame, text="", wraplength=320)
    generate_result_label.grid(row=8, column=0, columnspan=2)

    generate_btn = ttk.Button(scrollable_frame, text="Generate Keys")
    generate_btn.grid(row=9, column=0, columnspan=2, padx=10, pady=10)
    generate_btn.bind(
        "<Button-1>", lambda event: generate_keypair_callback(
            user=user,
            generate_result_label=generate_result_label,
            email=email_entry.get(),
            key_type=key_type_combo.get(),
            asym_algo=asym_algo_combo.get(),
            key_size=int(key_size_combo.get()),
            password=password_entry.get(),
            export_email_selection_combo=export_email_selection_combo,
            delete_email_selection_combo=delete_email_selection_combo
        )
    )

    separator1 = ttk.Separator(scrollable_frame, orient="horizontal")
    separator1.grid(row=10, column=0, columnspan=3, padx=0, pady=10, sticky="we")

    # IMPORT KEYS
    import_keys_label = ttk.Label(scrollable_frame, text="Import keys:", font=header_font)
    import_keys_label.grid(row=11, column=0, columnspan=2, padx=10, pady=10)

    import_public_key_label = ttk.Label(scrollable_frame, text="Public key:")
    import_public_key_label.grid(row=12, column=0, padx=12, pady=4, sticky=tk.W)
    import_public_key_entry = ttk.Entry(scrollable_frame)
    import_public_key_entry.grid(row=12, column=1, padx=12, pady=4)
    import_public_key_entry.config(width=23)

    browse_import_public_key_button = ttk.Button(scrollable_frame, text="Browse", command=browse_import_public_key)
    browse_import_public_key_button.grid(row=12, column=2, padx=4, pady=4)

    import_private_key_label = ttk.Label(scrollable_frame, text="Private key:")
    import_private_key_label.grid(row=13, column=0, padx=12, pady=4, sticky=tk.W)
    import_private_key_entry = ttk.Entry(scrollable_frame)
    import_private_key_entry.grid(row=13, column=1, padx=12, pady=4)
    import_private_key_entry.config(width=23)

    browse_import_private_key_button = ttk.Button(scrollable_frame, text="Browse", command=browse_import_private_key)
    browse_import_private_key_button.grid(row=13, column=2, padx=4, pady=4)

    import_keys_email_label = ttk.Label(scrollable_frame, text="Email:")
    import_keys_email_label.grid(row=14, column=0, padx=12, pady=4, sticky=tk.W)

    import_keys_email_entry = ttk.Entry(scrollable_frame)
    import_keys_email_entry.grid(row=14, column=1, padx=12, pady=4)
    import_keys_email_entry.config(width=23)

    import_keys_password_label = ttk.Label(scrollable_frame, text="Password:")
    import_keys_password_label.grid(row=15, column=0, padx=12, pady=4, sticky=tk.W)
    import_keys_password_entry = ttk.Entry(scrollable_frame, show="*")
    import_keys_password_entry.grid(row=15, column=1, padx=12, pady=4)
    import_keys_password_entry.config(width=23)

    import_key_type_label = ttk.Label(scrollable_frame, text="Key type:")
    import_key_type_label.grid(row=16, column=0, padx=12, pady=4, sticky=tk.W)
    import_key_type_combo = ttk.Combobox(scrollable_frame, values=["Encryption", "Signature"], state="readonly")
    import_key_type_combo.grid(row=16, column=1, padx=12, pady=4)
    import_key_type_combo.config(width=21)
    import_key_type_combo.set("Encryption")

    import_keys_result_label = ttk.Label(scrollable_frame, text="", wraplength=320)
    import_keys_result_label.grid(row=17, column=0, columnspan=2)

    import_keys_button = ttk.Button(scrollable_frame, text="Import")
    import_keys_button.grid(row=18, column=0, columnspan=2, padx=10, pady=10)
    import_keys_button.bind(
        "<Button-1>", lambda event: import_keys_callback(
            user,
            import_keys_result_label,
            path_public=import_public_key_entry.get(),
            path_private=import_private_key_entry.get(),
            email=import_keys_email_entry.get(),
            password=import_keys_password_entry.get(),
            key_type=import_key_type_combo.get(),
            export_email_selection_combo=export_email_selection_combo,
            delete_email_selection_combo=delete_email_selection_combo,
        )
    )

    separator2 = ttk.Separator(scrollable_frame, orient="horizontal")
    separator2.grid(row=19, column=0, columnspan=3, padx=0, pady=10, sticky="we")

    # EXPORT KEYS
    export_keys_label = ttk.Label(scrollable_frame, text="Export keys:", font=header_font)
    export_keys_label.grid(row=20, column=0, columnspan=2, padx=10, pady=10)

    export_key_label = ttk.Label(scrollable_frame, text="Export location:")
    export_key_label.grid(row=21, column=0, padx=12, pady=4, sticky=tk.W)
    export_key_entry = ttk.Entry(scrollable_frame)
    export_key_entry.grid(row=21, column=1, padx=12, pady=4)
    export_key_entry.config(width=23)

    browse_export_key_button = ttk.Button(scrollable_frame, text="Browse", command=browse_export_key)
    browse_export_key_button.grid(row=21, column=2, padx=4, pady=4)

    export_password_label = ttk.Label(scrollable_frame, text="Password:")
    export_password_label.grid(row=22, column=0, padx=12, pady=4, sticky=tk.W)
    export_password_entry = ttk.Entry(scrollable_frame, show="*")
    export_password_entry.grid(row=22, column=1, padx=12, pady=4)
    export_password_entry.config(width=23)

    export_email_selection_label = ttk.Label(scrollable_frame, text="Email:")
    export_email_selection_label.grid(row=23, column=0, padx=12, pady=4, sticky=tk.W)
    export_email_selection_combo = ttk.Combobox(
        scrollable_frame,
        values=user.key_manager.get_all_private_keyring_mails(),
        state="readonly"
    )
    export_email_selection_combo.grid(row=23, column=1, padx=12, pady=4)
    export_email_selection_combo.config(width=21)

    export_key_type_label = ttk.Label(scrollable_frame, text="Key type:")
    export_key_type_label.grid(row=24, column=0, padx=12, pady=4, sticky=tk.W)
    export_key_type_combo = ttk.Combobox(scrollable_frame, values=["Encryption", "Signature"], state="readonly")
    export_key_type_combo.grid(row=24, column=1, padx=12, pady=4)
    export_key_type_combo.config(width=21)
    export_key_type_combo.set("Encryption")

    export_keys_result_label = ttk.Label(scrollable_frame, text="", wraplength=320)
    export_keys_result_label.grid(row=25, column=0, columnspan=2)
    export_keys_button = ttk.Button(scrollable_frame, text="Export")
    export_keys_button.grid(row=26, column=0, columnspan=2, padx=10, pady=10)
    export_keys_button.bind(
        "<Button-1>", lambda event: export_keys_callback(
            user,
            export_keys_result_label,
            path=export_key_entry.get(),
            password=export_password_entry.get(),
            email=export_email_selection_combo.get(),
            key_type=export_key_type_combo.get(),

        )
    )

    separator3 = ttk.Separator(scrollable_frame, orient="horizontal")
    separator3.grid(row=27, column=0, columnspan=3, padx=0, pady=10, sticky="we")


    # DELETE KEYS
    delete_keys_label = ttk.Label(scrollable_frame, text="Delete keys:", font=header_font)
    delete_keys_label.grid(row=28, column=0, columnspan=2, padx=10, pady=10)

    delete_email_selection_label = ttk.Label(scrollable_frame, text="Email:")
    delete_email_selection_label.grid(row=29, column=0, padx=12, pady=4, sticky=tk.W)
    delete_email_selection_combo = ttk.Combobox(
        scrollable_frame,
        values=user.key_manager.get_all_private_keyring_mails(),
        state="readonly"
    )
    delete_email_selection_combo.grid(row=29, column=1, padx=12, pady=4)
    delete_email_selection_combo.config(width=21)

    delete_key_type_label = ttk.Label(scrollable_frame, text="Key Type:")
    delete_key_type_label.grid(row=30, column=0, padx=12, pady=4, sticky=tk.W)
    delete_key_type_combo = ttk.Combobox(
        scrollable_frame,
        values = [AlgorithmType.ASYMMETRIC_ENCRYPTION.value, AlgorithmType.SIGNING.value],
        state="readonly"
    )
    delete_key_type_combo.grid(row=30, column=1, padx=12, pady=4)
    delete_key_type_combo.current(0)

    delete_password_label = ttk.Label(scrollable_frame, text="Password:")
    delete_password_label.grid(row=31, column=0, padx=12, pady=4, sticky=tk.W)
    delete_password_entry = ttk.Entry(scrollable_frame, show="*")
    delete_password_entry.grid(row=31, column=1, padx=12, pady=4)
    delete_password_entry.config(width=23)

    delete_keys_result_label = ttk.Label(scrollable_frame, text="", wraplength=320)
    delete_keys_result_label.grid(row=32, column=0, columnspan=2)
    delete_keys_button = ttk.Button(scrollable_frame, text="Delete")
    delete_keys_button.grid(row=33, column=0, columnspan=2, padx=10, pady=10)
    delete_keys_button.bind(
        "<Button-1>", lambda event: delete_keys_callback(
            user,
            delete_keys_result_label,
            password=delete_password_entry.get(),
            email=delete_email_selection_combo.get(),
            key_type=delete_key_type_combo.get(),
            delete_email_selection_combo=delete_email_selection_combo,
            export_email_selection_combo=export_email_selection_combo,
        )
    )

    logout_separator = ttk.Separator(scrollable_frame, orient="horizontal")
    logout_separator.grid(row=34, column=0, columnspan=3, padx=0, pady=10, sticky="we")
    username_label = ttk.Label(scrollable_frame, text=f"Current user: {user.user_name}")
    username_label.grid(row=35, column=0, padx=12, pady=4, sticky=tk.W)
    logout_btn = ttk.Button(scrollable_frame, text="Logout", command=logout_callback)
    logout_btn.grid(row=36, column=0, padx=12, pady=4, sticky=tk.W)

    scrollable_frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
    canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
    canvas.configure(yscrollcommand=scrollbar.set)
    canvas.pack(side="left", fill="both", expand=True)
    scrollbar.pack(side="right", fill="y")

    def _on_mousewheel(event):
        canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")

    key_gen_tab.bind_all("<MouseWheel>", _on_mousewheel)
