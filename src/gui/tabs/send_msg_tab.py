import random
import tkinter as tk
from tkinter import filedialog
from tkinter import ttk

from src.pgp.consts.consts import SYMMETRIC_ENCRYPTION_ALGORITHMS, Algorithm, AlgorithmType
from src.pgp.key.key import PublicKey
from src.pgp.message.message import PGPMessage
from src.pgp.user.user import User


def select_directory(directory_label: ttk.Label):
    directory = filedialog.askdirectory()
    if directory:
        directory_label.config(text=directory)
    else:
        directory_label.config(text="No directory selected", foreground="black")


def send_message_callback(user: User,
                          message_text: tk.Text,
                          to_email_combobox: ttk.Combobox,
                          from_email_combobox: ttk.Combobox,
                          symmetric_algo_combobox: ttk.Combobox,
                          encrypt_var: tk.BooleanVar,
                          sign_var: tk.BooleanVar,
                          password_entry: tk.Entry,
                          directory_label: ttk.Label,
                          result_label: ttk.Label):
    try:
        message = message_text.get("1.0", tk.END)
        to_email = to_email_combobox.get()
        from_email = from_email_combobox.get()
        directory = directory_label["text"]
        password = password_entry.get()
        password = password.replace("\n", "")
        symmetric_algo = symmetric_algo_combobox.get()
        encrypt = encrypt_var.get()
        sign = sign_var.get()
        if not encrypt:
            symmetric_algo = None
        else:
            symmetric_algo = Algorithm(symmetric_algo)
        print(f"|{password}|", len(password))
        pgp_message_str: str = user.sender.prepare_message_with_mails(plaintext=message,
                                                                      sender_mail=from_email,
                                                                      receiver_mail=to_email,
                                                                      password=password,
                                                                      symmetric_encryption_algorithm=symmetric_algo,
                                                                      sign=sign,
                                                                      encrypt=encrypt
                                                                      )
        user.sender.send_message(pgp_message_str=pgp_message_str,
                                 message_path=f"{directory}/{from_email}_{to_email}_{random.randint(0, 10000)}.pgp")
        result_label.config(text="Message sent successfully", foreground="green")
    except Exception as e:
        print(f"Error while sending message: {e}")
        result_label.config(text=f"Error while sending message: {e}", foreground="red")


def set_key_id_label(email_combobox: ttk.Combobox,
                     user: User,
                     key_selected_label: ttk.Label,
                     algorithm_type: AlgorithmType):
    public_key: PublicKey = user.key_manager.get_public_key_by_user_email(email=email_combobox.get(),
                                                                          algorithm_type=algorithm_type)
    if algorithm_type == AlgorithmType.ASYMMETRIC_ENCRYPTION:
        key_id = user.key_manager.get_signing_key_id_by_user_email(email=email_combobox.get())
    elif algorithm_type == AlgorithmType.SIGNING:
        key_id = user.key_manager.get_encryption_key_id_by_user_email(email=email_combobox.get())
    else:
        raise Exception("Invalid algorithm type")
    key_selected_label.config(
        text=f"Algorithm use: {algorithm_type.value},"
             f" Algorithm: {public_key.get_algorithm().value},"
             f" Key ID: {key_id[0:32]}..."
    )


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
    from_email_combobox = ttk.Combobox(send_msg_tab,
                                       values=user.key_manager.get_all_private_keyring_mails(),
                                       state="readonly")
    from_email_combobox.grid(row=1, column=1, padx=12, pady=4)

    from_email_key_selected_label = ttk.Label(send_msg_tab, text="")
    from_email_key_selected_label.grid(row=1, column=3, padx=12, pady=4, sticky=tk.W)

    from_email_combobox.bind("<<ComboboxSelected>>", lambda event: set_key_id_label(
        email_combobox=from_email_combobox,
        key_selected_label=from_email_key_selected_label,
        user=user,
        algorithm_type=AlgorithmType.ASYMMETRIC_ENCRYPTION))

    # Password
    password_label = ttk.Label(send_msg_tab, text="Password:")
    password_label.grid(row=2, column=0, padx=12, pady=4, sticky=tk.W)
    password_entry = ttk.Entry(send_msg_tab, show="*")
    password_entry.grid(row=2, column=1, padx=12, pady=4)
    password_entry.config(width=23)

    # To Email
    to_email_label = ttk.Label(send_msg_tab, text="To Email:")
    to_email_label.grid(row=3, column=0, padx=12, pady=4, sticky=tk.W)
    to_email_combobox = ttk.Combobox(send_msg_tab, values=user.key_manager.get_all_public_keyring_mails(),
                                     state="readonly")

    to_email_combobox.grid(row=3, column=1, padx=12, pady=4)

    to_email_key_selected_label = ttk.Label(send_msg_tab, text="")
    to_email_key_selected_label.grid(row=3, column=3, padx=12, pady=4, sticky=tk.W)
    to_email_combobox.bind("<<ComboboxSelected>>", lambda event: set_key_id_label(
        email_combobox=to_email_combobox,
        key_selected_label=to_email_key_selected_label,
        user=user,
        algorithm_type=AlgorithmType.SIGNING))

    # Symmetric Algorithm
    symmetric_algo_label = ttk.Label(send_msg_tab, text="Symmetric Algorithm:")
    symmetric_algo_label.grid(row=5, column=0, padx=12, pady=4, sticky=tk.W)
    symmetric_algo_combo = ttk.Combobox(send_msg_tab,
                                        values=[algorithm.value for algorithm in SYMMETRIC_ENCRYPTION_ALGORITHMS],
                                        state="disabled")
    symmetric_algo_combo.grid(row=5, column=1, padx=12, pady=4)

    def set_symmetric_algo_combo_state(enabled: bool):
        if enabled:
            symmetric_algo_combo.config(state="readonly")
        else:
            symmetric_algo_combo.config(state="disabled")

    # Encrypt
    encrypt_label = ttk.Label(send_msg_tab, text="Encrypt:")
    encrypt_label.grid(row=4, column=0, padx=12, pady=4, sticky=tk.W)
    encrypt_var = tk.BooleanVar()
    encrypt_var.set(True)
    encrypt_checkbox = ttk.Checkbutton(send_msg_tab, variable=encrypt_var, command=lambda:
    set_symmetric_algo_combo_state(encrypt_var.get()))
    encrypt_checkbox.grid(row=4, column=1, padx=12, pady=4)

    # Sign
    sign_label = ttk.Label(send_msg_tab, text="Sign message:")
    sign_label.grid(row=6, column=0, padx=12, pady=4, sticky=tk.W)
    sign_var = tk.BooleanVar()
    sign_var.set(True)
    sign_checkbox = ttk.Checkbutton(send_msg_tab, variable=sign_var)
    sign_checkbox.grid(row=6, column=1, padx=12, pady=4)

    # Directory Label
    directory_label = ttk.Label(send_msg_tab, text="No directory selected", wraplength=300)
    directory_label.grid(row=7, column=1, padx=12, pady=4, sticky=tk.W)

    # Select Directory Button
    select_directory_button = ttk.Button(send_msg_tab, text="Select Directory",
                                         command=lambda: select_directory(directory_label))
    select_directory_button.grid(row=7, column=0, padx=12, pady=4, sticky=tk.W)

    # Result
    result_label = ttk.Label(send_msg_tab, text="", wraplength=300)
    result_label.grid(row=9, column=1, padx=12, pady=4, sticky=tk.W)

    # Send Message button
    send_msg_btn = ttk.Button(send_msg_tab, text="Send Message")
    send_msg_btn.grid(row=8, column=0, columnspan=2, padx=10, pady=10)
    send_msg_btn.bind("<Button-1>", lambda event: send_message_callback(
        message_text=message_text,
        from_email_combobox=from_email_combobox,
        password_entry=password_entry,
        to_email_combobox=to_email_combobox,
        symmetric_algo_combobox=symmetric_algo_combo,
        encrypt_var=encrypt_var,
        sign_var=sign_var,
        directory_label=directory_label,
        user=user,
        result_label=result_label))

    # Logout
    logout_separator = ttk.Separator(send_msg_tab, orient="horizontal")
    logout_separator.grid(row=10, column=0, columnspan=12, padx=0, pady=10, sticky="we")
    username_label = ttk.Label(send_msg_tab, text=f"Current user: {user.user_name}")
    username_label.grid(row=11, column=0, padx=12, pady=4, sticky=tk.W)
    logout_btn = ttk.Button(send_msg_tab, text="Logout", command=logout_callback)

    logout_btn.grid(row=12, column=0, padx=12, pady=4, sticky=tk.W)
