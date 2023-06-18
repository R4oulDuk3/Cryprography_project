import tkinter as tk
from tkinter import ttk, filedialog
from src.pgp.compression.compressor import ZIPCompressor
from src.pgp.conversion.convertor import Radix64Convertor
from src.pgp.encryption.asymmetric import AsymmetricEncryptor
from src.pgp.encryption.symmetric import SymmetricEncryptor
from src.pgp.key.generate.session import SessionKeyGenerator
from src.pgp.key.key_serializer import KeySerializer
from src.pgp.key.manager import KeyManager
from src.pgp.message.message import PGPMessage
from src.pgp.signature.sign import Signer
from src.pgp.transfer.receiver import Receiver
from src.pgp.user.user import User


import traceback

import os
import random
import string


path_to_message = ""
plaintext = ""
export_folder_entry = None


def receive_message_callback(user: User, message_content_label: ttk.Label, path_to_message: str, password: str):
    global plaintext, export_folder_entry
    try:
        key_manager = KeyManager(user_name=user.user_name)
        message_signer = Signer()
        symmetric_encryptor = SymmetricEncryptor()
        asymmetric_encryptor = AsymmetricEncryptor()
        compressor = ZIPCompressor()
        convertor = Radix64Convertor()
        session_key_generator = SessionKeyGenerator()
        key_serializer = KeySerializer()
        receiver = Receiver(key_manager=key_manager,
                            message_signer=message_signer,
                            symmetric_encryptor=symmetric_encryptor,
                            asymmetric_encryptor=asymmetric_encryptor,
                            compressor=compressor,
                            convertor=convertor,
                            session_key_generator=session_key_generator,
                            key_serializer=key_serializer)
        message = receiver.unpack_message(path_to_message)
        sender, plaintext = receiver.decrypt_message(message, password)
        message_content_label.config(text=f"Sender: { sender } Message: { plaintext }", foreground="black")
        export_folder_entry.config(state="normal")
    except Exception as e:
        print(f"Error while receiving message: {e}")
        print(traceback.format_exc())
        message_content_label.config(text=f"Error while receiving message: {e}", foreground="red")
        export_folder_entry.config(state="disabled")


def export_message(folder_path, message_content_label, username):
    global plaintext
    try:
        if not folder_path:
            raise ValueError("No export folder path selected.")

        if not plaintext:
            raise ValueError("No message to export.")

        random_numbers = ''.join(random.choices(string.digits, k=4))
        filename = f"{username}_received_message_{random_numbers}.txt"
        file_path = os.path.join(folder_path, filename)
        with open(file_path, "w") as file:
            file.write(plaintext)
    except ValueError as e:
        print(f"Error while exporting message: {e}")
        message_content_label.config(text=str(e), foreground="red")
    except Exception as e:
        print(f"Error while exporting message: {e}")
        message_content_label.config(text=f"Error while exporting message: {e}", foreground="red")


def select_directory(user: User, msg_path_label: ttk.Label, password_entry: tk.Entry):
    global path_to_message, export_folder_entry
    file_path = filedialog.askopenfilename(filetypes=[("Key Files", "*.pgp")])
    if file_path:
        path_to_message = file_path
        message: PGPMessage = user.receiver.unpack_message(file_path)
        if message.is_encrypted:
            email = user.key_manager.get_user_mail_by_key_id(key_id=message.asymmetric_encryption_key_id)

            msg_path_label.config(text=f"file path: {file_path},encrypted, receiver_email: {email},"
                                       f" key_id {message.asymmetric_encryption_key_id}", foreground="black")
            password_entry.config(state="normal")
        else:
            msg_path_label.config(text=f"file path: {file_path}, not encrypted", foreground="black")
            password_entry.config(state="disabled")
        export_folder_entry.config(state="disabled")
        export_folder_entry.delete(0, tk.END)
    else:
        msg_path_label.config(text="No message selected.", foreground="black")
        password_entry.config(state="disabled")
        export_folder_entry.config(state="disabled")
        export_folder_entry.delete(0, tk.END)


def receive_msg_tab_gen(notebook, user: User, logout_callback):
    global path_to_message, export_folder_entry
    receive_msg_tab = ttk.Frame(notebook)
    notebook.add(receive_msg_tab, text="Receive message")

    password_label = ttk.Label(receive_msg_tab, text="Password:")
    password_label.grid(row=0, column=0, padx=12, pady=4, sticky=tk.W)
    password_entry = ttk.Entry(receive_msg_tab, show="*")
    password_entry.grid(row=0, column=1, padx=12, pady=4, sticky=tk.W)
    password_entry.config(state="disabled")

    receive_msg_label = ttk.Label(receive_msg_tab, text="Message path:")
    receive_msg_label.grid(row=1, column=0, padx=12, pady=4, sticky=tk.W)
    msg_path_label = ttk.Label(receive_msg_tab, text="No message selected.", wraplength=300)
    msg_path_label.grid(row=2, column=1, padx=12, pady=4, sticky=tk.W)

    browse_private_key_button = ttk.Button(receive_msg_tab, text="Browse",
                                           command=lambda: select_directory(user=user,
                                                                            msg_path_label=msg_path_label,
                                                                            password_entry=password_entry)
                                           )
    browse_private_key_button.grid(row=2, column=0, padx=0, pady=4)

    receive_msg_btn = ttk.Button(receive_msg_tab, text="Open message")
    receive_msg_btn.grid(row=3, column=1, columnspan=2, padx=0, pady=10, sticky="w")
    message_content_label = ttk.Label(receive_msg_tab, text="", wraplength=310)
    message_content_label.grid(row=7, column=0, columnspan=2, padx=12, pady=4, sticky=tk.W)
    receive_msg_btn.bind(
        "<Button-1>", lambda event: receive_message_callback(
            user,
            message_content_label,
            password=password_entry.get(),
            path_to_message=path_to_message
        )
    )

    export_folder_label = ttk.Label(receive_msg_tab, text="Export folder path:")
    export_folder_label.grid(row=5, column=0, padx=12, pady=4, sticky=tk.W)
    export_folder_entry = ttk.Entry(receive_msg_tab, state="disabled")
    export_folder_entry.grid(row=5, column=1, padx=12, pady=4, sticky=tk.W)

    def select_export_directory():
        folder_path = filedialog.askdirectory()
        if folder_path:
            export_folder_entry.delete(0, tk.END)
            export_folder_entry.insert(0, folder_path)

    export_button = ttk.Button(
        receive_msg_tab, text="Export",
        command=lambda: export_message(export_folder_entry.get(), message_content_label, user.user_name)
    )
    export_button.grid(row=6, column=1, padx=0, pady=4, sticky=tk.W)

    browse_export_folder_button = ttk.Button(receive_msg_tab, text="Browse", command=select_export_directory)
    browse_export_folder_button.grid(row=5, column=2, padx=0, pady=4)

    logout_separator = ttk.Separator(receive_msg_tab, orient="horizontal")
    logout_separator.grid(row=9, column=0, columnspan=12, padx=0, pady=10, sticky="we")
    username_label = ttk.Label(receive_msg_tab, text=f"Current user: {user.user_name}")
    username_label.grid(row=10, column=0, padx=12, pady=4, sticky=tk.W)
    logout_btn = ttk.Button(receive_msg_tab, text="Logout", command=logout_callback)
    logout_btn.grid(row=11, column=0, padx=12, pady=4, sticky=tk.W)
