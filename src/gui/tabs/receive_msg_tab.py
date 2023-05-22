import tkinter as tk
from tkinter import ttk, filedialog

from src.pgp.compression.compressor import ZIPCompressor
from src.pgp.conversion.convertor import Radix64Convertor
from src.pgp.encryption.asymmetric import AsymmetricEncryptor
from src.pgp.encryption.symmetric import SymmetricEncryptor
from src.pgp.key.generate.session import SessionKeyGenerator
from src.pgp.key.key_serializer import KeySerializer
from src.pgp.key.manager import KeyManager
from src.pgp.signature.sign import Signer
from src.pgp.transfer.receiver import Receiver
from src.pgp.user.user import User


def receive_message_callback(user: User, message_content_label: ttk.Label, path_to_message: str):
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
    # print(message)
    plaintext = receiver.decrypt_message(message, password="1234")
    print(plaintext)
    message_content_label.config(text="Message:\t" + plaintext.decode())


def select_directory(msg_path_label: ttk.Label):
    file_path = filedialog.askopenfilename(filetypes=[("Key Files", "*.pgp")])
    if file_path:
        msg_path_label.config(text=file_path)
    else:
        msg_path_label.config(text="No message selected.")


def receive_msg_tab_gen(notebook, user: User, logout_callback):
    receive_msg_tab = ttk.Frame(notebook)
    notebook.add(receive_msg_tab, text="Receive message")

    # Message path
    receive_msg_label = ttk.Label(receive_msg_tab, text="Message path:")
    receive_msg_label.grid(row=1, column=0, padx=12, pady=4, sticky=tk.W)
    msg_path_label = ttk.Label(receive_msg_tab, text="No message selected.")
    msg_path_label.grid(row=2, column=1, padx=12, pady=4, sticky=tk.W)
    browse_private_key_button = ttk.Button(receive_msg_tab, text="Browse",
                                           command= lambda:select_directory(msg_path_label))
    browse_private_key_button.grid(row=2, column=0, padx=4, pady=4)

    # Open message to be received
    receive_msg_btn = ttk.Button(receive_msg_tab, text="Open message")
    receive_msg_btn.grid(row=3, column=0, columnspan=2, padx=10, pady=10)

    # Message
    message_content_label = ttk.Label(receive_msg_tab, text="")
    message_content_label.grid(row=4, column=0, padx=12, pady=4, sticky=tk.W)

    receive_msg_btn.bind("<Button-1>", lambda event: receive_message_callback(
                        user,
                        message_content_label,
                        path_to_message=msg_path_label.cget("text")
                        ))

    # Logout
    logout_separator = ttk.Separator(receive_msg_tab, orient="horizontal")
    logout_separator.grid(row=5, column=0, columnspan=12, padx=0, pady=10, sticky="we")
    username_label = ttk.Label(receive_msg_tab, text=f"Current user: {user.user_name}")
    username_label.grid(row=6, column=0, padx=12, pady=4, sticky=tk.W)
    logout_btn = ttk.Button(receive_msg_tab, text="Logout", command=logout_callback)
    logout_btn.grid(row=7, column=0, padx=12, pady=4, sticky=tk.W)

