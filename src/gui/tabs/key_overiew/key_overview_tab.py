from tkinter import ttk
import tkinter as tk

from src.gui.util.util import show_full_text
from src.pgp.user.user import User
from src.pgp.consts.consts import KeyPairPrivateRingAttributes, PublicKeyPublicRingAttributes


def make_secret_key_ring_table(notebook: ttk.Notebook):
    secret_key_tab = ttk.Frame(notebook)
    notebook.add(secret_key_tab, text="Secret Key Ring")

    secret_key_table = ttk.Treeview(secret_key_tab, columns=(
        "USER_NAME", "USER_EMAIL", "PUBLIC_KEY", "ENCRYPTED_PRIVATE_KEY", "HASHED_PASSWORD_WITH_SALT", "ALGORITHM"),
                                    show="headings")

    secret_key_table.heading("USER_NAME", text="User Name")
    secret_key_table.heading("USER_EMAIL", text="User Email")
    secret_key_table.heading("PUBLIC_KEY", text="Public Key (Shortened)")
    secret_key_table.heading("ENCRYPTED_PRIVATE_KEY", text="Encrypted Private Key (Shortened)")
    secret_key_table.heading("HASHED_PASSWORD_WITH_SALT", text="Hashed Password with Salt")
    secret_key_table.heading("ALGORITHM", text="Algorithm")

    secret_key_table.column("PUBLIC_KEY", width=200)
    secret_key_table.column("ENCRYPTED_PRIVATE_KEY", width=200)
    return secret_key_table


def reset_and_fill_secret_ring_table(secret_key_table: ttk.Treeview, user: User):
    secret_key_table.delete(*secret_key_table.get_children())
    for email in user.key_manager.get_private_keyring_dictionary().keys():
        key_pair_json: dict = user.key_manager.get_private_keyring_dictionary()[email]
        secret_key_table.insert("", "end",
                                values=(key_pair_json[KeyPairPrivateRingAttributes.USER_NAME.value],
                                        key_pair_json[KeyPairPrivateRingAttributes.USER_EMAIL.value],
                                        key_pair_json[KeyPairPrivateRingAttributes.PUBLIC_KEY.value],
                                        key_pair_json[KeyPairPrivateRingAttributes.ENCRYPTED_PRIVATE_KEY.value],
                                        key_pair_json[KeyPairPrivateRingAttributes.HASHED_PASSWORD_WITH_SALT.value],
                                        key_pair_json[KeyPairPrivateRingAttributes.ALGORITHM.value]))


def make_public_key_ring_table(notebook: ttk.Notebook):
    public_key_tab = ttk.Frame(notebook)
    notebook.add(public_key_tab, text="Public Key Ring")

    # Create the public key ring table
    public_key_table = ttk.Treeview(public_key_tab, columns=("PUBLIC_KEY", "USER_EMAIL", "USER_NAME", "ALGORITHM"),
                                    show="headings")

    # Set column headings
    public_key_table.heading("PUBLIC_KEY", text="Public Key (Shortened)")
    public_key_table.heading("USER_EMAIL", text="User Email")
    public_key_table.heading("USER_NAME", text="User Name")
    public_key_table.heading("ALGORITHM", text="Algorithm")

    # Add column tooltips
    public_key_table.column("PUBLIC_KEY", width=200)
    # public_key_table.bind("<Enter>", show_full_text)

    return public_key_table


def reset_and_fill_public_ring_table(public_key_table: ttk.Treeview, user: User):
    public_key_table.delete(*public_key_table.get_children())
    for email in user.key_manager.get_public_keyring_dictionary().keys():
        public_key_json: dict = user.key_manager.get_public_keyring_dictionary()[email]
        public_key_table.insert("", "end",
                                values=(
                                    public_key_json[PublicKeyPublicRingAttributes.PUBLIC_KEY.value],
                                    public_key_json[PublicKeyPublicRingAttributes.USER_EMAIL.value],
                                    public_key_json[PublicKeyPublicRingAttributes.USER_NAME.value],
                                    public_key_json[PublicKeyPublicRingAttributes.ALGORITHM.value]))


def tab_changed(secret_key_table, public_key_table, event, user):
    # print("Tab changed, refreshing tables")
    reset_and_fill_public_ring_table(public_key_table, user)
    reset_and_fill_secret_ring_table(secret_key_table, user)


def key_overview_tab_gen(notebook: ttk.Notebook, user: User):
    notebook.pack(fill=tk.BOTH, expand=True)
    secret_key_table = make_secret_key_ring_table(notebook)

    reset_and_fill_secret_ring_table(secret_key_table, user)
    # Pack the secret key ring table
    secret_key_table.pack(fill=tk.BOTH, expand=True)

    public_key_table = make_public_key_ring_table(notebook)
    reset_and_fill_public_ring_table(public_key_table, user)

    notebook.bind("<<NotebookTabChanged>>", lambda event: tab_changed(secret_key_table, public_key_table, event, user))

    # Pack the public key ring table
    public_key_table.pack(fill=tk.BOTH, expand=True)
