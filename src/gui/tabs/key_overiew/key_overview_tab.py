import tkinter as tk
from tkinter import ttk

from src.pgp.consts.consts import KeyPairPrivateRingAttributes, PublicKeyPublicRingAttributes
from src.pgp.user.user import User


def make_secret_key_ring_table(notebook: ttk.Notebook):
    secret_key_tab = ttk.Frame(notebook)
    notebook.add(secret_key_tab, text="Secret Key Ring")

    secret_key_table = ttk.Treeview(secret_key_tab, columns=(
        "USER_NAME", "USER_EMAIL", "KEY_ID", "PUBLIC_KEY", "ENCRYPTED_PRIVATE_KEY", "HASHED_PASSWORD_WITH_SALT",
        "ALGORITHM", "TYPE"),
                                    show="headings")

    secret_key_table.heading("USER_NAME", text="User Name")
    secret_key_table.heading("USER_EMAIL", text="User Email")
    secret_key_table.heading("KEY_ID", text="Key ID")
    secret_key_table.heading("PUBLIC_KEY", text="Public Key (Shortened)")
    secret_key_table.heading("ENCRYPTED_PRIVATE_KEY", text="Encrypted Private Key (Shortened)")
    secret_key_table.heading("HASHED_PASSWORD_WITH_SALT", text="Hashed Password with Salt")
    secret_key_table.heading("ALGORITHM", text="Algorithm")
    secret_key_table.heading("TYPE", text="Type")

    secret_key_table.column("PUBLIC_KEY", width=200)
    secret_key_table.column("ENCRYPTED_PRIVATE_KEY", width=200)
    return secret_key_table


def reset_and_fill_secret_ring_table(secret_key_table: ttk.Treeview, user: User):
    secret_key_table.delete(*secret_key_table.get_children())
    emails = user.key_manager.get_private_keyring_dictionary().keys()
    for email in emails:
        keys_pairs_for_email = user.key_manager.get_private_keyring_dictionary()[email]
        for key_pair in keys_pairs_for_email:
            secret_key_table.insert("", "end",
                                    values=(
                                        keys_pairs_for_email[key_pair][KeyPairPrivateRingAttributes.USER_NAME.value],
                                        keys_pairs_for_email[key_pair][KeyPairPrivateRingAttributes.USER_EMAIL.value],
                                        keys_pairs_for_email[key_pair][KeyPairPrivateRingAttributes.KEY_ID.value],
                                        keys_pairs_for_email[key_pair][KeyPairPrivateRingAttributes.PUBLIC_KEY.value],
                                        keys_pairs_for_email[key_pair][
                                            KeyPairPrivateRingAttributes.ENCRYPTED_PRIVATE_KEY.value],
                                        keys_pairs_for_email[key_pair][
                                            KeyPairPrivateRingAttributes.HASHED_PASSWORD_WITH_SALT.value],
                                        keys_pairs_for_email[key_pair][KeyPairPrivateRingAttributes.ALGORITHM.value],
                                        key_pair,
                                    ))


def make_public_key_ring_table(notebook: ttk.Notebook):
    public_key_tab = ttk.Frame(notebook)
    notebook.add(public_key_tab, text="Public Key Ring")

    public_key_table = ttk.Treeview(public_key_tab,
                                    columns=("PUBLIC_KEY", "KEY_ID", "USER_EMAIL", "USER_NAME", "ALGORITHM", "TYPE"),
                                    show="headings")

    public_key_table.heading("PUBLIC_KEY", text="Public Key (Shortened)")
    public_key_table.heading("KEY_ID", text="Key ID")
    public_key_table.heading("USER_EMAIL", text="User Email")
    public_key_table.heading("USER_NAME", text="User Name")
    public_key_table.heading("ALGORITHM", text="Algorithm")
    public_key_table.heading("TYPE", text="Type")

    # Add column tooltips
    public_key_table.column("PUBLIC_KEY", width=200)
    # public_key_table.bind("<Enter>", show_full_text)

    return public_key_table


def reset_and_fill_public_ring_table(public_key_table: ttk.Treeview, user: User):
    public_key_table.delete(*public_key_table.get_children())
    emails = user.key_manager.get_public_keyring_dictionary().keys()
    for email in emails:
        public_keys_for_email = user.key_manager.get_public_keyring_dictionary()[email]
        for public_key in public_keys_for_email:
            public_key_table.insert("", "end",
                                    values=(
                                        public_keys_for_email[public_key][
                                            PublicKeyPublicRingAttributes.PUBLIC_KEY.value],
                                        public_keys_for_email[public_key][PublicKeyPublicRingAttributes.KEY_ID.value],
                                        public_keys_for_email[public_key][
                                            PublicKeyPublicRingAttributes.USER_EMAIL.value],
                                        public_keys_for_email[public_key][
                                            PublicKeyPublicRingAttributes.USER_NAME.value],
                                        public_keys_for_email[public_key][
                                            PublicKeyPublicRingAttributes.ALGORITHM.value],
                                        public_key,
                                    ))


def refresh(secret_key_table, public_key_table, user):
    reset_and_fill_public_ring_table(public_key_table, user)
    reset_and_fill_secret_ring_table(secret_key_table, user)


def key_overview_tab_gen(notebook: ttk.Notebook, user: User, logout_callback):
    notebook.pack(fill=tk.BOTH, expand=True)
    secret_key_table = make_secret_key_ring_table(notebook)

    reset_and_fill_secret_ring_table(secret_key_table, user)
    secret_key_table.pack(fill=tk.BOTH, expand=True)

    public_key_table = make_public_key_ring_table(notebook)
    reset_and_fill_public_ring_table(public_key_table, user)

    public_key_table.pack(fill=tk.BOTH, expand=True)
