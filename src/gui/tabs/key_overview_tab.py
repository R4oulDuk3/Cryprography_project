import tkinter as tk
from tkinter import ttk
from typing import List

from src.pgp.consts.consts import PublicKeyPublicRingAttributes
from src.pgp.key.keyring.keyring_dto import PrivateKeyringRowDTO, PublicKeyringRowDTO
from src.pgp.user.user import User


def make_secret_key_ring_table(notebook: ttk.Notebook, refresh_callback):
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

    refresh_button = tk.Button(secret_key_tab, text="Refresh", command=refresh_callback)
    refresh_button.pack(side=tk.BOTTOM)
    return secret_key_table


def reset_and_fill_secret_ring_table(secret_key_table: ttk.Treeview, user: User):
    print("reset_and_fill_secret_ring_table")
    secret_key_table.delete(*secret_key_table.get_children())
    rows: List[PrivateKeyringRowDTO] = user.key_manager.get_all_private_keyring_rows()
    for row in rows:
        secret_key_table.insert("", "end",
                                values=(
                                    row.user_name,
                                    row.user_email,
                                    row.key_id,
                                    row.public_key,
                                    row.encrypted_private_key,
                                    row.hashed_password_with_salt,
                                    row.algorithm,
                                    row.algorithm_type
                                ))


def make_public_key_ring_table(notebook: ttk.Notebook, refresh_callback):
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
    refresh_button = tk.Button(public_key_tab, text="Refresh", command=refresh_callback)
    refresh_button.pack(side=tk.BOTTOM)
    return public_key_table


def reset_and_fill_public_ring_table(public_key_table: ttk.Treeview, user: User):
    print("reset_and_fill_public_ring_table")
    public_key_table.delete(*public_key_table.get_children())
    rows: List[PublicKeyringRowDTO] = user.key_manager.get_all_public_keyring_rows()
    for row in rows:
        public_key_table.insert("", "end",
                                values=(
                                    row.public_key,
                                    row.key_id,
                                    row.user_email,
                                    row.user_name,
                                    row.algorithm,
                                    row.algorithm_type
                                ))


def key_overview_tab_gen(notebook: ttk.Notebook, user: User, logout_callback):
    notebook.pack(fill=tk.BOTH, expand=True)
    secret_key_table = make_secret_key_ring_table(notebook,
                                                  refresh_callback=lambda:
                                                  reset_and_fill_secret_ring_table(secret_key_table=secret_key_table,
                                                                                   user=user))

    reset_and_fill_secret_ring_table(secret_key_table, user)
    secret_key_table.pack(fill=tk.BOTH, expand=True)

    public_key_table = make_public_key_ring_table(notebook,
                                                  refresh_callback=lambda:
                                                  reset_and_fill_public_ring_table(public_key_table=public_key_table,
                                                                                   user=user))
    reset_and_fill_public_ring_table(public_key_table, user)

    public_key_table.pack(fill=tk.BOTH, expand=True)
