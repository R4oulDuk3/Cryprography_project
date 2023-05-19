import tkinter as tk
from tkinter import ttk
from src.pgp.consts.consts import KEY_SIZES, AsymmetricEncryptionAlgorithm


def gui_start():
    window = tk.Tk()
    window.title("PGP - Zastita podataka")
    window.geometry("900x800")
    tabs = ttk.Notebook(window)
    keyg_tab_gen(tabs)
    keyoverview_tab_gen(tabs)
    msgsend_tab_gen(tabs)
    msgreceive_tab_gen(tabs)

    tabs.pack()
    window.mainloop()


def keyg_tab_gen(notebook):
    key_gen_tab = ttk.Frame(notebook)
    notebook.add(key_gen_tab, text="Key Generation")

    generate_label = ttk.Label(key_gen_tab, text="Generate a new key pair:")
    generate_label.grid(row=0, column=0, columnspan=2, padx=10, pady=10)
    ttk.Label(key_gen_tab).grid(row=1)

    # Name
    username_label = ttk.Label(key_gen_tab, text="Username:")
    username_label.grid(row=2, column=0, padx=12, pady=4, sticky=tk.W)
    username_entry = ttk.Entry(key_gen_tab)
    username_entry.grid(row=2, column=1, padx=12, pady=4)
    username_entry.config(width=23)

    # Email
    email_label = ttk.Label(key_gen_tab, text="Email:")
    email_label.grid(row=3, column=0, padx=12, pady=4, sticky=tk.W)
    email_entry = ttk.Entry(key_gen_tab)
    email_entry.grid(row=3, column=1, padx=12, pady=4)
    email_entry.config(width=23)

    # Algorithm
    asym_algo_label = ttk.Label(key_gen_tab, text="Asymmetric algorithm")
    asym_algo_label.grid(row=4, column=0, padx=12, pady=4, sticky=tk.W)
    asym_algo_combo = ttk.Combobox(key_gen_tab, values=[algorithm.value for algorithm in AsymmetricEncryptionAlgorithm])
    asym_algo_combo.grid(row=4, column=1, padx=12, pady=4)
    asym_algo_combo.current(0)
    asym_algo_combo.bind("<<ComboboxSelected>>", lambda event: update_signature_label(asym_algo_combo))

    # Signature Type Label
    signature_type_label = ttk.Label(key_gen_tab, text="Signature type:")
    signature_type_label.grid(row=5, column=0, padx=12, pady=4, sticky=tk.W)

    # Signature Label
    global signature_label
    signature_label = ttk.Label(key_gen_tab, text="")
    signature_label.grid(row=5, column=1, padx=12, pady=4, sticky=tk.W)

    # Key Size
    key_size_label = ttk.Label(key_gen_tab, text="Key Size:")
    key_size_label.grid(row=6, column=0, padx=12, pady=4, sticky=tk.W)
    key_size_combo = ttk.Combobox(key_gen_tab, values=KEY_SIZES)
    key_size_combo.grid(row=6, column=1, padx=12, pady=4)
    key_size_combo.current(0)

    # Password
    ttk.Label(key_gen_tab, text="Password:").grid(row=7, column=0, padx=12, pady=4, sticky=tk.W)
    password_entry = ttk.Entry(key_gen_tab, show="*")
    password_entry.grid(row=7, column=1, padx=12, pady=4)
    password_entry.config(width=23)
    ttk.Label(key_gen_tab).grid(row=8)

    # Generate Keys button
    generate_btn = ttk.Button(key_gen_tab, text="Generate Keys")
    generate_btn.grid(row=9, column=0, columnspan=2, padx=10, pady=10)

    default_asym_algo = AsymmetricEncryptionAlgorithm(asym_algo_combo.get())
    update_signature_label(asym_algo_combo, default_asym_algo)


def update_signature_label(asym_algo_combo, default_asym_algo=None):
    selected_asym_algo = AsymmetricEncryptionAlgorithm(asym_algo_combo.get())
    if default_asym_algo is None:
        default_algorithm = selected_asym_algo
    signature_label.config(text="RSA Signature" if default_asym_algo == AsymmetricEncryptionAlgorithm.RSA else "DSA Signature")


def keyoverview_tab_gen(notebook):
    keyoverview_tab = ttk.Frame(notebook)
    notebook.add(keyoverview_tab, text="Key Overview")

def msgsend_tab_gen(notebook):
    msgsend_tab_gen = ttk.Frame(notebook)
    notebook.add(msgsend_tab_gen, text="Send Message")


def msgreceive_tab_gen(notebook):
    msgreceive_tab_gen = ttk.Frame(notebook)
    notebook.add(msgreceive_tab_gen, text="Receive message")


if __name__ == "__main__":
    gui_start()
