import tkinter as tk
from tkinter import ttk, filedialog


def receive_msg_tab_gen(notebook, username):
    receive_msg_tab = ttk.Frame(notebook)
    notebook.add(receive_msg_tab, text="Receive message")

    def browse_receive_message():
        file_path = filedialog.askopenfilename(filetypes=[("Key Files", "*.pem")])
        receive_msg_entry.delete(0, tk.END)
        receive_msg_entry.insert(tk.END, file_path)

    # Message path
    receive_msg_label = ttk.Label(receive_msg_tab, text="Message path:")
    receive_msg_label.grid(row=1, column=0, padx=12, pady=4, sticky=tk.W)
    receive_msg_entry = ttk.Entry(receive_msg_tab)
    receive_msg_entry.grid(row=1, column=1, padx=12, pady=4)
    receive_msg_entry.config(width=23)
    browse_private_key_button = ttk.Button(receive_msg_tab, text="Browse", command=browse_receive_message)
    browse_private_key_button.grid(row=1, column=2, padx=4, pady=4)

    # Open message to be received
    receive_msg_btn = ttk.Button(receive_msg_tab, text="Open")
    receive_msg_btn.grid(row=2, column=0, columnspan=2, padx=10, pady=10)