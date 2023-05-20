import tkinter as tk
from tkinter import ttk
from tkinter.font import Font


def gui_start(callback):
    window = tk.Tk()
    window.title("PGP - Log in")
    window.geometry("450x400")

    def login_window_btn():
        window.destroy()
        callback()

    header_font = Font(size=20, weight="bold")
    header_label = ttk.Label(window, text="Pretty Good Privacy", font=header_font)
    header_label.pack(pady=20)

    login_window = ttk.Frame(window)
    login_window.pack(padx=50, pady=20)

    username_label = ttk.Label(login_window, text="Username:")
    username_label.pack(padx=10, pady=10)

    username_entry = ttk.Entry(login_window)
    username_entry.pack(padx=10, pady=10)

    continue_button = ttk.Button(login_window, text="Continue", command=login_window_btn)
    continue_button.pack(padx=10, pady=10)

    window.mainloop()
