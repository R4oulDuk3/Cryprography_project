import tkinter as tk
from tkinter import ttk
from tkinter.font import Font


def gui_start(show_main_window):
    window = tk.Tk()
    window.title("PGP - Log in")
    window.geometry("450x400")

    header_font = Font(size=20, weight="bold")
    header_label = ttk.Label(window, text="Pretty Good Privacy", font=header_font)
    header_label.pack(pady=20)

    login_window = ttk.Frame(window)
    login_window.pack(padx=50, pady=20)

    username_label = ttk.Label(login_window, text="Username:")
    username_label.pack(padx=10, pady=10)

    username_entry = ttk.Entry(login_window)
    username_entry.pack(padx=10, pady=10)

    def login_window_btn():
        username = username_entry.get()
        if username == "":
            login_result_label.config(text="Username field empty!", foreground="red")
            return
        window.destroy()
        show_main_window(username)

    login_result_label = ttk.Label(login_window, text="")
    login_result_label.pack(padx=10, pady=10)

    continue_button = ttk.Button(login_window, text="Continue", command=login_window_btn)
    continue_button.pack(padx=10, pady=10)

    window.mainloop()
