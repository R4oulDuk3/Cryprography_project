import tkinter as tk
from tkinter import ttk
from tabs.key_gen_tab import keyg_tab_gen
from tabs.key_overview_tab import keyoverview_tab_gen
from tabs.send_msg_tab import send_msg_tab_gen
from tabs.receive_msg_tab import receive_msg_tab_gen
from tabs.initial_login_tab import gui_start


def show_main_window(username):
    window = tk.Tk()
    window.title(f"PGP - Zastita podataka")
    window.geometry("900x800")

    tabs = ttk.Notebook(window)

    def logout_callback():
        window.destroy()
        gui_start(show_main_window)

    keyg_tab_gen(tabs, username, logout_callback)
    keyoverview_tab_gen(tabs, username)
    send_msg_tab_gen(tabs, username)
    receive_msg_tab_gen(tabs, username)

    tabs.pack()
    window.mainloop()


def main():
    gui_start(show_main_window)


if __name__ == "__main__":
    main()
