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
    keyg_tab_gen(tabs)
    keyoverview_tab_gen(tabs)
    send_msg_tab_gen(tabs)
    receive_msg_tab_gen(tabs)

    tabs.pack()
    window.mainloop()


def main():
    gui_start(show_main_window)


if __name__ == "__main__":
    main()
