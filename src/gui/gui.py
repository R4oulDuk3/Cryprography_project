import tkinter as tk
from tkinter import ttk

from src.pgp.consts.consts import Algorithm, AlgorithmType
from src.pgp.user.user import User
from tabs.key_gen_tab import keyg_tab_gen
from src.gui.tabs.key_overiew.key_overview_tab import key_overview_tab_gen
from tabs.send_msg_tab import send_msg_tab_gen
from tabs.receive_msg_tab import receive_msg_tab_gen
from tabs.initial_login_tab import gui_start
from src.pgp.user.user import User


def show_main_window(username):
    window = tk.Tk()
    window.title(f"PGP - Zastita podataka")
    window.geometry("900x800")
    user: User = User(username)
    tabs = ttk.Notebook(window)

    def logout_callback():
        window.destroy()
        gui_start(show_main_window)

    keyg_tab_gen(tabs, user, logout_callback)
    # key_overview_tab_gen(tabs, user, logout_callback)
    send_msg_tab_gen(tabs, user, logout_callback)
    receive_msg_tab_gen(tabs, user, logout_callback)

    tabs.pack()
    window.mainloop()


def init_test_data():
    user = User("gavrilo")
    user.key_manager.generate_key_pair(algorithm=Algorithm.RSA, key_size=1024, password="123",
                                       email="gavrilo@gmail.com", algorithm_type=AlgorithmType.ASYMMETRIC_ENCRYPTION)
    user.key_manager.generate_key_pair(algorithm=Algorithm.RSA, key_size=1024, password="123",
                                       email="gavrilo@gmail.com", algorithm_type=AlgorithmType.SIGNING)
    user.key_manager.generate_key_pair(algorithm=Algorithm.RSA, key_size=1024, password="123",
                                       email="gavrilo2@gmail.com", algorithm_type=AlgorithmType.ASYMMETRIC_ENCRYPTION)
    user.key_manager.generate_key_pair(algorithm=Algorithm.RSA, key_size=1024, password="123",
                                       email="gavrilo2@gmail.com", algorithm_type=AlgorithmType.SIGNING)
    user.key_manager.generate_key_pair(algorithm=Algorithm.RSA, key_size=1024, password="123",
                                       email="gavrilo3@gmail.com", algorithm_type=AlgorithmType.ASYMMETRIC_ENCRYPTION)
    user.key_manager.generate_key_pair(algorithm=Algorithm.RSA, key_size=1024, password="123",
                                       email="gavrilo3@gmail.com", algorithm_type=AlgorithmType.SIGNING)

    user2 = User("stanoje")
    user2.key_manager.generate_key_pair(algorithm=Algorithm.RSA, key_size=1024, password="661",
                                        email="stanoje@gmail.com", algorithm_type=AlgorithmType.ASYMMETRIC_ENCRYPTION)
    user2.key_manager.generate_key_pair(algorithm=Algorithm.RSA, key_size=1024, password="661",
                                        email="stanoje@gmail.com", algorithm_type=AlgorithmType.SIGNING)
    user2.key_manager.generate_key_pair(algorithm=Algorithm.RSA, key_size=1024, password="661",
                                        email="stanoje2@gmail.com", algorithm_type=AlgorithmType.ASYMMETRIC_ENCRYPTION)
    user2.key_manager.generate_key_pair(algorithm=Algorithm.RSA, key_size=1024, password="661",
                                        email="stanoje2@gmail.com", algorithm_type=AlgorithmType.SIGNING)
    user2.key_manager.generate_key_pair(algorithm=Algorithm.RSA, key_size=1024, password="661",
                                        email="stanoje3@gmail.com", algorithm_type=AlgorithmType.ASYMMETRIC_ENCRYPTION)
    user2.key_manager.generate_key_pair(algorithm=Algorithm.RSA, key_size=1024, password="661",
                                        email="stanoje3@gmail.com", algorithm_type=AlgorithmType.SIGNING)


def main():
    try:
        init_test_data()
    except Exception as e:
        print(f"Error while initializing test data: {e}")
    gui_start(show_main_window)


if __name__ == "__main__":
    main()
