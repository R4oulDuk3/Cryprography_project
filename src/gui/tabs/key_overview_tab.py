from tkinter import ttk

def keyoverview_tab_gen(notebook):
    keyoverview_tab = ttk.Frame(notebook)
    notebook.add(keyoverview_tab, text="Key Overview")