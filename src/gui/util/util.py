import tkinter as tk
from tkinter import messagebox


def show_full_text(event):
    widget = event.widget
    x, y, _, _ = widget.bbox(tk.CURRENT)
    if x < 0:
        column = widget.identify_column(event.x)
        row = widget.identify_row(event.y)
        if column and row:
            messagebox.showinfo("Full Text", widget.set(row, column))

