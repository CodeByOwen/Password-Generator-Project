import tkinter as tk
from tkinter import ttk, messagebox
import random
import string

# Function to generate password
def generate_password():
    try:
        length = int(length_var.get())
    except ValueError:
        messagebox.showerror("Invalid Input", "Password length must be a number.")
        return

    if length < 4:
        messagebox.showwarning("Too Short", "Password length should be at least 4.")
        return

    characters = ""
    if use_upper.get():
        characters += string.ascii_uppercase
    if use_lower.get():
        characters += string.ascii_lowercase
    if use_digits.get():
        characters += string.digits
    if use_symbols.get():
        characters += "!@#$%^&*()-_=+[]{};:,.<>?/|\\"

    if not characters:
        messagebox.showerror("No Characters", "Please select at least one character set.")
        return

    password = "".join(random.choice(characters) for _ in range(length))
    password_var.set(password)

# Function to copy password
def copy_to_clipboard():
    pwd = password_var.get()
    if pwd:
        root.clipboard_clear()
        root.clipboard_append(pwd)
        messagebox.showinfo("Copied", "Password copied to clipboard!")
    else:
        messagebox.showwarning("Empty", "No password to copy.")

# GUI setup
root = tk.Tk()
root.title("Password Generator")
root.geometry("400x350")
root.resizable(False, False)

# Styling
style = ttk.Style(root)
style.configure("TButton", font=("Segoe UI", 10))
style.configure("TLabel", font=("Segoe UI", 10))

# Widgets
ttk.Label(root, text="Password Length:").pack(pady=(15, 5))
length_var = tk.StringVar(value="12")
ttk.Entry(root, textvariable=length_var, width=10, justify="center").pack()

# Checkboxes
use_upper = tk.BooleanVar(value=True)
use_lower = tk.BooleanVar(value=True)
use_digits = tk.BooleanVar(value=True)
use_symbols = tk.BooleanVar(value=True)

ttk.Checkbutton(root, text="Include Uppercase (A-Z)", variable=use_upper).pack(anchor="w", padx=40)
ttk.Checkbutton(root, text="Include Lowercase (a-z)", variable=use_lower).pack(anchor="w", padx=40)
ttk.Checkbutton(root, text="Include Digits (0-9)", variable=use_digits).pack(anchor="w", padx=40)
ttk.Checkbutton(root, text="Include Symbols (!@#$...)", variable=use_symbols).pack(anchor="w", padx=40)

# Generate Button
ttk.Button(root, text="Generate Password", command=generate_password).pack(pady=15)

# Output field
password_var = tk.StringVar()
ttk.Entry(root, textvariable=password_var, width=30, justify="center", state="readonly").pack()

# Copy Button
ttk.Button(root, text="Copy to Clipboard", command=copy_to_clipboard).pack(pady=10)

root.mainloop()
