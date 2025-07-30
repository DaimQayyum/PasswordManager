import tkinter as tk
from tkinter import messagebox
from storage import save_vault
from utils import password_strength, generate_password

class EntryFrame(tk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        self.mode = 'add'  # or 'edit'
        self.edit_site = None
        self.setup_ui()

    def setup_ui(self):
        # Configure frame to expand properly
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)
        
        # Main content frame
        main_frame = tk.Frame(self)
        main_frame.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)
        
        tk.Label(main_frame, text="Site:").pack(pady=(20, 0))
        self.site_entry = tk.Entry(main_frame, width=40)
        self.site_entry.pack(pady=5)
        
        tk.Label(main_frame, text="Username:").pack(pady=(10, 0))
        self.username_entry = tk.Entry(main_frame, width=40)
        self.username_entry.pack(pady=5)
        
        tk.Label(main_frame, text="Password:").pack(pady=(10, 0))
        pw_frame = tk.Frame(main_frame)
        pw_frame.pack(pady=5)
        self.password_entry = tk.Entry(pw_frame, show="*", width=32)
        self.password_entry.pack(side="left")
        self.password_entry.bind('<KeyRelease>', self.update_strength)
        gen_btn = tk.Button(pw_frame, text="Generate", command=self.generate_password)
        gen_btn.pack(side="left", padx=5)
        
        self.strength_label = tk.Label(main_frame, text="Strength: ")
        self.strength_label.pack()
        
        button_frame = tk.Frame(main_frame)
        button_frame.pack(pady=20)
        tk.Button(button_frame, text="Save", command=self.save_entry).pack(side="left", padx=10)
        tk.Button(button_frame, text="Cancel", command=self.cancel).pack(side="left", padx=10)

    def set_mode(self, mode, site=None, entry=None):
        self.mode = mode
        self.edit_site = site
        if mode == 'edit' and entry:
            self.site_entry.delete(0, tk.END)
            self.site_entry.insert(0, site if site is not None else "")
            self.site_entry.config(state='disabled')
            self.username_entry.delete(0, tk.END)
            self.username_entry.insert(0, str(entry.get('username', '')))
            self.password_entry.delete(0, tk.END)
            self.password_entry.insert(0, str(entry.get('password', '')))
        else:
            self.site_entry.config(state='normal')
            self.site_entry.delete(0, tk.END)
            self.username_entry.delete(0, tk.END)
            self.password_entry.delete(0, tk.END)
        self.update_strength()

    def update_strength(self, event=None):
        pw = self.password_entry.get()
        score, label = password_strength(pw)
        self.strength_label.config(text=f"Strength: {label}")

    def generate_password(self):
        pw = generate_password()
        self.password_entry.delete(0, tk.END)
        self.password_entry.insert(0, pw)
        self.update_strength()

    def save_entry(self):
        site = self.site_entry.get().strip()
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()
        if not site:
            messagebox.showerror("Error", "Site is required.")
            return
        vault_data = self.controller.vault_data or {}
        vault_data[site] = {"username": username, "password": password}
        self.controller.vault_data = vault_data
        save_vault("vault.dat", vault_data, self.controller.password)
        self.controller.show_frame("VaultFrame")

    def cancel(self):
        self.controller.show_frame("VaultFrame")
