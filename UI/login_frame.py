import tkinter as tk
from tkinter import messagebox
import os
import json
import base64
from storage import load_vault, save_vault

class LoginFrame(tk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        
        # Title
        title_label = tk.Label(self, text="Password Manager Login", font=("Arial", 16, "bold"))
        title_label.pack(pady=20)
        
        # Password frame
        pw_frame = tk.Frame(self)
        pw_frame.pack(pady=10)
        
        tk.Label(pw_frame, text="Master Password:", font=("Arial", 12)).pack(anchor="w")
        
        # Password entry with show/hide toggle
        entry_frame = tk.Frame(pw_frame)
        entry_frame.pack(fill="x", pady=5)
        
        self.password_entry = tk.Entry(entry_frame, show="*", width=30, font=("Arial", 11))
        self.password_entry.pack(side="left", fill="x", expand=True)
        
        self.show_password_var = tk.BooleanVar()
        self.show_password_check = tk.Checkbutton(entry_frame, text="Show", variable=self.show_password_var, 
                                                command=self.toggle_password_visibility)
        self.show_password_check.pack(side="right", padx=(5, 0))
        
        # Login button
        login_button = tk.Button(self, text="Login", command=self.login, 
                               bg="green", fg="white", font=("Arial", 11, "bold"), 
                               width=15, height=2)
        login_button.pack(pady=15)
        
        # Forgot Password link
        forgot_link = tk.Label(self, text="Forgot Password?", fg="blue", cursor="hand2", 
                             font=("Arial", 10, "underline"))
        forgot_link.pack(pady=5)
        forgot_link.bind("<Button-1>", self.forgot_password)

    def toggle_password_visibility(self):
        """Toggle between showing and hiding the password."""
        if self.show_password_var.get():
            self.password_entry.config(show="")
        else:
            self.password_entry.config(show="*")

    def login(self):
        password = self.password_entry.get()
        vault_file = "vault.dat"
        try:
            if os.path.exists(vault_file):
                vault_data = load_vault(vault_file, password)
                # Remove recovery data from vault_data for normal use
                clean_vault = {k: v for k, v in vault_data.items() 
                              if k not in ['recovery_hash', 'security_questions']}
                self.controller.vault_data = clean_vault
                self.controller.password = password
                self.controller.show_frame("VaultFrame")
            else:
                vault_data = {}
                save_vault(vault_file, vault_data, password)
                self.controller.vault_data = vault_data
                self.controller.password = password
                self.controller.show_frame("VaultFrame")
        except Exception as e:
            messagebox.showerror("Login Failed", "Incorrect password or vault is corrupted.")

    def forgot_password(self, event=None):
        vault_file = "vault.dat"
        if not os.path.exists(vault_file):
            messagebox.showinfo("No Vault", "No vault exists. Please set up your password manager first.")
            return
        
        # For recovery, we need to read the vault file structure
        # We'll create a minimal vault_data structure for the recovery frame
        # The recovery frame will handle the actual decryption when the user provides recovery info
        try:
            with open(vault_file, 'r') as f:
                content = f.read()
            # Just verify the file has the expected format
            if ':' in content and len(content.split(':')) == 4:
                # Create a placeholder vault_data - the recovery frame will handle actual decryption
                self.controller.vault_data = {'_needs_recovery': True}
                self.controller.show_frame("RecoveryFrame")
            else:
                messagebox.showerror("Error", "Vault file format is invalid.")
        except Exception as e:
            messagebox.showerror("Error", f"Cannot access vault for recovery: {str(e)}")
