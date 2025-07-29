import tkinter as tk
from tkinter import messagebox, ttk
import os
import json

class RecoveryFrame(tk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        self.vault_data = None
        self.encrypted_vault_content = None
        self.setup_ui()

    def setup_ui(self):
        # Title
        title_label = tk.Label(self, text="Recover Master Password", font=("Arial", 16, "bold"))
        title_label.pack(pady=20)

        # Method Selection
        method_frame = tk.LabelFrame(self, text="Recovery Method", padx=10, pady=10)
        method_frame.pack(fill="x", padx=20, pady=10)

        self.method_var = tk.StringVar(value="recovery_code")
        tk.Radiobutton(method_frame, text="Use Recovery Code", variable=self.method_var, 
                      value="recovery_code", command=self.show_method_ui).pack(anchor="w")
        tk.Radiobutton(method_frame, text="Use Security Questions", variable=self.method_var, 
                      value="security_questions", command=self.show_method_ui).pack(anchor="w")

        # Recovery Code UI
        self.recovery_code_frame = tk.LabelFrame(self, text="Recovery Code", padx=10, pady=10)
        tk.Label(self.recovery_code_frame, text="Enter your recovery code:").pack(anchor="w")
        self.recovery_code_entry = tk.Entry(self.recovery_code_frame, width=40, font=("Courier", 10))
        self.recovery_code_entry.pack(fill="x", pady=5)

        # Security Questions UI
        self.security_questions_frame = tk.LabelFrame(self, text="Security Questions", padx=10, pady=10)
        self.question_labels = []
        self.answer_entries = []
        
        questions = [
            "What was the name of your first pet?",
            "In which city were you born?",
            "What was your mother's maiden name?",
            "What was the name of your first school?",
            "What is your favorite book?"
        ]

        for i, question in enumerate(questions[:3]):
            q_frame = tk.Frame(self.security_questions_frame)
            q_frame.pack(fill="x", pady=5)
            
            label = tk.Label(q_frame, text=f"{i+1}. {question}")
            label.pack(anchor="w")
            self.question_labels.append(label)
            
            answer_entry = tk.Entry(q_frame, width=40)
            answer_entry.pack(fill="x", pady=2)
            self.answer_entries.append(answer_entry)

        # New Password UI
        self.new_password_frame = tk.LabelFrame(self, text="New Master Password", padx=10, pady=10)
        tk.Label(self.new_password_frame, text="Enter New Master Password:").pack(anchor="w")
        
        # New password entry with show/hide toggle
        new_pw_frame = tk.Frame(self.new_password_frame)
        new_pw_frame.pack(fill="x", pady=5)
        self.new_password_entry = tk.Entry(new_pw_frame, show="*", width=30)
        self.new_password_entry.pack(side="left", fill="x", expand=True)
        self.new_password_entry.bind('<KeyRelease>', self.update_strength)
        
        self.show_new_password_var = tk.BooleanVar()
        self.show_new_password_check = tk.Checkbutton(new_pw_frame, text="Show", variable=self.show_new_password_var, 
                                                    command=self.toggle_new_password_visibility)
        self.show_new_password_check.pack(side="right", padx=(5, 0))

        tk.Label(self.new_password_frame, text="Confirm New Master Password:").pack(anchor="w", pady=(10, 0))
        
        # Confirm password entry with show/hide toggle
        confirm_pw_frame = tk.Frame(self.new_password_frame)
        confirm_pw_frame.pack(fill="x", pady=5)
        self.confirm_password_entry = tk.Entry(confirm_pw_frame, show="*", width=30)
        self.confirm_password_entry.pack(side="left", fill="x", expand=True)
        
        self.show_confirm_password_var = tk.BooleanVar()
        self.show_confirm_password_check = tk.Checkbutton(confirm_pw_frame, text="Show", variable=self.show_confirm_password_var, 
                                                       command=self.toggle_confirm_password_visibility)
        self.show_confirm_password_check.pack(side="right", padx=(5, 0))

        self.strength_label = tk.Label(self.new_password_frame, text="Strength: ")
        self.strength_label.pack(anchor="w")

        # Buttons
        button_frame = tk.Frame(self)
        button_frame.pack(pady=20)
        tk.Button(button_frame, text="Verify & Reset Password", command=self.verify_and_reset, bg="green", fg="white").pack(side="left", padx=10)
        tk.Button(button_frame, text="Back to Login", command=self.back_to_login).pack(side="left", padx=10)

        # Show initial UI
        self.show_method_ui()

    def toggle_new_password_visibility(self):
        """Toggle between showing and hiding the new password."""
        if self.show_new_password_var.get():
            self.new_password_entry.config(show="")
        else:
            self.new_password_entry.config(show="*")

    def toggle_confirm_password_visibility(self):
        """Toggle between showing and hiding the confirm password."""
        if self.show_confirm_password_var.get():
            self.confirm_password_entry.config(show="")
        else:
            self.confirm_password_entry.config(show="*")

    def show_method_ui(self):
        # Hide all frames
        self.recovery_code_frame.pack_forget()
        self.security_questions_frame.pack_forget()
        self.new_password_frame.pack_forget()

        # Show selected method
        if self.method_var.get() == "recovery_code":
            self.recovery_code_frame.pack(fill="x", padx=20, pady=10)
        else:
            self.security_questions_frame.pack(fill="x", padx=20, pady=10)
        
        self.new_password_frame.pack(fill="x", padx=20, pady=10)

    def update_strength(self, event=None):
        pw = self.new_password_entry.get()
        from utils import password_strength
        score, label = password_strength(pw)
        self.strength_label.config(text=f"Strength: {label}")

    def set_vault_data(self, vault_data):
        self.vault_data = vault_data
        # Load the encrypted vault content for recovery
        if vault_data and '_needs_recovery' in vault_data:
            try:
                with open("vault.dat", 'r') as f:
                    self.encrypted_vault_content = f.read()
            except Exception as e:
                messagebox.showerror("Error", f"Cannot read vault file: {str(e)}")

    def decrypt_vault_with_recovery(self, recovery_info):
        """Decrypt the vault using recovery code or security questions."""
        if not self.encrypted_vault_content:
            return None
        
        try:
            from storage import decode_b64
            from crypto import derive_key, decrypt
            
            # Parse the encrypted content
            salt_b64, nonce_b64, tag_b64, ciphertext_b64 = self.encrypted_vault_content.split(':')
            salt = decode_b64(salt_b64)
            nonce = decode_b64(nonce_b64)
            tag = decode_b64(tag_b64)
            ciphertext = decode_b64(ciphertext_b64)
            
            # Try different passwords derived from recovery info
            test_passwords = []
            
            if self.method_var.get() == "recovery_code":
                # Use recovery code as password
                test_passwords.append(recovery_info)
            else:
                # Use security question answers as password
                for question, answer in recovery_info:
                    test_passwords.append(answer)
                    test_passwords.append(question + answer)
                    test_passwords.append(answer + question)
            
            # Try each test password
            for test_pw in test_passwords:
                try:
                    key, _ = derive_key(test_pw, salt)
                    plaintext = decrypt(ciphertext, key, nonce, tag)
                    vault_data = json.loads(plaintext.decode())
                    
                    # Verify this is the correct password by checking recovery data
                    if self.method_var.get() == "recovery_code":
                        from storage import check_recovery_code
                        if check_recovery_code(vault_data, recovery_info):
                            return vault_data
                    else:
                        from storage import check_security_questions
                        if check_security_questions(vault_data, recovery_info):
                            return vault_data
                except:
                    continue
            
            return None
        except Exception as e:
            return None

    def verify_and_reset(self):
        if not self.encrypted_vault_content:
            messagebox.showerror("Error", "No vault data available.")
            return

        # Get recovery info
        if self.method_var.get() == "recovery_code":
            recovery_code = self.recovery_code_entry.get().strip()
            if not recovery_code:
                messagebox.showerror("Error", "Please enter your recovery code.")
                return
            recovery_info = recovery_code
        else:
            # Security questions
            answers = []
            for i, entry in enumerate(self.answer_entries):
                answer = entry.get().strip()
                if not answer:
                    messagebox.showerror("Error", f"Please answer question {i+1}.")
                    return
                answers.append((self.question_labels[i].cget("text").split(". ", 1)[1], answer))
            recovery_info = answers

        # Try to decrypt the vault
        vault_data = self.decrypt_vault_with_recovery(recovery_info)
        if not vault_data:
            messagebox.showerror("Error", "Recovery information is incorrect.")
            return

        # Get new password
        new_password = self.new_password_entry.get()
        confirm_password = self.confirm_password_entry.get()
        
        if not new_password:
            messagebox.showerror("Error", "Please enter a new master password.")
            return
        
        if new_password != confirm_password:
            messagebox.showerror("Error", "Passwords do not match.")
            return

        # Re-encrypt vault with new password
        from storage import save_vault
        # Remove recovery data from vault data for re-encryption
        clean_vault = {k: v for k, v in vault_data.items() 
                      if k not in ['recovery_hash', 'security_questions']}
        
        save_vault("vault.dat", clean_vault, new_password)
        
        self.controller.vault_data = clean_vault
        self.controller.password = new_password
        
        messagebox.showinfo("Success", "Master password has been reset successfully!")
        self.controller.show_frame("VaultFrame")

    def back_to_login(self):
        self.controller.show_frame("LoginFrame") 