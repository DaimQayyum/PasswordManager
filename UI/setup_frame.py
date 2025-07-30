import tkinter as tk
from tkinter import messagebox, ttk
from utils import password_strength, generate_recovery_code

class SetupFrame(tk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        self.recovery_code = None
        self.setup_ui()

    def setup_ui(self):
        # Configure frame to expand properly
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)
        
        # Main content frame
        main_frame = tk.Frame(self)
        main_frame.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)
        
        # Title
        title_label = tk.Label(main_frame, text="Set Up Your Password Manager", font=("Arial", 16, "bold"))
        title_label.pack(pady=20)

        # Instructions
        instructions_frame = tk.LabelFrame(main_frame, text="Important Instructions", padx=10, pady=10)
        instructions_frame.pack(fill="x", padx=20, pady=10)
        
        instruction_text = """Welcome to your Password Manager setup!

1. Choose a strong master password that you'll remember
2. Generate and save your recovery code in a safe place
3. Optionally answer security questions for additional backup
4. Keep your master password and recovery code secure

This setup will create your encrypted password vault."""
        
        tk.Label(instructions_frame, text=instruction_text, justify="left", wraplength=400).pack(anchor="w")

        # Master Password Setup
        pw_frame = tk.LabelFrame(main_frame, text="Master Password", padx=10, pady=10)
        pw_frame.pack(fill="x", padx=20, pady=10)

        tk.Label(pw_frame, text="Enter Master Password:").pack(anchor="w")
        
        # Password entry with show/hide toggle
        pw_entry_frame = tk.Frame(pw_frame)
        pw_entry_frame.pack(fill="x", pady=5)
        self.password_entry = tk.Entry(pw_entry_frame, show="*", width=30)
        self.password_entry.pack(side="left", fill="x", expand=True)
        self.password_entry.bind('<KeyRelease>', self.update_strength)
        
        self.show_password_var = tk.BooleanVar()
        self.show_password_check = tk.Checkbutton(pw_entry_frame, text="Show", variable=self.show_password_var, 
                                                command=self.toggle_password_visibility)
        self.show_password_check.pack(side="right", padx=(5, 0))

        tk.Label(pw_frame, text="Confirm Master Password:").pack(anchor="w", pady=(10, 0))
        
        # Confirm password entry with show/hide toggle
        confirm_entry_frame = tk.Frame(pw_frame)
        confirm_entry_frame.pack(fill="x", pady=5)
        self.confirm_entry = tk.Entry(confirm_entry_frame, show="*", width=30)
        self.confirm_entry.pack(side="left", fill="x", expand=True)
        
        self.show_confirm_var = tk.BooleanVar()
        self.show_confirm_check = tk.Checkbutton(confirm_entry_frame, text="Show", variable=self.show_confirm_var, 
                                               command=self.toggle_confirm_visibility)
        self.show_confirm_check.pack(side="right", padx=(5, 0))

        self.strength_label = tk.Label(pw_frame, text="Strength: ")
        self.strength_label.pack(anchor="w")

        # Password Tips
        tips_frame = tk.LabelFrame(main_frame, text="Password Security Tips", padx=10, pady=10)
        tips_frame.pack(fill="x", padx=20, pady=10)
        
        tips_text = """• Use at least 12 characters
• Include uppercase and lowercase letters
• Include numbers and special characters
• Avoid common words or patterns
• Don't reuse passwords from other accounts"""
        
        tk.Label(tips_frame, text=tips_text, justify="left", wraplength=400).pack(anchor="w")

        # Recovery Code
        recovery_frame = tk.LabelFrame(main_frame, text="Recovery Code", padx=10, pady=10)
        recovery_frame.pack(fill="x", padx=20, pady=10)

        tk.Label(recovery_frame, text="Your recovery code (write this down!):", font=("Arial", 10, "bold")).pack(anchor="w")
        self.recovery_code_label = tk.Label(recovery_frame, text="Click 'Generate Recovery Code'", font=("Courier", 12), fg="blue")
        self.recovery_code_label.pack(pady=5)
        
        code_btn_frame = tk.Frame(recovery_frame)
        code_btn_frame.pack(pady=5)
        tk.Button(code_btn_frame, text="Generate Recovery Code", command=self.generate_recovery_code).pack(side="left", padx=5)
        tk.Button(code_btn_frame, text="Copy Code", command=self.copy_recovery_code).pack(side="left", padx=5)

        # Recovery Code Instructions
        recovery_instructions = tk.LabelFrame(main_frame, text="Recovery Code Instructions", padx=10, pady=10)
        recovery_instructions.pack(fill="x", padx=20, pady=10)
        
        recovery_text = """IMPORTANT: Write down your recovery code and keep it in a safe place!

• This code is your backup if you forget your master password
• Store it securely (not on your computer)
• You can use it to reset your master password
• Without this code, you may lose access to your passwords"""
        
        tk.Label(recovery_instructions, text=recovery_text, justify="left", wraplength=400, fg="red").pack(anchor="w")

        # Security Questions
        questions_frame = tk.LabelFrame(main_frame, text="Security Questions (Optional Backup)", padx=10, pady=10)
        questions_frame.pack(fill="x", padx=20, pady=10)

        self.question_entries = []
        self.answer_entries = []
        
        questions = [
            "What was the name of your first pet?",
            "In which city were you born?",
            "What was your mother's maiden name?",
            "What was the name of your first school?",
            "What is your favorite book?"
        ]

        for i, question in enumerate(questions[:3]):  # Use first 3 questions
            q_frame = tk.Frame(questions_frame)
            q_frame.pack(fill="x", pady=5)
            
            tk.Label(q_frame, text=f"{i+1}. {question}").pack(anchor="w")
            answer_entry = tk.Entry(q_frame, width=40)
            answer_entry.pack(fill="x", pady=2)
            
            self.question_entries.append(question)
            self.answer_entries.append(answer_entry)

        # Security Questions Note
        security_note = tk.LabelFrame(main_frame, text="Security Questions Note", padx=10, pady=10)
        security_note.pack(fill="x", padx=20, pady=10)
        
        note_text = """Security questions provide an additional recovery method:
• Answer truthfully but consider using slight variations
• These can help you recover your account if needed
• Optional but recommended for better security"""
        
        tk.Label(security_note, text=note_text, justify="left", wraplength=400).pack(anchor="w")

        # Buttons
        button_frame = tk.Frame(main_frame)
        button_frame.pack(pady=20)
        tk.Button(button_frame, text="Create Vault", command=self.create_vault, bg="green", fg="white").pack(side="left", padx=10)
        tk.Button(button_frame, text="Cancel", command=self.cancel).pack(side="left", padx=10)

        # Final Note
        final_note = tk.LabelFrame(main_frame, text="Final Note", padx=10, pady=10)
        final_note.pack(fill="x", padx=20, pady=10)
        
        final_text = """Your password vault will be encrypted and stored locally on your computer.
Only you can access it with your master password or recovery code.
Your passwords are never sent to any server and remain under your control."""
        
        tk.Label(final_note, text=final_text, justify="left", wraplength=400).pack(anchor="w")

    def toggle_password_visibility(self):
        """Toggle between showing and hiding the password."""
        if self.show_password_var.get():
            self.password_entry.config(show="")
        else:
            self.password_entry.config(show="*")

    def toggle_confirm_visibility(self):
        """Toggle between showing and hiding the confirm password."""
        if self.show_confirm_var.get():
            self.confirm_entry.config(show="")
        else:
            self.confirm_entry.config(show="*")

    def update_strength(self, event=None):
        pw = self.password_entry.get()
        score, label = password_strength(pw)
        self.strength_label.config(text=f"Strength: {label}")

    def generate_recovery_code(self):
        self.recovery_code = generate_recovery_code()
        self.recovery_code_label.config(text=self.recovery_code)

    def copy_recovery_code(self):
        if self.recovery_code:
            self.clipboard_clear()
            self.clipboard_append(self.recovery_code)
            messagebox.showinfo("Copied", "Recovery code copied to clipboard!")

    def create_vault(self):
        password = self.password_entry.get()
        confirm = self.confirm_entry.get()
        
        if not password:
            messagebox.showerror("Error", "Please enter a master password.")
            return
        
        if password != confirm:
            messagebox.showerror("Error", "Passwords do not match.")
            return
        
        if not self.recovery_code:
            messagebox.showerror("Error", "Please generate a recovery code.")
            return
        
        # Get security questions
        security_qa = []
        for i, answer_entry in enumerate(self.answer_entries):
            answer = answer_entry.get().strip()
            if answer:  # Only include if user provided an answer
                security_qa.append((self.question_entries[i], answer))
        
        # Create vault
        vault_data = {}
        if security_qa:
            from storage import set_security_questions
            vault_data = set_security_questions(vault_data, security_qa)
        
        from storage import set_recovery_code, save_vault
        vault_data = set_recovery_code(vault_data, self.recovery_code)
        
        save_vault("vault.dat", vault_data, password)
        
        self.controller.vault_data = vault_data
        self.controller.password = password
        
        messagebox.showinfo("Success", "Vault created successfully! You can now add your passwords.")
        self.controller.show_frame("VaultFrame")

    def cancel(self):
        self.controller.show_frame("LoginFrame") 