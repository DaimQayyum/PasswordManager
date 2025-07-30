import tkinter as tk
from tkinter import ttk, messagebox
from storage import save_vault
from utils import clear_clipboard_after, CLIPBOARD_CLEAR_DELAY_MS

class VaultFrame(tk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        self.setup_ui()

    def setup_ui(self):
        # Configure frame to expand properly
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)
        
        # Main content frame
        main_frame = tk.Frame(self)
        main_frame.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)
        
        # Search frame
        search_frame = tk.Frame(main_frame)
        search_frame.pack(fill="x", pady=5)
        tk.Label(search_frame, text="Search:").pack(side="left", padx=5)
        self.search_entry = tk.Entry(search_frame)
        self.search_entry.pack(side="left", fill="x", expand=True)
        self.search_entry.bind('<KeyRelease>', self.on_search)
        
        # Treeview with scrollbars
        tree_frame = tk.Frame(main_frame)
        tree_frame.pack(fill="both", expand=True, pady=10)
        
        # Create treeview
        self.tree = ttk.Treeview(tree_frame, columns=("Site", "Username", "Password"), show="headings")
        self.tree.heading("Site", text="Site")
        self.tree.heading("Username", text="Username")
        self.tree.heading("Password", text="Password")
        
        # Add scrollbars to treeview
        tree_v_scrollbar = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview)
        tree_h_scrollbar = ttk.Scrollbar(tree_frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=tree_v_scrollbar.set, xscrollcommand=tree_h_scrollbar.set)
        
        # Pack treeview and scrollbars
        self.tree.grid(row=0, column=0, sticky="nsew")
        tree_v_scrollbar.grid(row=0, column=1, sticky="ns")
        tree_h_scrollbar.grid(row=1, column=0, sticky="ew")
        
        # Configure grid weights
        tree_frame.grid_rowconfigure(0, weight=1)
        tree_frame.grid_columnconfigure(0, weight=1)
        
        # Button frame
        button_frame = tk.Frame(main_frame)
        button_frame.pack(fill="x", pady=5)
        tk.Button(button_frame, text="Copy", command=self.copy_entry).pack(side="left", padx=5)
        tk.Button(button_frame, text="Add", command=self.add_entry).pack(side="left", padx=5)
        tk.Button(button_frame, text="Edit", command=self.edit_entry).pack(side="left", padx=5)
        tk.Button(button_frame, text="Delete", command=self.delete_entry).pack(side="left", padx=5)

    def refresh(self):
        self.update_tree()

    def on_search(self, event=None):
        self.update_tree()

    def update_tree(self):
        self.tree.delete(*self.tree.get_children())
        vault_data = self.controller.vault_data or {}
        query = self.search_entry.get().lower().strip()
        for site, entry in vault_data.items():
            username = entry.get("username", "")
            if (not query or query in site.lower() or query in username.lower()):
                self.tree.insert("", "end", iid=site, values=(site, username, entry.get("password", "")))

    def copy_entry(self):
        selected = self.tree.selection()
        if not selected:
            messagebox.showerror("Error", "No entry selected.")
            return
        site = selected[0]
        entry = self.controller.vault_data.get(site, {})
        password = entry.get("password", "")
        if not password:
            messagebox.showerror("Error", "No password to copy.")
            return
        self.clipboard_clear()
        self.clipboard_append(password)
        clear_clipboard_after(CLIPBOARD_CLEAR_DELAY_MS, self)
        messagebox.showinfo("Copied", "Password copied to clipboard. It will be cleared soon.")

    def add_entry(self):
        entry_frame = self.controller.frames["EntryFrame"]
        entry_frame.set_mode('add')
        self.controller.show_frame("EntryFrame")

    def edit_entry(self):
        selected = self.tree.selection()
        if not selected:
            messagebox.showerror("Error", "No entry selected.")
            return
        site = selected[0]
        entry = self.controller.vault_data.get(site, {})
        entry_frame = self.controller.frames["EntryFrame"]
        entry_frame.set_mode('edit', site, entry)
        self.controller.show_frame("EntryFrame")

    def delete_entry(self):
        selected = self.tree.selection()
        if not selected:
            messagebox.showerror("Error", "No entry selected.")
            return
        site = selected[0]
        confirm = messagebox.askyesno("Delete", f"Delete entry for '{site}'?")
        if not confirm:
            return
        vault_data = self.controller.vault_data or {}
        if site in vault_data:
            del vault_data[site]
            self.controller.vault_data = vault_data
            save_vault("vault.dat", vault_data, self.controller.password)
            self.refresh()
            messagebox.showinfo("Deleted", f"Entry for '{site}' deleted.")
