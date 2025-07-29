import tkinter as tk
import os
from UI.login_frame import LoginFrame
from UI.setup_frame import SetupFrame
from UI.vault_frame import VaultFrame
from UI.entry_frame import EntryFrame
from UI.recovery_frame import RecoveryFrame

class PasswordManagerApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Password Manager")
        self.geometry("600x400")
        self.resizable(False, False)
        
        # Shared state
        self.vault_data = None
        self.password = None

        # Container for all frames
        container = tk.Frame(self)
        container.pack(side="top", fill="both", expand=True)
        container.grid_rowconfigure(0, weight=1)
        container.grid_columnconfigure(0, weight=1)

        self.frames = {}
        for F in (LoginFrame, SetupFrame, VaultFrame, EntryFrame, RecoveryFrame):
            frame = F(parent=container, controller=self)
            self.frames[F.__name__] = frame
            frame.grid(row=0, column=0, sticky="nsew")

        # Show appropriate initial frame
        if os.path.exists("vault.dat"):
            self.show_frame("LoginFrame")
        else:
            self.show_frame("SetupFrame")

    def show_frame(self, frame_name):
        frame = self.frames[frame_name]
        if frame_name == "VaultFrame":
            frame.refresh()
        elif frame_name == "RecoveryFrame" and self.vault_data:
            frame.set_vault_data(self.vault_data)
        frame.tkraise()

if __name__ == "__main__":
    app = PasswordManagerApp()
    app.mainloop()
