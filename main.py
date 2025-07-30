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
        self.geometry("500x350")  # Smaller default size to force scrolling
        self.resizable(True, True)  # Make window resizable
        self.minsize(300, 200)  # Set minimum window size
        
        # Shared state
        self.vault_data = None
        self.password = None

        # Create main scrollable frame
        self.create_scrollable_frame()

        self.frames = {}
        for F in (LoginFrame, SetupFrame, VaultFrame, EntryFrame, RecoveryFrame):
            frame = F(parent=self.scrollable_frame, controller=self)
            self.frames[F.__name__] = frame
            frame.grid(row=0, column=0, sticky="nsew")

        # Show appropriate initial frame
        if os.path.exists("vault.dat"):
            self.show_frame("LoginFrame")
        else:
            self.show_frame("SetupFrame")

    def create_scrollable_frame(self):
        """Create a scrollable frame that can accommodate all content."""
        # Create main frame
        main_frame = tk.Frame(self)
        main_frame.pack(fill="both", expand=True)
        
        # Create canvas with scrollbars
        self.canvas = tk.Canvas(main_frame, bg="white")
        self.v_scrollbar = tk.Scrollbar(main_frame, orient="vertical", command=self.canvas.yview)
        self.h_scrollbar = tk.Scrollbar(main_frame, orient="horizontal", command=self.canvas.xview)
        
        # Configure canvas
        self.scrollable_frame = tk.Frame(self.canvas)
        self.scrollable_frame.bind(
            "<Configure>",
            lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all"))
        )
        
        # Create window in canvas
        self.canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")
        self.canvas.configure(yscrollcommand=self.v_scrollbar.set, xscrollcommand=self.h_scrollbar.set)
        
        # Pack scrollbars and canvas
        self.v_scrollbar.pack(side="right", fill="y")
        self.h_scrollbar.pack(side="bottom", fill="x")
        self.canvas.pack(side="left", fill="both", expand=True)
        
        # Bind mouse wheel scrolling
        self.canvas.bind("<MouseWheel>", self._on_mousewheel)
        self.canvas.bind("<Button-4>", self._on_mousewheel)
        self.canvas.bind("<Button-5>", self._on_mousewheel)
        
        # Bind frame resize to update scroll region
        self.bind("<Configure>", self._on_frame_configure)
        
        # Force initial scroll region update
        self.after(100, self._update_scroll_region)

    def _on_mousewheel(self, event):
        """Handle mouse wheel scrolling."""
        if event.num == 4:  # Linux scroll up
            self.canvas.yview_scroll(-1, "units")
        elif event.num == 5:  # Linux scroll down
            self.canvas.yview_scroll(1, "units")
        else:  # Windows/Mac
            self.canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")

    def _on_frame_configure(self, event=None):
        """Update scroll region when frame is configured."""
        self._update_scroll_region()

    def _update_scroll_region(self):
        """Update the scroll region of the canvas."""
        self.canvas.update_idletasks()
        self.canvas.configure(scrollregion=self.canvas.bbox("all"))

    def show_frame(self, frame_name):
        frame = self.frames[frame_name]
        if frame_name == "VaultFrame":
            frame.refresh()
        elif frame_name == "RecoveryFrame" and self.vault_data:
            frame.set_vault_data(self.vault_data)
        frame.tkraise()
        
        # Update scroll region after showing frame
        self.after(100, self._update_scroll_region)

if __name__ == "__main__":
    app = PasswordManagerApp()
    app.mainloop()
