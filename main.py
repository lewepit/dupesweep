import os
import tkinter as tk
from tkinter import filedialog

class DupeSweep:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("DupeSweep v0.1")
        
        # Basic UI elements
        tk.Button(self.root, text="Select Folder", command=self.select_folder).pack()
        self.listbox = tk.Listbox(self.root, width=100)
        self.listbox.pack()
        
    def select_folder(self):
        folder = filedialog.askdirectory()
        if folder:
            self.listbox.insert(tk.END, f"Selected: {folder}")
    
    def run(self):
        self.root.mainloop()

if __name__ == "__main__":
    app = DupeSweep()
    app.run()
