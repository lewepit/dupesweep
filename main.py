import os
import collections
import tkinter as tk
from tkinter import filedialog, ttk

class DupeSweep:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("DupeSweep v0.2")
        self.duplicates = collections.defaultdict(list)
        
        # UI Improvements
        ttk.Button(self.root, text="Scan Folder", command=self.scan).pack(pady=10)
        self.progress = ttk.Progressbar(self.root, length=400)
        self.progress.pack()
        self.tree = ttk.Treeview(self.root, columns=("Size", "Count"), show="headings")
        self.tree.heading("#0", text="File Size")
        self.tree.heading("Size", text="Size (bytes)")
        self.tree.heading("Count", text="Duplicates")
    
    def scan(self):
        folder = filedialog.askdirectory()
        if not folder: return
        
        size_map = collections.defaultdict(list)
        file_count = 0
        
        # Phase 1: Group by file size
        for root, _, files in os.walk(folder):
            for f in files:
                path = os.path.join(root, f)
                try:
                    size = os.path.getsize(path)
                    size_map[size].append(path)
                    file_count += 1
                except OSError:
                    pass
        
        # Find duplicates (same size)
        self.duplicates = {size: paths for size, paths in size_map.items() if len(paths) > 1}
        
        # Display results
        for size, paths in self.duplicates.items():
            self.tree.insert("", tk.END, text=str(size), values=(size, len(paths)))
        self.tree.pack(fill=tk.BOTH, expand=True)

    def run(self):
        self.root.mainloop()

if __name__ == "__main__":
    app = DupeSweep()
    app.run()
