import os
import hashlib
import gc
import tkinter as tk
from tkinter import filedialog, ttk, messagebox
from collections import defaultdict
from PIL import Image, ImageTk

class DupeSweep:
    BATCH_SIZE = 1000
    
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("DupeSweep Pro")
        self.root.geometry("1000x800")
        self.duplicates = defaultdict(list)
        self.hash_groups = defaultdict(list)
        self.file_map = {}
        self.selection_map = {}
        
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        scan_frame = ttk.Frame(main_frame)
        scan_frame.pack(fill=tk.X, pady=5)
        scan_btn = ttk.Button(scan_frame, text="Scan Folder", command=self.scan)
        scan_btn.pack(side=tk.LEFT, padx=5)
        
        self.cancel_btn = ttk.Button(scan_frame, text="Cancel Scan", command=self.cancel_scan, state=tk.DISABLED)
        self.cancel_btn.pack(side=tk.LEFT, padx=5)
        
        progress_frame = ttk.Frame(main_frame)
        progress_frame.pack(fill=tk.X, pady=5)
        
        self.progress_var = tk.DoubleVar()
        self.progress = ttk.Progressbar(progress_frame, length=850, variable=self.progress_var)
        self.progress.pack(fill=tk.X)
        
        self.status = tk.StringVar()
        self.status.set("Ready to scan")
        status_lbl = ttk.Label(progress_frame, textvariable=self.status)
        status_lbl.pack(pady=5)
        
        tree_frame = ttk.Frame(main_frame)
        tree_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        
        self.tree = ttk.Treeview(tree_frame, columns=("Size", "Count", "Hash"), show="headings", selectmode="extended")
        self.tree.heading("#0", text="Preview")
        self.tree.heading("Size", text="Size (bytes)")
        self.tree.column("Size", width=120, anchor=tk.E)
        self.tree.heading("Count", text="Duplicates")
        self.tree.column("Count", width=80, anchor=tk.CENTER)
        self.tree.heading("Hash", text="Content Hash (SHA-256)")
        self.tree.column("Hash", width=150)
        
        vsb = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview)
        hsb = ttk.Scrollbar(tree_frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        
        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        
        tree_frame.grid_rowconfigure(0, weight=1)
        tree_frame.grid_columnconfigure(0, weight=1)
        
        preview_frame = ttk.LabelFrame(main_frame, text="Selected Duplicate Group")
        preview_frame.pack(fill=tk.X, pady=5)
        
        self.path_var = tk.StringVar()
        path_label = ttk.Label(preview_frame, textvariable=self.path_var, wraplength=950)
        path_label.pack(fill=tk.X, padx=5, pady=2)
        
        preview_canvas_frame = ttk.Frame(preview_frame)
        preview_canvas_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.preview_canvas = tk.Canvas(preview_canvas_frame, height=80)
        self.preview_canvas.pack(fill=tk.X)
        self.previews = []
        self.preview_labels = []
        
        self.file_listbox = tk.Listbox(preview_frame, selectmode=tk.EXTENDED, height=6)
        self.file_listbox.pack(fill=tk.X, padx=5, pady=5)
        
        selection_frame = ttk.Frame(preview_frame)
        selection_frame.pack(fill=tk.X, pady=5)
        
        ttk.Button(selection_frame, text="Select All", command=self.select_all).pack(side=tk.LEFT, padx=5)
        ttk.Button(selection_frame, text="Clear Selection", command=self.clear_selection).pack(side=tk.LEFT, padx=5)
        
        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(fill=tk.X, pady=5)
        
        self.delete_selected_btn = ttk.Button(btn_frame, text="Delete Selected Files", command=self.delete_selected_files, state=tk.DISABLED)
        self.delete_selected_btn.pack(side=tk.LEFT, padx=5)
        
        self.delete_all_btn = ttk.Button(btn_frame, text="Delete All Duplicates in Group", command=self.delete_all_duplicates, state=tk.DISABLED)
        self.delete_all_btn.pack(side=tk.LEFT, padx=5)
        
        self.tree.bind("<<TreeviewSelect>>", self.show_group_details)
        self.file_listbox.bind("<<ListboxSelect>>", self.show_file_details)
        
        self.scan_canceled = False
        self.current_group = None
            
    def get_hash(self, filepath):
        hasher = hashlib.sha256()
        try:
            with open(filepath, "rb") as f:
                while chunk := f.read(8192):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except Exception:
            return None
            
    def cancel_scan(self):
        self.scan_canceled = True
        self.cancel_btn.config(state=tk.DISABLED)
    
    def scan(self):
        folder = filedialog.askdirectory()
        if not folder:
            return
            
        self.scan_canceled = False
        self.cancel_btn.config(state=tk.NORMAL)
        self.selection_map.clear()
        
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.duplicates.clear()
        self.hash_groups.clear()
        self.file_map.clear()
        self.previews.clear()
        self.file_listbox.delete(0, tk.END)
        self.path_var.set("")
        self.delete_selected_btn.config(state=tk.DISABLED)
        self.delete_all_btn.config(state=tk.DISABLED)
        self.status.set("Counting files...")
        self.progress_var.set(0)
        self.root.update()
        
        total_files = 0
        for root, _, files in os.walk(folder):
            total_files += len(files)
        self.status.set(f"Found {total_files} files to scan")
        self.root.update()
        
        size_map = defaultdict(list)
        file_count = 0
        processed_files = 0
        batch_count = 0
        
        for root, _, files in os.walk(folder):
            if self.scan_canceled:
                self.status.set("Scan canceled")
                self.cancel_btn.config(state=tk.DISABLED)
                return
                
            for f in files:
                file_count += 1
                path = os.path.join(root, f)
                try:
                    if not os.path.isfile(path):
                        continue
                    size = os.path.getsize(path)
                    size_map[size].append(path)
                    processed_files += 1
                    
                    if processed_files % 100 == 0:
                        self.progress_var.set(processed_files * 50 / total_files)
                        self.status.set(f"Files scanned: {processed_files}/{total_files}")
                        self.root.update()
                except OSError:
                    pass
                
                batch_count += 1
                if batch_count >= self.BATCH_SIZE:
                    gc.collect()
                    batch_count = 0
            
            gc.collect()
        
        self.duplicates = {size: paths for size, paths in size_map.items() if len(paths) > 1}
        self.status.set(f"Found {len(self.duplicates)} potential duplicate groups")
        self.root.update()
        
        hash_group_count = 0
        hash_files_processed = 0
        total_to_hash = sum(len(paths) for paths in self.duplicates.values())
        batch_count = 0
        
        for size_idx, (size, paths) in enumerate(self.duplicates.items()):
            if self.scan_canceled:
                self.status.set("Scan canceled")
                self.cancel_btn.config(state=tk.DISABLED)
                return
                
            hash_map = defaultdict(list)
            for path in paths:
                file_hash = self.get_hash(path)
                if file_hash:
                    hash_map[file_hash].append(path)
                
                hash_files_processed += 1
                batch_count += 1
                
                if hash_files_processed % 5 == 0:
                    progress = 50 + (hash_files_processed * 50 / total_to_hash)
                    self.progress_var.set(progress)
                    self.status.set(f"Hashing: {hash_files_processed}/{total_to_hash}")
                    self.root.update()
                
                if batch_count >= self.BATCH_SIZE:
                    gc.collect()
                    batch_count = 0
            
            for h, dupes in hash_map.items():
                if len(dupes) > 1:
                    self.hash_groups[(size, h)] = dupes
                    hash_group_count += 1
            
            if size_idx % 10 == 0:
                gc.collect()
        
        self.status.set(f"Building display for {hash_group_count} duplicate groups")
        self.root.update()
        
        batch_count = 0
        for group_idx, ((size, h), paths) in enumerate(self.hash_groups.items()):
            item_id = self.tree.insert("", tk.END, text="", values=(f"{size:,}", len(paths), h[:16] + "..."))
            self.file_map[item_id] = (size, h, paths)
            
            if paths[0].lower().endswith(('.png', '.jpg', '.jpeg', '.bmp', '.gif', '.webp')):
                try:
                    img = Image.open(paths[0])
                    img.thumbnail((48, 48), Image.LANCZOS)
                    photo = ImageTk.PhotoImage(img)
                    self.previews.append(photo)
                    self.tree.item(item_id, image=photo)
                except Exception:
                    pass
            
            batch_count += 1
            if batch_count >= self.BATCH_SIZE:
                self.root.update()
                gc.collect()
                batch_count = 0
        
        self.progress_var.set(100)
        self.status.set(f"Scan complete! Found {hash_group_count} duplicate groups")
        self.cancel_btn.config(state=tk.DISABLED)
    
    def show_group_details(self, event):
        self.file_listbox.delete(0, tk.END)
        self.preview_canvas.delete("all")
        for label in self.preview_labels:
            label.destroy()
        self.preview_labels = []
        self.previews = []
        self.path_var.set("")
        self.current_group = None
        self.delete_selected_btn.config(state=tk.DISABLED)
        self.delete_all_btn.config(state=tk.DISABLED)
        
        selected_items = self.tree.selection()
        if not selected_items:
            return
        
        item_id = selected_items[0]
        group_data = self.file_map.get(item_id)
        if not group_data:
            return
            
        size, h, paths = group_data
        self.current_group = group_data
        self.path_var.set(f"Duplicate Group: {len(paths)} files, Size: {size:,} bytes, Hash: {h[:16]}...")
        
        preview_frame = ttk.Frame(self.preview_canvas)
        self.preview_canvas.create_window((0, 0), window=preview_frame, anchor=tk.NW)
        
        for idx, path in enumerate(paths[:12]):
            try:
                frame = ttk.Frame(preview_frame)
                frame.grid(row=0, column=idx, padx=5, pady=5)
                filename = os.path.basename(path)
                if len(filename) > 15:
                    filename = filename[:12] + "..."
                if path.lower().endswith(('.png', '.jpg', '.jpeg', '.bmp', '.gif', '.webp')):
                    img = Image.open(path)
                    img.thumbnail((64, 64), Image.LANCZOS)
                    photo = ImageTk.PhotoImage(img)
                    self.previews.append(photo)
                    label = ttk.Label(frame, image=photo, compound=tk.TOP, text=filename)
                    label.image = photo
                else:
                    label = ttk.Label(frame, text=filename, compound=tk.TOP)
                label.pack()
                self.preview_labels.append(label)
            except Exception:
                pass
        
        preview_frame.update_idletasks()
        self.preview_canvas.config(scrollregion=self.preview_canvas.bbox("all"))
        
        for path in paths:
            self.file_listbox.insert(tk.END, path)
        
        self.delete_all_btn.config(state=tk.NORMAL)
    
    def show_file_details(self, event):
        selected = self.file_listbox.curselection()
        if not selected:
            return
            
        path = self.file_listbox.get(selected[0])
        self.path_var.set(f"Selected File: {path}")
    
    def select_all(self):
        self.file_listbox.select_set(0, tk.END)
    
    def clear_selection(self):
        self.file_listbox.select_clear(0, tk.END)
    
    def delete_selected_files(self):
        if not self.current_group:
            return
            
        selected = self.file_listbox.curselection()
        if not selected:
            messagebox.showinfo("No Selection", "Select files to delete first")
            return
            
        if not messagebox.askyesno("Confirm Deletion", "Permanently delete selected files?"):
            return
            
        deleted_count = 0
        paths_to_delete = [self.file_listbox.get(i) for i in selected]
        
        for path in paths_to_delete:
            try:
                os.remove(path)
                deleted_count += 1
            except Exception:
                pass
        
        messagebox.showinfo("Deletion Complete", f"Deleted {deleted_count} files")
        self.scan()
    
    def delete_all_duplicates(self):
        if not self.current_group:
            return
            
        size, h, paths = self.current_group
        if len(paths) < 2:
            return
            
        if not messagebox.askyesno("Confirm Deletion", 
                                  f"Permanently delete all duplicates in this group?\n\n"
                                  f"This will delete {len(paths)-1} files, keeping the first one."):
            return
            
        deleted_count = 0
        for path in paths[1:]:
            try:
                os.remove(path)
                deleted_count += 1
            except Exception:
                pass
        
        messagebox.showinfo("Deletion Complete", f"Deleted {deleted_count} files")
        self.scan()
    
    def run(self):
        self.root.mainloop()

if __name__ == "__main__":
    app = DupeSweep()
    app.run()
