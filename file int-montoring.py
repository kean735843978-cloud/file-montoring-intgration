import os
import hashlib
import json
import time
from json import JSONDecodeError
import re
import threading
from visualizer import count_log_events, visualize_log_counts_horizontal
import customtkinter as ctk
from tkinter import messagebox, scrolledtext, ttk
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import webbrowser

# Set appearance mode and color theme
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")


class DirectoryMonitorGUI:
    def __init__(self):
        self.root = ctk.CTk()
        self.root.title("File Monitor Tool - Professional Edition")
        self.root.geometry("1200x800")
        self.root.minsize(900, 600)

        # Variables
        self.monitor = None
        self.monitoring_thread = None
        self.monitor_active = False
        self.log_file = '../log.txt'

        self.setup_gui()

    def setup_gui(self):
        # Main container
        self.main_frame = ctk.CTkFrame(self.root)
        self.main_frame.pack(fill="both", expand=True, padx=20, pady=20)

        # Header
        header_frame = ctk.CTkFrame(self.main_frame, fg_color="transparent")
        header_frame.pack(fill="x", pady=(0, 20))

        title_label = ctk.CTkLabel(
            header_frame,
            text="🛡️  File & Directory Monitor Tool",
            font=ctk.CTkFont(size=28, weight="bold")
        )
        title_label.pack(pady=10)

        subtitle_label = ctk.CTkLabel(
            header_frame,
            text="Professional real-time file system change detection",
            font=ctk.CTkFont(size=16)
        )
        subtitle_label.pack()

        # Path input section
        path_frame = ctk.CTkFrame(self.main_frame)
        path_frame.pack(fill="x", pady=(0, 20))

        ctk.CTkLabel(path_frame, text="Directory Path:", font=ctk.CTkFont(size=16, weight="bold")).pack(pady=(20, 10),
                                                                                                          anchor="w",
                                                                                                          padx=20)

        path_input_frame = ctk.CTkFrame(path_frame)
        path_input_frame.pack(fill="x", padx=20, pady=(0, 20))

        self.path_entry = ctk.CTkEntry(
            path_input_frame,
            placeholder_text="Enter directory path to monitor...",
            height=40,
            font=ctk.CTkFont(size=14)
        )
        self.path_entry.pack(side="left", fill="x", expand=True, padx=(10, 10), pady=10)

        self.browse_btn = ctk.CTkButton(
            path_input_frame,
            text=" Browse",
            width=100,
            height=40,
            command=self.browse_directory
        )
        self.browse_btn.pack(side="right", padx=(0, 10), pady=10)

        # Control buttons frame
        control_frame = ctk.CTkFrame(self.main_frame)
        control_frame.pack(fill="x", pady=(0, 20))

        self.start_btn = ctk.CTkButton(
            control_frame,
            text="▶ START MONITORING",
            width=200,
            height=50,
            font=ctk.CTkFont(size=16, weight="bold"),
            fg_color="#28a745",
            hover_color="#218838",
            command=self.start_monitoring
        )
        self.start_btn.pack(side="left", padx=20, pady=20)

        self.stop_btn = ctk.CTkButton(
            control_frame,
            text=" STOP MONITORING",
            width=200,
            height=50,
            font=ctk.CTkFont(size=16, weight="bold"),
            fg_color="#dc3545",
            hover_color="#c82333",
            command=self.stop_monitoring,
            state="disabled"
        )
        self.stop_btn.pack(side="left", padx=10, pady=20)

        self.status_label = ctk.CTkLabel(
            control_frame,
            text="⚪ Ready",
            font=ctk.CTkFont(size=16, weight="bold")
        )
        self.status_label.pack(side="right", padx=20, pady=25)

        # Notebook for tabs
        self.notebook = ctk.CTkTabview(self.main_frame)
        self.notebook.pack(fill="both", expand=True, padx=20, pady=(0, 20))

        # Live Logs Tab
        self.logs_tab = self.notebook.add(" Live Logs")
        self.setup_logs_tab()

        # Events Tab
        self.events_tab = self.notebook.add(" Events")
        self.setup_events_tab()

        # Visualization Tab
        self.viz_tab = self.notebook.add("Visualization")
        self.setup_viz_tab()

        # Status bar
        self.status_bar = ctk.CTkFrame(self.main_frame, height=30)
        self.status_bar.pack(fill="x")
        self.status_bar.pack_propagate(False)

        self.status_text = ctk.CTkLabel(self.status_bar, text="Ready to monitor...", anchor="w")
        self.status_text.pack(pady=5, padx=10)

    def setup_logs_tab(self):
        # Logs text area
        self.logs_text = scrolledtext.ScrolledText(
            self.logs_tab,
            wrap="word",
            font=("Consolas", 11),
            bg="#1a1a1a",
            fg="#00ff00",
            insertbackground="#00ff00"
        )
        self.logs_text.pack(fill="both", expand=True, padx=10, pady=10)

        # Filter buttons
        filter_frame = ctk.CTkFrame(self.logs_tab)
        filter_frame.pack(fill="x", padx=10, pady=(0, 10))

        self.filter_all_btn = ctk.CTkButton(
            filter_frame, text="All", width=80, command=lambda: self.filter_logs("all")
        )
        self.filter_all_btn.pack(side="left", padx=5, pady=5)

        self.filter_created_btn = ctk.CTkButton(
            filter_frame, text="Created", width=80, command=lambda: self.filter_logs("created")
        )
        self.filter_created_btn.pack(side="left", padx=5, pady=5)

        self.filter_deleted_btn = ctk.CTkButton(
            filter_frame, text="Deleted", width=80, command=lambda: self.filter_logs("deleted")
        )
        self.filter_deleted_btn.pack(side="left", padx=5, pady=5)

        self.filter_modified_btn = ctk.CTkButton(
            filter_frame, text="Modified", width=80, command=lambda: self.filter_logs("modified")
        )
        self.filter_modified_btn.pack(side="left", padx=5, pady=5)

        self.clear_logs_btn = ctk.CTkButton(
            filter_frame, text="Clear", width=80, fg_color="#ff6b6b", command=self.clear_logs_display
        )
        self.clear_logs_btn.pack(side="right", padx=5, pady=5)

    def setup_events_tab(self):
        # Treeview for events
        columns = ("Time", "Type", "Path", "Details")
        self.events_tree = ttk.Treeview(self.events_tab, columns=columns, show="headings", height=20)

        for col in columns:
            self.events_tree.heading(col, text=col)
            self.events_tree.column(col, width=200)

        # Scrollbars
        v_scrollbar = ttk.Scrollbar(self.events_tab, orient="vertical", command=self.events_tree.yview)
        h_scrollbar = ttk.Scrollbar(self.events_tab, orient="horizontal", command=self.events_tree.xview)
        self.events_tree.configure(yscrollcommand=v_scrollbar.set, xscrollcommand=h_scrollbar.set)

        self.events_tree.pack(side="left", fill="both", expand=True, padx=10, pady=10)
        v_scrollbar.pack(side="right", fill="y", pady=10)
        h_scrollbar.pack(side="bottom", fill="x", padx=10)

        # Refresh button
        refresh_btn = ctk.CTkButton(
            self.events_tab, text=" Refresh", command=self.refresh_events
        )
        refresh_btn.pack(pady=10)

    def setup_viz_tab(self):
        self.viz_frame = ctk.CTkFrame(self.viz_tab)
        self.viz_frame.pack(fill="both", expand=True, padx=10, pady=10)

        self.viz_btn = ctk.CTkButton(
            self.viz_frame,
            text=" Generate Visualization",
            width=200,
            height=40,
            command=self.show_visualization,
            font=ctk.CTkFont(size=16, weight="bold")
        )
        self.viz_btn.pack(pady=20)

        self.viz_label = ctk.CTkLabel(
            self.viz_frame,
            text="Click the button above to generate visualization",
            font=ctk.CTkFont(size=14)
        )
        self.viz_label.pack(pady=10)

    def browse_directory(self):
        from tkinter import filedialog
        directory = filedialog.askdirectory()
        if directory:
            self.path_entry.delete(0, "end")
            self.path_entry.insert(0, directory)

    def log_callback(self, message):
        """Callback for logging from monitor thread"""
        self.root.after(0, lambda: self.update_logs(message))

    def update_logs(self, message):
        timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
        log_message = f"[{timestamp}] {message}\n"
        self.logs_text.insert("end", log_message)
        self.logs_text.see("end")

        # Update status
        if "CREATED" in message.upper():
            self.status_label.configure(text="🟢 Created", text_color="#28a745")
        elif "DELETED" in message.upper():
            self.status_label.configure(text="🔴 Deleted", text_color="#dc3545")
        elif "MODIFIED" in message.upper():
            self.status_label.configure(text="🟡 Modified", text_color="#ffc107")
        elif "RENAMED" in message.upper():
            self.status_label.configure(text="🔵 Renamed", text_color="#007bff")

    def update_status(self, text, color="white"):
        self.status_label.configure(text=text, text_color=color)

    def start_monitoring(self):
        path = self.path_entry.get().strip()
        if not path:
            messagebox.showerror("Error", "Please enter a directory path!")
            return

        if not os.path.isdir(path):
            messagebox.showerror("Error", f"Directory does not exist:\n{path}")
            return

        try:
            self.monitor = DirectoryMonitor(path, self.log_file, self.log_callback)
            self.monitoring_thread = threading.Thread(target=self.monitor.start_monitoring_gui)
            self.monitoring_thread.daemon = True
            self.monitoring_thread.start()

            self.start_btn.configure(state="disabled")
            self.stop_btn.configure(state="normal")
            self.update_status("🟢 MONITORING ACTIVE", "#28a745")

        except Exception as e:
            messagebox.showerror("Error", f"Failed to start monitoring:\n{str(e)}")

    def stop_monitoring(self):
        if self.monitor:
            self.monitor.stop_monitor()
        self.start_btn.configure(state="normal")
        self.stop_btn.configure(state="disabled")
        self.update_status("⚪ Monitoring Stopped", "#6c757d")

    def filter_logs(self, filter_type):
        self.logs_text.tag_config("highlight", background="#404040")
        # Implementation for filtering would go here
        pass

    def clear_logs_display(self):
        self.logs_text.delete(1.0, "end")

    def refresh_events(self):
        # Implementation for refreshing events treeview
        pass

    def show_visualization(self):
        try:
            counts = count_log_events(self.log_file)
            visualize_log_counts_horizontal(counts)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate visualization:\n{str(e)}")

    def run(self):
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.root.mainloop()

    def on_closing(self):
        self.stop_monitoring()
        self.root.destroy()


# Modified DirectoryMonitor class to support GUI
class DirectoryMonitor:
    def __init__(self, dir_path, log_file='log.txt', log_callback=None):
        if not os.path.isdir(dir_path):
            raise FileNotFoundError(f"The specified directory does not exist: {dir_path}")
        self.dir_path = dir_path
        self.log_file = log_file
        self.snapshot_file = os.path.join(dir_path, '.monitor_states.json')
        self.log_callback = log_callback
        self.current_state = {'files': {}, 'directories': {}}
        self.previous_state = self.load_state()
        self.file_metadata = {}
        self.monitor_active = False

    # ... (keep all existing DirectoryMonitor methods exactly the same until start_monitoring) ...

    def _log_event(self, message):
        timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
        log_message = f"[{timestamp}] {message}"
        print(log_message)

        # Call GUI callback if available
        if self.log_callback:
            self.log_callback(message)

        try:
            with open(self.log_file, 'a', encoding='utf-8') as f:
                f.write(log_message + "\n")
        except IOError:
            print(f"[{timestamp}] Cannot write to log.txt file")

    def start_monitoring_gui(self, interval=5):
        """GUI-friendly monitoring that doesn't block"""
        if not os.path.isdir(self.dir_path):
            self._log_event(f"ERROR: Directory not found: {self.dir_path}")
            return

        self._log_event("First scan complete. Monitoring started...")
        self.monitor_active = True

        try:
            while self.monitor_active:
                self.monitor_changes()
                time.sleep(interval)
        except KeyboardInterrupt:
            pass
        finally:
            self.monitor_active = False

    def stop_monitor(self):
        self.monitor_active = False
        self._log_event("Monitor stopped")

    # Include all other existing methods (_calculate_hash, _get_current_state, etc.)
    # Copy them exactly from your original code - I'm keeping them the same
    def _calculate_hash(self, file_path):
        hasher = hashlib.sha256()
        try:
            with open(file_path, 'rb') as f:
                while True:
                    text_body = f.read(4096)
                    if not text_body:
                        break
                    hasher.update(text_body)
            return hasher.hexdigest()
        except (IOError, PermissionError):
            self._log_event(f"Cannot access this file {os.path.basename(file_path)}")
            return None

    def _get_current_state(self):
        state = {'files': {}, 'directories': {}}
        for root, dirs, files in os.walk(self.dir_path):
            for d in dirs:
                dir_path = os.path.join(root, d)
                try:
                    state['directories'][dir_path] = {
                        'modified': os.path.getmtime(dir_path),
                        'basename': os.path.basename(dir_path)
                    }
                except FileNotFoundError:
                    continue
            for file in files:
                file_path = os.path.join(root, file)
                if file_path == self.snapshot_file or file_path == self.log_file:
                    continue
                file_hash = self._calculate_hash(file_path)
                if file_hash is not None:
                    try:
                        state['files'][file_path] = {
                            'hash': file_hash,
                            'size': os.path.getsize(file_path),
                            'basename': os.path.basename(file_path),
                            'modified_time': os.path.getmtime(file_path)
                        }
                    except FileNotFoundError:
                        continue
        return state

    def load_state(self):
        if os.path.exists(self.snapshot_file):
            try:
                with open(self.snapshot_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except JSONDecodeError:
                self._log_event("Cannot load this file")
        return {'files': {}, 'directories': {}}

    def save_state(self, state):
        try:
            with open(self.snapshot_file, 'w', encoding='utf-8') as f:
                json.dump(state, f, indent=4)
        except IOError:
            self._log_event("Cannot save this file")

    def _find_renamed_items(self, old_file_data, new_files_state, item_type):
        for new_path, new_data in new_files_state.items():
            if item_type == 'files':
                if (new_data['hash'] == old_file_data['hash'] and
                        new_data['size'] == old_file_data['size'] and
                        new_data['modified_time'] == old_file_data['modified_time'] and
                        new_path not in self.current_state['files']):
                    return new_path
            elif item_type == 'directories':
                if (new_data['modified'] == old_file_data['modified'] and
                        new_path not in self.current_state['directories']):
                    return new_path
        return None

    def monitor_changes(self):
        self._log_event(f"Monitoring: {self.dir_path}")
        current_state = self._get_current_state()

        old_files = self.previous_state.get('files', {})
        new_files = current_state.get('files', {})
        old_dirs = self.previous_state.get('directories', {})
        new_dirs = current_state.get('directories', {})

        renamed_files = {}
        for old_path, old_data in old_files.items():
            new_path = self._find_renamed_items(old_data, new_files, 'files')
            if new_path and old_data['basename'] != os.path.basename(new_path):
                renamed_files[old_path] = new_path
                self._log_event(f"File RENAMED: {old_path} -> {new_path}")

        for file_path in set(old_files) - set(new_files) - set(renamed_files):
            self._log_event(f"File DELETED: {file_path}")

        for file_path, new_data in new_files.items():
            if file_path not in old_files and file_path not in renamed_files.values():
                self._log_event(f"File CREATED: {file_path} (Size: {new_data['size']} bytes)")
            elif file_path in old_files and old_files[file_path]['hash'] != new_data['hash']:
                self._log_event(f"File MODIFIED: {file_path}")

        renamed_directories = {}
        for old_path, old_data in old_dirs.items():
            new_path = self._find_renamed_items(old_data, new_dirs, 'directories')
            if new_path and old_data['basename'] != os.path.basename(new_path):
                renamed_directories[old_path] = new_path
                self._log_event(f"Directory RENAMED: {old_path} -> {new_path}")

        for old_path in old_dirs:
            if old_path not in new_dirs and old_path not in renamed_directories:
                self._log_event(f"Directory DELETED: {old_path}")

        for new_path in new_dirs:
            if new_path not in old_dirs and new_path not in renamed_directories.values():
                self._log_event(f"Directory CREATED: {new_path}")

        self.previous_state = current_state
        self.save_state(current_state)


def main():
    app = DirectoryMonitorGUI()
    app.run()


if __name__ == "__main__":
    main()