"""
main_window.py — Control Center giao diện chính

Yêu cầu password -> Hiển thị control panel
"""

import tkinter as tk
from tkinter import ttk, messagebox
from pathlib import Path
import sys

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from agent.password_manager import verify_password
from agent.config import get_config, update_config
from agent.service_manager import get_service_manager
from agent.server_tester import test_server_connection


class MainWindow:
    """Control Center giao diện chính."""
    
    def __init__(self, on_close_callback=None):
        self.root = tk.Tk()
        self.root.title(" HybridDLP - Control Center")
        self.root.geometry("500x450")
        self.root.resizable(False, False)
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        
        self.on_close_callback = on_close_callback
        self.authenticated = False
        self.manager = get_service_manager()
        
        self._create_widgets()
        self.root.after(100, self._center_window)
        self._show_login()
    
    def _center_window(self):
        """Đặt cửa sổ vào giữa màn hình."""
        try:
            self.root.update_idletasks()
            w, h = self.root.winfo_width(), self.root.winfo_height()
            x = (self.root.winfo_screenwidth() // 2) - (w // 2)
            y = (self.root.winfo_screenheight() // 2) - (h // 2)
            self.root.geometry(f"+{x}+{y}")
        except:
            pass
    
    def _create_widgets(self):
        """Tạo main frame."""
        self.main_frame = ttk.Frame(self.root, padding=20)
        self.main_frame.pack(fill=tk.BOTH, expand=True)
    
    def _clear_main_frame(self):
        """Clear content."""
        for widget in self.main_frame.winfo_children():
            widget.destroy()
    
    def _show_login(self):
        """Hiển thị login screen."""
        self._clear_main_frame()
        
        title = ttk.Label(
            self.main_frame,
            text="Master Password",
            font=("Segoe UI", 14, "bold")
        )
        title.pack(pady=(0, 20))
        
        ttk.Label(self.main_frame, text="Nhập mật khẩu để truy cập:", font=("Segoe UI", 10)).pack(anchor=tk.W, pady=(0, 10))
        
        self.password_var = tk.StringVar()
        pwd_entry = ttk.Entry(self.main_frame, textvariable=self.password_var, show="●", width=30)
        pwd_entry.pack(fill=tk.X, pady=(0, 20))
        pwd_entry.focus()
        
        # Bind enter key
        pwd_entry.bind("<Return>", lambda e: self._login())
        
        button_frame = ttk.Frame(self.main_frame)
        button_frame.pack(fill=tk.X)
        
        ttk.Button(button_frame, text="Cancel", command=self._on_close).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(button_frame, text="Login", command=self._login).pack(side=tk.RIGHT)
    
    def _login(self):
        """Kiểm tra password."""
        pwd = self.password_var.get()
        if not pwd:
            messagebox.showwarning("Error", "Vui lòng nhập mật khẩu")
            return
        
        if not verify_password(pwd):
            messagebox.showerror("Error", "Mật khẩu không đúng")
            self.password_var.set("")
            return
        
        self.authenticated = True
        self._show_control_center()
    
    def _show_control_center(self):
        """Hiển thị control center."""
        self._clear_main_frame()
        
        # Title
        title = ttk.Label(
            self.main_frame,
            text="️  Control Center",
            font=("Segoe UI", 14, "bold")
        )
        title.pack(pady=(0, 15))
        
        # Sensor section
        sensor_frame = ttk.LabelFrame(self.main_frame, text="Sensor", padding=10)
        sensor_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.sensor_status_label = ttk.Label(sensor_frame, text="", font=("Segoe UI", 10))
        self.sensor_status_label.pack(anchor=tk.W, pady=(0, 10))
        self._update_sensor_status()
        
        sensor_btn_frame = ttk.Frame(sensor_frame)
        sensor_btn_frame.pack(fill=tk.X)
        
        ttk.Button(sensor_btn_frame, text="▶️  Start", command=self._start_sensor).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(sensor_btn_frame, text="⏹️  Stop", command=self._stop_sensor).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(sensor_btn_frame, text=" Refresh", command=self._update_sensor_status).pack(side=tk.LEFT)
        
        # Worker section
        worker_frame = ttk.LabelFrame(self.main_frame, text="Worker", padding=10)
        worker_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.worker_status_label = ttk.Label(worker_frame, text="", font=("Segoe UI", 10))
        self.worker_status_label.pack(anchor=tk.W, pady=(0, 10))
        self._update_worker_status()
        
        worker_btn_frame = ttk.Frame(worker_frame)
        worker_btn_frame.pack(fill=tk.X)
        
        ttk.Button(worker_btn_frame, text="▶️  Start", command=self._start_worker).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(worker_btn_frame, text="⏹️  Stop", command=self._stop_worker).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(worker_btn_frame, text=" Refresh", command=self._update_worker_status).pack(side=tk.LEFT)
        
        # Config section
        config_frame = ttk.LabelFrame(self.main_frame, text="Configuration", padding=10)
        config_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Button(config_frame, text="[SYS]  Edit Server Settings", command=self._show_config_dialog).pack(fill=tk.X)
        
        # Bottom buttons
        btn_frame = ttk.Frame(self.main_frame)
        btn_frame.pack(fill=tk.X, pady=(10, 0))
        
        ttk.Button(btn_frame, text="Logout", command=self._logout).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(btn_frame, text="Exit", command=self._on_close).pack(side=tk.RIGHT)
    
    def _update_sensor_status(self):
        """Update sensor status."""
        is_running = self.manager.is_sensor_running()
        status_text = " Running" if is_running else " Stopped"
        self.sensor_status_label.config(text=status_text)
    
    def _update_worker_status(self):
        """Update worker status."""
        is_running = self.manager.is_worker_running()
        status_text = " Running" if is_running else " Stopped"
        self.worker_status_label.config(text=status_text)
    
    def _start_sensor(self):
        """Start sensor."""
        success, msg = self.manager.start_sensor()
        if success:
            messagebox.showinfo("Success", msg)
            self._update_sensor_status()
        else:
            messagebox.showerror("Error", msg)
    
    def _stop_sensor(self):
        """Stop sensor."""
        success, msg = self.manager.stop_sensor()
        if success:
            messagebox.showinfo("Success", msg)
            self._update_sensor_status()
        else:
            messagebox.showerror("Error", msg)
    
    def _start_worker(self):
        """Start worker."""
        success, msg = self.manager.start_worker()
        if success:
            messagebox.showinfo("Success", msg)
            self._update_worker_status()
        else:
            messagebox.showerror("Error", msg)
    
    def _stop_worker(self):
        """Stop worker."""
        success, msg = self.manager.stop_worker()
        if success:
            messagebox.showinfo("Success", msg)
            self._update_worker_status()
        else:
            messagebox.showerror("Error", msg)
    
    def _show_config_dialog(self):
        """Hiển thị dialog chỉnh server settings."""
        config = get_config()
        
        dialog = tk.Toplevel(self.root)
        dialog.title("Edit Server Settings")
        dialog.geometry("450x350")
        dialog.resizable(False, False)
        
        frame = ttk.Frame(dialog, padding=15)
        frame.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(frame, text="Server URL:", font=("Segoe UI", 10)).pack(anchor=tk.W)
        url_var = tk.StringVar(value=config.get_server_url())
        url_entry = ttk.Entry(frame, textvariable=url_var, width=35)
        url_entry.pack(fill=tk.X, pady=(0, 15))
        
        ttk.Label(frame, text="API Key:", font=("Segoe UI", 10)).pack(anchor=tk.W)
        
        key_var = tk.StringVar(value=config.get_api_key())
        show_key_var = tk.BooleanVar(value=False)
        
        key_frame = ttk.Frame(frame)
        key_frame.pack(fill=tk.X, pady=(0, 20))
        
        key_entry = ttk.Entry(key_frame, textvariable=key_var, width=35, show="*")
        key_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        
        def toggle_api_key():
            show_key_var.set(not show_key_var.get())
            key_entry.config(show="" if show_key_var.get() else "*")
            show_btn.config(text="️ Hide" if show_key_var.get() else "️ Show")
        
        show_btn = ttk.Button(key_frame, text="️ Show", command=toggle_api_key, width=8)
        show_btn.pack(side=tk.RIGHT)
        
        # Test button frame
        test_btn_frame = ttk.Frame(frame)
        test_btn_frame.pack(fill=tk.X, pady=(0, 10))
        
        status_var = tk.StringVar(value="")
        status_label = ttk.Label(test_btn_frame, textvariable=status_var, font=("Segoe UI", 9))
        status_label.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        def test_connection():
            status_var.set("⏳ Testing...")
            dialog.update()
            success, message = test_server_connection(url_var.get(), key_var.get())
            status_var.set(message)
            color = "green" if success else "red"
            status_label.config(foreground=color)
        
        ttk.Button(test_btn_frame, text=" Test", command=test_connection).pack(side=tk.RIGHT, padx=(5, 0))
        
        def save_config():
            try:
                update_config(url_var.get(), key_var.get())
                messagebox.showinfo("Success", "Configuration saved!")
                dialog.destroy()
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save: {e}")
        
        btn_frame = ttk.Frame(frame)
        btn_frame.pack(fill=tk.X, pady=(10, 0))
        
        ttk.Button(btn_frame, text="Cancel", command=dialog.destroy).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(btn_frame, text="Save", command=save_config).pack(side=tk.RIGHT)
    
    def _logout(self):
        """Logout."""
        self.authenticated = False
        self._show_login()
    
    def _on_close(self):
        """Close window."""
        self.root.destroy()
        if self.on_close_callback:
            self.on_close_callback()
    
    def show(self):
        """Hiển thị window."""
        try:
            self.root.mainloop()
        except Exception as e:
            print(f"[FAIL] Window error: {e}")


def show_main_window(on_close_callback=None):
    """Hiển thị main window."""
    window = MainWindow(on_close_callback)
    window.show()
