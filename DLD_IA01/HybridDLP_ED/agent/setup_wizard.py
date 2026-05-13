"""
setup_wizard.py — Popup Setup lần đầu

Flow:
1. Set password
2. Set Server URL + API Key
3. Option bật Sensor + Worker
"""

import tkinter as tk
from tkinter import ttk, messagebox
from pathlib import Path
import sys

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from agent.password_manager import set_password, is_password_set
from agent.config import update_config, get_server_url, get_api_key
from agent.service_manager import get_service_manager
from agent.server_tester import test_server_connection


class SetupWizard:
    """Wizard setup HybridDLP lần đầu."""
    
    def __init__(self):
        self.root = tk.Tk()
        self.root.title(" HybridDLP - First Time Setup")
        self.root.geometry("500x400")
        self.root.resizable(False, False)
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        
        self.result = False
        self.current_step = 1  # Step 1: password, Step 2: config, Step 3: services
        
        self._create_widgets()
        self.root.after(100, self._center_window)
    
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
        """Tạo các widget."""
        self.main_frame = ttk.Frame(self.root, padding=20)
        self.main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Title
        self.title_label = ttk.Label(
            self.main_frame,
            text="Step 1/3: Set Master Password",
            font=("Segoe UI", 14, "bold")
        )
        self.title_label.pack(pady=(0, 10))
        
        # Content frame (swap based on step)
        self.content_frame = ttk.Frame(self.main_frame)
        self.content_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 15))
        
        # Buttons frame
        self.button_frame = ttk.Frame(self.main_frame)
        self.button_frame.pack(fill=tk.X)
        
        self._show_step_1()
    
    def _clear_content(self):
        """Xóa content frame."""
        for widget in self.content_frame.winfo_children():
            widget.destroy()
    
    def _show_step_1(self):
        """Step 1: Set Password."""
        self.current_step = 1
        self.title_label.config(text="Step 1/3: Set Master Password")
        self._clear_content()
        
        # Help text
        desc = ttk.Label(
            self.content_frame,
            text="Tạo mật khẩu master để bảo vệ cài đặt của bạn",
            wraplength=400,
            justify=tk.LEFT
        )
        desc.pack(pady=(0, 15), fill=tk.X)
        
        # Password
        ttk.Label(self.content_frame, text="Master Password:", font=("Segoe UI", 10)).pack(anchor=tk.W)
        self.pwd1_var = tk.StringVar()
        pwd1_entry = ttk.Entry(self.content_frame, textvariable=self.pwd1_var, show="●", width=35)
        pwd1_entry.pack(fill=tk.X, pady=(0, 10))
        pwd1_entry.focus()
        
        # Confirm password
        ttk.Label(self.content_frame, text="Confirm Password:", font=("Segoe UI", 10)).pack(anchor=tk.W)
        self.pwd2_var = tk.StringVar()
        pwd2_entry = ttk.Entry(self.content_frame, textvariable=self.pwd2_var, show="●", width=35)
        pwd2_entry.pack(fill=tk.X)
        
        # Update buttons
        self._update_buttons("Next", self._step_1_next, None)
    
    def _step_1_next(self):
        """Validate and proceed to step 2."""
        pwd1 = self.pwd1_var.get()
        pwd2 = self.pwd2_var.get()
        
        if not pwd1:
            messagebox.showwarning("Error", "Password không được rỗng")
            return
        if len(pwd1) < 4:
            messagebox.showwarning("Error", "Password tối thiểu 4 ký tự")
            return
        if pwd1 != pwd2:
            messagebox.showwarning("Error", "Mật khẩu không khớp")
            return
        
        try:
            set_password(pwd1)
            self._show_step_2()
        except Exception as e:
            messagebox.showerror("Error", f"Lỗi set password: {e}")
    
    def _show_step_2(self):
        """Step 2: Server URL + API Key."""
        self.current_step = 2
        self.title_label.config(text="Step 2/3: Server Configuration")
        self._clear_content()
        
        # Help text
        desc = ttk.Label(
            self.content_frame,
            text="Nhập Server URL và API Key để gửi dữ liệu",
            wraplength=400,
            justify=tk.LEFT
        )
        desc.pack(pady=(0, 15), fill=tk.X)
        
        # Server URL
        ttk.Label(self.content_frame, text="Server URL:", font=("Segoe UI", 10)).pack(anchor=tk.W)
        self.server_url_var = tk.StringVar(value=get_server_url())
        url_entry = ttk.Entry(self.content_frame, textvariable=self.server_url_var, width=35)
        url_entry.pack(fill=tk.X, pady=(0, 10))
        url_entry.focus()
        
        # API Key
        ttk.Label(self.content_frame, text="API Key:", font=("Segoe UI", 10)).pack(anchor=tk.W)
        self.api_key_var = tk.StringVar(value=get_api_key())
        key_entry = ttk.Entry(self.content_frame, textvariable=self.api_key_var, width=35, show="*")
        key_entry.pack(fill=tk.X, pady=(0, 15))
        
        # Test connection button
        test_btn_frame = ttk.Frame(self.content_frame)
        test_btn_frame.pack(fill=tk.X, pady=(0, 15))
        
        ttk.Button(
            test_btn_frame,
            text=" Test Connection",
            command=self._test_connection
        ).pack(side=tk.LEFT, padx=(0, 5))
        
        # Status label
        self.connection_status = ttk.Label(
            test_btn_frame,
            text="",
            font=("Segoe UI", 9)
        )
        self.connection_status.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        # Update buttons
        self._update_buttons("Next", self._step_2_next, self._show_step_1)
    
    def _test_connection(self):
        """Test kết nối tới server."""
        server_url = self.server_url_var.get().strip()
        api_key = self.api_key_var.get().strip()
        
        if not server_url:
            self.connection_status.config(text="[FAIL] Server URL trống", foreground="red")
            return
        if not api_key:
            self.connection_status.config(text="[FAIL] API Key trống", foreground="red")
            return
        
        # Show testing status
        self.connection_status.config(text="⏳ Đang test...", foreground="blue")
        self.root.update()
        
        # Run test
        success, message = test_server_connection(server_url, api_key)
        
        # Update status
        color = "green" if success else "red"
        self.connection_status.config(text=message, foreground=color)

    
    def _step_2_next(self):
        """Validate and proceed to step 3."""
        server_url = self.server_url_var.get().strip()
        api_key = self.api_key_var.get().strip()
        
        if not server_url:
            messagebox.showwarning("Error", "Server URL không được rỗng")
            return
        if not api_key:
            messagebox.showwarning("Error", "API Key không được rỗng")
            return
        
        try:
            update_config(server_url, api_key)
            self._show_step_3()
        except Exception as e:
            messagebox.showerror("Error", f"Lỗi lưu config: {e}")
    
    def _show_step_3(self):
        """Step 3: Start Services."""
        self.current_step = 3
        self.title_label.config(text="Step 3/3: Start Services")
        self._clear_content()
        
        # Help text
        desc = ttk.Label(
            self.content_frame,
            text="Chọn service muốn khởi động ngay bây giờ",
            wraplength=400,
            justify=tk.LEFT
        )
        desc.pack(pady=(0, 15), fill=tk.X)
        
        # Connection status frame
        conn_frame = ttk.LabelFrame(self.content_frame, text="Server Status", padding=5)
        conn_frame.pack(fill=tk.X, pady=(0, 15))
        
        server_url = self.server_url_var.get().strip()
        api_key = self.api_key_var.get().strip()
        
        # Test connection first
        success, message = test_server_connection(server_url, api_key)
        color = "green" if success else "red"
        
        status_label = ttk.Label(
            conn_frame,
            text=message,
            foreground=color,
            font=("Segoe UI", 9, "bold")
        )
        status_label.pack(anchor=tk.W)
        
        # Services frame
        srv_frame = ttk.LabelFrame(self.content_frame, text="Services", padding=5)
        srv_frame.pack(fill=tk.X, pady=(0, 15))
        
        # Checkboxes
        self.start_sensor_var = tk.BooleanVar(value=True)
        sensor_check = ttk.Checkbutton(
            srv_frame,
            text="• Khởi động Sensor (Thu thập dữ liệu)",
            variable=self.start_sensor_var
        )
        sensor_check.pack(fill=tk.X, pady=5)
        
        self.start_worker_var = tk.BooleanVar(value=True)
        worker_check = ttk.Checkbutton(
            srv_frame,
            text="• Khởi động Worker (Docker - ML Processing)",
            variable=self.start_worker_var
        )
        worker_check.pack(fill=tk.X, pady=5)
        
        # Status label
        self.status_label = ttk.Label(self.content_frame, text="", foreground="blue")
        self.status_label.pack(pady=(15, 0), fill=tk.X)
        
        # Update buttons
        self._update_buttons("Complete", self._step_3_complete, self._show_step_2)
    
    def _step_3_complete(self):
        """Khởi động services và kết thúc setup."""
        manager = get_service_manager()
        
        self.status_label.config(text="Đang khởi động services...")
        self.root.update()
        
        if self.start_sensor_var.get():
            success, msg = manager.start_sensor()
            if success:
                self.status_label.config(text=self.status_label.cget("text") + "\n[v] Sensor: " + msg, foreground="green")
            else:
                self.status_label.config(text=self.status_label.cget("text") + "\n[x] Sensor: " + msg, foreground="red")
            self.root.update()
        
        if self.start_worker_var.get():
            success, msg = manager.start_worker()
            if success:
                self.status_label.config(text=self.status_label.cget("text") + "\n[v] Worker: " + msg, foreground="green")
            else:
                self.status_label.config(text=self.status_label.cget("text") + "\n[x] Worker: " + msg, foreground="red")
            self.root.update()
        
        self.result = True
        self.root.update()
        self.root.after(2000, self._close)
    
    def _update_buttons(self, next_text, next_cmd, back_cmd):
        """Update buttons in button frame."""
        for widget in self.button_frame.winfo_children():
            widget.destroy()
        
        if back_cmd:
            ttk.Button(
                self.button_frame,
                text="← Back",
                command=back_cmd
            ).pack(side=tk.LEFT, padx=(0, 10))
        
        ttk.Button(
            self.button_frame,
            text=next_text + " →",
            command=next_cmd
        ).pack(side=tk.RIGHT)
    
    def _on_close(self):
        """User click close button."""
        if messagebox.askokcancel("Exit Setup", "Thoát setup? Có thể setup lại sau"):
            self.result = False
            self.root.destroy()
    
    def _close(self):
        """Close window."""
        self.root.destroy()
    
    def show(self) -> bool:
        """Hiển thị wizard."""
        try:
            self.root.mainloop()
            return self.result
        except Exception as e:
            print(f"[FAIL] Setup wizard error: {e}")
            return False


def run_setup_wizard() -> bool:
    """Chạy setup wizard."""
    if is_password_set():
        return True  # Đã setup rồi
    
    print("[SetupWizard] First-time setup required...")
    wizard = SetupWizard()
    return wizard.show()


if __name__ == "__main__":
    result = run_setup_wizard()
    print(f"Setup result: {result}")
