"""
Windows notification module for HybridDLP.

Preferred UI: CustomTkinter modern dark-mode alert.
Fallbacks: win32 MessageBox, win10toast, plyer, console.
"""
from __future__ import annotations

import os
import sys
import threading
from typing import Any, Dict, Optional

from loguru import logger


try:
    import customtkinter as ctk

    CUSTOMTKINTER_AVAILABLE = True
except ImportError:
    ctk = None
    CUSTOMTKINTER_AVAILABLE = False
    logger.debug("customtkinter not available for modern DLP popup")

try:
    import win10toast

    WIN10TOAST_AVAILABLE = True
except ImportError:
    WIN10TOAST_AVAILABLE = False
    logger.warning("win10toast not available, trying alternative methods")

try:
    import win32api
    import win32con

    WIN32_AVAILABLE = True
except ImportError:
    WIN32_AVAILABLE = False
    logger.debug("pywin32 not available for message box")

try:
    from plyer import notification

    PLYER_AVAILABLE = True
except ImportError:
    PLYER_AVAILABLE = False
    logger.debug("plyer not available")


class WindowsNotification:
    """Show endpoint DLP warnings to the current Windows user."""

    def __init__(self):
        self.method = self._detect_best_method()
        if self.method == "console":
            logger.info("Windows notification: Using console fallback")
        else:
            logger.info(f"Windows notification method: {self.method}")

    def _detect_best_method(self) -> str:
        """
        Detect best available notification method.

        DLP_NOTIFICATION_METHOD can force:
        customtkinter | win32_messagebox | win10toast | plyer | console
        """
        forced = os.getenv("DLP_NOTIFICATION_METHOD", "").strip().lower()
        valid = {"customtkinter", "win32_messagebox", "win10toast", "plyer", "console"}
        if forced in valid:
            if forced == "customtkinter" and CUSTOMTKINTER_AVAILABLE:
                return "customtkinter"
            if forced == "win32_messagebox" and WIN32_AVAILABLE:
                return "win32_messagebox"
            if forced == "win10toast" and WIN10TOAST_AVAILABLE:
                return "win10toast"
            if forced == "plyer" and PLYER_AVAILABLE:
                return "plyer"
            if forced == "console":
                return "console"
            logger.warning(f"Forced notification method unavailable: {forced}")

        if CUSTOMTKINTER_AVAILABLE and os.name == "nt":
            return "customtkinter"
        if WIN32_AVAILABLE:
            return "win32_messagebox"
        if WIN10TOAST_AVAILABLE:
            return "win10toast"
        if PLYER_AVAILABLE:
            return "plyer"
        return "console"

    def show_alert(
        self,
        title: str,
        message: str,
        severity: str = "warning",
        duration: int = 15,
    ) -> bool:
        """Show a generic alert."""
        try:
            if self.method == "customtkinter":
                return self._show_customtkinter_message(title, message, severity, duration)
            if self.method == "win10toast":
                return self._show_win10toast(title, message, duration)
            if self.method == "plyer":
                return self._show_plyer(title, message, duration)
            if self.method == "win32_messagebox":
                return self._show_win32_messagebox(title, message, severity)

            logger.warning(f"ALERT: {title} - {message}")
            return True
        except Exception as e:
            logger.error(f"Error showing notification: {e}")
            logger.warning(f"ALERT: {title} - {message}")
            return False

    def _show_win10toast(self, title: str, message: str, duration: int) -> bool:
        try:
            toaster = win10toast.ToastNotifier()
            toaster.show_toast(
                title=title,
                msg=message,
                duration=duration,
                icon_path=None,
                threaded=False,
            )
            return True
        except Exception as e:
            logger.error(f"win10toast error (will fallback): {e}")
            if PLYER_AVAILABLE:
                try:
                    return self._show_plyer(title, message, duration)
                except Exception:
                    pass
            if WIN32_AVAILABLE:
                try:
                    return self._show_win32_messagebox(title, message, severity="warning")
                except Exception:
                    pass
            return False

    def _show_plyer(self, title: str, message: str, duration: int) -> bool:
        try:
            notification.notify(
                title=title,
                message=message,
                timeout=duration,
                app_name="HybridDLP",
            )
            return True
        except Exception as e:
            logger.error(f"plyer error: {e}")
            return False

    def _show_win32_messagebox(self, title: str, message: str, severity: str) -> bool:
        try:
            if severity == "error":
                mb_type = win32con.MB_ICONERROR | win32con.MB_OK | win32con.MB_TOPMOST
            elif severity == "warning":
                mb_type = win32con.MB_ICONWARNING | win32con.MB_OK | win32con.MB_TOPMOST
            else:
                mb_type = win32con.MB_ICONINFORMATION | win32con.MB_OK | win32con.MB_TOPMOST

            win32api.MessageBox(0, message, title, mb_type)
            return True
        except Exception as e:
            logger.error(f"win32 messagebox error: {e}")
            return False

    def _show_customtkinter_message(
        self,
        title: str,
        message: str,
        severity: str,
        duration: int,
    ) -> bool:
        fields = {"message": message}
        return self._show_customtkinter_violation(
            title=title,
            violation_type=severity.title(),
            details=fields,
            duration=duration,
        )

    def show_violation_alert(
        self,
        violation_type: str,
        details: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """Show a policy-violation alert with a DLP-specific modern layout."""
        title = "HybridDLP - Cảnh báo vi phạm"
        details = details or {}

        if self.method == "customtkinter":
            ok = self._show_customtkinter_violation(
                title=title,
                violation_type=violation_type,
                details=details,
                duration=15,
            )
            if ok:
                return True

        return self.show_alert(
            title=title,
            message=self._build_violation_message(violation_type, details),
            severity="warning",
            duration=15,
        )

    def _build_violation_message(self, violation_type: str, details: Dict[str, Any]) -> str:
        def clip(value: Any, limit: int = 220) -> str:
            text = str(value or "").strip()
            return text if len(text) <= limit else text[: limit - 3].rstrip() + "..."

        parts = [
            "CẢNH BÁO: Bạn đang vi phạm chính sách bảo vệ dữ liệu.",
            "",
            f"Loại vi phạm: {violation_type}",
        ]

        fields = [
            ("Nguyên nhân", details.get("violation_reason")),
            ("Hành vi", details.get("action_description")),
            ("File/Nội dung", details.get("file_name")),
            ("Đích/Ứng dụng", details.get("destination") or details.get("window_title")),
            ("Phân loại", details.get("file_sensitivity")),
        ]
        for label, value in fields:
            if value:
                parts.append(f"{label}: {clip(value)}")

        rules = self._format_rule_names(details.get("yara_matches") or [])
        if rules:
            parts.append(f"Dấu hiệu phát hiện: {rules}")

        ml_evidence = details.get("ml_evidence")
        if ml_evidence:
            parts.append(f"Bang chung ML/NLP: {clip(ml_evidence, 360)}")

        ueba_evidence = details.get("ueba_evidence")
        if ueba_evidence:
            parts.append(f"Bang chung UEBA/Isolation Forest: {clip(ueba_evidence, 360)}")

        if details.get("risk_score") is not None:
            try:
                parts.append(f"Mức nguy hiểm: {float(details['risk_score']):.1f}/10")
            except Exception:
                parts.append(f"Mức nguy hiểm: {details['risk_score']}/10")

        guidance = details.get("user_guidance")
        if guidance:
            parts.extend(["", f"Cần làm ngay: {clip(guidance)}"])

        parts.extend(
            [
                "",
                "Sự kiện này đã được ghi nhận và có thể được gửi cho quản trị viên.",
                "Nếu tiếp tục lặp lại, hành vi sẽ bị xem là cố ý vi phạm chính sách bảo mật.",
            ]
        )
        return "\n".join(parts)

    def _show_customtkinter_violation(
        self,
        title: str,
        violation_type: str,
        details: Dict[str, Any],
        duration: int,
    ) -> bool:
        if not CUSTOMTKINTER_AVAILABLE or ctk is None:
            return False

        def run_popup() -> None:
            try:
                self._render_customtkinter_violation(title, violation_type, details, duration)
            except Exception as e:
                logger.error(f"CustomTkinter popup error: {e}")

        # Keep worker processing responsive. All Tk calls stay inside this one thread.
        t = threading.Thread(target=run_popup, name="HybridDLPAlertPopup", daemon=True)
        t.start()
        return True

    def _render_customtkinter_violation(
        self,
        title: str,
        violation_type: str,
        details: Dict[str, Any],
        duration: int,
    ) -> None:
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("dark-blue")

        root = ctk.CTk()
        root.title(title)
        root.resizable(False, False)
        root.attributes("-topmost", True)
        root.configure(fg_color="#09090b")

        screen_w = root.winfo_screenwidth()
        screen_h = root.winfo_screenheight()
        width = min(680, max(560, int(screen_w * 0.42)))
        height = min(560, max(440, int(screen_h * 0.50)))
        x = max(20, int((screen_w - width) / 2))
        y = max(20, int((screen_h - height) / 2))
        root.geometry(f"{width}x{height}+{x}+{y}")
        content_wrap = max(380, width - 170)
        full_wrap = max(430, width - 80)

        accent = self._risk_color(details.get("risk_score"))
        shell = ctk.CTkFrame(root, fg_color="#18181b", corner_radius=8, border_width=1, border_color="#3f3f46")
        shell.pack(fill="both", expand=True, padx=8, pady=8)

        top_line = ctk.CTkFrame(shell, height=4, fg_color=accent, corner_radius=4)
        top_line.pack(fill="x", padx=0, pady=0)

        header = ctk.CTkFrame(shell, fg_color="transparent")
        header.pack(fill="x", padx=14, pady=(12, 6))
        header.grid_columnconfigure(1, weight=1)

        mark = ctk.CTkFrame(header, width=34, height=34, fg_color=accent, corner_radius=6)
        mark.grid(row=0, column=0, rowspan=2, padx=(0, 10), pady=0, sticky="n")
        mark.grid_propagate(False)
        ctk.CTkLabel(mark, text="!", text_color="#ffffff", font=("Segoe UI", 20, "bold")).place(relx=0.5, rely=0.48, anchor="center")

        ctk.CTkLabel(
            header,
            text="Cảnh báo vi phạm",
            text_color="#f8fafc",
            font=("Segoe UI", 14, "bold"),
            anchor="w",
        ).grid(row=0, column=1, padx=0, pady=(0, 1), sticky="ew")

        ctk.CTkLabel(
            header,
            text=self._clip(violation_type, 140),
            text_color="#d4d4d8",
            font=("Segoe UI", 10),
            anchor="w",
        ).grid(row=1, column=1, padx=0, pady=0, sticky="ew")

        risk_text = self._risk_text(details.get("risk_score"))
        ctk.CTkLabel(
            header,
            text=risk_text,
            text_color="#ffffff",
            fg_color=accent,
            corner_radius=12,
            font=("Segoe UI", 10, "bold"),
            padx=9,
            pady=4,
        ).grid(row=0, column=2, rowspan=2, padx=(10, 0), pady=0, sticky="e")

        body = ctk.CTkFrame(shell, fg_color="#202024", corner_radius=8, border_width=1, border_color="#3f3f46")
        body.pack(fill="both", expand=True, padx=14, pady=(0, 8))
        body.grid_columnconfigure(1, weight=1)

        reason = details.get("violation_reason") or details.get("message") or violation_type
        rows = [
            ("Nguyên nhân", self._clip(reason, 280), "#fca5a5"),
            ("Hành vi", self._clip(details.get("action_description"), 190), "#fed7aa"),
            ("File", self._clip(details.get("file_name"), 180), "#e5e7eb"),
            ("Đích", self._clip(details.get("destination") or details.get("window_title"), 160), "#e5e7eb"),
        ]

        meta = []
        if details.get("file_sensitivity"):
            meta.append(str(details["file_sensitivity"]))
        rules = self._format_rule_names(details.get("yara_matches") or [])
        if rules:
            meta.append(rules)
        if details.get("ml_evidence"):
            meta.append("ML/NLP: " + str(details.get("ml_evidence")))
        if details.get("ueba_evidence"):
            meta.append("UEBA/IF: " + str(details.get("ueba_evidence")))
        if details.get("process_name"):
            meta.append(str(details["process_name"]))
        rows.append(("Bằng chứng", self._clip(" | ".join(meta), 220), "#fde68a"))

        for row_idx, (label, value, color) in enumerate(rows):
            if not value:
                continue
            ctk.CTkLabel(
                body,
                text=label,
                text_color="#a1a1aa",
                font=("Segoe UI", 9, "bold"),
                anchor="w",
                width=78,
            ).grid(row=row_idx, column=0, sticky="nw", padx=(12, 8), pady=(9 if row_idx == 0 else 3, 0))
            ctk.CTkLabel(
                body,
                text=value,
                text_color=color,
                font=("Segoe UI", 10 if row_idx == 0 else 9),
                anchor="w",
                justify="left",
                wraplength=content_wrap,
            ).grid(row=row_idx, column=1, sticky="ew", padx=(0, 12), pady=(9 if row_idx == 0 else 3, 0))

        guidance = details.get("user_guidance") or "Dừng thao tác và liên hệ quản trị viên nếu cần xử lý hợp lệ."
        guidance_frame = ctk.CTkFrame(body, fg_color="#292524", corner_radius=6, border_width=1, border_color="#9a3412")
        guidance_frame.grid(row=6, column=0, columnspan=2, sticky="ew", padx=12, pady=(8, 6))
        ctk.CTkLabel(
            guidance_frame,
            text="Cần làm ngay",
            text_color="#f8fafc",
            font=("Segoe UI", 9, "bold"),
            anchor="w",
        ).pack(fill="x", padx=10, pady=(6, 1))
        ctk.CTkLabel(
            guidance_frame,
            text=self._clip(guidance, 260),
            text_color="#fed7aa",
            font=("Segoe UI", 9),
            anchor="w",
            justify="left",
            wraplength=full_wrap,
        ).pack(fill="x", padx=10, pady=(0, 6))

        enforcement_frame = ctk.CTkFrame(
            body,
            fg_color="#2a0f0f",
            corner_radius=6,
            border_width=1,
            border_color="#dc2626",
        )
        enforcement_frame.grid(row=7, column=0, columnspan=2, sticky="ew", padx=12, pady=(0, 8))
        ctk.CTkLabel(
            enforcement_frame,
            text="Sự kiện đã được ghi nhận. Tái phạm sẽ bị xem là cố ý vi phạm chính sách bảo mật.",
            text_color="#fecaca",
            font=("Segoe UI", 9, "bold"),
            anchor="w",
            justify="left",
            wraplength=full_wrap,
        ).pack(fill="x", padx=10, pady=7)

        footer = ctk.CTkFrame(shell, fg_color="transparent")
        footer.pack(fill="x", padx=14, pady=(0, 10))
        footer.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            footer,
            text="HybridDLP Endpoint Protection",
            text_color="#a3a3a3",
            font=("Segoe UI", 9),
            anchor="w",
            wraplength=260,
            justify="left",
        ).grid(row=0, column=0, padx=0, pady=0, sticky="w")

        ctk.CTkButton(
            footer,
            text="Đã hiểu",
            width=84,
            height=28,
            fg_color=accent,
            hover_color=self._darken(accent),
            text_color="#ffffff",
            font=("Segoe UI", 10, "bold"),
            command=root.destroy,
        ).grid(row=0, column=1, padx=(10, 0), pady=0, sticky="e")

        auto_close_ms = int(max(float(duration or 0), 15.0) * 1000)
        root.after(auto_close_ms, root.destroy)

        root.mainloop()

    def _add_section(
        self,
        parent: Any,
        label: str,
        value: Any,
        accent: str,
        row: int,
        strong: bool = False,
    ) -> None:
        if not value:
            value = "Không có dữ liệu"

        frame = ctk.CTkFrame(parent, fg_color="transparent")
        frame.grid(row=row, column=0, sticky="ew", padx=8, pady=(8 if row == 0 else 3, 0))
        frame.grid_columnconfigure(1, weight=1)

        strip = ctk.CTkFrame(frame, width=4, height=34, fg_color=accent, corner_radius=4)
        strip.grid(row=0, column=0, rowspan=2, padx=(0, 8), pady=2, sticky="ns")

        ctk.CTkLabel(
            frame,
            text=label,
            text_color="#94a3b8",
            font=("Segoe UI", 10, "bold"),
            anchor="w",
        ).grid(row=0, column=1, sticky="ew")

        clipped = self._clip(value, 360 if strong else 260)
        ctk.CTkLabel(
            frame,
            text=clipped,
            text_color="#f8fafc" if strong else "#d6e4ff",
            font=("Segoe UI", self._font_for_text(clipped, base=12 if strong else 11, small=10), "bold" if strong else "normal"),
            anchor="w",
            justify="left",
            wraplength=440,
        ).grid(row=1, column=1, sticky="ew")

    def _format_rule_names(self, matches: Any) -> str:
        names = []
        if not isinstance(matches, list):
            return ""
        for match in matches[:3]:
            if isinstance(match, dict):
                name = match.get("rule") or match.get("name")
            else:
                name = str(match)
            if name:
                names.append(str(name))
        return ", ".join(names)

    def _risk_text(self, score: Any) -> str:
        try:
            return f"Risk {float(score):.1f}/10"
        except Exception:
            return "Risk cao"

    def _risk_color(self, score: Any) -> str:
        try:
            s = float(score)
        except Exception:
            s = 8.0
        if s >= 9.0:
            return "#dc2626"
        if s >= 7.0:
            return "#f97316"
        return "#eab308"

    def _darken(self, color: str) -> str:
        palette = {
            "#dc2626": "#991b1b",
            "#f97316": "#c2410c",
            "#eab308": "#a16207",
        }
        return palette.get(color, "#1d4ed8")

    def _font_for_text(self, value: Any, base: int = 12, small: int = 10) -> int:
        text_len = len(str(value or ""))
        if text_len > 220:
            return small
        if text_len > 120:
            return max(small, base - 1)
        return base

    def _clip(self, value: Any, limit: int) -> str:
        text = str(value or "").strip()
        return text if len(text) <= limit else text[: limit - 3].rstrip() + "..."
