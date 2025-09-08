#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AXIS Factory Reset – HTTP + Digest only
- Factory default (keeps IP/network/time/802.1X)  -> /axis-cgi/factorydefault.cgi
- Hard factory default (wipes everything incl. IP) -> /axis-cgi/hardfactorydefault.cgi

Requires: requests
"""

import tkinter as tk
from tkinter import ttk, messagebox
from tkinter.scrolledtext import ScrolledText
import requests
from requests.auth import HTTPDigestAuth
import threading
import time

FACTORY_URL = "/axis-cgi/factorydefault.cgi"
HARD_URL    = "/axis-cgi/hardfactorydefault.cgi"

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("AXIS Camera – Factory Reset (HTTP + Digest)")
        self.geometry("520x360")

        # Inputs
        self.ip   = tk.StringVar(value="192.168.5.40")
        self.user = tk.StringVar(value="root")
        self.pw   = tk.StringVar(value="root")
        self.timeout = tk.IntVar(value=15)
        self.reset_mode = tk.StringVar(value="factory")  # "factory" or "hard"

        self._build_ui()
        self._log("Ready. Enter IP, credentials, choose reset type, then press Reset.")

    def _build_ui(self):
        frm = ttk.Frame(self, padding=10)
        frm.pack(fill="both", expand=True)

        # Connection
        lf = ttk.LabelFrame(frm, text="Camera")
        lf.pack(fill="x", pady=6)

        def row(parent, label, var, width=24, show=None):
            f = ttk.Frame(parent); f.pack(fill="x", pady=3)
            ttk.Label(f, text=label, width=12).pack(side="left")
            e = ttk.Entry(f, textvariable=var, width=width, show=show)
            e.pack(side="left")
            return e

        row(lf, "IP address", self.ip)
        row(lf, "Username", self.user)
        row(lf, "Password", self.pw, show="*")
        f_timeout = ttk.Frame(lf); f_timeout.pack(fill="x", pady=3)
        ttk.Label(f_timeout, text="Timeout (s)", width=12).pack(side="left")
        ttk.Entry(f_timeout, textvariable=self.timeout, width=6).pack(side="left")

        # Mode
        mf = ttk.LabelFrame(frm, text="Reset Type")
        mf.pack(fill="x", pady=6)
        ttk.Radiobutton(mf, text="Factory default (keeps IP/network/802.1X/time)", value="factory", variable=self.reset_mode).pack(anchor="w", padx=6, pady=2)
        ttk.Radiobutton(mf, text="HARD factory default (wipes everything incl. IP)", value="hard", variable=self.reset_mode).pack(anchor="w", padx=6, pady=2)

        # Action
        af = ttk.Frame(frm)
        af.pack(fill="x", pady=8)
        ttk.Button(af, text="Reset to Factory Defaults", command=self._confirm_then_reset, style="Danger.TButton").pack(side="right")

        # Log
        lf2 = ttk.LabelFrame(frm, text="Log")
        lf2.pack(fill="both", expand=True)
        self.log = ScrolledText(lf2, height=8, wrap="word")
        self.log.pack(fill="both", expand=True)

        # Styles
        style = ttk.Style(self)
        try:
            style.configure("Danger.TButton", foreground="white")
        except:
            pass

    def _log(self, msg: str):
        ts = time.strftime("%H:%M:%S")
        self.log.insert("end", f"[{ts}] {msg}\n")
        self.log.see("end")

    def _confirm_then_reset(self):
        ip = self.ip.get().strip()
        user = self.user.get().strip()
        pw = self.pw.get()

        if not ip or not user:
            messagebox.showerror("Missing info", "Please enter IP address and username.")
            return

        mode = self.reset_mode.get()
        if mode == "hard":
            warning = (
                "HARD factory default will wipe ALL settings INCLUDING the IP address.\n"
                "After this, the camera will revert to its out-of-box network settings.\n\n"
                f"Target: http://{ip}{HARD_URL}\n\n"
                "Type the camera IP below to confirm:"
            )
        else:
            warning = (
                "Factory default will reset parameters but KEEP network settings (IP, mask, gateway, 802.1X, time).\n"
                "The device will reboot automatically.\n\n"
                f"Target: http://{ip}{FACTORY_URL}\n\n"
                "Type the camera IP below to confirm:"
            )

        # Double-confirm dialog
        confirm = tk.simpledialog.askstring("Confirm reset", warning, parent=self)
        if confirm is None:
            return
        if confirm.strip() != ip:
            messagebox.showerror("Confirmation mismatch", "Typed IP does not match camera IP. Aborting.")
            return

        # Final click-to-confirm
        if not messagebox.askokcancel("Final confirmation", f"Proceed to reset camera at {ip}?"):
            return

        threading.Thread(target=self._do_reset, args=(ip, user, pw, mode), daemon=True).start()

    def _do_reset(self, ip: str, user: str, pw: str, mode: str):
        try:
            self._log(f"Starting reset on {ip} using Digest Auth…")
            base = f"http://{ip}"
            url = base + (HARD_URL if mode == "hard" else FACTORY_URL)
            auth = HTTPDigestAuth(user, pw)
            tmo = int(self.timeout.get() or 15)

            with requests.Session() as s:
                s.headers.update({"User-Agent": "AxisFactoryReset/1.0"})
                r = s.get(url, auth=auth, timeout=tmo)
                # Axis returns 200 OK with an HTML page; it immediately schedules a reboot.
                if 200 <= r.status_code < 300:
                    self._log(f"Request accepted: {r.status_code}. Device will reboot shortly.")
                    messagebox.showinfo("Reset issued", "Factory reset command sent.\nThe device will reboot. This can take 1–3 minutes.")
                else:
                    self._log(f"Unexpected status: {r.status_code}")
                    messagebox.showerror("Reset failed", f"HTTP {r.status_code}\nBody (first 200 chars):\n{r.text[:200]}")
        except requests.HTTPError as e:
            self._log(f"HTTP error: {e}")
            messagebox.showerror("HTTP error", str(e))
        except requests.RequestException as e:
            self._log(f"Request error: {e}")
            messagebox.showerror("Request error", str(e))
        except Exception as e:
            self._log(f"Unexpected error: {e}")
            messagebox.showerror("Error", str(e))

if __name__ == "__main__":
    # Small helper: tk.simpledialog lives in a submodule; import after Tk is initialized on some Pythons.
    import tkinter.simpledialog as simpledialog  # noqa: F401
    App().mainloop()
