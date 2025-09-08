#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AXIS Camera Config Cloner — GUI (HTTP + Digest Auth only)
- Compare source/target params side-by-side
- Select-all or per-key selection to copy Source -> Target
- Toggleable skip rules (Network, Properties/Brand, Users/Passwords, Name/FriendlyName)
- Differences-only and Dry-run modes
- HTTP ONLY; Digest Auth ONLY (no TLS / HTTPS)
"""

import tkinter as tk
from tkinter import ttk, messagebox
from tkinter.scrolledtext import ScrolledText
import threading
import time
import re
from typing import Dict, List, Tuple
import requests
from requests.auth import HTTPDigestAuth

BATCH_SIZE = 80

# ------------ HTTP helpers (HTTP only) ------------

def parse_rfc_param_list(text: str) -> Dict[str, str]:
    params: Dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        params[k.strip()] = v.strip()
    return params

def build_base_url(host: str) -> str:
    # Force HTTP only
    return f"http://{host}"

def param_list_url(base: str) -> str:
    return f"{base}/axis-cgi/param.cgi?action=list&responseformat=rfc"

def fetch_params(session: requests.Session, base: str, auth: HTTPDigestAuth, timeout: int) -> Dict[str, str]:
    r = session.get(param_list_url(base), auth=auth, timeout=timeout)
    r.raise_for_status()
    return parse_rfc_param_list(r.text)

def post_param_updates(session: requests.Session, base: str, auth: HTTPDigestAuth, pairs: List[Tuple[str, str]], timeout: int) -> Tuple[bool, str]:
    url = f"{base}/axis-cgi/param.cgi"
    data = {"action": "update"}
    for k, v in pairs:
        data[k] = v
    r = session.post(url, data=data, auth=auth, timeout=timeout)
    ok = (200 <= r.status_code < 300)
    return ok, r.text

def make_session() -> requests.Session:
    s = requests.Session()
    s.headers.update({"User-Agent": "AxisConfigClonerGUI/HTTP-Digest/1.0"})
    return s

# ------------ GUI ------------

class AxisClonerGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("AXIS Config Cloner — HTTP + Digest (Source → Target)")
        self.geometry("1180x780")

        # Connection fields
        self.src_ip = tk.StringVar(value="192.168.5.40")
        self.dst_ip = tk.StringVar(value="192.168.5.41")
        self.timeout = tk.IntVar(value=20)

        self.src_user = tk.StringVar(value="root")
        self.src_pass = tk.StringVar(value="root")
        self.dst_user = tk.StringVar(value="root")
        self.dst_pass = tk.StringVar(value="root")

        # Options
        self.only_diff = tk.BooleanVar(value=False)
        self.dry_run = tk.BooleanVar(value=False)
        self.select_all_var = tk.BooleanVar(value=False)

        # Skip toggles
        self.skip_network = tk.BooleanVar(value=True)
        self.skip_properties = tk.BooleanVar(value=True)
        self.skip_users = tk.BooleanVar(value=True)
        self.skip_names = tk.BooleanVar(value=True)

        # Data
        self.src_params: Dict[str, str] = {}
        self.dst_params: Dict[str, str] = {}
        self.filtered_rows: List[str] = []          # keys visible in the table
        self.row_selected: Dict[str, bool] = {}     # key -> selected

        self._build_ui()
        self._log("Ready. This build forces HTTP + Digest Auth. Click 'Load & Compare'.")

    # ---------- Eligibility ----------
    def _eligible(self, key: str) -> bool:
        lk = key.lower()
        if self.skip_network.get() and key.startswith("root.Network."):
            return False
        if self.skip_properties.get() and (key.startswith("root.Properties.") or key.startswith("root.Brand.")):
            return False
        if self.skip_users.get() and (key.startswith("root.User.") or key.startswith("root.Pwdb.")):
            return False
        if self.skip_names.get() and ("name" in lk or "friendlyname" in lk):
            return False
        return True

    # ---------- UI ----------
    def _build_ui(self):
        top = ttk.Frame(self, padding=8)
        top.pack(fill="x")

        # Connection box
        conn = ttk.LabelFrame(top, text="Connection (HTTP + Digest)")
        conn.pack(fill="x", pady=4)

        def add_labeled(entry_parent, label, var, width=16, show=None):
            f = ttk.Frame(entry_parent)
            ttk.Label(f, text=label, width=12).pack(side="left")
            e = ttk.Entry(f, textvariable=var, width=width, show=show)
            e.pack(side="left", padx=4)
            return f

        row1 = ttk.Frame(conn); row1.pack(fill="x", pady=4)
        add_labeled(row1, "Source IP", self.src_ip).pack(side="left", padx=4)
        add_labeled(row1, "Target IP", self.dst_ip).pack(side="left", padx=12)
        ttk.Label(row1, text="Timeout (s)").pack(side="left", padx=(12,2))
        ttk.Entry(row1, textvariable=self.timeout, width=6).pack(side="left")

        row2 = ttk.Frame(conn); row2.pack(fill="x", pady=4)
        ttk.Label(row2, text="Source ↓").pack(side="left", padx=4)
        add_labeled(row2, "User", self.src_user, width=14).pack(side="left")
        add_labeled(row2, "Password", self.src_pass, width=14, show="*").pack(side="left", padx=(4,12))
        ttk.Label(row2, text="Target ↓").pack(side="left", padx=16)
        add_labeled(row2, "User", self.dst_user, width=14).pack(side="left")
        add_labeled(row2, "Password", self.dst_pass, width=14, show="*").pack(side="left", padx=(4,12))

        # Skip toggles panel
        skipf = ttk.LabelFrame(top, text="Skip Rules (toggle on/off before loading)")
        skipf.pack(fill="x", pady=4)
        ttk.Checkbutton(skipf, text="Skip Network/IP", variable=self.skip_network, command=self._refresh_table).pack(side="left", padx=8)
        ttk.Checkbutton(skipf, text="Skip Properties/Brand", variable=self.skip_properties, command=self._refresh_table).pack(side="left", padx=8)
        ttk.Checkbutton(skipf, text="Skip Users/Passwords", variable=self.skip_users, command=self._refresh_table).pack(side="left", padx=8)
        ttk.Checkbutton(skipf, text="Skip Name/FriendlyName", variable=self.skip_names, command=self._refresh_table).pack(side="left", padx=8)

        row3 = ttk.Frame(conn); row3.pack(fill="x", pady=4)
        ttk.Checkbutton(row3, text="Show differences only", variable=self.only_diff, command=self._refresh_table).pack(side="left", padx=4)
        ttk.Checkbutton(row3, text="Dry-run (no writes)", variable=self.dry_run).pack(side="left", padx=16)
        ttk.Checkbutton(row3, text="Select All (eligible)", variable=self.select_all_var, command=self._toggle_select_all).pack(side="left", padx=16)
        ttk.Button(row3, text="Load & Compare", command=self.load_compare_async).pack(side="right", padx=4)

        # Table
        table_frame = ttk.Frame(self, padding=(8,4))
        table_frame.pack(fill="both", expand=True)
        columns = ("apply", "key", "src", "dst")
        self.tree = ttk.Treeview(table_frame, columns=columns, show="headings", selectmode="browse")
        self.tree.heading("apply", text="Apply")
        self.tree.heading("key", text="Parameter Key")
        self.tree.heading("src", text="Source Value")
        self.tree.heading("dst", text="Target Value")
        self.tree.column("apply", width=70, anchor="center")
        self.tree.column("key", width=460, anchor="w")
        self.tree.column("src", width=300, anchor="w")
        self.tree.column("dst", width=300, anchor="w")
        self.tree.pack(side="left", fill="both", expand=True)
        vsb = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        vsb.pack(side="right", fill="y")
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.bind("<Button-1>", self._on_tree_click)

        # Action buttons
        actions = ttk.Frame(self, padding=8)
        actions.pack(fill="x")
        ttk.Button(actions, text="Apply Selected to Target", command=self.apply_selected_async).pack(side="right", padx=4)

        # Log pane
        logf = ttk.LabelFrame(self, text="Log")
        logf.pack(fill="both", expand=False, padx=8, pady=8)
        self.log = ScrolledText(logf, height=10, wrap="word")
        self.log.pack(fill="both", expand=True)

    # ---------- Logging ----------
    def _log(self, msg: str):
        ts = time.strftime("%H:%M:%S")
        self.log.insert("end", f"[{ts}] {msg}\n")
        self.log.see("end")

    # ---------- Load & compare ----------
    def load_compare_async(self):
        threading.Thread(target=self._load_compare, daemon=True).start()

    def _load_compare(self):
        try:
            self._log("Loading parameters from source and target… (HTTP + Digest)")
            self.tree.delete(*self.tree.get_children())
            self.filtered_rows.clear()

            timeout = int(self.timeout.get() or 20)

            s = make_session()

            src_base = build_base_url(self.src_ip.get().strip())
            dst_base = build_base_url(self.dst_ip.get().strip())

            src_user = self.src_user.get().strip()
            dst_user = self.dst_user.get().strip()
            # Enforce Digest Auth
            src_auth = HTTPDigestAuth(src_user, self.src_pass.get()) if src_user else None
            dst_auth = HTTPDigestAuth(dst_user, self.dst_pass.get()) if dst_user else None

            self._log(f"GET {src_base} … (Digest)")
            self.src_params = fetch_params(s, src_base, src_auth, timeout)
            self._log(f"Source loaded: {len(self.src_params)} params")

            self._log(f"GET {dst_base} … (Digest)")
            self.dst_params = fetch_params(s, dst_base, dst_auth, timeout)
            self._log(f"Target loaded: {len(self.dst_params)} params")

            self._refresh_table()
            self._log("Compare complete.")
        except requests.HTTPError as e:
            self._log(f"HTTP error: {e}")
            if e.response is not None and e.response.status_code == 401:
                messagebox.showerror("Auth error", "401 Unauthorized.\nEnsure the camera has HTTP enabled and Digest Auth accepted for this user.")
            else:
                messagebox.showerror("Load error", f"HTTP error:\n{e}")
        except requests.RequestException as e:
            self._log(f"Request error: {e}")
            messagebox.showerror("Load error", f"Request error:\n{e}")
        except Exception as e:
            self._log(f"Unexpected error: {e}")
            messagebox.showerror("Load error", str(e))

    # ---------- Table render ----------
    def _refresh_table(self):
        if not (self.src_params or self.dst_params):
            return
        only_diff = self.only_diff.get()
        self.tree.delete(*self.tree.get_children())
        self.filtered_rows.clear()

        all_keys = sorted(set(self.src_params.keys()) | set(self.dst_params.keys()))
        rows_added = 0

        for key in all_keys:
            src_val = self.src_params.get(key, "")
            dst_val = self.dst_params.get(key, "")

            eligible = self._eligible(key)
            if only_diff and (src_val == dst_val):
                continue

            self.filtered_rows.append(key)

            sel_default = eligible and (src_val != dst_val)
            sel = self.row_selected.get(key, sel_default)
            self.row_selected[key] = sel

            apply_cell = "[x]" if (sel and eligible) else ("[ ]" if eligible else "—")
            iid = self.tree.insert("", "end", values=(apply_cell, key, src_val, dst_val))

            tags = []
            if not eligible:
                tags.append("ineligible")
            elif src_val != dst_val:
                tags.append("diff")
            else:
                tags.append("same")
            self.tree.item(iid, tags=tuple(tags))
            rows_added += 1

        self.tree.tag_configure("diff", background="#fff6da")
        self.tree.tag_configure("same", background="#f5f5f5")
        self.tree.tag_configure("ineligible", foreground="#888888")

        self._log(f"Rendered {rows_added} row(s). {'(differences only)' if only_diff else ''}")
        self._update_select_all_checkbox_state()

    # ---------- Row toggle & Select All ----------
    def _on_tree_click(self, event):
        col = self.tree.identify_column(event.x)
        if col != "#1":
            return
        row_id = self.tree.identify_row(event.y)
        if not row_id:
            return
        key = self.tree.item(row_id, "values")[1]
        if not key or not self._eligible(key):
            return
        self.row_selected[key] = not self.row_selected.get(key, False)
        vals = list(self.tree.item(row_id, "values"))
        vals[0] = "[x]" if self.row_selected[key] else "[ ]"
        self.tree.item(row_id, values=vals)
        self._update_select_all_checkbox_state()

    def _toggle_select_all(self):
        flag = self.select_all_var.get()
        count = 0
        for iid in self.tree.get_children(""):
            vals = list(self.tree.item(iid, "values"))
            key = vals[1]
            if not self._eligible(key):
                continue
            self.row_selected[key] = flag
            vals[0] = "[x]" if flag else "[ ]"
            self.tree.item(iid, values=vals)
            count += 1
        self._log(("Selected" if flag else "Deselected") + f" {count} visible eligible rows.")

    def _update_select_all_checkbox_state(self):
        elig_keys = [k for k in self.filtered_rows if self._eligible(k)]
        if not elig_keys:
            self.select_all_var.set(False)
            return
        all_sel = all(self.row_selected.get(k, False) for k in elig_keys)
        self.select_all_var.set(all_sel)

    # ---------- Apply ----------
    def apply_selected_async(self):
        threading.Thread(target=self._apply_selected, daemon=True).start()

    def _apply_selected(self):
        try:
            to_write: Dict[str, str] = {}
            for key in self.filtered_rows:
                if not self._eligible(key):
                    continue
                if not self.row_selected.get(key, False):
                    continue
                sv = self.src_params.get(key, "")
                dv = self.dst_params.get(key, "")
                if sv != dv:
                    to_write[key] = sv

            if not to_write:
                self._log("No selected changes to apply.")
                messagebox.showinfo("Nothing to do", "No selected changes to apply.")
                return

            self._log(f"Preparing to apply {len(to_write)} key(s) to target…")

            if self.dry_run.get():
                self._log("[DRY-RUN] Keys that would be updated:")
                for k, v in list(to_write.items())[:40]:
                    self._log(f"  {k} = {v}")
                if len(to_write) > 40:
                    self._log(f"  … and {len(to_write)-40} more")
                messagebox.showinfo("Dry-run", f"{len(to_write)} key(s) would be updated (see log).")
                return

            timeout = int(self.timeout.get() or 20)
            s = make_session()

            dst_base = build_base_url(self.dst_ip.get().strip())
            dst_user = self.dst_user.get().strip()
            dst_auth = HTTPDigestAuth(dst_user, self.dst_pass.get()) if dst_user else None

            applied = 0
            failures = 0
            items = list(to_write.items())

            for i in range(0, len(items), BATCH_SIZE):
                batch = items[i:i+BATCH_SIZE]
                ok, text = post_param_updates(s, dst_base, dst_auth, batch, timeout)
                if ok and not re.search(r"(Error|ERROR|Failed|failed|not allowed|read-only)", text):
                    applied += len(batch)
                    self._log(f"[✓] Applied batch of {len(batch)}")
                else:
                    self._log("[!] Batch had errors; retrying individually…")
                    for k, v in batch:
                        ok1, t1 = post_param_updates(s, dst_base, dst_auth, [(k, v)], timeout)
                        if ok1 and not re.search(r"(Error|ERROR|Failed|failed|not allowed|read-only)", t1):
                            applied += 1
                            self._log(f"    [✓] {k}")
                        else:
                            failures += 1
                            self._log(f"    [×] {k} -> {t1.strip()[:160]}")
                time.sleep(0.1)

            self._log(f"Apply complete. Success: {applied}, Failed: {failures}")
            messagebox.showinfo("Completed", f"Updated {applied} key(s). Failed: {failures}. See log for details.")

            # Refresh target values so the table reflects current state
            try:
                self.dst_params = fetch_params(s, dst_base, dst_auth, timeout)
                self._refresh_table()
            except Exception as e:
                self._log(f"Refresh failed: {e}")

        except requests.HTTPError as e:
            self._log(f"HTTP error during apply: {e}")
            if e.response is not None and e.response.status_code == 401:
                messagebox.showerror("Auth error", "401 Unauthorized while applying.\nEnsure Digest is accepted for this user.")
            else:
                messagebox.showerror("Apply error", f"HTTP error:\n{e}")
        except requests.RequestException as e:
            self._log(f"Request error during apply: {e}")
            messagebox.showerror("Apply error", f"Request error:\n{e}")
        except Exception as e:
            self._log(f"Unexpected error: {e}")
            messagebox.showerror("Apply error", str(e))

# ------------ Main ------------

if __name__ == "__main__":
    app = AxisClonerGUI()
    app.mainloop()
