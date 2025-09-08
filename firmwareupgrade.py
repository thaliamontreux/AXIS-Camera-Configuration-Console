import os
import json
import socket
import threading
import subprocess
import sys
import time
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import ipaddress
import requests
from requests.auth import HTTPDigestAuth
from concurrent.futures import ThreadPoolExecutor, Future
from datetime import datetime
import urllib3


APP_TITLE = "Axis Companion Helper (HTTP only)"
DEFAULT_API_VERSION = "1.0"

# ---------------- Tunables & Limits ----------------
TIMEOUT_SHORT = 20          # short HTTP ops (sec) – general
TIMEOUT_LONG = 600          # firmware upload (sec)

# Coarse scan socket settings
SOCKET_TIMEOUT = 1.6        # connect timeout per port (general)
CONNECT_RETRIES_COARSE = 2  # retries per port (general)

# Make RTSP:554 easier to catch
SOCKET_TIMEOUT_554 = 2.8    # longer timeout just for 554
CONNECT_RETRIES_554 = 3     # more retries just for 554

# Deep scan settings for 554-hosts
SOCKET_TIMEOUT_DEEP = 0.6   # connect timeout per port (deep)
CONNECT_RETRIES_DEEP = 2
DEEP_MAX_WORKERS = 200      # per-host fanout
DEEP_PORT_MIN = 1
DEEP_PORT_MAX = 65535

# HTTP banner/manufacturer fetch timeout (HTTP only)
HTTP_TIMEOUT = 4.0

# Ping settings
PING_PROBES = 1
PING_TIMEOUT_MS = 2500

# Threading
MAX_WORKERS = 15  # parallel hosts for coarse scan & group actions

# CGI endpoints (HTTP only)
CGI_FIRMWARE   = "/axis-cgi/firmwaremanagement.cgi"
CGI_PARAM      = "/axis-cgi/param.cgi"
CGI_APIDISC    = "/axis-cgi/apidiscovery.cgi"
CGI_NETSET     = "/axis-cgi/network_settings.cgi"
CGI_CAPTURE    = "/axis-cgi/capturemode.cgi"
CGI_SNAPSHOT   = "/axis-cgi/jpg/image.cgi"


# =============== Progress wrapper (firmware upload) ===============
class ProgressFile:
    def __init__(self, filepath, progress_cb=None):
        self.filepath = filepath
        self.fp = open(filepath, "rb")
        self.total = os.path.getsize(filepath)
        self.read_bytes = 0
        self.progress_cb = progress_cb

    def __len__(self): return self.total

    def read(self, amt=8192):
        data = self.fp.read(amt)
        if data:
            self.read_bytes += len(data)
            if self.progress_cb:
                self.progress_cb(self.read_bytes, self.total)
        return data

    def close(self):
        try: self.fp.close()
        except Exception: pass


# ============================== Main GUI ==============================
class AxisGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_TITLE)
        self.geometry("1200x900")
        self.minsize(1160, 820)
        self.resizable(True, True)

        # -------- App State --------
        # Network defaults
        self.var_network_ip = tk.StringVar(value="192.168.5.0")
        self.var_cidr       = tk.StringVar(value="/24")
        self.var_optional_port = tk.StringVar(value="")

        # Octets (tight dropdowns)
        self.var_o1 = tk.StringVar(value="192")
        self.var_o2 = tk.StringVar(value="168")
        self.var_o3 = tk.StringVar(value="5")
        self.var_o4 = tk.StringVar(value="90")

        # Connection
        self.var_host = tk.StringVar(value="192.168.5.90")  # read-only assembled IP
        self.var_port = tk.StringVar(value="80")            # HTTP only
        self.var_user = tk.StringVar(value="")
        self.var_pass = tk.StringVar(value="")

        # Firmware / options
        self.var_fw_path = tk.StringVar(value="")
        self.var_context = tk.StringVar(value="AxisFWClient")
        self.var_autocommit = tk.StringVar(value="default")     # default|never|boot|started
        self.var_autorollback = tk.StringVar(value="default")   # default|never|<minutes>
        self.var_factory_default = tk.StringVar(value="none")   # none|soft|hard

        # HTTP session (accept all SSL certs; we only use HTTP)
        self.session = requests.Session()
        self.session.verify = False
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        # Scan state
        self.scan_executor = None
        self.scan_cancel_flag = threading.Event()
        self.scan_futures = {}   # future -> host

        # Deep scan state
        self.deep_futures = {}   # future -> (host, tree_item_id)
        self.deep_executor = ThreadPoolExecutor(max_workers=MAX_WORKERS)

        # Mapping for updating Group A rows after deep scan
        self.top_row_by_host = {}

        # Build UI
        self._build_ui()
        self._build_menu()

        # Initialize octet dropdowns from default network
        self._apply_network_to_octets()

        # Show log message
        self._log("Ready. Default network 192.168.5.0/24 set. Click 'Apply Network & Scan' to discover hosts.")

    # ------------------------ UI Layout ------------------------
    def _build_ui(self):
        pad = {"padx": 10, "pady": 8}

        # Only a single main frame
        main = ttk.Frame(self)
        main.pack(fill="both", expand=True)

        # ===== Network Definition =====
        fr_net = ttk.LabelFrame(main, text="Network")
        fr_net.pack(fill="x", **pad)

        r = 0
        ttk.Label(fr_net, text="Network IP:").grid(row=r, column=0, sticky="e")
        ttk.Entry(fr_net, textvariable=self.var_network_ip, width=18).grid(row=r, column=1, sticky="w")

        ttk.Label(fr_net, text="Subnet (CIDR):").grid(row=r, column=2, sticky="e")
        self.cb_cidr = ttk.Combobox(fr_net, textvariable=self.var_cidr, width=8, state="readonly",
                                    values=["/30","/29","/28","/27","/26","/25","/24","/23","/22","/21",
                                            "/20","/19","/18","/17","/16"])
        self.cb_cidr.grid(row=r, column=3, sticky="w")

        ttk.Label(fr_net, text="Optional Port:").grid(row=r, column=4, sticky="e")
        ttk.Entry(fr_net, textvariable=self.var_optional_port, width=8).grid(row=r, column=5, sticky="w")

        self.btn_apply = ttk.Button(fr_net, text="Apply Network & Scan", command=self._apply_network_and_scan)
        self.btn_apply.grid(row=r, column=6, sticky="w", padx=6)

        self.btn_stop = ttk.Button(fr_net, text="Stop Scan", command=self._stop_all, state="disabled")
        self.btn_stop.grid(row=r, column=7, sticky="w")

        # Row: Tight unlabeled octet dropdowns with dots between (box.box.box.box)
        r += 1
        ttk.Label(fr_net, text="Device IP:").grid(row=r, column=0, sticky="e")
        ipwrap = ttk.Frame(fr_net)
        ipwrap.grid(row=r, column=1, columnspan=7, sticky="w")

        self.cb_o1 = ttk.Combobox(ipwrap, textvariable=self.var_o1, width=4, state="readonly")
        self.cb_o2 = ttk.Combobox(ipwrap, textvariable=self.var_o2, width=4, state="readonly")
        self.cb_o3 = ttk.Combobox(ipwrap, textvariable=self.var_o3, width=4, state="readonly")
        self.cb_o4 = ttk.Combobox(ipwrap, textvariable=self.var_o4, width=4, state="readonly")

        self.cb_o1.pack(side="left")
        ttk.Label(ipwrap, text=".").pack(side="left")
        self.cb_o2.pack(side="left")
        ttk.Label(ipwrap, text=".").pack(side="left")
        self.cb_o3.pack(side="left")
        ttk.Label(ipwrap, text=".").pack(side="left")
        self.cb_o4.pack(side="left")

        # Cascade updates for octets
        self.cb_o1.bind("<<ComboboxSelected>>", lambda e: self._cascade_octets(level=1))
        self.cb_o2.bind("<<ComboboxSelected>>", lambda e: self._cascade_octets(level=2))
        self.cb_o3.bind("<<ComboboxSelected>>", lambda e: self._cascade_octets(level=3))
        self.cb_o4.bind("<<ComboboxSelected>>", lambda e: self._assemble_host())

        # ===== Connection =====
        fr_conn = ttk.LabelFrame(main, text="Connection (HTTP only)")
        fr_conn.pack(fill="x", **pad)
        r = 0
        ttk.Label(fr_conn, text="Host/IP:").grid(row=r, column=0, sticky="e")
        ttk.Entry(fr_conn, textvariable=self.var_host, width=26, state="readonly").grid(row=r, column=1, sticky="w")
        ttk.Label(fr_conn, text="Port:").grid(row=r, column=2, sticky="e")
        ttk.Entry(fr_conn, textvariable=self.var_port, width=8).grid(row=r, column=3, sticky="w")

        r += 1
        ttk.Label(fr_conn, text="Username:").grid(row=r, column=0, sticky="e")
        ttk.Entry(fr_conn, textvariable=self.var_user, width=20).grid(row=r, column=1, sticky="w")
        ttk.Label(fr_conn, text="Password:").grid(row=r, column=2, sticky="e")
        ttk.Entry(fr_conn, textvariable=self.var_pass, width=22, show="•").grid(row=r, column=3, sticky="w")

        # ===== Firmware =====
        fr_fw = ttk.LabelFrame(main, text="Firmware upgrade")
        fr_fw.pack(fill="x", **pad)
        r = 0
        ttk.Label(fr_fw, text="File (.bin):").grid(row=r, column=0, sticky="e")
        ttk.Entry(fr_fw, textvariable=self.var_fw_path).grid(row=r, column=1, columnspan=3, sticky="we")
        ttk.Button(fr_fw, text="Browse…", command=self._browse_fw).grid(row=r, column=4, sticky="w")

        r += 1
        ttk.Label(fr_fw, text="autoCommit:").grid(row=r, column=0, sticky="e")
        ttk.Combobox(fr_fw, textvariable=self.var_autocommit, width=10, state="readonly",
                     values=["default", "never", "boot", "started"]).grid(row=r, column=1, sticky="w")

        ttk.Label(fr_fw, text="autoRollback:").grid(row=r, column=2, sticky="e")
        ttk.Combobox(fr_fw, textvariable=self.var_autorollback, width=10, state="readonly",
                     values=["default", "never", "5", "10", "15", "30", "60"]).grid(row=r, column=3, sticky="w")

        ttk.Label(fr_fw, text="factoryDefault:").grid(row=r, column=4, sticky="e")
        ttk.Combobox(fr_fw, textvariable=self.var_factory_default, width=8, state="readonly",
                     values=["none", "soft", "hard"]).grid(row=r, column=5, sticky="w")

        r += 1
        ttk.Label(fr_fw, text="context:").grid(row=r, column=0, sticky="e")
        ttk.Entry(fr_fw, textvariable=self.var_context, width=26).grid(row=r, column=1, sticky="w")
        ttk.Button(fr_fw, text="Upgrade", command=self._do_upgrade).grid(row=r, column=2, sticky="w")
        ttk.Button(fr_fw, text="Commit", command=self._do_commit).grid(row=r, column=3, sticky="w")
        ttk.Button(fr_fw, text="Rollback", command=self._do_rollback).grid(row=r, column=4, sticky="w")

        # ===== Camera actions (auto-wrap, always enabled) =====
        fr_actions = ttk.LabelFrame(main, text="Camera actions")
        fr_actions.pack(fill="x", **pad)

        # Two rows that we repack dynamically on resize
        self.actions_row1 = ttk.Frame(fr_actions)
        self.actions_row2 = ttk.Frame(fr_actions)
        self.actions_row1.pack(fill="x", padx=6, pady=(6, 0))
        self.actions_row2.pack(fill="x", padx=6, pady=(6, 8))

        # Create buttons with parent = fr_actions (so we can pack into either row)
        def mkbtn(txt, cmd):
            return ttk.Button(fr_actions, text=txt, command=cmd, state="normal")

        self.btn_test     = mkbtn("Test Connection", self._do_test_connection)
        self.btn_listapis = mkbtn("List APIs", self._do_list_apis)
        self.btn_netinfo  = mkbtn("Network Info", self._do_network_info)
        self.btn_capture  = mkbtn("Capture Modes", self._do_capture_modes)
        self.btn_status   = mkbtn("Status", self._do_status)
        self.btn_reboot   = mkbtn("Reboot", self._do_reboot)
        self.btn_snapshot = mkbtn("Snapshot (Save…)", self._do_snapshot)

        self.action_buttons = [
            self.btn_test, self.btn_listapis, self.btn_netinfo,
            self.btn_capture, self.btn_status, self.btn_reboot, self.btn_snapshot
        ]

        # Initial packing into row1 (layout will reflow on <Configure>)
        for b in self.action_buttons:
            b.pack(in_=self.actions_row1, side="left", padx=4, pady=4)

        # Reflow on resize
        fr_actions.bind("<Configure>", self._layout_action_buttons)

        # ===== Progress =====
        fr_prog = ttk.LabelFrame(main, text="Progress")
        fr_prog.pack(fill="x", **pad)
        self.prog = ttk.Progressbar(fr_prog, mode="determinate")
        self.prog.pack(fill="x", padx=8, pady=6)
        self.lbl_prog = ttk.Label(fr_prog, text="Idle.")
        self.lbl_prog.pack(anchor="w", padx=8, pady=(0,6))

        # ===== Scan Results =====
        fr_scan = ttk.LabelFrame(main, text="Scan Results")
        fr_scan.pack(fill="both", expand=True, **pad)

        # Group A table
        ttk.Label(fr_scan, text="Group A — Hosts with RTSP 554").pack(anchor="w", padx=8, pady=(6,2))
        self.tree_top = ttk.Treeview(fr_scan, columns=("host","ports","mfg"), show="headings", height=8)
        self.tree_top.heading("host", text="Host", anchor="w")
        self.tree_top.heading("ports", text="Open Ports", anchor="w")
        self.tree_top.heading("mfg",  text="Manufacturer", anchor="w")
        self.tree_top.column("host", width=200, anchor="w")
        self.tree_top.column("ports", width=340, anchor="w")
        self.tree_top.column("mfg",  width=340, anchor="w")
        self.tree_top.pack(fill="x", padx=8, pady=(0,10))
        self.tree_top.bind("<<TreeviewSelect>>", lambda e: self._on_tree_select(self.tree_top))
        self.tree_top.bind("<Double-1>",       lambda e: self._on_tree_select(self.tree_top))
        # green highlight tag
        self.tree_top.tag_configure("axis", background="#c2f0c2")

        # Group B table
        ttk.Label(fr_scan, text="Group B — Hosts with HTTP 80 + HTTPS 443 (no 554)").pack(anchor="w", padx=8, pady=(6,2))
        self.tree_bottom = ttk.Treeview(fr_scan, columns=("host","ports","mfg"), show="headings", height=8)
        self.tree_bottom.heading("host", text="Host", anchor="w")
        self.tree_bottom.heading("ports", text="Open Ports", anchor="w")
        self.tree_bottom.heading("mfg",  text="Manufacturer", anchor="w")
        self.tree_bottom.column("host", width=200, anchor="w")
        self.tree_bottom.column("ports", width=340, anchor="w")
        self.tree_bottom.column("mfg",  width=340, anchor="w")
        self.tree_bottom.pack(fill="both", expand=True, padx=8, pady=(0,10))
        self.tree_bottom.bind("<<TreeviewSelect>>", lambda e: self._on_tree_select(self.tree_bottom))
        self.tree_bottom.bind("<Double-1>",       lambda e: self._on_tree_select(self.tree_bottom))

        # ===== Responses / Log =====
        fr_out = ttk.LabelFrame(main, text="Responses / Log")
        fr_out.pack(fill="both", expand=True, **pad)
        self.txt = tk.Text(fr_out, wrap="word", height=10)
        self.txt.pack(fill="both", expand=True, padx=8, pady=8)

    def _build_menu(self):
        menubar = tk.Menu(self)
        self.config(menu=menubar)
        view = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="View", menu=view)

    # ---------- Responsive layout for action buttons ----------
    def _layout_action_buttons(self, event=None):
        # Move buttons between row1 and row2 so they never get covered.
        container_width = self.actions_row1.winfo_width() or self.actions_row1.winfo_reqwidth()
        if container_width <= 0:
            return

        # Compute how many fit into row1
        x = 0
        gap = 8  # approximate combined padx
        fits = 0

        # Temporarily put all into row1 to measure
        for b in self.action_buttons:
            b.pack_forget()
            b.pack(in_=self.actions_row1, side="left", padx=4, pady=4)
        self.update_idletasks()

        for b in self.action_buttons:
            w = b.winfo_width() or b.winfo_reqwidth()
            if x + w + gap <= container_width:
                x += w + gap
                fits += 1
            else:
                break

        # Repack: first 'fits' buttons in row1, rest in row2
        for b in self.action_buttons:
            b.pack_forget()
        for b in self.action_buttons[:fits]:
            b.pack(in_=self.actions_row1, side="left", padx=4, pady=4)
        for b in self.action_buttons[fits:]:
            b.pack(in_=self.actions_row2, side="left", padx=4, pady=4)

    # ---------------------- Network → Octets ----------------------
    def _apply_network_and_scan(self):
        if not self._apply_network_to_octets():
            return
        self._start_scan()

    def _apply_network_to_octets(self):
        net_ip = self.var_network_ip.get().strip()
        cidr = self.var_cidr.get().strip().lstrip("/")

        # Validate CIDR
        try:
            prefixlen = int(cidr)
            if not (0 <= prefixlen <= 32): raise ValueError
        except Exception:
            messagebox.showerror("Invalid CIDR", "Please choose a valid CIDR like /24.")
            return False

        # Validate network address aligns with prefix
        try:
            net = ipaddress.IPv4Network(f"{net_ip}/{prefixlen}", strict=True)
        except Exception as e:
            messagebox.showerror("Invalid Network",
                                 "Please enter a valid network address aligned to the selected CIDR.\n"
                                 f"Tip: For /24 use something like 192.168.5.0\n\nDetails: {e}")
            return False

        if prefixlen < 16:
            messagebox.showwarning("Network too wide",
                                   "This network is very large. For dropdown selection, please use /16 or narrower.")
            return False

        self._log(f"Using network: {net.with_prefixlen}")

        # Compute usable host range
        first_host = int(net.network_address) + 1 if net.num_addresses >= 2 else int(net.network_address)
        last_host = int(net.broadcast_address) - 1 if net.num_addresses >= 2 else int(net.broadcast_address)
        if last_host < first_host:
            messagebox.showerror("No host range", "The selected network has no usable host addresses.")
            return False

        first = ipaddress.IPv4Address(first_host)
        last  = ipaddress.IPv4Address(last_host)
        f1, f2, f3, f4 = map(int, str(first).split("."))
        l1, l2, l3, l4 = map(int, str(last).split("."))

        # Helper to set combobox values
        def set_combo(cb, values, preselect=None, lock_if_single=True):
            cb.configure(state="readonly")
            vals = [str(v) for v in values]
            cb["values"] = vals
            sel = str(preselect if preselect is not None else values[0])
            cb.set(sel)
            if lock_if_single and len(values) == 1:
                cb.configure(state="disabled")
            else:
                cb.configure(state="readonly")

        # O1
        o1_vals = list(range(f1, l1 + 1))
        set_combo(self.cb_o1, o1_vals, preselect=f1)

        # O2 depends on O1 span
        if f1 == l1:
            o2_vals = list(range(f2, l2 + 1))
        else:
            o2_vals = list(range(0, 256))
        set_combo(self.cb_o2, o2_vals, preselect=f2)

        # O3 depends on O1 & O2
        sel_o2 = int(self.cb_o2.get())
        def calc_o3_vals(sel_o2x):
            if f1 == l1:
                if f2 == l2:
                    return list(range(f3, l3 + 1))
                else:
                    if sel_o2x == f2:  return list(range(f3, 256))
                    elif sel_o2x == l2: return list(range(0, l3 + 1))
                    else:               return list(range(0, 256))
            return list(range(0, 256))
        o3_vals = calc_o3_vals(sel_o2)
        set_combo(self.cb_o3, o3_vals, preselect=f3)

        # O4 depends on O2 & O3
        sel_o3 = int(self.cb_o3.get())
        def calc_o4_vals(sel_o2x, sel_o3x):
            if (f1, f2, f3) == (l1, l2, l3): return list(range(f4, l4 + 1))
            if (sel_o2x, sel_o3x) == (f2, f3): return list(range(f4, 256))
            if (sel_o2x, sel_o3x) == (l2, l3): return list(range(0, l4 + 1))
            return list(range(0, 256))
        o4_vals = calc_o4_vals(sel_o2, sel_o3)
        set_combo(self.cb_o4, o4_vals, preselect=f4, lock_if_single=False)

        # For /24 and narrower, lock first three octets (cleaner UI)
        if prefixlen >= 24:
            self.cb_o1.configure(state="disabled")
            self.cb_o2.configure(state="disabled")
            self.cb_o3.configure(state="disabled")
        else:
            self.cb_o1.configure(state="disabled")  # keep O1 fixed

        self._assemble_host()
        return True

    def _cascade_octets(self, level: int):
        net_ip = self.var_network_ip.get().strip()
        prefixlen = int(self.var_cidr.get().strip().lstrip("/"))
        net = ipaddress.IPv4Network(f"{net_ip}/{prefixlen}", strict=True)
        first_host = int(net.network_address) + 1 if net.num_addresses >= 2 else int(net.network_address)
        last_host = int(net.broadcast_address) - 1 if net.num_addresses >= 2 else int(net.broadcast_address)
        first = ipaddress.IPv4Address(first_host)
        last  = ipaddress.IPv4Address(last_host)
        f1, f2, f3, f4 = map(int, str(first).split("."))

        if level == 1:
            o2_vals = range(f2, int(str(last).split(".")[1]) + 1) if f1 == int(str(last).split(".")[0]) else range(0, 256)
            o2_list = [str(v) for v in o2_vals]
            if self.cb_o2.get() not in o2_list: self.cb_o2.set(o2_list[0])
            self.cb_o2["values"] = o2_list

        sel_o2 = int(self.cb_o2.get())
        def calc_o3_vals(sel_o2x):
            l1, l2, l3, l4 = map(int, str(last).split("."))
            if f1 == l1:
                if f2 == l2:
                    return list(range(f3, l3 + 1))
                else:
                    if sel_o2x == f2:  return list(range(f3, 256))
                    elif sel_o2x == l2: return list(range(0, l3 + 1))
                    else:               return list(range(0, 256))
            return list(range(0, 256))
        o3_vals = calc_o3_vals(sel_o2)
        o3_list = [str(v) for v in o3_vals]
        if level <= 2:
            if self.cb_o3.get() not in o3_list: self.cb_o3.set(o3_list[0])
            self.cb_o3["values"] = o3_list

        sel_o3 = int(self.cb_o3.get())
        def calc_o4_vals(sel_o2x, sel_o3x):
            l1, l2, l3, l4 = map(int, str(last).split("."))
            if (f1, f2, f3) == (l1, l2, l3): return list(range(f4, l4 + 1))
            if (sel_o2x, sel_o3x) == (f2, f3): return list(range(f4, 256))
            if (sel_o2x, sel_o3x) == (l2, l3): return list(range(0, l4 + 1))
            return list(range(0, 256))
        o4_vals = calc_o4_vals(sel_o2, sel_o3)
        self.cb_o4["values"] = [str(v) for v in o4_vals]
        if self.cb_o4.get() not in self.cb_o4["values"]:
            self.cb_o4.set(str(o4_vals[0]))

        self._assemble_host()

    # ------------------------ Helpers ------------------------
    def _assemble_host(self):
        host = f"{self.var_o1.get()}.{self.var_o2.get()}.{self.var_o3.get()}.{self.var_o4.get()}"
        self.var_host.set(host)

    def _set_host_from_ip(self, ip_str: str):
        try:
            parts = [int(x) for x in ip_str.split(".")]
            if len(parts) != 4: raise ValueError
            o1,o2,o3,o4 = parts
            for cb, val in ((self.cb_o1,o1),(self.cb_o2,o2),(self.cb_o3,o3),(self.cb_o4,o4)):
                vals = [int(v) for v in cb["values"]]
                cb.set(str(val if val in vals else val))
            self._assemble_host()
            self._log(f"Selected host → {self.var_host.get()}")
        except Exception:
            self._log(f"Could not parse selected host: {ip_str}")

    def _on_tree_select(self, tree: ttk.Treeview):
        sel = tree.selection()
        if not sel:
            return
        vals = tree.item(sel[0], "values")
        if not vals:
            return
        host = vals[0]
        self._set_host_from_ip(host)

    def _endpoint(self, path):
        host = self.var_host.get().strip()
        port = self.var_port.get().strip()
        port_part = f":{port}" if port and port != "80" else ""
        return f"http://{host}{port_part}{path}"

    def _auth(self):
        return HTTPDigestAuth(self.var_user.get().strip(), self.var_pass.get())

    def _log(self, text):
        line = text if text.endswith("\n") else text + "\n"
        self.txt.insert("end", line); self.txt.see("end")
        self.update_idletasks()

    def _set_progress(self, done, total):
        pct = 0 if total == 0 else int(done * 100 / total)
        self.prog["value"] = pct
        self.lbl_prog.config(text=f"Uploading… {pct}% ({done}/{total} bytes)")
        self.update_idletasks()

    def _reset_progress(self):
        self.prog["value"] = 0
        self.lbl_prog.config(text="Idle.")
        self.update_idletasks()

    def _browse_fw(self):
        _ = filedialog.asksaveasfilename  # guard to avoid accidental use
        path = filedialog.askopenfilename(
            title="Select Axis firmware (.bin)",
            filetypes=[("Axis firmware", "*.bin"), ("All files", "*.*")]
        )
        if path: self.var_fw_path.set(path)

    # -------------------- Low-level HTTP helpers --------------------
    def _post_json(self, path, payload, timeout=TIMEOUT_SHORT):
        url = self._endpoint(path)
        self._log(f"POST {url} :: {payload}")
        try:
            r = self.session.post(url, json=payload, auth=self._auth(), timeout=timeout)
            body_preview = r.text if (r.text and len(r.text) < 4000) else "<response too large>"
            self._log(f"HTTP {r.status_code}\n{body_preview}\n")
            return r
        except Exception as e:
            self._log(f"ERROR POST {url} :: {e}")
            messagebox.showerror("Request error", str(e))
            return None

    def _get(self, path, params=None, timeout=TIMEOUT_SHORT, stream=False):
        url = self._endpoint(path)
        self._log(f"GET {url} :: params={params}")
        try:
            r = self.session.get(url, params=params, auth=self._auth(), timeout=timeout, stream=stream)
            if not stream:
                body_preview = r.text if (r.text and len(r.text) < 4000) else "<response too large>"
                self._log(f"HTTP {r.status_code}\n{body_preview}\n")
            else:
                self._log(f"HTTP {r.status_code} (stream)\n")
            return r
        except Exception as e:
            self._log(f"ERROR GET {url} :: {e}")
            messagebox.showerror("Request error", str(e))
            return None

    # ----------------------- Actions -----------------------
    # Firmware mgmt
    def _do_upgrade(self):
        fw = self.var_fw_path.get().strip()
        if not fw or not os.path.isfile(fw):
            messagebox.showwarning("Missing file", "Please choose a valid firmware .bin file.")
            return

        params = {}
        if self.var_factory_default.get() != "none":
            params["factoryDefaultMode"] = self.var_factory_default.get()
        if self.var_autocommit.get() != "default":
            params["autoCommit"] = self.var_autocommit.get()
        if self.var_autorollback.get() != "default":
            params["autoRollback"] = self.var_autorollback.get()

        envelope = {
            "apiVersion": DEFAULT_API_VERSION,
            "context": self.var_context.get().strip() or "AxisFWClient",
            "method": "upgrade"
        }
        if params: envelope["params"] = params

        url = self._endpoint(CGI_FIRMWARE)
        self._log(f"Uploading firmware to {url}")
        self._log(f"JSON envelope: {json.dumps(envelope)}")

        pf = ProgressFile(fw, self._set_progress)
        try:
            files = [
                ("json", (None, json.dumps(envelope), "application/json")),
                ("file", (os.path.basename(fw), pf, "application/octet-stream")),
            ]
            r = self.session.post(url, files=files, auth=self._auth(), timeout=TIMEOUT_LONG)
            body_preview = r.text if (r.text and len(r.text) < 4000) else "<response too large>"
            self._log(f"HTTP {r.status_code}\n{body_preview}\n")
            if r.ok:
                messagebox.showinfo("Upload complete", "Firmware upload request sent.\nThe device will reboot as needed.")
            else:
                messagebox.showerror("Upgrade failed", f"HTTP {r.status_code}\n{r.text}")
        except Exception as e:
            self._log(f"ERROR Upload {url} :: {e}")
            messagebox.showerror("Upload error", str(e))
        finally:
            pf.close()
            self._reset_progress()

    def _do_commit(self):
        payload = {"apiVersion": DEFAULT_API_VERSION, "context": self.var_context.get().strip(), "method": "commit"}
        self._post_json(CGI_FIRMWARE, payload)

    def _do_status(self):
        payload = {"apiVersion": DEFAULT_API_VERSION, "context": self.var_context.get().strip(), "method": "status"}
        self._post_json(CGI_FIRMWARE, payload)

    def _do_rollback(self):
        if not messagebox.askyesno("Confirm rollback",
                                   "Rollback will revert to the previous firmware (if available) and reboot the device.\nProceed?"):
            return
        payload = {"apiVersion": DEFAULT_API_VERSION, "context": self.var_context.get().strip(), "method": "rollback"}
        self._post_json(CGI_FIRMWARE, payload)

    def _do_reboot(self):
        if not messagebox.askyesno("Confirm reboot", "Reboot the device now?"):
            return
        payload = {"apiVersion": DEFAULT_API_VERSION, "context": self.var_context.get().strip(), "method": "reboot"}
        self._post_json(CGI_FIRMWARE, payload)

    # General APIs
    def _do_test_connection(self):
        params = {"action": "list", "group": "Properties"}
        self._get(CGI_PARAM, params=params, timeout=TIMEOUT_SHORT)

    def _do_list_apis(self):
        payload = {"apiVersion": "1.0", "method": "getApiList"}
        self._post_json(CGI_APIDISC, payload)

    def _do_network_info(self):
        payload = {"apiVersion": "1.0", "method": "getNetworkInfo"}
        self._post_json(CGI_NETSET, payload)

    def _do_capture_modes(self):
        payload = {"apiVersion": "1.0", "method": "getCaptureModes"}
        self._post_json(CGI_CAPTURE, payload)

    def _do_snapshot(self):
        params = {"Axis-Orig-Sw": "true"}
        r = self._get(CGI_SNAPSHOT, params=params, stream=True, timeout=TIMEOUT_SHORT)
        if not r or not r.ok:
            messagebox.showerror("Snapshot failed", "Could not fetch snapshot.")
            return
        default_name = f"axis_snapshot_{self.var_host.get()}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.jpg"
        path = filedialog.asksaveasfilename(
            title="Save snapshot",
            defaultextension=".jpg",
            initialfile=default_name,
            filetypes=[("JPEG image", "*.jpg")]
        )
        if not path:
            r.close(); return
        try:
            with open(path, "wb") as f:
                for chunk in r.iter_content(chunk_size=8192):
                    if chunk: f.write(chunk)
            self._log(f"Saved snapshot to: {path}")
            messagebox.showinfo("Snapshot saved", f"Saved to:\n{path}")
        except Exception as e:
            self._log(f"ERROR saving snapshot :: {e}")
            messagebox.showerror("Save error", str(e))
        finally:
            r.close()

    # -------------------------- Scanner --------------------------
    def _start_scan(self):
        # Clear previous results
        for tree in (self.tree_top, self.tree_bottom):
            for item in tree.get_children(): tree.delete(item)
        self.top_row_by_host.clear()

        # Validate optional port
        opt_port = None
        opt_txt = self.var_optional_port.get().strip()
        if opt_txt:
            if not opt_txt.isdigit() or not (1 <= int(opt_txt) <= 65535):
                messagebox.showerror("Invalid Port", "Optional port must be a number between 1 and 65535.")
                return
            opt_port = int(opt_txt)

        # Build host list
        net_ip = self.var_network_ip.get().strip()
        prefixlen = int(self.var_cidr.get().strip().lstrip("/"))
        try:
            net = ipaddress.IPv4Network(f"{net_ip}/{prefixlen}", strict=True)
        except Exception as e:
            messagebox.showerror("Invalid Network", str(e))
            return

        hosts = [str(ip) for ip in net.hosts()]
        if not hosts:
            messagebox.showwarning("No hosts", "No usable hosts in this network.")
            return

        self._log(f"Scanning {len(hosts)} hosts on ports 80, 443, 554" + (f", {opt_port}" if opt_port else "") + " …")

        # UI state
        self.btn_apply.configure(state="disabled")
        self.btn_stop.configure(state="normal")
        self.scan_cancel_flag.clear()
        self.prog["value"] = 0
        self.lbl_prog.config(text="Scanning… 0%")
        self.update_idletasks()

        ports_to_check = [80, 443, 554] + ([opt_port] if opt_port else [])
        self.scan_executor = ThreadPoolExecutor(max_workers=MAX_WORKERS)
        self.scan_futures = {self.scan_executor.submit(self._scan_host, h, ports_to_check): h for h in hosts}

        # Poll results
        self.after(80, self._poll_scan_results, len(hosts))

    def _stop_all(self):
        # Stop scans
        if self.scan_executor:
            self._log("Stopping scan…")
            self.scan_cancel_flag.set()
            try: self.scan_executor.shutdown(wait=False)
            except Exception: pass
            self.scan_executor = None

        # Stop deep scans
        if self.deep_futures:
            self._log("Stopping deep scans…")
        self.deep_futures.clear()  # cannot cancel socket attempts easily

        self.btn_stop.configure(state="disabled")
        self.btn_apply.configure(state="normal")
        self.lbl_prog.config(text="Stopped.")
        self.update_idletasks()

    def _poll_scan_results(self, total):
        # consume coarse futures
        if self.scan_futures:
            for fut in list(self.scan_futures.keys()):
                if fut.done():
                    host = self.scan_futures.pop(fut)
                    try:
                        result = fut.result()
                    except Exception as e:
                        self._log(f"Scan error on {host}: {e}")
                        result = None
                    if result:
                        self._handle_scan_result(result)

        # deep scan futures (update rows when finished)
        if self.deep_futures:
            for fut in list(self.deep_futures.keys()):
                if fut.done():
                    host, item_id = self.deep_futures.pop(fut)
                    try:
                        extra_ports = fut.result() or []
                    except Exception as e:
                        self._log(f"Deep scan error on {host}: {e}")
                        extra_ports = []
                    # Merge extra ports into displayed row
                    current_vals = self.tree_top.item(item_id, "values")
                    if current_vals:
                        host_cell, ports_cell, mfg_cell = current_vals
                        try:
                            existing = set(int(p.strip()) for p in ports_cell.split(",") if p.strip().isdigit())
                        except Exception:
                            existing = set()
                        updated = sorted(existing.union(extra_ports))
                        self.tree_top.item(item_id, values=(host_cell, ", ".join(str(p) for p in updated), mfg_cell))
                        self._log(f"Deep scan complete for {host}: +{len(extra_ports)} ports")

        remaining = len(self.scan_futures) if self.scan_futures else 0
        processed = total - remaining
        pct = int(processed * 100 / total) if total else 100
        self.prog["value"] = pct
        self.lbl_prog.config(text=("Scan complete." if remaining == 0 else f"Scanning… {pct}%"))
        self.update_idletasks()

        if remaining == 0 and not self.deep_futures:
            self.btn_stop.configure(state="disabled")
            self.btn_apply.configure(state="normal")
            self._log("Scan complete.")
            return

        self.after(150, self._poll_scan_results, total)

    # --------------------- Ping & TCP probes ---------------------
    def _can_ping(self, host: str) -> bool:
        try:
            if sys.platform.startswith("win"):
                cmd = ["ping", "-n", str(PING_PROBES), "-w", str(PING_TIMEOUT_MS), host]
            else:
                cmd = ["ping", "-c", str(PING_PROBES), "-W", str(max(1, int(PING_TIMEOUT_MS/1000))), host]
            res = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return res.returncode == 0
        except Exception:
            return False

    def _scan_host(self, host, ports):
        if self.scan_cancel_flag.is_set(): return None

        alive = self._can_ping(host)
        self._log(f"Ping {host}: {'reply' if alive else 'no reply (continuing anyway)'}")

        open_ports = []
        for p in ports:
            if self.scan_cancel_flag.is_set(): return None
            # generous settings for RTSP 554
            if p == 554:
                is_open = self._is_port_open_with_retries(host, p, SOCKET_TIMEOUT_554, CONNECT_RETRIES_554)
            else:
                is_open = self._is_port_open_with_retries(host, p, SOCKET_TIMEOUT, CONNECT_RETRIES_COARSE)
            if is_open: open_ports.append(p)

        manufacturer = self._detect_manufacturer_http_only(host, open_ports)
        return {"host": host, "open_ports": open_ports, "manufacturer": manufacturer}

    def _is_port_open_with_retries(self, host, port, timeout, retries):
        attempts = max(1, int(retries))
        for _ in range(attempts):
            if self._is_port_open_once(host, port, timeout): return True
            time.sleep(0.05)
        return False

    def _is_port_open_once(self, host, port, timeout):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                return s.connect_ex((host, port)) == 0
        except Exception:
            return False

    def _detect_manufacturer_http_only(self, host, open_ports):
        """HTTP-only banner sniff."""
        text_head, headers = "", {}
        try:
            if 80 in open_ports:
                r = self.session.get(f"http://{host}/", timeout=HTTP_TIMEOUT, allow_redirects=True)
                headers = r.headers or {}
                text_head = r.text[:256] if r.text else ""
        except Exception:
            pass

        server = headers.get("Server", "")
        www_auth = headers.get("WWW-Authenticate", "")
        guessed = ""
        for token in ["AXIS", "Axis", "axis", "AXIS Camera", "AXIS Video"]:
            if token in server or token in www_auth or token in text_head:
                guessed = "Axis"; break
        if not guessed:
            for token, mfg in [
                ("GoAhead-Webs", "GoAhead"), ("Boa/", "Boa"), ("Lighttpd", "lighttpd"),
                ("nginx", "nginx"), ("Apache", "Apache"), ("thttpd", "thttpd"),
            ]:
                if token in server or token in text_head:
                    guessed = mfg; break
        if not guessed and server: guessed = server
        if not guessed and www_auth: guessed = www_auth
        return guessed or "Unknown"

    def _handle_scan_result(self, result):
        host = result["host"]
        if not result or not host: return
        open_ports = result["open_ports"]
        mfg = result["manufacturer"]
        ports_str = ", ".join(str(p) for p in sorted(open_ports))
        has_554 = 554 in open_ports

        # Any host with 554 → Group A
        if has_554:
            # Highlight Axis & move to top
            is_axis = isinstance(mfg, str) and ("axis" in mfg.lower())
            if is_axis:
                item_id = self.tree_top.insert("", 0, values=(host, ports_str, mfg), tags=("axis",))
            else:
                item_id = self.tree_top.insert("", "end", values=(host, ports_str, mfg))
            self.top_row_by_host[host] = item_id
            # Deep scan for 554 hosts
            self._start_deep_scan(host, set(open_ports), item_id)
        # Group B: HTTP+HTTPS, but NEVER include a 554 host
        elif (80 in open_ports) and (443 in open_ports):
            self.tree_bottom.insert("", "end", values=(host, ports_str, mfg))

    # --------------------- Deep scan for 554 hosts ---------------------
    def _start_deep_scan(self, host: str, already_open: set, item_id: str):
        """Fan out a fast TCP connect scan (1..65535) excluding already_open.
        When complete, merge extra ports into the Group A row.
        """
        self._log(f"Deep scanning {host} ports {DEEP_PORT_MIN}-{DEEP_PORT_MAX} (excluding {sorted(already_open)}) …")

        def deep_job() -> list:
            target_ports = [p for p in range(DEEP_PORT_MIN, DEEP_PORT_MAX + 1) if p not in already_open]
            extra_open = []

            def probe(p):
                return p if self._is_port_open_with_retries(host, p, SOCKET_TIMEOUT_DEEP, CONNECT_RETRIES_DEEP) else None

            with ThreadPoolExecutor(max_workers=DEEP_MAX_WORKERS) as pool:
                futures = [pool.submit(probe, p) for p in target_ports]
                for fut in futures:
                    try:
                        res = fut.result()
                        if res: extra_open.append(res)
                    except Exception:
                        pass
            return sorted(extra_open)

        fut: Future = self.deep_executor.submit(deep_job)
        self.deep_futures[fut] = (host, item_id)


# ============================ Main ============================
if __name__ == "__main__":
    app = AxisGUI()
    try:
        app.mainloop()
    except KeyboardInterrupt:
        pass
