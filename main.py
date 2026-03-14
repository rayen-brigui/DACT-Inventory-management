import tkinter as tk
from tkinter import ttk, messagebox, filedialog, simpledialog, PhotoImage
import sqlite3
from datetime import datetime
import csv
import json
import os
import sys
import hashlib
import binascii
import numpy as np
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure
import customtkinter as ctk
import sys, os
def resource_path(rel):
    if getattr(sys, "frozen", False):
        return os.path.join(sys._MEIPASS, rel)
    return os.path.join(os.path.dirname(__file__), rel)

DB_PATH = "inventory.db"

ctk.set_appearance_mode("System")
ctk.set_default_color_theme("blue")

# ─── Palette ──────────────────────────────────────────────────────────────────
COLORS = {
    "ok_bg":    "#EAF3DE", "ok_fg":    "#3B6D11",
    "low_bg":   "#FAEEDA", "low_fg":   "#854F0B",
    "zero_bg":  "#FCEBEB", "zero_fg":  "#A32D2D",
    "tech_bg":  "#E6F1FB", "tech_fg":  "#185FA5",
    "office_bg":"#EAF3DE", "office_fg":"#3B6D11",
    "infra_bg": "#FAECE7", "infra_fg": "#993C1D",
    "media_bg": "#F0EAFC", "media_fg": "#5B3498",
    "dept_bg":  "#F1EFE8", "dept_fg":  "#5F5E5A",
}
LOW_STOCK_THRESHOLD = 10

# ─── Database ─────────────────────────────────────────────────────────────────
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS items (
        id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL,
        category TEXT, department TEXT,
        quantity INTEGER NOT NULL DEFAULT 0,
        location TEXT, added_at TEXT NOT NULL)""")
    for tbl in ("categories","locations","departments"):
        c.execute(f"CREATE TABLE IF NOT EXISTS {tbl} (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE NOT NULL)")
    cols = [r[1] for r in c.execute("PRAGMA table_info(items)").fetchall()]
    if "department" not in cols:
        try: c.execute("ALTER TABLE items ADD COLUMN department TEXT")
        except: pass
    c.execute("""CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT, action TEXT NOT NULL,
        item_id INTEGER, user_id INTEGER, details TEXT, timestamp TEXT NOT NULL)""")
    cols = [r[1] for r in c.execute("PRAGMA table_info(logs)").fetchall()]
    if "user_id" not in cols:
        try: c.execute("ALTER TABLE logs ADD COLUMN user_id INTEGER")
        except: pass
    c.execute("""CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL, salt TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'user', created_at TEXT NOT NULL)""")
    conn.commit(); conn.close()

def _hash_password(password, salt=None):
    if salt is None: salt = os.urandom(16)
    elif isinstance(salt, str): salt = binascii.unhexlify(salt)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100000)
    return binascii.hexlify(dk).decode(), binascii.hexlify(salt).decode()

def _verify_password(password, salt_hex, hash_hex):
    dk, _ = _hash_password(password, salt_hex)
    return dk == hash_hex

def query_db(query, params=(), fetch=False):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute(query, params)
    res = c.fetchall() if fetch else None
    conn.commit(); conn.close()
    return res


def resource_path(rel_path):
    """Return an absolute path to resource, works for dev and for PyInstaller onefile.
    Pass a relative path like os.path.join('assets','logo.png')."""
    if getattr(sys, "frozen", False):
        return os.path.join(sys._MEIPASS, rel_path)
    return os.path.join(os.path.dirname(__file__), rel_path)

def add_log(action, item_id=None, details=None, user_id=None):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    query_db("INSERT INTO logs (action,item_id,user_id,details,timestamp) VALUES (?,?,?,?,?)",
             (action, item_id, user_id, json.dumps(details) if details else None, ts))

# ─── Helpers ──────────────────────────────────────────────────────────────────
def qty_style(qty):
    if qty == 0:   return COLORS["zero_bg"], COLORS["zero_fg"]
    if qty <= LOW_STOCK_THRESHOLD: return COLORS["low_bg"],  COLORS["low_fg"]
    return COLORS["ok_bg"], COLORS["ok_fg"]

# ─── Tooltip ──────────────────────────────────────────────────────────────────
class Tooltip:
    def __init__(self, widget, text):
        self.widget = widget; self.text = text; self.tw = None
        widget.bind("<Enter>", self.show)
        widget.bind("<Leave>", self.hide)
    def show(self, _=None):
        x = self.widget.winfo_rootx() + 20
        y = self.widget.winfo_rooty() + self.widget.winfo_height() + 4
        self.tw = tk.Toplevel(self.widget)
        self.tw.wm_overrideredirect(True)
        self.tw.wm_geometry(f"+{x}+{y}")
        tk.Label(self.tw, text=self.text, background="#1e1e2e", foreground="#cdd6f4",
                 font=("Helvetica", 11), padx=8, pady=4, relief="flat").pack()
    def hide(self, _=None):
        if self.tw: self.tw.destroy(); self.tw = None

# ─── Login Window ─────────────────────────────────────────────────────────────
class LoginWindow(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("DACT IT Materials Stock Manager")
        self.geometry("420x540")
        self.resizable(False, False)
        self.result = None
        self._build()

    def _build(self):
        self.configure(fg_color=("#f5f5f0", "#1a1a2e"))

        # Logo / branding block
        brand = ctk.CTkFrame(self, fg_color="transparent")
        brand.pack(pady=(52, 0))
        icon_box = ctk.CTkFrame(brand, width=56, height=56, corner_radius=14,
                                fg_color=("#1565C0", "#1565C0"))
        icon_box.pack()
        icon_box.pack_propagate(False)
        # Try to load a logo from assets; fall back to emoji
        icon_path = resource_path(os.path.join("assets", "logo.png"))
        self.logo_img = None
        if os.path.exists(icon_path):
            try:
                self.logo_img = PhotoImage(file=icon_path)
                ctk.CTkLabel(icon_box, image=self.logo_img, text="").pack(expand=True)
                try:
                    self.iconphoto(False, self.logo_img)
                except Exception:
                    pass
            except Exception:
                ctk.CTkLabel(icon_box, text="📦", font=("", 26)).pack(expand=True)
        else:
            ctk.CTkLabel(icon_box, text="📦", font=("", 26)).pack(expand=True)
        ctk.CTkLabel(self, text="Stock Manager",
                     font=ctk.CTkFont(size=22, weight="bold")).pack(pady=(14, 2))
        ctk.CTkLabel(self, text="DACT IT Materials",
                     font=ctk.CTkFont(size=13),
                     text_color=("gray50", "gray60")).pack()

        # Card
        card = ctk.CTkFrame(self, corner_radius=16, fg_color=("#ffffff","#1e1e2e"),
                            border_width=1, border_color=("#e0e0e0","#2e2e4e"))
        card.pack(padx=40, pady=32, fill="x")

        ctk.CTkLabel(card, text="Username", font=ctk.CTkFont(size=12),
                     text_color=("gray40","gray60"), anchor="w").pack(padx=24, pady=(24,3), fill="x")
        self.u_entry = ctk.CTkEntry(card, placeholder_text="Enter username",
                                    height=38, corner_radius=8)
        self.u_entry.pack(padx=24, fill="x")

        ctk.CTkLabel(card, text="Password", font=ctk.CTkFont(size=12),
                     text_color=("gray40","gray60"), anchor="w").pack(padx=24, pady=(14,3), fill="x")
        self.p_entry = ctk.CTkEntry(card, placeholder_text="Enter password",
                                    show="•", height=38, corner_radius=8)
        self.p_entry.pack(padx=24, fill="x")
        self.p_entry.bind("<Return>", lambda e: self._login())

        self.err_label = ctk.CTkLabel(card, text="", text_color="#e53935",
                                       font=ctk.CTkFont(size=12))
        self.err_label.pack(pady=(6,0))

        ctk.CTkButton(card, text="Sign in", height=40, corner_radius=8,
                      font=ctk.CTkFont(size=13, weight="bold"),
                      command=self._login).pack(padx=24, pady=(4, 24), fill="x")

        ctk.CTkLabel(self, text="© DACT IT Department",
                     font=ctk.CTkFont(size=11),
                     text_color=("gray60","gray50")).pack(side="bottom", pady=16)

    def _close(self):
        """Withdraw then quit so pending CTk 'after' callbacks don't fire on a dead window."""
        self.withdraw()
        self.quit()

    def _login(self):
        username = self.u_entry.get().strip()
        password = self.p_entry.get()
        # Bootstrap: no users yet
        cnt = query_db("SELECT COUNT(*) FROM users", fetch=True)[0][0]
        if cnt == 0:
            self._create_first_admin(username, password)
            return
        row = query_db("SELECT id,username,password_hash,salt,role FROM users WHERE username=?",
                       (username,), fetch=True)
        if not row:
            self.err_label.configure(text="User not found"); return
        uid, uname, pwd_hash, salt, role = row[0]
        if _verify_password(password, salt, pwd_hash):
            self.result = {"id": uid, "username": uname, "role": role}
            self._close()
        else:
            self.err_label.configure(text="Incorrect password")

    def _create_first_admin(self, username, password):
        if not username or not password:
            self.err_label.configure(text="Enter username and password to create admin")
            return
        pwd_hash, salt = _hash_password(password)
        created_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        query_db("INSERT INTO users (username,password_hash,salt,role,created_at) VALUES (?,?,?,?,?)",
                 (username, pwd_hash, salt, "admin", created_at))
        messagebox.showinfo("Admin created",
                            f"Admin account '{username}' created. Signing you in.")
        self.result = {"id": query_db("SELECT last_insert_rowid()", fetch=True)[0][0],
                       "username": username, "role": "admin"}
        self._close()

# ─── Sidebar icon button ───────────────────────────────────────────────────────
class SidebarBtn(ctk.CTkButton):
    def __init__(self, parent, icon, tooltip, command=None, **kw):
        super().__init__(parent, text=icon, width=40, height=40,
                         corner_radius=10, fg_color="transparent",
                         hover_color=("#e8e8e8","#2a2a3e"),
                         font=ctk.CTkFont(size=18),
                         command=command, **kw)
        Tooltip(self, tooltip)

# ─── KPI card ─────────────────────────────────────────────────────────────────
class KpiCard(ctk.CTkFrame):
    def __init__(self, parent, label, value="—", delta="", warn=False):
        super().__init__(parent, corner_radius=10,
                         fg_color=("#ffffff","#1e1e2e"),
                         border_width=1, border_color=("#e0e0e0","#2e2e4e"))
        self._warn = warn
        self.lbl = ctk.CTkLabel(self, text=label, font=ctk.CTkFont(size=11),
                                 text_color=("gray45","gray55"), anchor="w")
        self.lbl.pack(anchor="w", padx=14, pady=(12,0))
        val_color = ("#E65100","#FF8A65") if warn else ("black","white")
        self.val = ctk.CTkLabel(self, text=value, font=ctk.CTkFont(size=24, weight="bold"),
                                 text_color=val_color, anchor="w")
        self.val.pack(anchor="w", padx=14, pady=(2,0))
        delta_color = ("#E65100","#FF8A65") if warn else ("#2E7D32","#66BB6A")
        self.dlt = ctk.CTkLabel(self, text=delta, font=ctk.CTkFont(size=11),
                                 text_color=delta_color, anchor="w")
        self.dlt.pack(anchor="w", padx=14, pady=(2,12))

    def update(self, value, delta=""):
        self.val.configure(text=str(value))
        self.dlt.configure(text=delta)

# ─── Edit / Add Drawer ────────────────────────────────────────────────────────
class ItemDrawer(ctk.CTkFrame):
    """Right-side slide-in panel for add/edit."""
    def __init__(self, parent, app):
        super().__init__(parent, width=240, corner_radius=0,
                         fg_color=("#fafafa","#181825"),
                         border_width=1, border_color=("#e0e0e0","#2e2e4e"))
        self.app = app
        self.editing_id = None
        self._build()

    def _build(self):
        # Header
        hdr = ctk.CTkFrame(self, fg_color="transparent", height=48)
        hdr.pack(fill="x", padx=12, pady=(8,0))
        hdr.pack_propagate(False)
        self.title_lbl = ctk.CTkLabel(hdr, text="Add Item",
                                       font=ctk.CTkFont(size=14, weight="bold"))
        self.title_lbl.pack(side="left", pady=4)
        ctk.CTkButton(hdr, text="✕", width=28, height=28, corner_radius=8,
                      fg_color="transparent", hover_color=("#e0e0e0","#2a2a3e"),
                      command=self.hide).pack(side="right")

        sep = ctk.CTkFrame(self, height=1, fg_color=("#e0e0e0","#2e2e4e"))
        sep.pack(fill="x")

        scroll = ctk.CTkScrollableFrame(self, fg_color="transparent")
        scroll.pack(fill="both", expand=True, padx=4, pady=4)

        def field(parent, label):
            ctk.CTkLabel(parent, text=label, font=ctk.CTkFont(size=11),
                         text_color=("gray45","gray55"), anchor="w").pack(fill="x", pady=(8,2))

        # Category
        field(scroll, "CATEGORY")
        cat_row = ctk.CTkFrame(scroll, fg_color="transparent")
        cat_row.pack(fill="x")
        self.cat_var = tk.StringVar()
        self.cat_cb = ttk.Combobox(cat_row, textvariable=self.cat_var, state="readonly", width=22)
        self.cat_cb.pack(side="left", fill="x", expand=True)
        ctk.CTkButton(cat_row, text="+", width=28, height=26, corner_radius=6,
                      command=self.app.add_category_prompt).pack(side="left", padx=(4,0))

        # Department
        field(scroll, "DEPARTMENT")
        dep_row = ctk.CTkFrame(scroll, fg_color="transparent")
        dep_row.pack(fill="x")
        self.dep_var = tk.StringVar()
        self.dep_cb = ttk.Combobox(dep_row, textvariable=self.dep_var, state="readonly", width=22)
        self.dep_cb.pack(side="left", fill="x", expand=True)
        ctk.CTkButton(dep_row, text="+", width=28, height=26, corner_radius=6,
                      command=self.app.add_department_prompt).pack(side="left", padx=(4,0))

        # Quantity
        field(scroll, "QUANTITY")
        self.qty_var = tk.IntVar(value=1)
        ctk.CTkEntry(scroll, textvariable=self.qty_var).pack(fill="x")

        # Location
        field(scroll, "LOCATION")
        loc_row = ctk.CTkFrame(scroll, fg_color="transparent")
        loc_row.pack(fill="x")
        self.loc_var = tk.StringVar()
        self.loc_cb = ttk.Combobox(loc_row, textvariable=self.loc_var, state="readonly", width=22)
        self.loc_cb.pack(side="left", fill="x", expand=True)
        ctk.CTkButton(loc_row, text="+", width=28, height=26, corner_radius=6,
                      command=self.app.add_location_prompt).pack(side="left", padx=(4,0))

        # ── Stock action buttons (edit mode only, hidden in add mode) ──
        self.action_frame = ctk.CTkFrame(scroll, fg_color="transparent")
        self.action_frame.pack(fill="x", pady=(12, 0))

        ctk.CTkLabel(self.action_frame, text="STOCK ACTIONS",
                     font=ctk.CTkFont(size=11, weight="bold"),
                     text_color=("gray45", "gray55"), anchor="w").pack(fill="x", pady=(0, 8))

        # ── Add Stock row ──────────────────────────────────────────────
        add_row = ctk.CTkFrame(self.action_frame, corner_radius=10,
                               fg_color=("#F1FBF4", "#0d2e18"),
                               border_width=1, border_color=("#A8D5B5", "#1a4d2e"))
        add_row.pack(fill="x", pady=(0, 8))

        add_top = ctk.CTkFrame(add_row, fg_color="transparent")
        add_top.pack(fill="x", padx=12, pady=(10, 6))

        ctk.CTkLabel(add_top, text="+ Add Stock",
                     font=ctk.CTkFont(size=13, weight="bold"),
                     text_color=("#1B5E20", "#A5D6A7")).pack(side="left")
        ctk.CTkLabel(add_top, text="Increase quantity",
                     font=ctk.CTkFont(size=11),
                     text_color=("#4CAF50", "#81C784")).pack(side="left", padx=(8, 0))

        add_bottom = ctk.CTkFrame(add_row, fg_color="transparent")
        add_bottom.pack(fill="x", padx=12, pady=(0, 10))

        self.add_qty_var = tk.StringVar(value="1")
        ctk.CTkEntry(add_bottom, textvariable=self.add_qty_var,
                     width=64, height=32, corner_radius=6,
                     placeholder_text="Qty").pack(side="left")
        ctk.CTkButton(add_bottom, text="Confirm Add",
                      height=32, corner_radius=6,
                      fg_color=("#2E7D32", "#2E7D32"),
                      hover_color=("#1B5E20", "#388E3C"),
                      text_color=("#ffffff", "#ffffff"),
                      font=ctk.CTkFont(size=12, weight="bold"),
                      command=self._prompt_add).pack(side="left", padx=(8, 0))

        # ── Retrieve row ───────────────────────────────────────────────
        ret_row = ctk.CTkFrame(self.action_frame, corner_radius=10,
                               fg_color=("#FFF8EC", "#2e1f00"),
                               border_width=1, border_color=("#F5CC80", "#5c3d00"))
        ret_row.pack(fill="x", pady=(0, 4))

        ret_top = ctk.CTkFrame(ret_row, fg_color="transparent")
        ret_top.pack(fill="x", padx=12, pady=(10, 6))

        ctk.CTkLabel(ret_top, text="↑ Retrieve",
                     font=ctk.CTkFont(size=13, weight="bold"),
                     text_color=("#BF360C", "#FFCC80")).pack(side="left")
        ctk.CTkLabel(ret_top, text="Decrease quantity",
                     font=ctk.CTkFont(size=11),
                     text_color=("#FF6D00", "#FFA726")).pack(side="left", padx=(8, 0))

        ret_bottom = ctk.CTkFrame(ret_row, fg_color="transparent")
        ret_bottom.pack(fill="x", padx=12, pady=(0, 10))

        self.ret_qty_var = tk.StringVar(value="1")
        ctk.CTkEntry(ret_bottom, textvariable=self.ret_qty_var,
                     width=64, height=32, corner_radius=6,
                     placeholder_text="Qty").pack(side="left")
        ctk.CTkButton(ret_bottom, text="Confirm Take",
                      height=32, corner_radius=6,
                      fg_color=("#E65100", "#E65100"),
                      hover_color=("#BF360C", "#BF360C"),
                      text_color=("#ffffff", "#ffffff"),
                      font=ctk.CTkFont(size=12, weight="bold"),
                      command=self._prompt_retrieve).pack(side="left", padx=(8, 0))

        # ── Footer: save / delete ──────────────────────────────────────
        sep2 = ctk.CTkFrame(self, height=1, fg_color=("#e0e0e0", "#2e2e4e"))
        sep2.pack(fill="x", pady=(4, 0))
        btn_frame = ctk.CTkFrame(self, fg_color="transparent")
        btn_frame.pack(fill="x", padx=12, pady=12)

        self.save_btn = ctk.CTkButton(btn_frame, text="Add Item", height=36,
                                      corner_radius=8, command=self._do_save)
        self.save_btn.pack(side="left", fill="x", expand=True, padx=(0, 6))
        self.del_btn = ctk.CTkButton(btn_frame, text="🗑", width=36, height=36,
                                     corner_radius=8,
                                     fg_color=("#FCE4EC", "#4a1528"),
                                     hover_color=("#F8BBD9", "#6b2040"),
                                     text_color=("#C62828", "#F48FB1"),
                                     command=self.app.delete_item)
        self.del_btn.pack(side="left")

    # ── Comment dialog helper ─────────────────────────────────────────
    def _ask_comment(self, title="Comment"):
        """Pop a small inline dialog asking for an optional comment. Returns str or None if cancelled."""
        dlg = ctk.CTkToplevel(self)
        dlg.title(title)
        dlg.geometry("320x160")
        dlg.resizable(False, False)
        dlg.grab_set()
        dlg.transient(self)

        ctk.CTkLabel(dlg, text="Optional comment:",
                     font=ctk.CTkFont(size=12)).pack(padx=20, pady=(18, 4), anchor="w")
        comment_var = tk.StringVar()
        entry = ctk.CTkEntry(dlg, textvariable=comment_var,
                             placeholder_text="e.g. Received from supplier",
                             height=34, width=280)
        entry.pack(padx=20)
        entry.focus()

        result = {"value": None, "ok": False}

        def confirm(e=None):
            result["value"] = comment_var.get().strip()
            result["ok"] = True
            dlg.destroy()

        def cancel():
            dlg.destroy()

        entry.bind("<Return>", confirm)
        btn_row = ctk.CTkFrame(dlg, fg_color="transparent")
        btn_row.pack(fill="x", padx=20, pady=12)
        ctk.CTkButton(btn_row, text="Confirm", height=30, command=confirm).pack(side="left", fill="x", expand=True, padx=(0, 6))
        ctk.CTkButton(btn_row, text="Cancel", height=30,
                      fg_color="transparent", border_width=1,
                      command=cancel).pack(side="left", fill="x", expand=True)

        dlg.wait_window()
        return result if result["ok"] else None

    def _prompt_add(self):
        try:
            amt = int(self.add_qty_var.get())
            assert amt > 0
        except Exception:
            messagebox.showwarning("Amount", "Enter a positive integer", parent=self)
            return
        if not self.editing_id:
            return
        result = self._ask_comment("Add Stock — Comment")
        if result is None:
            return  # user cancelled
        comment = result["value"]
        query_db("UPDATE items SET quantity=quantity+? WHERE id=?", (amt, self.editing_id))
        user_id = self.app.current_user["id"] if self.app.current_user else None
        add_log("ADD_STOCK", self.editing_id, {"amount": amt, "comment": comment}, user_id)
        self.hide()
        self.app.load_items()
        self.app.status_var.set(f"Added {amt} units to stock.")

    def _prompt_retrieve(self):
        try:
            amt = int(self.ret_qty_var.get())
            assert amt > 0
        except Exception:
            messagebox.showwarning("Amount", "Enter a positive integer", parent=self)
            return
        if not self.editing_id:
            return
        row = query_db("SELECT quantity FROM items WHERE id=?", (self.editing_id,), fetch=True)
        if not row:
            return
        current = row[0][0]
        if amt > current:
            messagebox.showwarning("Insufficient stock",
                                   f"Cannot retrieve {amt}; only {current} in stock.", parent=self)
            return
        result = self._ask_comment("Retrieve — Comment")
        if result is None:
            return  # user cancelled
        comment = result["value"]
        query_db("UPDATE items SET quantity=quantity-? WHERE id=?", (amt, self.editing_id))
        user_id = self.app.current_user["id"] if self.app.current_user else None
        add_log("RETRIEVE", self.editing_id, {"amount": amt, "comment": comment}, user_id)
        self.hide()
        self.app.load_items()
        self.app.status_var.set(f"Retrieved {amt} units.")

    def _do_save(self):
        if self.editing_id is None:
            self.app.add_item()
        else:
            self.app.update_item()

    def show(self, editing_id=None):
        self.editing_id = editing_id
        if editing_id is None:
            self.title_lbl.configure(text="Add Item")
            self.action_frame.pack_forget()
            self.del_btn.pack_forget()
            self.save_btn.configure(text="Add Item")
        else:
            self.title_lbl.configure(text="Edit Item")
            self.action_frame.pack(fill="x", pady=(12, 0))
            self.del_btn.pack(side="left")
            self.save_btn.configure(text="Update Details")
        self.grid(row=0, column=1, sticky="ns", padx=(10, 0))

    def hide(self):
        self.grid_remove()
        self.editing_id = None
        try:
            self.app.tree.selection_remove(self.app.tree.selection())
        except Exception:
            pass

    def populate(self, category, department, qty, location):
        self.cat_var.set(category or "")
        self.dep_var.set(department or "")
        self.qty_var.set(qty or 1)
        self.loc_var.set(location or "")
        self.add_qty_var.set("1")
        self.ret_qty_var.set("1")

    def refresh_combos(self, cats, deps, locs):
        self.cat_cb["values"] = cats
        self.dep_cb["values"] = deps
        self.loc_cb["values"] = locs

# ─── Main Application ─────────────────────────────────────────────────────────
class StockApp(ctk.CTk):
    def __init__(self, current_user):
        super().__init__()
        self.current_user = current_user
        self.title("DACT IT Materials Stock Manager")
        self.geometry("1180x680")
        self.minsize(900, 560)
        icon_path = resource_path(os.path.join("assets", "logo.png"))
        if os.path.exists(icon_path):
            try: self.iconphoto(False, PhotoImage(file=icon_path))
            except: pass
        self._build()
        self.refresh_lookups()
        self.load_items()
        self.load_logs()
        self._update_kpis()

    # ── Layout ──────────────────────────────────────────────────────────────
    def _build(self):
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # ── Sidebar ──────────────────────────────────────────────────────
        sidebar = ctk.CTkFrame(self, width=58, corner_radius=0,
                               fg_color=("#ffffff","#12121f"),
                               border_width=1, border_color=("#e0e0e0","#1e1e2e"))
        sidebar.grid(row=0, column=0, sticky="ns")
        sidebar.grid_propagate(False)

        logo = ctk.CTkFrame(sidebar, width=38, height=38, corner_radius=10,
                            fg_color="#1565C0")
        logo.pack(pady=(14,18))
        logo.pack_propagate(False)
        ctk.CTkLabel(logo, text="📦", font=ctk.CTkFont(size=18)).pack(expand=True)

        self.nav_btns = {}
        for icon, tip, cmd in [
            ("🗃",  "Inventory",  lambda: self._show_view("inventory")),
            ("📊",  "Reports",    lambda: self._show_view("reports")),
            ("📋",  "Audit Log",  lambda: self._show_view("audit")),
        ]:
            b = SidebarBtn(sidebar, icon, tip, command=cmd)
            b.pack(pady=2)
            self.nav_btns[tip] = b
        self._set_active_nav("Inventory")

        # spacer
        ctk.CTkFrame(sidebar, fg_color="transparent").pack(expand=True)

        # User info at bottom
        role = self.current_user.get("role","user")
        ctk.CTkLabel(sidebar, text=self.current_user["username"][:2].upper(),
                     width=34, height=34, corner_radius=17,
                     fg_color=("#BBDEFB","#1565C0"),
                     font=ctk.CTkFont(size=11, weight="bold"),
                     text_color=("#1565C0","#BBDEFB")).pack(pady=(0,4))
        if role == "admin":
            b = SidebarBtn(sidebar, "👤", "User Management", command=self.open_user_mgmt)
            b.pack(pady=2)

        # ── Main content area ────────────────────────────────────────────
        content = ctk.CTkFrame(self, corner_radius=0, fg_color=("#f4f4f0","#12121f"))
        content.grid(row=0, column=1, sticky="nsew")
        content.grid_columnconfigure(0, weight=1)
        content.grid_rowconfigure(2, weight=1)
        self._content = content

        # Top bar
        topbar = ctk.CTkFrame(content, height=52, corner_radius=0,
                              fg_color=("#ffffff","#1a1a2e"),
                              border_width=1, border_color=("#e0e0e0","#2e2e4e"))
        topbar.grid(row=0, column=0, sticky="ew")
        topbar.grid_propagate(False)
        topbar.grid_columnconfigure(1, weight=1)

        self._page_title = tk.StringVar(value="Inventory")
        ctk.CTkLabel(topbar, textvariable=self._page_title,
                     font=ctk.CTkFont(size=15, weight="bold")).grid(row=0, column=0, padx=16)

        # Search
        search_frame = ctk.CTkFrame(topbar, fg_color=("#f0f0ec","#1e1e2e"),
                                     corner_radius=8, border_width=1,
                                     border_color=("#d0d0cc","#2a2a3e"))
        search_frame.grid(row=0, column=1, padx=12, pady=10, sticky="ew")
        ctk.CTkLabel(search_frame, text="🔍", font=ctk.CTkFont(size=13)).pack(side="left", padx=(8,0))
        self.search_var = tk.StringVar()
        search_entry = ctk.CTkEntry(search_frame, textvariable=self.search_var,
                                     placeholder_text="Search by category, department, location…",
                                     border_width=0, fg_color="transparent", height=32)
        search_entry.pack(side="left", fill="x", expand=True, padx=4)
        search_entry.bind("<Return>", lambda e: self.load_items())
        search_entry.bind("<KeyRelease>", lambda e: self.load_items())

        # Quick filters
        filter_row = ctk.CTkFrame(topbar, fg_color="transparent")
        filter_row.grid(row=0, column=2, padx=8)
        self.filter_var = tk.StringVar(value="All")
        for lbl in ["All", "Low Stock", "Out of Stock"]:
            b = ctk.CTkButton(filter_row, text=lbl, height=28, corner_radius=14,
                              font=ctk.CTkFont(size=11),
                              command=lambda l=lbl: self._quick_filter(l))
            b.pack(side="left", padx=2)

        # Add button
        self.add_btn = ctk.CTkButton(topbar, text="+ Add Item", height=32,
                                      corner_radius=8, font=ctk.CTkFont(size=12, weight="bold"),
                                      command=self._open_add_drawer)
        self.add_btn.grid(row=0, column=3, padx=(0,14))

        # KPI row
        kpi_row = ctk.CTkFrame(content, fg_color="transparent")
        kpi_row.grid(row=1, column=0, sticky="ew", padx=16, pady=(14,0))
        for i in range(4): kpi_row.columnconfigure(i, weight=1)

        self.kpi_total   = KpiCard(kpi_row, "Total Items")
        self.kpi_low     = KpiCard(kpi_row, "Low Stock", warn=True)
        self.kpi_cats    = KpiCard(kpi_row, "Categories")
        self.kpi_retriev = KpiCard(kpi_row, "Retrievals (month)")
        for i, card in enumerate([self.kpi_total, self.kpi_low, self.kpi_cats, self.kpi_retriev]):
            card.grid(row=0, column=i, padx=(0 if i==0 else 10, 0), sticky="ew")

        # Main body: table (col 0, expands) + drawer (col 1, fixed width)
        self._inventory_frame = ctk.CTkFrame(content, fg_color="transparent")
        self._inventory_frame.grid(row=2, column=0, sticky="nsew", padx=16, pady=14)
        body = self._inventory_frame
        body.grid_columnconfigure(0, weight=1)
        body.grid_columnconfigure(1, weight=0)
        body.grid_rowconfigure(0, weight=1)

        # Table card
        table_card = ctk.CTkFrame(body, corner_radius=12,
                                   fg_color=("#ffffff","#1a1a2e"),
                                   border_width=1, border_color=("#e0e0e0","#2e2e4e"))
        table_card.grid(row=0, column=0, sticky="nsew")
        table_card.grid_columnconfigure(0, weight=1)
        table_card.grid_rowconfigure(1, weight=1)

        # Column headers
        hdr = ctk.CTkFrame(table_card, height=36, fg_color="transparent",
                           border_width=1, border_color=("#e8e8e4","#2e2e4e"))
        hdr.grid(row=0, column=0, sticky="ew", padx=1, pady=(1,0))
        hdr.grid_propagate(False)
        for col, w, anchor in [("  #", 40, "w"), ("Category", 180, "w"),
                                ("Department", 140, "w"), ("Qty", 70, "center"),
                                ("Location", 120, "w"), ("Added", 100, "w")]:
            ctk.CTkLabel(hdr, text=col, font=ctk.CTkFont(size=11, weight="bold"),
                         text_color=("gray45","gray55"), width=w, anchor=anchor).pack(side="left", padx=4)

        # Treeview with style
        style = ttk.Style()
        style.configure("Modern.Treeview",
                         rowheight=42, font=("Helvetica", 12),
                         background="#ffffff", fieldbackground="#ffffff",
                         foreground="#1a1a2e", borderwidth=0)
        style.configure("Modern.Treeview.Heading",
                         font=("Helvetica", 11, "bold"),
                         background="#f4f4f0", foreground="#666660", relief="flat")
        style.map("Modern.Treeview",
                  background=[("selected", "#E3F2FD")],
                  foreground=[("selected", "#1565C0")])

        tree_frame = ctk.CTkFrame(table_card, fg_color="transparent")
        tree_frame.grid(row=1, column=0, sticky="nsew", padx=8, pady=(0,8))
        tree_frame.grid_columnconfigure(0, weight=1)
        tree_frame.grid_rowconfigure(0, weight=1)

        cols = ("id", "category", "department", "quantity", "location", "added_at")
        self.tree = ttk.Treeview(tree_frame, columns=cols, show="headings",
                                  selectmode="browse", style="Modern.Treeview")
        col_widths = {"id":40, "category":180, "department":140, "quantity":70,
                      "location":130, "added_at":110}
        for col in cols:
            self.tree.heading(col, text=col.replace("_"," ").title(),
                              command=lambda c=col: self._sort_col(c))
            self.tree.column(col, width=col_widths[col],
                             anchor="center" if col in ("id","quantity") else "w")

        vsb = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscroll=vsb.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")

        # Row color tags
        self.tree.tag_configure("ok",   background="#ffffff")
        self.tree.tag_configure("low",  background="#FFFDE7")
        self.tree.tag_configure("zero", background="#FFEBEE")
        self.tree.tag_configure("odd",  background="#fafaf7")
        self.tree.bind("<<TreeviewSelect>>", self.on_select)
        self.tree.bind("<Double-Button-1>", lambda e: self._open_edit_drawer())

        # Drawer — uses grid col 1 in body, starts hidden via grid_remove()
        self.drawer = ItemDrawer(body, self)

        # ── Embedded Reports frame ────────────────────────────────────
        self._reports_frame = ctk.CTkFrame(content, fg_color="transparent")
        self._reports_frame.grid(row=2, column=0, sticky="nsew", padx=16, pady=14)
        self._reports_frame.grid_columnconfigure(0, weight=1)
        self._reports_frame.grid_rowconfigure(0, weight=1)
        self._build_reports_view(self._reports_frame)

        # ── Embedded Audit Log frame ──────────────────────────────────
        self._audit_frame = ctk.CTkFrame(content, fg_color="transparent")
        self._audit_frame.grid(row=2, column=0, sticky="nsew", padx=16, pady=14)
        self._audit_frame.grid_columnconfigure(0, weight=1)
        self._audit_frame.grid_rowconfigure(0, weight=1)
        self._build_audit_view(self._audit_frame)

        # Show inventory by default
        self._show_view("inventory")

        # Status bar
        status_bar = ctk.CTkFrame(content, height=28, corner_radius=0,
                                   fg_color=("#f0f0ec","#12121f"),
                                   border_width=1, border_color=("#e0e0e0","#1e1e2e"))
        status_bar.grid(row=3, column=0, sticky="ew")
        status_bar.grid_propagate(False)
        self.status_var = tk.StringVar(value="Ready")
        ctk.CTkLabel(status_bar, textvariable=self.status_var,
                     font=ctk.CTkFont(size=11),
                     text_color=("gray50","gray60")).pack(side="left", padx=12)
        role_badge = ctk.CTkLabel(status_bar,
                                   text=f"  {self.current_user['username']}  ·  {role}  ",
                                   font=ctk.CTkFont(size=11),
                                   fg_color=("#E8F5E9","#1B5E20") if role=="admin" else ("#E3F2FD","#0D47A1"),
                                   text_color=("#2E7D32","#A5D6A7") if role=="admin" else ("#1565C0","#90CAF9"),
                                   corner_radius=6)
        role_badge.pack(side="right", padx=12, pady=4)

        # Export button in status bar
        ctk.CTkButton(status_bar, text="Export CSV", height=20, width=90,
                      corner_radius=6, font=ctk.CTkFont(size=10),
                      fg_color="transparent", hover_color=("#e0e0e0","#2a2a3e"),
                      border_width=1, border_color=("#cccccc","#3a3a5e"),
                      command=self.export_csv).pack(side="right", padx=4, pady=4)

        # Advanced filters (collapsible row)
        adv = ctk.CTkFrame(content, fg_color="transparent")
        adv.grid(row=4, column=0, sticky="ew", padx=16, pady=(0,4))

        ctk.CTkLabel(adv, text="Filter:", font=ctk.CTkFont(size=11),
                     text_color=("gray50","gray60")).pack(side="left")
        for lbl, var_name, width in [
            ("Category", "category_var", 130),
            ("Department", "department_var", 130),
            ("Location", "location_var", 130),
        ]:
            ctk.CTkLabel(adv, text=lbl, font=ctk.CTkFont(size=11),
                         text_color=("gray50","gray60")).pack(side="left", padx=(10,2))
            var = tk.StringVar()
            setattr(self, var_name, var)
            cb = ttk.Combobox(adv, textvariable=var, state="readonly", width=width//8)
            cb.pack(side="left")
            cb.bind("<<ComboboxSelected>>", lambda e: self.load_items())

        self.date_from = tk.StringVar()
        self.date_to   = tk.StringVar()
        ctk.CTkLabel(adv, text="From", font=ctk.CTkFont(size=11),
                     text_color=("gray50","gray60")).pack(side="left", padx=(10,2))
        ctk.CTkEntry(adv, textvariable=self.date_from, width=96,
                     placeholder_text="YYYY-MM-DD").pack(side="left")
        ctk.CTkLabel(adv, text="To", font=ctk.CTkFont(size=11),
                     text_color=("gray50","gray60")).pack(side="left", padx=(6,2))
        ctk.CTkEntry(adv, textvariable=self.date_to, width=96,
                     placeholder_text="YYYY-MM-DD").pack(side="left")
        ctk.CTkButton(adv, text="Apply", height=26, width=60, corner_radius=6,
                      font=ctk.CTkFont(size=11), command=self.load_items).pack(side="left", padx=6)
        ctk.CTkButton(adv, text="Clear", height=26, width=60, corner_radius=6,
                      font=ctk.CTkFont(size=11),
                      fg_color="transparent", hover_color=("#e0e0e0","#2a2a3e"),
                      border_width=1, border_color=("#cccccc","#3a3a5e"),
                      command=self.clear_filters).pack(side="left")

        # Stash references for refresh_lookups
        self._cat_cb  = adv.winfo_children()[3]   # rough index — reassign properly
        # Re-grab by iterating
        self._filter_combos = {}
        for child in adv.winfo_children():
            if isinstance(child, ttk.Combobox):
                pass  # handled in refresh_lookups via textvariable names

    # ── Navigation helpers ────────────────────────────────────────────────
    def _set_active_nav(self, name):
        for k, b in self.nav_btns.items():
            b.configure(fg_color=("#E3F2FD","#1565C0") if k==name else "transparent")

    def _show_view(self, view):
        frames = {
            "inventory": (self._inventory_frame, "Inventory",  "Inventory"),
            "reports":   (self._reports_frame,   "Reports",    "Reports"),
            "audit":     (self._audit_frame,      "Audit Log",  "Audit Log"),
        }
        for key, (frame, _, __) in frames.items():
            if key == view:
                frame.tkraise()
            else:
                pass  # tkraise handles z-order; all frames sit in same grid cell

        _, page_title, nav_name = frames.get(view, (None, "Inventory", "Inventory"))
        self._page_title.set(page_title)
        self._set_active_nav(nav_name)

        # refresh audit data when switching to it
        if view == "audit" and hasattr(self, "_audit_refresh_fn"):
            self._audit_refresh_fn()

    def _build_reports_view(self, parent):
        notebook = ttk.Notebook(parent)
        notebook.grid(row=0, column=0, sticky="nsew")

        # Tab 1: Donut — by category
        tab1 = ttk.Frame(notebook)
        notebook.add(tab1, text="  Stock by Category  ")
        fig1 = Figure(figsize=(6, 5), dpi=100, facecolor="none")
        ax1  = fig1.add_subplot(111)
        rows = query_db("SELECT category,SUM(quantity) FROM items GROUP BY category ORDER BY 2 DESC", fetch=True)
        if rows:
            cats = [r[0] for r in rows if r[0]]
            qtys = [r[1] for r in rows if r[0]]
            if cats:
                colors = plt.cm.Set3(range(len(cats)))
                wedges, _, autotexts = ax1.pie(qtys, labels=cats, autopct="%1.1f%%",
                                                colors=colors, startangle=90, pctdistance=0.82)
                ax1.add_artist(plt.Circle((0, 0), .68, fc="white"))
                ax1.set_title("Stock Distribution by Category", pad=16, fontsize=13)
                for at in autotexts: at.set_fontsize(8)
        FigureCanvasTkAgg(fig1, master=tab1).get_tk_widget().pack(fill="both", expand=True)

        # Tab 2: Bar — by department
        tab2 = ttk.Frame(notebook)
        notebook.add(tab2, text="  Stock by Department  ")
        fig2 = Figure(figsize=(8, 5), dpi=100, facecolor="none")
        ax2  = fig2.add_subplot(111)
        rows = query_db("SELECT department,SUM(quantity) FROM items GROUP BY department ORDER BY 2 DESC", fetch=True)
        if rows:
            depts = [r[0] if r[0] else "Unassigned" for r in rows]
            qtys  = [r[1] for r in rows]
            colors = plt.cm.Set2(range(len(depts)))
            bars = ax2.bar(depts, qtys, color=colors, edgecolor="#cccccc", linewidth=0.8)
            ax2.set_ylabel("Quantity", fontsize=11)
            ax2.set_title("Stock Quantity by Department", fontsize=13)
            ax2.grid(axis="y", alpha=0.3)
            if len(depts) > 3: fig2.autofmt_xdate(rotation=35, ha="right")
            for bar in bars:
                h = bar.get_height()
                ax2.text(bar.get_x() + bar.get_width() / 2, h + 0.5, f"{int(h)}",
                         ha="center", va="bottom", fontsize=9)
        FigureCanvasTkAgg(fig2, master=tab2).get_tk_widget().pack(fill="both", expand=True)

        # Tab 3: Grouped bar — category × department
        tab3 = ttk.Frame(notebook)
        notebook.add(tab3, text="  Category × Department  ")
        fig3 = Figure(figsize=(10, 5), dpi=100, facecolor="none")
        ax3  = fig3.add_subplot(111)
        rows = query_db("""SELECT category,department,SUM(quantity)
                           FROM items GROUP BY category,department ORDER BY category,department""", fetch=True)
        if rows:
            cat_set = sorted(set(r[0] for r in rows if r[0]))
            dep_set = sorted(set(r[1] if r[1] else "Unassigned" for r in rows))
            if cat_set and dep_set:
                x = np.arange(len(cat_set))
                w = 0.8 / len(dep_set)
                colors = plt.cm.Pastel1(range(len(dep_set)))
                for idx, dept in enumerate(dep_set):
                    vals = [next((r[2] for r in rows if r[0] == cat and (r[1] if r[1] else "Unassigned") == dept), 0)
                            for cat in cat_set]
                    offset = (idx - len(dep_set) / 2) * w + w / 2
                    ax3.bar(x + offset, vals, w, label=dept, color=colors[idx])
                ax3.set_ylabel("Quantity", fontsize=11)
                ax3.set_title("Category vs Department", fontsize=13)
                ax3.set_xticks(x); ax3.set_xticklabels(cat_set, rotation=40, ha="right")
                ax3.legend(); ax3.grid(axis="y", alpha=0.3)
        FigureCanvasTkAgg(fig3, master=tab3).get_tk_widget().pack(fill="both", expand=True)

        # Tab 4: Low-stock alert table
        tab4 = ttk.Frame(notebook)
        notebook.add(tab4, text="  ⚠ Low Stock  ")
        cols = ("category", "department", "quantity", "location")
        tree = ttk.Treeview(tab4, columns=cols, show="headings")
        tree.tag_configure("zero", foreground="#C62828")
        tree.tag_configure("low",  foreground="#E65100")
        for c in cols:
            tree.heading(c, text=c.title())
            tree.column(c, width=160)
        rows = query_db(f"""SELECT category,department,quantity,location FROM items
                            WHERE quantity<={LOW_STOCK_THRESHOLD} ORDER BY quantity ASC""", fetch=True)
        for r in rows:
            tag = "zero" if r[2] == 0 else "low"
            tree.insert("", "end", values=r, tags=(tag,))
        tree.pack(fill="both", expand=True, padx=12, pady=12)

    def _build_audit_view(self, parent):
        parent.grid_rowconfigure(0, weight=1)
        parent.grid_columnconfigure(0, weight=1)

        # Toolbar
        toolbar = ctk.CTkFrame(parent, fg_color="transparent", height=40)
        toolbar.grid(row=0, column=0, sticky="ew", pady=(0, 8))
        toolbar.grid_propagate(False)
        ctk.CTkLabel(toolbar, text="Audit Log",
                     font=ctk.CTkFont(size=14, weight="bold")).pack(side="left")
        refresh_btn = ctk.CTkButton(toolbar, text="↻ Refresh", height=28, width=90,
                                     corner_radius=6, font=ctk.CTkFont(size=11),
                                     fg_color="transparent", border_width=1,
                                     command=lambda: self._audit_refresh_fn())
        refresh_btn.pack(side="right")

        # Table card
        card = ctk.CTkFrame(parent, corner_radius=12,
                            fg_color=("#ffffff", "#1a1a2e"),
                            border_width=1, border_color=("#e0e0e0", "#2e2e4e"))
        card.grid(row=1, column=0, sticky="nsew")
        card.grid_columnconfigure(0, weight=1)
        card.grid_rowconfigure(0, weight=1)
        parent.grid_rowconfigure(1, weight=1)

        style = ttk.Style()
        style.configure("Audit.Treeview", rowheight=36, font=("Helvetica", 11),
                        background="#ffffff", fieldbackground="#ffffff",
                        foreground="#1a1a2e", borderwidth=0)
        style.configure("Audit.Treeview.Heading",
                        font=("Helvetica", 11, "bold"),
                        background="#f4f4f0", foreground="#666660", relief="flat")

        cols = ("id", "action", "item_id", "username", "details", "timestamp")
        tree = ttk.Treeview(card, columns=cols, show="headings", style="Audit.Treeview")
        widths = {"id": 40, "action": 110, "item_id": 60, "username": 120, "details": 0, "timestamp": 150}
        for c in cols:
            tree.heading(c, text=c.title())
            tree.column(c, width=widths[c], anchor="w",
                        stretch=(c == "details"))

        vsb = ttk.Scrollbar(card, orient="vertical", command=tree.yview)
        hsb = ttk.Scrollbar(card, orient="horizontal", command=tree.xview)
        tree.configure(yscroll=vsb.set, xscroll=hsb.set)
        tree.grid(row=0, column=0, sticky="nsew", padx=(8, 0), pady=8)
        vsb.grid(row=0, column=1, sticky="ns", pady=8)
        hsb.grid(row=1, column=0, columnspan=2, sticky="ew", padx=8)

        def refresh():
            for i in tree.get_children(): tree.delete(i)
            rows = query_db("""SELECT l.id, l.action, l.item_id,
                                      COALESCE(u.username,'System'),
                                      l.details, l.timestamp
                               FROM logs l LEFT JOIN users u ON l.user_id=u.id
                               ORDER BY l.timestamp DESC LIMIT 500""", fetch=True)
            for r in rows:
                tree.insert("", "end", values=r)

        self._audit_refresh_fn = refresh

    def _quick_filter(self, label):
        self.filter_var.set(label)
        self.load_items()

    # ── Drawer helpers ────────────────────────────────────────────────────
    def _open_add_drawer(self):
        self.drawer.hide()
        self.drawer.populate("", "", 1, "")
        self.drawer.show(editing_id=None)

    def _open_edit_drawer(self):
        sel = self.tree.selection()
        if not sel: return
        vals = self.tree.item(sel[0])["values"]
        self.drawer.populate(vals[1], vals[2], vals[3], vals[4])
        self.drawer.show(editing_id=vals[0])

    # ── Sorting ───────────────────────────────────────────────────────────
    _sort_reverse = {}
    def _sort_col(self, col):
        rev = self._sort_reverse.get(col, False)
        data = [(self.tree.set(k, col), k) for k in self.tree.get_children("")]
        try:    data.sort(key=lambda x: int(x[0]), reverse=rev)
        except: data.sort(key=lambda x: x[0].lower(), reverse=rev)
        for i, (_, k) in enumerate(data):
            self.tree.move(k, "", i)
        self._sort_reverse[col] = not rev

    # ── KPIs ──────────────────────────────────────────────────────────────
    def _update_kpis(self):
        total = query_db("SELECT COALESCE(SUM(quantity),0) FROM items", fetch=True)[0][0]
        low   = query_db(f"SELECT COUNT(*) FROM items WHERE quantity>0 AND quantity<={LOW_STOCK_THRESHOLD}", fetch=True)[0][0]
        zero  = query_db("SELECT COUNT(*) FROM items WHERE quantity=0", fetch=True)[0][0]
        cats  = query_db("SELECT COUNT(DISTINCT category) FROM items WHERE category IS NOT NULL", fetch=True)[0][0]
        month = datetime.now().strftime("%Y-%m")
        retrievals = query_db("SELECT COUNT(*) FROM logs WHERE action='RETRIEVE' AND timestamp LIKE ?",
                              (f"{month}%",), fetch=True)[0][0]
        self.kpi_total.update(f"{total:,}", "items in stock")
        self.kpi_low.update(f"{low}", f"{zero} out of stock")
        self.kpi_cats.update(cats, "unique categories")
        self.kpi_retriev.update(retrievals, "this month")

    # ── Lookups ───────────────────────────────────────────────────────────
    def refresh_lookups(self):
        def get(tbl, fallback_col):
            rows = [r[0] for r in query_db(f"SELECT name FROM {tbl} ORDER BY name", fetch=True) or []]
            if not rows:
                rows = [r[0] for r in query_db(
                    f"SELECT DISTINCT {fallback_col} FROM items WHERE {fallback_col} IS NOT NULL AND {fallback_col}!='' ORDER BY {fallback_col}",
                    fetch=True) or []]
            return rows
        cats = get("categories","category")
        locs = get("locations","location")
        deps = get("departments","department")

        # Filter dropdowns in adv bar
        for widget in self.winfo_children():
            self._update_comboboxes_recursive(widget, cats, deps, locs)

        # Drawer combos
        self.drawer.refresh_combos(cats, deps, locs)

    def _update_comboboxes_recursive(self, widget, cats, deps, locs):
        try:
            if isinstance(widget, ttk.Combobox):
                var_name = str(widget.cget("textvariable")) if hasattr(widget,"cget") else ""
                # Match by associated variable
                for attr, vals in [("category_var", [""] + cats),
                                    ("department_var", [""] + deps),
                                    ("location_var", [""] + locs)]:
                    if hasattr(self, attr) and widget["textvariable"] == str(getattr(self, attr)):
                        widget["values"] = vals
        except: pass
        for child in widget.winfo_children():
            self._update_comboboxes_recursive(child, cats, deps, locs)

    def add_lookup_value(self, table, value):
        if value: query_db(f"INSERT OR IGNORE INTO {table} (name) VALUES (?)", (value,))

    def add_category_prompt(self):
        name = simpledialog.askstring("Add Category", "Category name:", parent=self)
        if name and name.strip():
            self.add_lookup_value("categories", name.strip())
            self.refresh_lookups()
            self.drawer.cat_var.set(name.strip())

    def add_location_prompt(self):
        name = simpledialog.askstring("Add Location", "Location name:", parent=self)
        if name and name.strip():
            self.add_lookup_value("locations", name.strip())
            self.refresh_lookups()
            self.drawer.loc_var.set(name.strip())

    def add_department_prompt(self):
        name = simpledialog.askstring("Add Department", "Department name:", parent=self)
        if name and name.strip():
            self.add_lookup_value("departments", name.strip())
            self.refresh_lookups()
            self.drawer.dep_var.set(name.strip())

    # ── Load items ────────────────────────────────────────────────────────
    def load_items(self):
        q = "SELECT id,category,department,quantity,location,added_at FROM items WHERE 1=1"
        params = []
        s = self.search_var.get().strip()
        if s:
            like = f"%{s}%"
            q += " AND (category LIKE ? OR location LIKE ? OR department LIKE ?)"
            params += [like, like, like]
        for attr, col in [("category_var","category"),
                           ("department_var","department"),
                           ("location_var","location")]:
            if hasattr(self, attr):
                val = getattr(self, attr).get().strip()
                if val: q += f" AND {col}=?"; params.append(val)
        qf = self.filter_var.get()
        if qf == "Low Stock":     q += f" AND quantity>0 AND quantity<={LOW_STOCK_THRESHOLD}"
        elif qf == "Out of Stock": q += " AND quantity=0"
        for attr, op in [("date_from",">="), ("date_to","<=")]:
            val = getattr(self, attr).get().strip()
            if val:
                try:
                    datetime.strptime(val, "%Y-%m-%d")
                    q += f" AND date(added_at){op}date(?)"
                    params.append(val)
                except ValueError:
                    pass
        q += " ORDER BY added_at DESC"
        rows = query_db(q, params, fetch=True)

        for i in self.tree.get_children(): self.tree.delete(i)
        for idx, row in enumerate(rows):
            qty = row[3]
            if qty == 0:             tag = "zero"
            elif qty <= LOW_STOCK_THRESHOLD: tag = "low"
            elif idx % 2 == 1:       tag = "odd"
            else:                    tag = "ok"
            self.tree.insert("", "end", values=row, tags=(tag,))

        self.status_var.set(f"{len(rows)} items shown")
        self.refresh_lookups()
        self._update_kpis()

    def load_logs(self):
        pass  # Logs shown in audit log dialog only

    def on_select(self, _=None):
        sel = self.tree.selection()
        if not sel: return
        vals = self.tree.item(sel[0])["values"]
        self.drawer.populate(vals[1], vals[2], vals[3], vals[4])
        self.drawer.show(editing_id=vals[0])

    def clear_filters(self):
        self.search_var.set("")
        for attr in ("category_var","department_var","location_var"):
            if hasattr(self, attr): getattr(self, attr).set("")
        self.date_from.set("")
        self.date_to.set("")
        self.filter_var.set("All")
        self.load_items()

    # ── CRUD ──────────────────────────────────────────────────────────────
    def add_item(self):
        category   = self.drawer.cat_var.get().strip()
        department = self.drawer.dep_var.get().strip()
        location   = self.drawer.loc_var.get().strip()
        try:
            qty = int(self.drawer.qty_var.get())
            assert qty >= 0
        except:
            messagebox.showwarning("Quantity", "Enter a valid non-negative integer"); return
        if not category:
            messagebox.showwarning("Category required", "Select or add a category"); return

        existing = query_db("SELECT id,quantity FROM items WHERE category=? AND department=?",
                            (category, department), fetch=True)
        user_id = self.current_user["id"] if self.current_user else None
        if existing:
            item_id = existing[0][0]
            query_db("UPDATE items SET quantity=quantity+? WHERE id=?", (qty, item_id))
            add_log("ADD_STOCK", item_id, {"category":category,"amount":qty}, user_id)
        else:
            ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            query_db("INSERT INTO items (name,category,department,quantity,location,added_at) VALUES (?,?,?,?,?,?)",
                     (category, category, department, qty, location, ts))
            for tbl, val in [("categories",category),("departments",department),("locations",location)]:
                if val: query_db(f"INSERT OR IGNORE INTO {tbl} (name) VALUES (?)", (val,))
            item_id = query_db("SELECT last_insert_rowid()", fetch=True)[0][0]
            add_log("ADD", item_id, {"category":category,"department":department,
                                     "quantity":qty,"location":location}, user_id)

        self.drawer.hide()
        self.load_items()
        self.status_var.set(f"Item '{category}' saved.")

    def update_item(self):
        item_id    = self.drawer.editing_id
        category   = self.drawer.cat_var.get().strip()
        department = self.drawer.dep_var.get().strip()
        location   = self.drawer.loc_var.get().strip()
        try: qty = int(self.drawer.qty_var.get())
        except: messagebox.showwarning("Quantity","Enter a valid integer"); return
        if not category:
            messagebox.showwarning("Category required","Select or add a category"); return
        query_db("UPDATE items SET name=?,category=?,department=?,quantity=?,location=? WHERE id=?",
                 (category, category, department, qty, location, item_id))
        for tbl, val in [("categories",category),("departments",department),("locations",location)]:
            if val: query_db(f"INSERT OR IGNORE INTO {tbl} (name) VALUES (?)", (val,))
        user_id = self.current_user["id"] if self.current_user else None
        add_log("UPDATE", item_id, {"category":category,"department":department,
                                    "quantity":qty,"location":location}, user_id)
        self.drawer.hide()
        self.load_items()
        self.status_var.set(f"Item '{category}' updated.")

    def add_stock(self):
        item_id = self.drawer.editing_id
        if not item_id: return
        try: amt = int(self.drawer.qty_var.get()); assert amt > 0
        except: messagebox.showwarning("Amount","Enter a positive integer"); return
        comment = self.drawer.comment_var.get().strip()
        query_db("UPDATE items SET quantity=quantity+? WHERE id=?", (amt, item_id))
        user_id = self.current_user["id"] if self.current_user else None
        add_log("ADD_STOCK", item_id, {"amount":amt,"comment":comment}, user_id)
        self.drawer.hide()
        self.load_items()
        self.status_var.set(f"Added {amt} units to stock.")

    def retrieve_asset(self):
        item_id = self.drawer.editing_id
        if not item_id: return
        try: amt = int(self.drawer.qty_var.get()); assert amt > 0
        except: messagebox.showwarning("Amount","Enter a positive integer"); return
        row = query_db("SELECT quantity FROM items WHERE id=?", (item_id,), fetch=True)
        if not row: return
        current = row[0][0]
        if amt > current:
            messagebox.showwarning("Insufficient stock",
                                   f"Cannot retrieve {amt}; only {current} available"); return
        comment = self.drawer.comment_var.get().strip()
        query_db("UPDATE items SET quantity=quantity-? WHERE id=?", (amt, item_id))
        user_id = self.current_user["id"] if self.current_user else None
        add_log("RETRIEVE", item_id, {"amount":amt,"comment":comment}, user_id)
        self.drawer.hide()
        self.load_items()
        self.status_var.set(f"Retrieved {amt} units.")

    def delete_item(self):
        item_id = self.drawer.editing_id
        if not item_id: return
        sel = self.tree.selection()
        item_name = self.tree.item(sel[0])["values"][1] if sel else "this item"
        if not messagebox.askyesno("Confirm Delete", f"Delete '{item_name}'?\nThis cannot be undone."):
            return
        query_db("DELETE FROM items WHERE id=?", (item_id,))
        user_id = self.current_user["id"] if self.current_user else None
        add_log("DELETE", item_id, {"name":item_name}, user_id)
        self.drawer.hide()
        self.load_items()
        self.status_var.set(f"Deleted '{item_name}'.")

    # ── Export ────────────────────────────────────────────────────────────
    def export_csv(self):
        path = filedialog.asksaveasfilename(defaultextension=".csv",
                                             filetypes=[("CSV files","*.csv")])
        if not path: return
        rows = query_db("SELECT id,category,department,quantity,location,added_at FROM items ORDER BY added_at DESC",
                        fetch=True)
        try:
            with open(path,"w",newline="",encoding="utf-8") as f:
                w = csv.writer(f)
                w.writerow(["id","category","department","quantity","location","added_at"])
                w.writerows(rows)
            messagebox.showinfo("Exported", f"Exported {len(rows)} rows to:\n{os.path.abspath(path)}")
            user_id = self.current_user["id"] if self.current_user else None
            add_log("EXPORT", None, {"path":os.path.abspath(path),"rows":len(rows)}, user_id)
        except Exception as e:
            messagebox.showerror("Export failed", str(e))

    # ── Audit log dialog ──────────────────────────────────────────────────
    # ── User management ───────────────────────────────────────────────────
    def open_user_mgmt(self):
        if self.current_user.get("role") != "admin":
            messagebox.showwarning("Permission", "Only admins can manage users"); return
        dlg = ctk.CTkToplevel(self)
        dlg.title("User Management")
        dlg.geometry("520x360")
        dlg.grab_set()

        cols = ("id","username","role","created_at")
        tree = ttk.Treeview(dlg, columns=cols, show="headings")
        for c in cols:
            tree.heading(c, text=c.title())
            tree.column(c, width=110)
        tree.pack(fill="both", expand=True, padx=16, pady=(16,8))

        def refresh():
            for i in tree.get_children(): tree.delete(i)
            for r in query_db("SELECT id,username,role,created_at FROM users ORDER BY username", fetch=True):
                tree.insert("","end",values=r)

        def add_user():
            u = simpledialog.askstring("Username","Enter username:",parent=dlg)
            if not u: return
            p = simpledialog.askstring("Password","Enter password:",parent=dlg)
            if not p: messagebox.showwarning("Password required","Password cannot be empty"); return
            role = simpledialog.askstring("Role","Enter role (admin/user):",parent=dlg,initialvalue="user") or "user"
            pwd_hash, salt = _hash_password(p)
            created_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            try:
                query_db("INSERT INTO users (username,password_hash,salt,role,created_at) VALUES (?,?,?,?,?)",
                         (u.strip(), pwd_hash, salt, role.strip(), created_at))
                refresh()
            except Exception as e:
                messagebox.showerror("Error", str(e))

        def delete_sel():
            sel = tree.selection()
            if not sel: return
            vals = tree.item(sel[0])["values"]
            if not messagebox.askyesno("Confirm",f"Delete user '{vals[1]}'?"): return
            query_db("DELETE FROM users WHERE id=?", (vals[0],))
            refresh()

        btn_row = ctk.CTkFrame(dlg, fg_color="transparent")
        btn_row.pack(fill="x", padx=16, pady=(0,12))
        ctk.CTkButton(btn_row, text="Add User", command=add_user).pack(side="left")
        ctk.CTkButton(btn_row, text="Delete Selected", command=delete_sel,
                      fg_color=("#FCE4EC","#4a1528"),
                      hover_color=("#F8BBD9","#6b2040"),
                      text_color=("#C62828","#F48FB1")).pack(side="left", padx=8)
        ctk.CTkButton(btn_row, text="Close", command=dlg.destroy,
                      fg_color="transparent", border_width=1).pack(side="right")
        refresh()

    # ── Reports ───────────────────────────────────────────────────────────

# ─── Entry point ──────────────────────────────────────────────────────────────
if __name__ == "__main__":
    init_db()

    login = LoginWindow()
    login.mainloop()
    # mainloop() has returned (quit() was called); now safe to destroy
    try:
        login.destroy()
    except Exception:
        pass

    if login.result is None:
        exit()

    app = StockApp(current_user=login.result)
    app.mainloop()