import tkinter as tk
from tkinter import ttk, messagebox, filedialog, simpledialog
import sqlite3
from datetime import datetime
import csv
import json
import os
import hashlib
import binascii
from matplotlib import category
import numpy as np
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure

DB_PATH = "inventory.db"

# --- Database setup ---
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    # items table with department column (added in migration if missing)
    c.execute("""
    CREATE TABLE IF NOT EXISTS items (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        category TEXT,
        department TEXT,
        quantity INTEGER NOT NULL DEFAULT 0,
        location TEXT,
        added_at TEXT NOT NULL
    )""")
    # lookup tables for dynamic dropdowns
    c.execute("""
    CREATE TABLE IF NOT EXISTS categories (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT UNIQUE NOT NULL
    )""")
    c.execute("""
    CREATE TABLE IF NOT EXISTS locations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT UNIQUE NOT NULL
    )""")
    c.execute("""
    CREATE TABLE IF NOT EXISTS departments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT UNIQUE NOT NULL
    )""")
    # Migration safety: ensure department column exists for older DBs
    cols = [r[1] for r in c.execute("PRAGMA table_info(items)").fetchall()]
    if 'department' not in cols:
        try:
            c.execute("ALTER TABLE items ADD COLUMN department TEXT")
        except Exception:
            # If ALTER fails for some reason, ignore; table already created above includes column for new DBs
            pass
    c.execute("""
    CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        action TEXT NOT NULL,
        item_id INTEGER,
        user_id INTEGER,
        details TEXT,
        timestamp TEXT NOT NULL
    )""")
    # Migration: add user_id column if it doesn't exist
    cols = [r[1] for r in c.execute("PRAGMA table_info(logs)").fetchall()]
    if 'user_id' not in cols:
        try:
            c.execute("ALTER TABLE logs ADD COLUMN user_id INTEGER")
        except Exception:
            pass
    # users table for basic auth
    c.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        salt TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'user',
        created_at TEXT NOT NULL
    )""")
    conn.commit()
    conn.close()


def _hash_password(password, salt=None):
    # PBKDF2 with SHA256
    if salt is None:
        salt = os.urandom(16)
    elif isinstance(salt, str):
        salt = binascii.unhexlify(salt)
    dk = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
    return binascii.hexlify(dk).decode('ascii'), binascii.hexlify(salt).decode('ascii')


def _verify_password(password, salt_hex, hash_hex):
    dk, _ = _hash_password(password, salt_hex)
    return dk == hash_hex

def query_db(query, params=(), fetch=False):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute(query, params)
    res = None
    if fetch:
        res = c.fetchall()
    conn.commit()
    conn.close()
    return res

# --- Logging helper ---
def add_log(action, item_id=None, details=None, user_id=None):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    details_json = json.dumps(details) if details is not None else None
    query_db("INSERT INTO logs (action, item_id, user_id, details, timestamp) VALUES (?, ?, ?, ?, ?)",
             (action, item_id, user_id, details_json, timestamp))

# --- App ---
class StockApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("DACT IT Materials Stock Manager")
        self.geometry("1000x600")
        self.current_user = None
        self.create_widgets()
        self.refresh_lookups()
        self.load_items()
        self.load_logs()

    def create_widgets(self):
        # Top: Filters
        top_frame = ttk.Frame(self)
        top_frame.pack(fill="x", padx=8, pady=6)

        ttk.Label(top_frame, text="Search:").pack(side="left")
        self.search_var = tk.StringVar()
        search_entry = ttk.Entry(top_frame, textvariable=self.search_var)
        search_entry.pack(side="left", padx=4)
        search_entry.bind("<Return>", lambda e: self.load_items())
        ttk.Label(top_frame, text="Category:").pack(side="left", padx=(10,0))
        self.category_var = tk.StringVar()
        self.category_cb = ttk.Combobox(top_frame, textvariable=self.category_var, state="readonly", width=18)
        self.category_cb.pack(side="left", padx=4)
        self.category_cb.bind("<<ComboboxSelected>>", lambda e: self.load_items())

        ttk.Label(top_frame, text="Department:").pack(side="left", padx=(10,0))
        self.department_var = tk.StringVar()
        self.department_cb = ttk.Combobox(top_frame, textvariable=self.department_var, state="readonly", width=18)
        self.department_cb.pack(side="left", padx=4)
        self.department_cb.bind("<<ComboboxSelected>>", lambda e: self.load_items())

        ttk.Label(top_frame, text="Location:").pack(side="left", padx=(10,0))
        self.location_var = tk.StringVar()
        self.location_cb = ttk.Combobox(top_frame, textvariable=self.location_var, state="readonly", width=18)
        self.location_cb.pack(side="left", padx=4)
        self.location_cb.bind("<<ComboboxSelected>>", lambda e: self.load_items())

        ttk.Label(top_frame, text="Date from (YYYY-MM-DD):").pack(side="left", padx=(10,0))
        self.date_from = tk.StringVar()
        ttk.Entry(top_frame, textvariable=self.date_from, width=12).pack(side="left", padx=4)

        ttk.Label(top_frame, text="to:").pack(side="left")
        self.date_to = tk.StringVar()
        ttk.Entry(top_frame, textvariable=self.date_to, width=12).pack(side="left", padx=4)

        ttk.Button(top_frame, text="Apply Filters", command=self.load_items).pack(side="left", padx=8)
        ttk.Button(top_frame, text="Clear Filters", command=self.clear_filters).pack(side="left")

        # User management button (only enabled for admins after login)
        self.user_mgmt_btn = ttk.Button(top_frame, text="Users", command=self.open_user_mgmt)
        self.user_mgmt_btn.pack(side="right", padx=(4,0))
        self.user_mgmt_btn.state(['disabled'])

        # Audit Log button
        self.audit_log_btn = ttk.Button(top_frame, text="Audit Log", command=self.open_audit_log)
        self.audit_log_btn.pack(side="right")

        # Reports button
        self.reports_btn = ttk.Button(top_frame, text="Reports", command=self.open_reports)
        self.reports_btn.pack(side="right", padx=(4,0))

        # Main: Left form, center treeview, right logs
        main_frame = ttk.Frame(self)
        main_frame.pack(fill="both", expand=True, padx=8, pady=6)

        # Form
        form = ttk.Labelframe(main_frame, text="Item")
        form.pack(side="left", fill="y", padx=(0,8))

        ttk.Label(form, text="Category:").grid(row=0, column=0, sticky="e")
        self.form_category_var = tk.StringVar()
        cat_frame = ttk.Frame(form)
        cat_frame.grid(row=0, column=1, pady=4, sticky="w")
        self.form_category_cb = ttk.Combobox(cat_frame, textvariable=self.form_category_var, state="readonly", width=26)
        self.form_category_cb.pack(side="left")
        ttk.Button(cat_frame, text="+", width=2, command=self.add_category_prompt).pack(side="left", padx=(4,0))

        ttk.Label(form, text="Department:").grid(row=1, column=0, sticky="e")
        self.form_department_var = tk.StringVar()
        dep_frame = ttk.Frame(form)
        dep_frame.grid(row=1, column=1, pady=4, sticky="w")
        self.form_department_cb = ttk.Combobox(dep_frame, textvariable=self.form_department_var, state="readonly", width=26)
        self.form_department_cb.pack(side="left")
        ttk.Button(dep_frame, text="+", width=2, command=self.add_department_prompt).pack(side="left", padx=(4,0))

        ttk.Label(form, text="Quantity:").grid(row=2, column=0, sticky="e")
        self.qty_var = tk.IntVar(value=1)
        ttk.Entry(form, textvariable=self.qty_var, width=10).grid(row=2, column=1, sticky="w", pady=4)

        ttk.Label(form, text="Location:").grid(row=3, column=0, sticky="e")
        self.loc_var = tk.StringVar()
        loc_frame = ttk.Frame(form)
        loc_frame.grid(row=3, column=1, pady=4, sticky="w")
        self.form_location_cb = ttk.Combobox(loc_frame, textvariable=self.loc_var, state="readonly", width=26)
        self.form_location_cb.pack(side="left")
        ttk.Button(loc_frame, text="+", width=2, command=self.add_location_prompt).pack(side="left", padx=(4,0))

        btn_frame = ttk.Frame(form)
        btn_frame.grid(row=4, column=0, columnspan=2, pady=6)
        ttk.Button(btn_frame, text="Add", command=self.add_item).pack(side="left", padx=4)
        ttk.Button(btn_frame, text="Update", command=self.update_item).pack(side="left", padx=4)
        ttk.Button(btn_frame, text="Add Stock", command=self.add_stock).pack(side="left", padx=4)
        ttk.Button(btn_frame, text="Retrieve", command=self.retrieve_asset).pack(side="left", padx=4)
        ttk.Button(btn_frame, text="Delete", command=self.delete_item).pack(side="left", padx=4)
        ttk.Button(btn_frame, text="Export CSV", command=self.export_csv).pack(side="left", padx=4)

        # Items Treeview
        center = ttk.Frame(main_frame)
        center.pack(side="left", fill="both", expand=True)

        columns = ("id","category","department","quantity","location","added_at")
        self.tree = ttk.Treeview(center, columns=columns, show="headings", selectmode="browse")
        for col in columns:
            self.tree.heading(col, text=col.title())
            self.tree.column(col, anchor="w", width=120 if col != "id" else 40)
        self.tree.pack(fill="both", expand=True)
        self.tree.bind("<<TreeviewSelect>>", self.on_select)

        # Logs
        log_frame = ttk.Labelframe(main_frame, text="Logs")
        log_frame.pack(side="right", fill="y", padx=(8,0))

        self.log_tree = ttk.Treeview(log_frame, columns=("id","action","item_id","timestamp"), show="headings", height=10)
        for col in ("id","action","item_id","timestamp"):
            self.log_tree.heading(col, text=col.title())
            self.log_tree.column(col, anchor="w", width=100)
        self.log_tree.pack(fill="both", expand=True, padx=4, pady=4)
        ttk.Button(log_frame, text="Refresh Logs", command=self.load_logs).pack(pady=(0,6))

    def clear_filters(self):
        self.search_var.set("")
        self.category_var.set("")
        self.date_from.set("")
        self.date_to.set("")
        self.load_items()

    def refresh_lookups(self):
        # Load values from lookup tables; if tables are empty, fall back to distinct values from items
        cats = [r[0] for r in query_db("SELECT name FROM categories ORDER BY name", fetch=True) or []]
        locs = [r[0] for r in query_db("SELECT name FROM locations ORDER BY name", fetch=True) or []]
        deps = [r[0] for r in query_db("SELECT name FROM departments ORDER BY name", fetch=True) or []]

        # fallback to distinct values already present in items
        if not cats:
            cats = [r[0] for r in query_db("SELECT DISTINCT category FROM items WHERE category IS NOT NULL AND category != '' ORDER BY category", fetch=True) or []]
        if not locs:
            locs = [r[0] for r in query_db("SELECT DISTINCT location FROM items WHERE location IS NOT NULL AND location != '' ORDER BY location", fetch=True) or []]
        if not deps:
            deps = [r[0] for r in query_db("SELECT DISTINCT department FROM items WHERE department IS NOT NULL AND department != '' ORDER BY department", fetch=True) or []]

        categories = [""] + cats
        locations = [""] + locs
        departments = [""] + deps

        # Top filters
        try:
            self.category_cb["values"] = categories
            self.department_cb["values"] = departments
            self.location_cb["values"] = locations
        except Exception:
            pass

        # Form fields
        try:
            self.form_category_cb["values"] = cats
            self.form_location_cb["values"] = locs
            self.form_department_cb["values"] = deps
        except Exception:
            pass

    def load_items(self):
        q = "SELECT id, category, department, quantity, location, added_at FROM items WHERE 1=1"
        params = []
        s = self.search_var.get().strip()
        if s:
            q += " AND (category LIKE ? OR location LIKE ? OR department LIKE ?)"
            like = f"%{s}%"
            params += [like, like, like]
        cat = self.category_var.get().strip()
        if cat:
            q += " AND category = ?"
            params.append(cat)
        dep = self.department_var.get().strip()
        if dep:
            q += " AND department = ?"
            params.append(dep)
        loc = self.location_var.get().strip()
        if loc:
            q += " AND location = ?"
            params.append(loc)

        df = self.date_from.get().strip()
        dt = self.date_to.get().strip()
        if df:
            try:
                datetime.strptime(df, "%Y-%m-%d")
                q += " AND date(added_at) >= date(?)"
                params.append(df)
            except ValueError:
                messagebox.showwarning("Date format", "Date from must be YYYY-MM-DD")
        if dt:
            try:
                datetime.strptime(dt, "%Y-%m-%d")
                q += " AND date(added_at) <= date(?)"
                params.append(dt)
            except ValueError:
                messagebox.showwarning("Date format", "Date to must be YYYY-MM-DD")

        q += " ORDER BY added_at DESC"
        rows = query_db(q, params, fetch=True)

        for i in self.tree.get_children():
            self.tree.delete(i)
        for row in rows:
            self.tree.insert("", "end", values=row)

        # refresh lookup values shown in comboboxes
        self.refresh_lookups()

    def load_logs(self):
        rows = query_db("SELECT id, action, item_id, timestamp FROM logs ORDER BY timestamp DESC LIMIT 200", fetch=True)
        for i in self.log_tree.get_children():
            self.log_tree.delete(i)
        for r in rows:
            self.log_tree.insert("", "end", values=r)

    # --- Lookup management ---
    def add_lookup_value(self, table, value):
        if not value:
            return
        query_db(f"INSERT OR IGNORE INTO {table} (name) VALUES (?)", (value,))

    def add_category_prompt(self):
        name = simpledialog.askstring("Add Category", "Category name:", parent=self)
        if name:
            name = name.strip()
            if name:
                self.add_lookup_value('categories', name)
                self.refresh_lookups()
                self.form_category_var.set(name)

    def add_location_prompt(self):
        name = simpledialog.askstring("Add Location", "Location name:", parent=self)
        if name:
            name = name.strip()
            if name:
                self.add_lookup_value('locations', name)
                self.refresh_lookups()
                self.loc_var.set(name)

    def add_department_prompt(self):
        name = simpledialog.askstring("Add Department", "Department name:", parent=self)
        if name:
            name = name.strip()
            if name:
                self.add_lookup_value('departments', name)
                self.refresh_lookups()
                self.form_department_var.set(name)

    # --- User auth & management ---
    def get_user_by_username(self, username):
        rows = query_db("SELECT id, username, password_hash, salt, role, created_at FROM users WHERE username = ?", (username,), fetch=True)
        return rows[0] if rows else None

    def add_user(self, username, password, role='user'):
        username = username.strip()
        if not username or not password:
            return False, "Username and password required"
        pwd_hash, salt = _hash_password(password)
        created_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        try:
            query_db("INSERT INTO users (username, password_hash, salt, role, created_at) VALUES (?, ?, ?, ?, ?)",
                     (username, pwd_hash, salt, role, created_at))
            return True, None
        except Exception as e:
            return False, str(e)

    def run_login(self):
        # If no users exist, prompt to create initial admin
        cnt = query_db("SELECT COUNT(*) FROM users", fetch=True)[0][0]
        if cnt == 0:
            # create initial admin
            dlg = tk.Toplevel(self)
            dlg.title("Create initial admin")
            dlg.grab_set()
            ttk.Label(dlg, text="No users found. Create initial admin account").pack(padx=12, pady=(12,4))
            ttk.Label(dlg, text="Username:").pack(padx=12, anchor="w")
            uvar = tk.StringVar()
            ttk.Entry(dlg, textvariable=uvar).pack(padx=12, fill="x")
            ttk.Label(dlg, text="Password:").pack(padx=12, anchor="w")
            pvar = tk.StringVar()
            ttk.Entry(dlg, textvariable=pvar, show="*").pack(padx=12, fill="x")
            def create_admin():
                user = uvar.get().strip()
                pwd = pvar.get()
                ok, err = self.add_user(user, pwd, role='admin')
                if not ok:
                    messagebox.showerror("Error", f"Could not create admin: {err}")
                    return
                messagebox.showinfo("Created", "Initial admin created. Please login.")
                dlg.destroy()
            ttk.Button(dlg, text="Create", command=create_admin).pack(pady=8)
            dlg.transient(self)
            self.wait_window(dlg)

        # Login dialog
        logged_in = {'ok': False}
        dlg = tk.Toplevel(self)
        dlg.title("Login")
        dlg.grab_set()
        ttk.Label(dlg, text="Username:").grid(row=0, column=0, padx=8, pady=(8,4), sticky="e")
        uvar = tk.StringVar()
        ttk.Entry(dlg, textvariable=uvar).grid(row=0, column=1, padx=8, pady=(8,4))
        ttk.Label(dlg, text="Password:").grid(row=1, column=0, padx=8, pady=4, sticky="e")
        pvar = tk.StringVar()
        ttk.Entry(dlg, textvariable=pvar, show="*").grid(row=1, column=1, padx=8, pady=4)

        def do_login():
            username = uvar.get().strip()
            pwd = pvar.get()
            row = self.get_user_by_username(username)
            if not row:
                messagebox.showwarning("Login failed", "User not found")
                return
            _, uname, pwd_hash, salt, role, _ = row
            if _verify_password(pwd, salt, pwd_hash):
                self.current_user = {'id': row[0], 'username': uname, 'role': role}
                logged_in['ok'] = True
                dlg.destroy()
            else:
                messagebox.showwarning("Login failed", "Invalid password")

        def do_quit():
            dlg.destroy()

        ttk.Button(dlg, text="Login", command=do_login).grid(row=2, column=0, pady=8)
        ttk.Button(dlg, text="Quit", command=do_quit).grid(row=2, column=1, pady=8)
        dlg.transient(self)
        dlg.wait_visibility()
        self.wait_window(dlg)

        if not logged_in['ok']:
            return False
        # enable admin-only controls
        if self.current_user and self.current_user.get('role') == 'admin':
            try:
                self.user_mgmt_btn.state(['!disabled'])
            except Exception:
                pass
        return True

    def open_user_mgmt(self):
        if not self.current_user or self.current_user.get('role') != 'admin':
            messagebox.showwarning("Permission", "Only admins can manage users")
            return
        dlg = tk.Toplevel(self)
        dlg.title("User Management")
        dlg.geometry("500x300")

        cols = ("id","username","role","created_at")
        tree = ttk.Treeview(dlg, columns=cols, show="headings")
        for c in cols:
            tree.heading(c, text=c.title())
            tree.column(c, width=100)
        tree.pack(fill="both", expand=True, padx=8, pady=8)

        def refresh_users():
            for i in tree.get_children():
                tree.delete(i)
            rows = query_db("SELECT id, username, role, created_at FROM users ORDER BY username", fetch=True)
            for r in rows:
                tree.insert("", "end", values=r)

        def add_user_prompt():
            u = simpledialog.askstring("Username", "Enter username:", parent=dlg)
            if not u:
                return
            p = simpledialog.askstring("Password", "Enter password:", parent=dlg)
            if p is None or p == "":
                messagebox.showwarning("Password required", "Password cannot be empty")
                return
            role = simpledialog.askstring("Role", "Enter role (admin/user):", parent=dlg, initialvalue="user")
            role = role.strip() if role else 'user'
            ok, err = self.add_user(u, p, role=role)
            if not ok:
                messagebox.showerror("Error", f"Could not add user: {err}")
            refresh_users()

        def delete_selected():
            sel = tree.selection()
            if not sel:
                return
            item = tree.item(sel[0])['values']
            uid = item[0]
            if not messagebox.askyesno("Confirm", f"Delete user {item[1]}?"):
                return
            query_db("DELETE FROM users WHERE id=?", (uid,))
            refresh_users()

        btns = ttk.Frame(dlg)
        btns.pack(fill="x", padx=8, pady=(0,8))
        ttk.Button(btns, text="Add User", command=add_user_prompt).pack(side="left")
        ttk.Button(btns, text="Delete", command=delete_selected).pack(side="left", padx=8)
        ttk.Button(btns, text="Close", command=dlg.destroy).pack(side="right")

        refresh_users()

    def open_audit_log(self):
        dlg = tk.Toplevel(self)
        dlg.title("Audit Log")
        dlg.geometry("1000x500")

        cols = ("id","action","item_id","username","details","timestamp")
        tree = ttk.Treeview(dlg, columns=cols, show="headings")
        for c in cols:
            tree.heading(c, text=c.title())
            if c == "details":
                tree.column(c, width=250)
            elif c == "id":
                tree.column(c, width=40)
            else:
                tree.column(c, width=100)
        
        # Scrollbars
        vsb = ttk.Scrollbar(dlg, orient="vertical", command=tree.yview)
        hsb = ttk.Scrollbar(dlg, orient="horizontal", command=tree.xview)
        tree.configure(yscroll=vsb.set, xscroll=hsb.set)
        
        tree.grid(row=0, column=0, sticky="nsew", padx=8, pady=8)
        vsb.grid(row=0, column=1, sticky="ns", pady=8)
        hsb.grid(row=1, column=0, sticky="ew", padx=8)
        
        dlg.grid_rowconfigure(0, weight=1)
        dlg.grid_columnconfigure(0, weight=1)

        def refresh_audit():
            for i in tree.get_children():
                tree.delete(i)
            # Join logs with users table to get usernames
            rows = query_db("""
                SELECT l.id, l.action, l.item_id, COALESCE(u.username, 'System'), l.details, l.timestamp 
                FROM logs l 
                LEFT JOIN users u ON l.user_id = u.id 
                ORDER BY l.timestamp DESC 
                LIMIT 500
            """, fetch=True)
            for r in rows:
                tree.insert("", "end", values=r)

        refresh_audit()
        
        btn_frame = ttk.Frame(dlg)
        btn_frame.grid(row=2, column=0, columnspan=2, sticky="ew", padx=8, pady=8)
        ttk.Button(btn_frame, text="Refresh", command=refresh_audit).pack(side="left")
        ttk.Button(btn_frame, text="Close", command=dlg.destroy).pack(side="right")

    def open_reports(self):
        dlg = tk.Toplevel(self)
        dlg.title("Reports")
        dlg.geometry("1200x600")

        # Create notebook for tabs
        notebook = ttk.Notebook(dlg)
        notebook.pack(fill="both", expand=True, padx=8, pady=8)

        # Tab 1: Stock by Category (Donut Chart)
        category_frame = ttk.Frame(notebook)
        notebook.add(category_frame, text="Stock by Category")
        
        fig1 = Figure(figsize=(6, 5), dpi=100)
        ax1 = fig1.add_subplot(111)
        
        # Get stock data by category
        cat_rows = query_db("SELECT category, SUM(quantity) as total FROM items GROUP BY category ORDER BY total DESC", fetch=True)
        if cat_rows:
            categories = [r[0] for r in cat_rows if r[0]]
            quantities = [r[1] for r in cat_rows if r[0]]
            if categories:
                colors = plt.cm.Set3(range(len(categories)))
                wedges, texts, autotexts = ax1.pie(quantities, labels=categories, autopct='%1.1f%%', 
                                                     colors=colors, startangle=90, pctdistance=0.85)
                # Draw circle for donut
                centre_circle = plt.Circle((0, 0), 0.70, fc='white')
                ax1.add_artist(centre_circle)
                ax1.set_title("Stock Distribution by Category")
                
                # Make percentage text smaller
                for autotext in autotexts:
                    autotext.set_color('black')
                    autotext.set_fontsize(8)
        
        canvas1 = FigureCanvasTkAgg(fig1, master=category_frame)
        canvas1.draw()
        canvas1.get_tk_widget().pack(fill="both", expand=True, padx=4, pady=4)

        # Tab 2: Stock by Department (Bar Chart)
        dept_frame = ttk.Frame(notebook)
        notebook.add(dept_frame, text="Stock by Department")
        
        fig2 = Figure(figsize=(8, 5), dpi=100)
        ax2 = fig2.add_subplot(111)
        
        # Get stock data by department
        dept_rows = query_db("SELECT department, SUM(quantity) as total FROM items GROUP BY department ORDER BY total DESC", fetch=True)
        if dept_rows:
            departments = [r[0] if r[0] else "Unassigned" for r in dept_rows]
            quantities = [r[1] for r in dept_rows]
            if departments:
                colors = plt.cm.Set2(range(len(departments)))
                bars = ax2.bar(departments, quantities, color=colors, edgecolor='black', linewidth=1.2)
                ax2.set_ylabel("Quantity", fontsize=12)
                ax2.set_xlabel("Department", fontsize=12)
                ax2.set_title("Stock Quantity by Department")
                ax2.grid(axis='y', alpha=0.3)
                
                # Add value labels on bars
                for bar in bars:
                    height = bar.get_height()
                    ax2.text(bar.get_x() + bar.get_width()/2., height,
                            f'{int(height)}',
                            ha='center', va='bottom', fontsize=10)
                
                # Rotate x-axis labels if many departments
                if len(departments) > 3:
                    fig2.autofmt_xdate(rotation=45, ha='right')
        
        canvas2 = FigureCanvasTkAgg(fig2, master=dept_frame)
        canvas2.draw()
        canvas2.get_tk_widget().pack(fill="both", expand=True, padx=4, pady=4)

        # Tab 3: Stock by Category and Department (Grouped Bar Chart)
        detail_frame = ttk.Frame(notebook)
        notebook.add(detail_frame, text="Category x Department")
        
        fig3 = Figure(figsize=(10, 5), dpi=100)
        ax3 = fig3.add_subplot(111)
        
        # Get detailed data: category and department combination
        detail_rows = query_db("""
            SELECT category, department, SUM(quantity) as total 
            FROM items 
            GROUP BY category, department 
            ORDER BY category, department
        """, fetch=True)
        
        if detail_rows:
            # Build data structure for grouped bar chart
            categories_set = sorted(set(r[0] for r in detail_rows if r[0]))
            departments_set = sorted(set(r[1] if r[1] else "Unassigned" for r in detail_rows))
            
            if categories_set and departments_set:
                # Create data matrix
                x = np.arange(len(categories_set))
                width = 0.8 / len(departments_set)
                colors = plt.cm.Pastel1(range(len(departments_set)))
                
                for idx, dept in enumerate(departments_set):
                    values = []
                    for cat in categories_set:
                        qty = next((r[2] for r in detail_rows if r[0] == cat and (r[1] if r[1] else "Unassigned") == dept), 0)
                        values.append(qty)
                    offset = (idx - len(departments_set)/2) * width + width/2
                    ax3.bar(x + offset, values, width, label=dept, color=colors[idx])
                
                ax3.set_ylabel("Quantity", fontsize=12)
                ax3.set_xlabel("Category", fontsize=12)
                ax3.set_title("Stock Quantity: Category vs Department")
                ax3.set_xticks(x)
                ax3.set_xticklabels(categories_set, rotation=45, ha='right')
                ax3.legend()
                ax3.grid(axis='y', alpha=0.3)
        
        canvas3 = FigureCanvasTkAgg(fig3, master=detail_frame)
        canvas3.draw()
        canvas3.get_tk_widget().pack(fill="both", expand=True, padx=4, pady=4)

    def add_item(self):
        category = self.form_category_var.get().strip()
        if not category:
            messagebox.showwarning("Category required", "Select or enter a category")
            return
        department = self.form_department_var.get().strip()
        try:
            qty = int(self.qty_var.get())
        except Exception:
            messagebox.showwarning("Quantity", "Enter a valid integer quantity")
            return
        location = self.loc_var.get().strip()
        
        # Check if this category already exists in this department - if so, just add stock to it instead of creating a new item
        existing = query_db("SELECT id, quantity FROM items WHERE category = ? AND department = ?", (category, department), fetch=True)
        
        if existing:
            # Update existing category
            item_id = existing[0][0]
            query_db("UPDATE items SET quantity = quantity + ? WHERE id=?", (qty, item_id))
            comment = simpledialog.askstring("Comment", "Optional comment when adding stock:", parent=self)
            user_id = self.current_user['id'] if self.current_user else None
            add_log("ADD_STOCK", item_id, {"category": category, "amount": qty, "comment": comment}, user_id)
        else:
            # Create new item for this category
            added_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            query_db("INSERT INTO items (name, category, department, quantity, location, added_at) VALUES (?, ?, ?, ?, ?, ?)",
                     (category, category, department, qty, location, added_at))
            # ensure lookup tables include the new values
            if category:
                query_db("INSERT OR IGNORE INTO categories (name) VALUES (?)", (category,))
            if department:
                query_db("INSERT OR IGNORE INTO departments (name) VALUES (?)", (department,))
            if location:
                query_db("INSERT OR IGNORE INTO locations (name) VALUES (?)", (location,))
            item_id = query_db("SELECT last_insert_rowid()", fetch=True)[0][0]
            comment = simpledialog.askstring("Comment", "Optional comment when adding item:", parent=self)
            user_id = self.current_user['id'] if self.current_user else None
            add_log("ADD", item_id, {"category": category, "department": department, "quantity": qty, "location": location, "comment": comment}, user_id)
        
        self.load_items()
        self.load_logs()
        self.clear_form()

    def update_item(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showwarning("Select", "Select an item to update")
            return
        item = self.tree.item(sel[0])["values"]
        item_id = item[0]
        category = self.form_category_var.get().strip()
        if not category:
            messagebox.showwarning("Category required", "Select or enter a category")
            return
        department = self.form_department_var.get().strip()
        try:
            qty = int(self.qty_var.get())
        except Exception:
            messagebox.showwarning("Quantity", "Enter a valid integer quantity")
            return
        location = self.loc_var.get().strip()
        query_db("UPDATE items SET name=?, category=?, department=?, quantity=?, location=? WHERE id=?",
                 (category, category, department, qty, location, item_id))
        # ensure lookup tables include the updated values
        if category:
            query_db("INSERT OR IGNORE INTO categories (name) VALUES (?)", (category,))
        if department:
            query_db("INSERT OR IGNORE INTO departments (name) VALUES (?)", (department,))
        if location:
            query_db("INSERT OR IGNORE INTO locations (name) VALUES (?)", (location,))
        user_id = self.current_user['id'] if self.current_user else None
        add_log("UPDATE", item_id, {"category": category, "department": department, "quantity": qty, "location": location}, user_id)
        self.load_items()
        self.load_logs()
        self.clear_form()

    def add_stock(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showwarning("Select", "Select an item to add stock to")
            return
        item = self.tree.item(sel[0])['values']
        item_id = item[0]
        # ask for amount to add
        try:
            amt = simpledialog.askinteger("Add Stock", "Quantity to add:", parent=self, minvalue=1, initialvalue=1)
        except Exception:
            amt = None
        if not amt:
            return
        comment = simpledialog.askstring("Comment", "Optional comment for this stock addition:", parent=self)
        query_db("UPDATE items SET quantity = quantity + ? WHERE id=?", (amt, item_id))
        user_id = self.current_user['id'] if self.current_user else None
        add_log("ADD_STOCK", item_id, {"amount": amt, "comment": comment}, user_id)
        self.load_items()
        self.load_logs()

    def retrieve_asset(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showwarning("Select", "Select an item to retrieve")
            return
        item = self.tree.item(sel[0])['values']
        print("Selected item for retrieval:", item)
        item_id = item[0]
        current_qty = item[3]
        department = item[2]  

        try:
            amt = simpledialog.askinteger("Retrieve", "Quantity to retrieve:", parent=self, minvalue=1, initialvalue=1)
        except Exception:
            amt = None
        if not amt:
            return
        if amt > current_qty:
            messagebox.showwarning("Insufficient stock", f"Cannot retrieve {amt} items; only {current_qty} available")
            return
        comment = simpledialog.askstring("Comment", "Optional comment for retrieval:", parent=self)
        query_db("UPDATE items SET quantity = quantity - ? WHERE id=?", (amt, item_id))
        user_id = self.current_user['id'] if self.current_user else None
        add_log("RETRIEVE", item_id, {"amount": amt, "department": department, "comment": comment}, user_id)
        self.load_items()
        self.load_logs()

    def delete_item(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showwarning("Select", "Select an item to delete")
            return
        item = self.tree.item(sel[0])["values"]
        item_id = item[0]
        if not messagebox.askyesno("Confirm", f"Delete item '{item[1]}'?"):
            return
        query_db("DELETE FROM items WHERE id=?", (item_id,))
        # item values: id, category, department, quantity, location, added_at
        user_id = self.current_user['id'] if self.current_user else None
        add_log("DELETE", item_id, {"category": item[1], "department": item[2], "quantity": item[3]}, user_id)
        self.load_items()
        self.load_logs()
        self.clear_form()

    def on_select(self, event):
        sel = self.tree.selection()
        if not sel:
            return
        item = self.tree.item(sel[0])["values"]
        # id, category, department, quantity, location, added_at
        self.form_category_var.set(item[1] or "")
        self.form_department_var.set(item[2] or "")
        self.qty_var.set(item[3])
        self.loc_var.set(item[4] or "")

    def clear_form(self):
        self.form_category_var.set("")
        self.form_department_var.set("")
        self.qty_var.set(1)
        self.loc_var.set("")
        for s in self.tree.selection():
            self.tree.selection_remove(s)

    def export_csv(self):
        path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files","*.csv")])
        if not path:
            return
        rows = query_db("SELECT id, category, department, quantity, location, added_at FROM items ORDER BY added_at DESC", fetch=True)
        try:
            with open(path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["id","category","department","quantity","location","added_at"])
                writer.writerows(rows)
            messagebox.showinfo("Exported", f"Exported {len(rows)} rows to {os.path.abspath(path)}")
            user_id = self.current_user['id'] if self.current_user else None
            add_log("EXPORT", None, {"path": os.path.abspath(path), "rows": len(rows)}, user_id)
            self.load_logs()
        except Exception as e:
            messagebox.showerror("Error", str(e))

if __name__ == "__main__":
    init_db()
    app = StockApp()
    ok = app.run_login()
    if not ok:
        # user cancelled or failed login
        try:
            app.destroy()
        except Exception:
            pass
    else:
        app.mainloop()