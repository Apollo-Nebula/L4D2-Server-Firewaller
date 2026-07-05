"""
l4d_blocker_tk.py — L4D Server Blocker (simple Tkinter version)
Blocks Lewd4Dead servers using Windows Firewall (netsh advfirewall).
Must be run as Administrator. Pure stdlib — no extra packages needed.
"""

import ctypes, sys, os, json, subprocess, threading
import urllib.request, urllib.error
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog

# ── config ──────────────────────────────────────────────────────────────────
RULE_PREFIX = "L4D-BLOCK"
DATA_FILE   = os.path.join(os.path.dirname(os.path.abspath(__file__)), "l4d_ips.json")

# Online IP list used by the "Update List" button. Must return either:
#   - a JSON array of IP strings:            ["1.2.3.4", "5.6.7.8", ...]
#   - a JSON array of [ip, note] pairs:       [["1.2.3.4", "some note"], ...]
#   - a JSON array of {"ip": .., "note": ..}: [{"ip": "1.2.3.4", "note": ""}, ...]
#   - or plain text, one IP (optionally "ip,note") per line
UPDATE_URL = "https://raw.githubusercontent.com/Apollo-Nebula/L4D2-Modded-server-IP-list/main/Ip_list.json"

DEFAULT_IPS = [
    ("175.141.9.200",   "Lewd4Dead MY"), ("155.138.194.251", "Lewd4Dead US"),
    ("202.186.102.95",  "Lewd4Dead MY"), ("103.131.188.71",  "Lewd4Dead SG"),
    ("108.181.54.69",   "Lewd4Dead US"), ("172.93.102.9",    "Lewd4Dead US"),
    ("212.8.248.124",   "Lewd4Dead EU"), ("43.230.163.166",  "Lewd4Dead SG"),
    ("46.174.52.5",     "Lewd4Dead RU"), ("192.168.88.30",   ""),
    ("192.168.100.110", ""),             ("8.12.16.195",     "Lewd4Dead US"),
    ("85.214.110.16",   "Lewd4Dead DE"), ("192.168.19.11",   ""),
    ("188.127.244.198", "Lewd4Dead RU"), ("188.127.241.206", "Lewd4Dead RU"),
    ("148.251.130.211", "Lewd4Dead DE"), ("5.189.124.206",   "Lewd4Dead EU"),
    ("175.137.203.55",  "Lewd4Dead MY"), ("202.186.47.138",  "Lewd4Dead MY"),
    ("219.95.53.226",   "Lewd4Dead MY"), ("93.190.139.252",  "Lewd4Dead EU"),
    ("45.67.86.40",     "Lewd4Dead EU"), ("202.186.162.161", "Lewd4Dead MY"),
    ("118.100.98.186",  "Lewd4Dead MY"), ("202.186.160.125", "Lewd4Dead MY"),
    ("60.50.29.31",     "Lewd4Dead MY"), ("202.186.164.240", "Lewd4Dead MY"),
    ("94.72.141.139",   "Lewd4Dead US"), ("2.58.201.66",     "Lewd4Dead EU"),
    ("18.180.172.93",   "Lewd4Dead JP"), ("185.187.155.10",  "Lewd4Dead EU"),
    ("45.134.110.25",   "Lewd4Dead EU"), ("45.67.85.139",    "Lewd4Dead EU"),
    ("45.11.231.30",    "Lewd4Dead EU"), ("185.121.26.7",    "Lewd4Dead EU"),
    ("2.58.201.55",     "Lewd4Dead EU"), ("2.58.200.5",      "Lewd4Dead EU"),
    ("190.2.141.8",     "Lewd4Dead EU"), ("178.239.171.97",  "Lewd4Dead EU"),
    ("45.11.230.10",    "Lewd4Dead EU"), ("157.20.105.71",   ""),
    ("175.140.7.65",    "Lewd4Dead MY"), ("109.205.214.65",  "Lewd4Dead EU"),
    ("151.158.198.49",  ""),             ("202.184.45.168",  "Lewd4Dead MY"),
]

# ── firewall helpers ─────────────────────────────────────────────────────────
def is_admin():
    try:    return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except: return False

def _strip_port(ip): return ip.split(":")[0].strip()
def _rule_name(ip):  return f"{RULE_PREFIX}-{_strip_port(ip)}"

def _run(cmd):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True,
                           creationflags=subprocess.CREATE_NO_WINDOW)
        return r.returncode == 0, r.stdout + r.stderr
    except Exception as e:
        return False, str(e)

def ip_blocked(ip):
    ok, out = _run(f'netsh advfirewall firewall show rule name="{_rule_name(ip)}"')
    return ok and "Block" in out

def block_ip(ip):
    bare, name = _strip_port(ip), _rule_name(ip)
    _run(f'netsh advfirewall firewall delete rule name="{name}"')
    ok1, _ = _run(f'netsh advfirewall firewall add rule name="{name}" dir=in  action=block remoteip="{bare}"')
    ok2, _ = _run(f'netsh advfirewall firewall add rule name="{name}" dir=out action=block remoteip="{bare}"')
    return ok1 and ok2

def unblock_ip(ip):
    ok, _ = _run(f'netsh advfirewall firewall delete rule name="{_rule_name(ip)}"')
    return ok

def load_data():
    if os.path.exists(DATA_FILE):
        try:
            with open(DATA_FILE) as f: return json.load(f)
        except: pass
    return [{"ip": ip, "note": note} for ip, note in DEFAULT_IPS]

def save_data(data):
    try:
        with open(DATA_FILE, "w") as f: json.dump(data, f, indent=2)
    except: pass

# ── online list update ───────────────────────────────────────────────────────
def parse_remote_ips(raw_text):
    """Turn the downloaded list into [(ip, note), ...]. Accepts a JSON array
    of strings / [ip, note] pairs / {"ip":..,"note":..} objects, or falls
    back to plain text with one IP (optionally 'ip,note') per line."""
    entries = []
    try:
        data = json.loads(raw_text)
    except (json.JSONDecodeError, ValueError):
        data = None

    if isinstance(data, list):
        for item in data:
            if isinstance(item, str):
                ip, note = item.strip(), ""
            elif isinstance(item, dict):
                ip, note = str(item.get("ip", "")).strip(), str(item.get("note", ""))
            elif isinstance(item, (list, tuple)) and item:
                ip = str(item[0]).strip()
                note = str(item[1]) if len(item) > 1 else ""
            else:
                continue
            if ip:
                entries.append((ip, note))
    else:
        # plain text fallback: one IP per line, optional ",note"
        for line in raw_text.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("//"):
                continue
            if "," in line:
                ip, note = line.split(",", 1)
            else:
                ip, note = line, ""
            ip = ip.strip()
            if ip:
                entries.append((ip, note.strip()))
    return entries

def fetch_remote_ips(url, timeout=10):
    req = urllib.request.Request(url, headers={"User-Agent": "l4d-blocker/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        raw = resp.read().decode("utf-8", errors="replace")
    return parse_remote_ips(raw)

# ── app ──────────────────────────────────────────────────────────────────────
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("l4d2 firewall manager")
        self.geometry("680x560")          # slightly narrower window
        self.minsize(520, 400)

        self.ip_data = load_data()
        self.blocked_state = {e["ip"]: ip_blocked(e["ip"]) for e in self.ip_data}

        self._build()
        self._populate()
        self._refresh_stats()

    # ── UI construction ──────────────────────────────────────────────────────
    def _build(self):
        # toolbar
        toolbar = ttk.Frame(self, padding=8)
        toolbar.pack(fill="x")
        self._toolbar_buttons = []

        for text, cmd, pad in [
            ("Add IP",           self._add_dialog,        0),
            ("Remove Selected",  self._remove_selected,   6),
            ("Toggle Block",     self._toggle_selected,   6),
            ("Block All",        self._block_all,         18),
            ("Allow All",        self._allow_all,         6),
            ("Update List",      self._update_list_dialog, 18),
        ]:
            btn = ttk.Button(toolbar, text=text, command=cmd)
            btn.pack(side="left", padx=(pad, 0))
            self._toolbar_buttons.append(btn)

        ttk.Label(toolbar, text="Filter:").pack(side="left", padx=(18, 4))
        self.search_var = tk.StringVar()
        self.search_var.trace_add("write", lambda *_: self._populate())
        ttk.Entry(toolbar, textvariable=self.search_var, width=20).pack(side="left")

        # table
        cols = ("ip", "note", "status")
        self.tree = ttk.Treeview(self, columns=cols, show="headings", selectmode="extended")
        self.tree.heading("ip", text="server ips")
        self.tree.heading("note", text="Note")
        self.tree.heading("status", text="Status")
        self.tree.column("ip", width=170, anchor="w")
        self.tree.column("note", width=180, anchor="w")   # smaller note column
        self.tree.column("status", width=100, anchor="center")
        self.tree.pack(fill="both", expand=True, padx=8, pady=(0, 8))
        self.tree.bind("<Double-1>", lambda _e: self._toggle_selected())

        # Right-click context menu
        self.context_menu = tk.Menu(self, tearoff=0)
        self.context_menu.add_command(label="Toggle Block", command=self._toggle_selected)
        self.context_menu.add_command(label="Edit Note", command=self._edit_note_selected)
        self.context_menu.add_separator()
        self.context_menu.add_command(label="Remove", command=self._remove_selected)
        self.tree.bind("<Button-3>", self._show_context_menu)

        self.tree.tag_configure("blocked", foreground="#c0392b")
        self.tree.tag_configure("allowed", foreground="#27ae60")

        # status bar
        self.status_var = tk.StringVar()
        ttk.Label(self, textvariable=self.status_var, anchor="w", padding=(8, 4)).pack(fill="x")

        self.protocol("WM_DELETE_WINDOW", self._on_close)

    def _show_context_menu(self, event):
        item = self.tree.identify_row(event.y)
        if item:
            self.tree.selection_set(item)
            self.context_menu.post(event.x_root, event.y_root)

    # ── populate / refresh ───────────────────────────────────────────────────
    def _populate(self):
        self.tree.delete(*self.tree.get_children())
        filt = self.search_var.get().lower().strip()
        for e in self.ip_data:
            ip, note = e["ip"], e.get("note", "")
            if filt and filt not in ip.lower() and filt not in note.lower():
                continue
            blocked = self.blocked_state.get(ip, False)
            status = "BLOCKED" if blocked else "ALLOWED"
            tag = "blocked" if blocked else "allowed"
            self.tree.insert("", "end", iid=ip, values=(ip, note, status), tags=(tag,))
        self._refresh_stats()

    def _refresh_stats(self):
        total = len(self.ip_data)
        blocked = sum(1 for v in self.blocked_state.values() if v)
        self.status_var.set(f"Total: {total}    Blocked: {blocked}    Allowed: {total - blocked}")

    # ── actions ───────────────────────────────────────────────────────────────
    def _selected_ips(self):
        return list(self.tree.selection())

    def _toggle_selected(self):
        ips = self._selected_ips()
        if not ips:
            messagebox.showinfo("No selection", "Select one or more rows first.")
            return
        fail = False
        for ip in ips:
            new_state = not self.blocked_state.get(ip, False)
            ok = block_ip(ip) if new_state else unblock_ip(ip)
            if ok:
                self.blocked_state[ip] = new_state
            else:
                fail = True
        if fail:
            self._no_admin()
        self._populate()

    def _block_all(self):
        fail = False
        for e in self.ip_data:
            if block_ip(e["ip"]):
                self.blocked_state[e["ip"]] = True
            else:
                fail = True
        if fail:
            self._no_admin()
        self._populate()

    def _allow_all(self):
        fail = False
        for e in self.ip_data:
            if unblock_ip(e["ip"]):
                self.blocked_state[e["ip"]] = False
            else:
                fail = True
        if fail:
            self._no_admin()
        self._populate()

    def _update_list_dialog(self):
        proceed = messagebox.askyesno(
            "Update IP List",
            "This grabs the latest known server IPs from an online list and "
            "adds any that aren't already in your list.\n\n"
            "• IPs already in your list are left untouched (notes, block "
            "state, etc. are not changed).\n"
            "• New IPs are added as ALLOWED — nothing gets blocked "
            "automatically.\n"
            "• This requires an internet connection.\n\n"
            "Continue?",
        )
        if not proceed:
            return
        self._set_update_ui_busy(True)
        threading.Thread(target=self._update_worker, daemon=True).start()

    def _set_update_ui_busy(self, busy):
        state = ["disabled"] if busy else ["!disabled"]
        for btn in self._toolbar_buttons:
            btn.state(state)
        if busy:
            self.status_var.set("Checking online list for new IPs…")
        else:
            self._refresh_stats()

    def _update_worker(self):
        try:
            remote = fetch_remote_ips(UPDATE_URL)
            error = None
        except urllib.error.URLError as e:
            remote, error = [], f"Couldn't reach the update URL:\n{e}"
        except Exception as e:
            remote, error = [], f"Update failed:\n{e}"
        self.after(0, self._apply_update_results, remote, error)

    def _apply_update_results(self, remote, error):
        self._set_update_ui_busy(False)
        if error:
            messagebox.showerror("Update Failed", error)
            self._populate()
            return
        if not remote:
            messagebox.showinfo("Update List", "No IPs were found in the online list.")
            self._populate()
            return

        existing = {e["ip"] for e in self.ip_data}
        added = 0
        for ip, note in remote:
            if ip in existing:
                continue
            self.ip_data.append({"ip": ip, "note": note})
            self.blocked_state[ip] = False
            existing.add(ip)
            added += 1

        skipped = len(remote) - added
        if added:
            save_data(self.ip_data)
        self._populate()
        messagebox.showinfo(
            "Update List",
            f"Added {added} new IP(s).\n{skipped} were already in your list and were skipped.",
        )

    def _add_dialog(self):
        ip = simpledialog.askstring("Add IP", "IP address:", parent=self)
        if not ip:
            return
        ip = ip.strip()
        if any(e["ip"] == ip for e in self.ip_data):
            messagebox.showwarning("Duplicate", f"{ip} is already in the list.")
            return
        
        note = simpledialog.askstring("Add Note", f"Note for {ip} (optional):", parent=self) or ""
        
        self.ip_data.append({"ip": ip, "note": note})
        self.blocked_state[ip] = ip_blocked(ip)
        save_data(self.ip_data)
        self._populate()

    def _edit_note_selected(self):
        ips = self._selected_ips()
        if not ips:
            messagebox.showinfo("No selection", "Select a row first.")
            return
        if len(ips) > 1:
            messagebox.showinfo("Multiple selected", "Please select only one IP to edit its note.")
            return
        ip = ips[0]
        current_note = next((e.get("note", "") for e in self.ip_data if e["ip"] == ip), "")
        new_note = simpledialog.askstring("Edit Note", f"Update note for {ip}:", 
                                         initialvalue=current_note, parent=self)
        if new_note is None:
            return
        for e in self.ip_data:
            if e["ip"] == ip:
                e["note"] = new_note
                break
        save_data(self.ip_data)
        self._populate()

    def _remove_selected(self):
        ips = self._selected_ips()
        if not ips:
            messagebox.showinfo("No selection", "Select one or more rows first.")
            return
        if not messagebox.askyesno("Remove IP(s)",
                                    f"Remove {len(ips)} IP(s) from the list?\n"
                                    "Firewall rules will also be deleted."):
            return
        for ip in ips:
            unblock_ip(ip)
            self.blocked_state.pop(ip, None)
        self.ip_data = [e for e in self.ip_data if e["ip"] not in ips]
        save_data(self.ip_data)
        self._populate()

    def _no_admin(self):
        messagebox.showwarning("Insufficient Privileges",
            "Firewall rules require Administrator privileges.\n"
            "Please restart the application as Administrator.")

    def _on_close(self):
        save_data(self.ip_data)
        self.destroy()

# ── entry ────────────────────────────────────────────────────────────────────
def main():
    App().mainloop()

if __name__ == "__main__":
    if not is_admin():
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable,
            " ".join(f'"{a}"' for a in sys.argv), None, 1)
        sys.exit(0)
    main()