#!/usr/bin/env python3
import os
import json
import base64
import secrets
import time
import hashlib
import tkinter as tk
from datetime import datetime
from pathlib import Path
from collections import deque
from tkinter import ttk, filedialog, messagebox

# Cryptography Imports
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa, padding

# --- CONFIG ---
COLORS = {
    "bg": "#0f172a", "card": "#1e293b", "accent": "#38bdf8",
    "success": "#10b981", "warning": "#facc15", "danger": "#ef4444",
    "text": "#f8fafc", "border": "#334155", "terminal_bg": "#020617",
}
STORAGE_DIR = Path.home() / ".securecrypt_final"
STORAGE_DIR.mkdir(parents=True, exist_ok=True)
USERS_DB = STORAGE_DIR / "users_db.json"
HEADER_MAGIC = b"SCP5_V6"
KDF_ITER = 200_000

# --- CRYPTO & UTILITY HELPERS ---
def b64(b: bytes) -> str: return base64.urlsafe_b64encode(b).decode()
def ub64(s: str) -> bytes: return base64.urlsafe_b64decode(s.encode())

def hash_password(password, salt=None):
    if salt is None: salt = secrets.token_bytes(16)
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=KDF_ITER)
    return b64(salt), b64(kdf.derive(password.encode()))

def derive_key(password: str, salt: bytes):
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=KDF_ITER)
    return kdf.derive(password.encode('utf-8'))

def secure_shred(file_path: Path):
    try:
        size = file_path.stat().st_size
        with open(file_path, "ba+", buffering=0) as f:
            for _ in range(3):
                f.seek(0); f.write(secrets.token_bytes(size)); os.fsync(f.fileno())
        file_path.rename(file_path.with_name(secrets.token_hex(8))).unlink()
        return True
    except: return False

def get_user_keys(username):
    priv_path = STORAGE_DIR / f"{username}_private.pem"
    pub_path = STORAGE_DIR / f"{username}_public.pem"
    if not priv_path.exists():
        private_key = rsa.generate_private_key(65537, 2048)
        with open(priv_path, "wb") as f:
            f.write(private_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        with open(pub_path, "wb") as f:
            f.write(private_key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    with open(priv_path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)

# --- MAIN APP ---
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("SecureCrypt Pro V6")
        self.geometry("1150x800")
        self.configure(bg=COLORS["bg"])
        self.current_user = None
        self.recent_files = deque(maxlen=5)

        style = ttk.Style()
        style.theme_use('clam')
        style.configure("TProgressbar", thickness=10, troughcolor=COLORS["terminal_bg"], background=COLORS["success"])

        self.container = tk.Frame(self, bg=COLORS["bg"])
        self.container.pack(fill="both", expand=True)
        self.frames = {}
        for F in (LoginPage, MainPage, EncryptPage, DecryptPage, IdentityPage):
            frame = F(self.container, self)
            self.frames[F.__name__] = frame
            frame.grid(row=0, column=0, sticky="nsew")

        self.show_frame("LoginPage")

    def show_frame(self, name):
        if name != "LoginPage" and not self.current_user:
            name = "LoginPage"
        frame = self.frames[name]
        frame.tkraise()
        if hasattr(frame, 'on_show'): frame.on_show()

    def logout(self):
        self.current_user = None
        self.recent_files.clear()
        for frame in self.frames.values():
            if hasattr(frame, 'reset_fields'): frame.reset_fields()
        self.show_frame("LoginPage")

# --- PAGES ---
class LoginPage(tk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent, bg=COLORS["bg"])
        self.controller = controller
        card = tk.Frame(self, bg=COLORS["card"], padx=40, pady=40, highlightthickness=1, highlightbackground=COLORS["border"])
        card.place(relx=0.5, rely=0.5, anchor="center")

        tk.Label(card, text="🛡️CipherVault Pro", font=("Segoe UI", 22, "bold"), fg=COLORS["accent"], bg=COLORS["card"]).pack(pady=(0, 20))
        
        tk.Label(card, text="Operator Name", fg=COLORS["text"], bg=COLORS["card"]).pack(anchor="w")
        self.u = tk.Entry(card, bg=COLORS["bg"], fg="white", relief="flat", width=35, font=("Segoe UI", 11)); self.u.pack(pady=(5, 15), ipady=5)

        tk.Label(card, text="Master Password", fg=COLORS["text"], bg=COLORS["card"]).pack(anchor="w")
        self.p_var = tk.StringVar(); self.p_var.trace_add("write", self.check_strength)
        self.p = tk.Entry(card, textvariable=self.p_var, show="*", bg=COLORS["bg"], fg="white", relief="flat", width=35, font=("Segoe UI", 11)); self.p.pack(pady=(5, 5), ipady=5)

        self.strength_bar = ttk.Progressbar(card, orient="horizontal", mode="determinate", length=280); self.strength_bar.pack(pady=5)
        self.strength_lbl = tk.Label(card, text="Strength: 0%", font=("Segoe UI", 8), bg=COLORS["card"], fg=COLORS["border"]); self.strength_lbl.pack()

        tk.Button(card, text="LOGIN / REGISTER", bg=COLORS["accent"], fg=COLORS["bg"], font=("Segoe UI", 10, "bold"),
                  relief="flat", pady=12, command=self.auth_action).pack(fill="x", pady=20)

    def check_strength(self, *args):
        p = self.p_var.get()
        score = min(100, (len(p)*10))
        self.strength_bar['value'] = score
        color = COLORS["danger"] if score < 40 else (COLORS["warning"] if score < 70 else COLORS["success"])
        self.strength_lbl.config(text=f"Security Level: {score}%", fg=color)

    def auth_action(self):
        user, pw = self.u.get().strip(), self.p_var.get()
        if not user or len(pw) < 4:
            messagebox.showwarning("Incomplete", "Enter name and password (min 4 chars).")
            return
        
        db = {}
        if USERS_DB.exists():
            with open(USERS_DB, "r") as f: db = json.load(f)

        if user not in db:
            salt, h_pw = hash_password(pw)
            db[user] = {"salt": salt, "hash": h_pw}
            with open(USERS_DB, "w") as f: json.dump(db, f)
            messagebox.showinfo("Account Created", f"New operator registered: {user}")
        else:
            salt = ub64(db[user]["salt"])
            _, check_h = hash_password(pw, salt)
            if check_h != db[user]["hash"]:
                messagebox.showerror("Denied", "Incorrect password.")
                return

        self.controller.current_user = user
        get_user_keys(user)
        self.controller.show_frame("MainPage")

    def reset_fields(self):
        self.u.delete(0, tk.END); self.p_var.set(""); self.strength_bar['value'] = 0

class MainPage(tk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent, bg=COLORS["bg"])
        self.controller = controller
        
        side = tk.Frame(self, bg=COLORS["card"], width=260); side.pack(side="left", fill="y"); side.pack_propagate(False)
        tk.Label(side, text="MENU", bg=COLORS["card"], fg=COLORS["accent"], font=("Segoe UI", 10, "bold")).pack(pady=30)
        
        for txt, pg in [("Dashboard", "MainPage"), ("Identity Manager", "IdentityPage"), ("Encrypt Asset", "EncryptPage"), ("Decrypt Asset", "DecryptPage")]:
            tk.Button(side, text=f"  {txt}", bg=COLORS["card"], fg="white", relief="flat", anchor="w", padx=25, pady=12,
                      command=lambda p=pg: self.controller.show_frame(p)).pack(fill="x")
        
        tk.Label(side, text="LATEST ACTIVITY", bg=COLORS["card"], fg=COLORS["border"], font=("Segoe UI", 8, "bold")).pack(pady=(40, 10), padx=25, anchor="w")
        self.activity_frame = tk.Frame(side, bg=COLORS["card"]); self.activity_frame.pack(fill="x", padx=10)

        tk.Button(side, text="LOGOUT", bg=COLORS["danger"], fg="white", relief="flat", command=controller.logout).pack(side="bottom", fill="x", pady=20)

        main = tk.Frame(self, bg=COLORS["bg"], padx=40, pady=40); main.pack(side="right", expand=True, fill="both")
        tk.Label(main, text="Console Log", font=("Segoe UI", 22, "bold"), fg=COLORS["accent"], bg=COLORS["bg"]).pack(anchor="w")
        self.term = tk.Text(main, bg=COLORS["terminal_bg"], fg=COLORS["success"], font=("Consolas", 11), relief="flat", padx=20, pady=20)
        self.term.pack(expand=True, fill="both", pady=20)

    def log(self, msg):
        ts = datetime.now().strftime('%H:%M:%S')
        self.term.insert(tk.END, f"[{ts}] # {msg}\n"); self.term.see(tk.END)

    def on_show(self):
        for w in self.activity_frame.winfo_children(): w.destroy()
        for f in self.controller.recent_files:
            tk.Label(self.activity_frame, text=f"📄 {f}", bg=COLORS["card"], fg=COLORS["text"], font=("Segoe UI", 8)).pack(anchor="w", pady=2, padx=15)

    def reset_fields(self): self.term.delete("1.0", tk.END)

class EncryptPage(tk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent, bg=COLORS["bg"])
        self.controller, self.selected = controller, None
        card = tk.Frame(self, bg=COLORS["card"], padx=40, pady=40); card.place(relx=0.5, rely=0.5, anchor="center")
        
        tk.Label(card, text="Encrypt Asset", font=("Segoe UI", 18, "bold"), fg=COLORS["accent"], bg=COLORS["card"]).pack()
        self.lbl = tk.Label(card, text="No file selected", bg=COLORS["card"], fg=COLORS["border"]); self.lbl.pack(pady=10)
        tk.Button(card, text="SELECT FILE", command=self.pick).pack()
        
        tk.Label(card, text="Shared Key Phrase", bg=COLORS["card"], fg="white").pack(anchor="w", pady=(20,0))
        self.k_ent = tk.Entry(card, bg=COLORS["bg"], fg="white", relief="flat", width=40); self.k_ent.pack(pady=10, ipady=8)

        self.shred_v = tk.BooleanVar()
        tk.Checkbutton(card, text="Securely Shred Original File?", variable=self.shred_v, bg=COLORS["card"], fg=COLORS["danger"], selectcolor=COLORS["bg"]).pack()

        tk.Button(card, text="ENCRYPT & SIGN", bg=COLORS["success"], command=self.run, pady=12).pack(fill="x", pady=10)
        tk.Button(card, text="← BACK", bg=COLORS["card"], fg=COLORS["accent"], command=lambda: controller.show_frame("MainPage")).pack()

    def pick(self):
        p = filedialog.askopenfilename()
        if p: self.selected = Path(p); self.lbl.config(text=self.selected.name, fg=COLORS["accent"])

    def run(self):
        if not self.selected or not self.k_ent.get(): return
        try:
            salt = secrets.token_bytes(16); key = derive_key(self.k_ent.get(), salt)
            aesgcm = AESGCM(key); nonce = secrets.token_bytes(12)
            with open(self.selected, "rb") as f: pt = f.read()
            f_hash = hashlib.sha256(pt).digest()
            ct = aesgcm.encrypt(nonce, pt, None)
            
            sig = get_user_keys(self.controller.current_user).sign(f_hash, padding.PSS(padding.MGF1(hashes.SHA256()), padding.PSS.MAX_LENGTH), hashes.SHA256())
            meta = {"salt": b64(salt), "nonce": b64(nonce), "hash": f_hash.hex(), "creator": self.controller.current_user, "sig": b64(sig)}
            
            meta_b = json.dumps(meta).encode()
            payload = HEADER_MAGIC + len(meta_b).to_bytes(4, 'big') + meta_b + ct
            out = self.selected.with_suffix(self.selected.suffix + ".crypt")
            with open(out, "wb") as f: f.write(payload)
            
            msg = f"ENCRYPTED: {out.name}"
            self.controller.recent_files.appendleft(out.name)
            if self.shred_v.get(): secure_shred(self.selected); msg += " (Original Shredded 🗑️)"
            
            self.controller.frames["MainPage"].log(msg)
            self.controller.show_frame("MainPage")
        except Exception as e: messagebox.showerror("Error", str(e))

    def reset_fields(self):
        self.selected = None
        self.lbl.config(text="No file selected", fg=COLORS["border"])
        self.k_ent.delete(0, tk.END); self.shred_v.set(False)

class DecryptPage(tk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent, bg=COLORS["bg"])
        self.controller, self.selected = controller, None
        card = tk.Frame(self, bg=COLORS["card"], padx=40, pady=40); card.place(relx=0.5, rely=0.5, anchor="center")
        self.lbl = tk.Label(card, text="Select .crypt file", bg=COLORS["card"], fg="white"); self.lbl.pack()
        tk.Button(card, text="LOAD ASSET", command=self.pick).pack(pady=10)
        self.k_ent = tk.Entry(card, bg=COLORS["bg"], fg="white", relief="flat", width=40); self.k_ent.pack(pady=10, ipady=8)
        tk.Button(card, text="VALIDATE & RESTORE", bg=COLORS["accent"], command=self.run, pady=12).pack(fill="x")
        tk.Button(card, text="BACK", bg=COLORS["card"], fg=COLORS["accent"], command=lambda: controller.show_frame("MainPage")).pack()

    def pick(self):
        p = filedialog.askopenfilename(filetypes=[("Crypt Files", "*.crypt")])
        if p: self.selected = Path(p); self.lbl.config(text=self.selected.name)

    def run(self):
        try:
            with open(self.selected, "rb") as f: data = f.read()
            pos = len(HEADER_MAGIC)
            m_len = int.from_bytes(data[pos:pos+4], 'big'); pos += 4
            meta = json.loads(data[pos:pos+m_len].decode()); pos += m_len
            key = derive_key(self.k_ent.get(), ub64(meta['salt']))
            pt = AESGCM(key).decrypt(ub64(meta['nonce']), data[pos:], None)
            
            out = self.selected.with_name(self.selected.stem)
            with open(out, "wb") as f: f.write(pt)
            
            self.controller.recent_files.appendleft(out.name)
            self.controller.frames["MainPage"].log(f"RESTORED: {out.name} (Signed by {meta['creator']})")
            self.controller.show_frame("MainPage")
        except: messagebox.showerror("Error", "Invalid key or corrupt file.")

    def reset_fields(self): self.selected = None; self.k_ent.delete(0, tk.END)

class IdentityPage(tk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent, bg=COLORS["bg"])
        self.controller = controller
        card = tk.Frame(self, bg=COLORS["card"], padx=40, pady=40); card.place(relx=0.5, rely=0.5, anchor="center")
        tk.Label(card, text="Operator Identity", font=("Segoe UI", 18, "bold"), bg=COLORS["card"], fg=COLORS["accent"]).pack()
        self.info = tk.Label(card, text="", bg=COLORS["card"], fg="white"); self.info.pack(pady=20)
        tk.Button(card, text="EXPORT PUBLIC KEY (.PEM)", command=self.export, bg=COLORS["success"]).pack(fill="x")
        tk.Button(card, text="← BACK", command=lambda: controller.show_frame("MainPage")).pack(pady=10)

        tk.Label(card, text="⚠️ DISCLAIMER: Developer is not responsible for data loss due to lost passwords or keys.", 
         font=("Segoe UI", 8, "italic"), fg=COLORS["danger"], bg=COLORS["card"], wraplength=350).pack(side="bottom", pady=10)

    def on_show(self): self.info.config(text=f"Operator: {self.controller.current_user}\nEncryption: RSA-2048 / AES-GCM")
    
    def export(self):
        path = STORAGE_DIR / f"{self.controller.current_user}_public.pem"
        save = filedialog.asksaveasfilename(defaultextension=".pem", initialfile=f"{self.controller.current_user}_pub.pem")
        if save:
            import shutil; shutil.copy(path, save) 
            messagebox.showinfo("Success", "Public key exported!")

    def reset_fields(self): self.info.config(text="")

if __name__ == "__main__":
    App().mainloop()