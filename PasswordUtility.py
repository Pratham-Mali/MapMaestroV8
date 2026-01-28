import os
import base64
import tkinter as tk
import tkinter.font as tkfont
from tkinter.scrolledtext import ScrolledText
from tkinter import ttk, messagebox
from tkinter.scrolledtext import ScrolledText
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet

def derive_key(master: bytes, salt: bytes) -> bytes:
    """Derive a Fernet-compatible key from the master password and salt."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390_000,
    )
    return base64.urlsafe_b64encode(kdf.derive(master))

def encrypt_value(master: bytes, plaintext: bytes) -> str:
    """Encrypt a single plaintext value and return the raw base64 blob."""
    salt = os.urandom(16)
    key = derive_key(master, salt)
    token = Fernet(key).encrypt(plaintext)
    blob = base64.urlsafe_b64encode(salt + token).decode()
    return blob

class EncryptorApp:
    def __init__(self, root):
        root.title("Password Encryption Utility")
        root.resizable(False, False)

        # Master password
        ttk.Label(root, text="Master Password:").grid(row=0, column=0, padx=10, pady=5, sticky="e")
        self.master_entry = ttk.Entry(root, show="*", width=40)
        self.master_entry.grid(row=0, column=1, padx=10, pady=5)

        # Fields to encrypt
        self.fields = [
            ("Postgres DB URL", False),
            ("Postgres DB Password", True),
            ("Data Lineage DB URL", False),
            ("Data Lineage DB Password", True),
        ]
        self.entries = {}
        for i, (label, is_secret) in enumerate(self.fields, start=1):
            ttk.Label(root, text=label + ":").grid(row=i, column=0, padx=10, pady=5, sticky="e")
            ent = ttk.Entry(root, show="*" if is_secret else "", width=40)
            ent.grid(row=i, column=1, padx=10, pady=5)
            self.entries[label] = ent

        # Encrypt button
        encrypt_btn = ttk.Button(root, text="Encrypt All", command=self.on_encrypt)
        encrypt_btn.grid(row=len(self.fields)+1, column=0, columnspan=2, pady=10)

        # Output area
        self.bold_font = tkfont.Font(root=root, weight="bold")

        # Output area
        self.output = ScrolledText(root, width=70, height=10, wrap=tk.WORD)
        self.output.grid(row=len(self.fields)+2, column=0, columnspan=2, padx=10, pady=(0,10))

        # configure a tag that uses that bold font
        self.output.tag_configure("label_bold", font=self.bold_font)

    def on_encrypt(self):
        master_pw = self.master_entry.get().encode()
        if not master_pw:
            messagebox.showerror("Error", "Master password cannot be empty.")
            return

        self.output.delete("1.0", tk.END)
        try:
            for label, _ in self.fields:
                plain = self.entries[label].get().encode()
                blob  = encrypt_value(master_pw, plain)
                self.output.insert(tk.END, f"{label}=  ", "label_bold")
                # insert the rest normally
                self.output.insert(tk.END, f"ENC({blob})\n")
        except Exception as e:
            messagebox.showerror("Encryption Error", str(e))

if __name__ == "__main__":
    root = tk.Tk()
    EncryptorApp(root)
    root.mainloop()
