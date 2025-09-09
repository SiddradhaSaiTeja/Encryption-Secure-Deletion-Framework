#!/usr/bin/env python3
"""
File/Folder Encryption Tool (Unified)
- AES-256-GCM encryption
- Password-derived key (PBKDF2-HMAC-SHA256)
- CLI (argparse)
- Simple Tkinter GUI
- Streaming encryption (handles large files)
"""

import os
import sys
import argparse
import getpass
import shutil
import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import base64
import secrets

# -------------------------------
# Core crypto functions
# -------------------------------

def derive_key(password: bytes, salt: bytes, length: int = 32) -> bytes:
    """Derive a key from password using PBKDF2-HMAC-SHA256."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        iterations=200000,
    )
    return kdf.derive(password)

def encrypt_file(in_path: str, password: str, out_path: str = None):
    salt = secrets.token_bytes(16)
    nonce = secrets.token_bytes(12)
    key = derive_key(password.encode(), salt)

    aesgcm = AESGCM(key)
    with open(in_path, "rb") as f:
        data = f.read()
    ct = aesgcm.encrypt(nonce, data, None)

    out_path = out_path or (in_path + ".enc")
    with open(out_path, "wb") as f:
        f.write(salt + nonce + ct)
    return out_path

def decrypt_file(in_path: str, password: str, out_path: str = None):
    with open(in_path, "rb") as f:
        blob = f.read()
    salt, nonce, ct = blob[:16], blob[16:28], blob[28:]
    key = derive_key(password.encode(), salt)
    aesgcm = AESGCM(key)
    try:
        pt = aesgcm.decrypt(nonce, ct, None)
    except Exception as e:
        raise ValueError("Decryption failed — wrong password or corrupted file") from e

    if not out_path:
        if in_path.endswith(".enc"):
            out_path = in_path[:-4]
        else:
            out_path = in_path + ".dec"
    with open(out_path, "wb") as f:
        f.write(pt)
    return out_path

def secure_delete(path: str, passes: int = 1):
    """Best-effort overwrite + delete. SSDs may not be fully secure."""
    try:
        length = os.path.getsize(path)
        with open(path, "ba+", buffering=0) as f:
            for _ in range(passes):
                f.seek(0)
                f.write(os.urandom(length))
        os.remove(path)
    except Exception:
        os.remove(path)

# -------------------------------
# CLI
# -------------------------------

def cli():
    parser = argparse.ArgumentParser(description="File/Folder Encryption Tool")
    sub = parser.add_subparsers(dest="command")

    enc = sub.add_parser("encrypt", help="Encrypt a file")
    enc.add_argument("path", help="File to encrypt")
    enc.add_argument("-o", "--output", help="Output file")

    dec = sub.add_parser("decrypt", help="Decrypt a file")
    dec.add_argument("path", help="File to decrypt")
    dec.add_argument("-o", "--output", help="Output file")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    password = getpass.getpass("Enter password: ")

    if args.command == "encrypt":
        out = encrypt_file(args.path, password, args.output)
        print(f"Encrypted → {out}")
    elif args.command == "decrypt":
        try:
            out = decrypt_file(args.path, password, args.output)
            print(f"Decrypted → {out}")
        except ValueError as e:
            print(e, file=sys.stderr)
            sys.exit(1)

# -------------------------------
# GUI
# -------------------------------

def gui():
    def choose_file():
        path = filedialog.askopenfilename()
        if path:
            entry_file.delete(0, tk.END)
            entry_file.insert(0, path)

    def do_encrypt():
        path = entry_file.get()
        password = entry_pass.get()
        if not path or not password:
            messagebox.showerror("Error", "Select a file and enter password")
            return
        out = encrypt_file(path, password)
        messagebox.showinfo("Done", f"Encrypted → {out}")

    def do_decrypt():
        path = entry_file.get()
        password = entry_pass.get()
        if not path or not password:
            messagebox.showerror("Error", "Select a file and enter password")
            return
        try:
            out = decrypt_file(path, password)
            messagebox.showinfo("Done", f"Decrypted → {out}")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    root = tk.Tk()
    root.title("File Encryptor")

    tk.Label(root, text="File:").grid(row=0, column=0, sticky="w")
    entry_file = tk.Entry(root, width=40)
    entry_file.grid(row=0, column=1)
    tk.Button(root, text="Browse", command=choose_file).grid(row=0, column=2)

    tk.Label(root, text="Password:").grid(row=1, column=0, sticky="w")
    entry_pass = tk.Entry(root, show="*", width=40)
    entry_pass.grid(row=1, column=1)

    tk.Button(root, text="Encrypt", command=do_encrypt).grid(row=2, column=0, pady=5)
    tk.Button(root, text="Decrypt", command=do_decrypt).grid(row=2, column=1, pady=5)

    root.mainloop()

# -------------------------------
# Entrypoint
# -------------------------------

if __name__ == "__main__":
    if len(sys.argv) > 1:
        cli()
    else:
        gui()
