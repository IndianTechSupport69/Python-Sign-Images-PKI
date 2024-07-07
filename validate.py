import os
import hashlib
import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter import ttk
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

def verify_image(signed_image_path, public_key_path):
    with open(signed_image_path, 'rb') as signed_file:
        content = signed_file.read()
    
    try:
        image_data, signature = content.split(b'\n--SIGNATURE--\n')
    except ValueError:
        raise ValueError("The signed image file is not correctly formatted or not signed.")
    
    hash_object = hashlib.sha256(image_data)
    image_hash = hash_object.digest()
    
    with open(public_key_path, 'rb') as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(),
        )
    
    try:
        public_key.verify(
            signature,
            image_hash,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        return False

def open_signed_image_file():
    initial_dir = os.path.abspath(os.path.dirname(__file__))
    file_path = filedialog.askopenfilename(
        initialdir=initial_dir,
        filetypes=[("Signed Image Files", "*")]
    )
    if file_path:
        signed_image_entry.delete(0, tk.END)
        signed_image_entry.insert(0, file_path)

def open_public_key_file():
    initial_dir = os.path.abspath(os.path.dirname(__file__))
    file_path = filedialog.askopenfilename(
        initialdir=initial_dir,
        filetypes=[("PEM Files", "*.pem")]
    )
    if file_path:
        public_key_entry.delete(0, tk.END)
        public_key_entry.insert(0, file_path)

def validate_image():
    signed_image_path = signed_image_entry.get()
    public_key_path = public_key_entry.get()
    
    if not signed_image_path:
        messagebox.showerror("Error", "Please select a signed image file.")
        return
    
    if not public_key_path:
        messagebox.showerror("Error", "Please select a public key file.")
        return
    
    try:
        if verify_image(signed_image_path, public_key_path):
            messagebox.showinfo("Success", "The image signature is valid.")
        else:
            messagebox.showerror("Error", "The image signature is invalid.")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to validate the image: {e}")

app = tk.Tk()
app.title("Image Signature Validator")
app.geometry("600x200")

style = ttk.Style()
style.configure("TLabel", font=("Helvetica", 12))
style.configure("TButton", font=("Helvetica", 12))
style.configure("TEntry", font=("Helvetica", 12))

frame = ttk.Frame(app, padding="10 10 10 10")
frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

app.columnconfigure(0, weight=1)
app.rowconfigure(0, weight=1)

ttk.Label(frame, text="Select Signed Image File:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
signed_image_entry = ttk.Entry(frame, width=50)
signed_image_entry.grid(row=0, column=1, padx=5, pady=5)
ttk.Button(frame, text="Browse...", command=open_signed_image_file).grid(row=0, column=2, padx=5, pady=5)

ttk.Label(frame, text="Select Public Key File:").grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
public_key_entry = ttk.Entry(frame, width=50)
public_key_entry.grid(row=1, column=1, padx=5, pady=5)
ttk.Button(frame, text="Browse...", command=open_public_key_file).grid(row=1, column=2, padx=5, pady=5)

ttk.Button(frame, text="Validate Image", command=validate_image).grid(row=2, column=0, columnspan=3, pady=20)

app.mainloop()
