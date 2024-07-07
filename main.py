import os
import hashlib
import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter import ttk
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

def generate_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    keys_dir = 'keys'
    os.makedirs(keys_dir, exist_ok=True)
    private_key_path = os.path.join(keys_dir, 'private_key.pem')
    public_key_path = os.path.join(keys_dir, 'public_key.pem')
    
    with open(private_key_path, 'wb') as key_file:
        key_file.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

    public_key = private_key.public_key()
    with open(public_key_path, 'wb') as key_file:
        key_file.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    return private_key_path, public_key_path

def sign_image(image_path, private_key_path, signed_image_path):
    with open(image_path, 'rb') as image_file:
        image_data = image_file.read()

    hash_object = hashlib.sha256(image_data)
    image_hash = hash_object.digest()

    with open(private_key_path, 'rb') as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
        )

    signature = private_key.sign(
        image_hash,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    with open(signed_image_path, 'wb') as signed_file:
        signed_file.write(image_data)
        signed_file.write(b'\n--SIGNATURE--\n')
        signed_file.write(signature)

def open_image_file():
    initial_dir = os.path.abspath(os.path.dirname(__file__))
    file_path = filedialog.askopenfilename(
        initialdir=initial_dir,
        filetypes=[("Image Files", "*.png;*.jpg;*.jpeg;*.bmp;*.gif;*.tiff")]
    )
    if file_path:
        image_entry.delete(0, tk.END)
        image_entry.insert(0, file_path)

def open_private_key_file():
    initial_dir = os.path.abspath(os.path.dirname(__file__))
    file_path = filedialog.askopenfilename(
        initialdir=initial_dir,
        filetypes=[("PEM Files", "*.pem")]
    )
    if file_path:
        key_entry.delete(0, tk.END)
        key_entry.insert(0, file_path)

def process_image():
    image_path = image_entry.get()
    key_path = key_entry.get()
    signed_image_name = signed_name_entry.get()
    
    if not image_path:
        messagebox.showerror("Error", "Please select an image file.")
        return

    if not signed_image_name:
        messagebox.showerror("Error", "Please enter a name for the signed image.")
        return

    if not key_path:
        private_key_path, public_key_path = generate_key_pair()
        messagebox.showinfo("Info", f"New key pair generated and saved in 'keys' folder.")
    else:
        private_key_path = key_path

    ext = os.path.splitext(image_path)[1]  # Keep the original file extension
    signed_image_path = f"{signed_image_name}{ext}"
    
    try:
        sign_image(image_path, private_key_path, signed_image_path)
        messagebox.showinfo("Success", f"Image signed and saved as {signed_image_path}")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to sign the image: {e}")

app = tk.Tk()
app.title("Image Signer")
app.geometry("600x250")

style = ttk.Style()
style.configure("TLabel", font=("Helvetica", 12))
style.configure("TButton", font=("Helvetica", 12))
style.configure("TEntry", font=("Helvetica", 12))

frame = ttk.Frame(app, padding="10 10 10 10")
frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

app.columnconfigure(0, weight=1)
app.rowconfigure(0, weight=1)

ttk.Label(frame, text="Select Image File:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
image_entry = ttk.Entry(frame, width=50)
image_entry.grid(row=0, column=1, padx=5, pady=5)
ttk.Button(frame, text="Browse...", command=open_image_file).grid(row=0, column=2, padx=5, pady=5)

ttk.Label(frame, text="Select Private Key File (optional):").grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
key_entry = ttk.Entry(frame, width=50)
key_entry.grid(row=1, column=1, padx=5, pady=5)
ttk.Button(frame, text="Browse...", command=open_private_key_file).grid(row=1, column=2, padx=5, pady=5)

ttk.Label(frame, text="Enter Signed Image Name:").grid(row=2, column=0, padx=5, pady=5, sticky=tk.W)
signed_name_entry = ttk.Entry(frame, width=50)
signed_name_entry.grid(row=2, column=1, padx=5, pady=5)

ttk.Button(frame, text="Sign Image", command=process_image).grid(row=3, column=0, columnspan=3, pady=20)

app.mainloop()
