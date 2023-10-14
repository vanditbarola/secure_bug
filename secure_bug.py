import os
import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.fernet import Fernet
import hashlib
import zlib
import subprocess
from PIL import Image
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import base64


def compress_image(file_path):
    img = Image.open(file_path)
    img.save("compressed_" + os.path.basename(file_path), "JPEG", quality=50)
def encrypt_and_compress_file(input_file, output_file, passphrase):
    key = generate_key_from_passphrase(passphrase)  # Generate a key from the passphrase
    fernet = Fernet(key)


    with open(input_file, 'rb') as f_in:
        data = f_in.read()
    compressed_data = zlib.compress(data)
    encrypted_data = fernet.encrypt(compressed_data)

    with open(output_file, 'wb') as f_out:
        f_out.write(encrypted_data)


    print("Encryption Complete.")    

def decrypt_and_decompress(input_file, output_file, passphrase):
    key = generate_key_from_passphrase(passphrase)  # Generate a key from the passphrase
    fernet = Fernet(key)

    
    with open(input_file, 'rb') as f_in:
        encrypted_data = f_in.read()
    decompressed_data = zlib.decompress(fernet.decrypt(encrypted_data))

    with open(output_file, 'wb') as f_out:
        f_out.write(decompressed_data)


    print("Decryption Complete.")

def compress_video(input_file, output_file):
    try:
        # Adjust video settings for compression
        subprocess.run([
            'ffmpeg',
            '-i', input_file,
            '-vf', 'scale=1280:720',  # Adjust the resolution as needed
            '-b:v', '1000k',  # Adjust the video bitrate as needed
            '-c:v', 'libx264',  # Video codec
            '-crf', '23',  # Adjust the video quality (lower values mean higher quality)
            '-c:a', 'aac',  # Audio codec
            '-b:a', '128k',  # Adjust the audio bitrate as needed
            output_file
        ], check=True)
        print("Compression successful.")
    except subprocess.CalledProcessError as e:
        print(f"Error compressing video: {e}")
    
def encrypt_and_compress_image(input_file, output_file, passphrase):
    key = generate_key_from_passphrase(passphrase)  # Generate a key from the passphrase
    fernet = Fernet(key)


    with open(input_file, 'rb') as f_in:
        data = f_in.read()
    compressed_data = zlib.compress(data)
    encrypted_data = fernet.encrypt(compressed_data)

    with open(output_file, 'wb') as f_out:
        f_out.write(encrypted_data)

        
def encrypt_and_compress_video(input_file, output_file, passphrase):
    key = generate_key_from_passphrase(passphrase)
    fernet = Fernet(key)

    try:
        with open(input_file, 'rb') as f_in:
            data = f_in.read()
        compressed_data = zlib.compress(data)
        encrypted_data = fernet.encrypt(compressed_data)

        with open(output_file, 'wb') as f_out:
            f_out.write(encrypted_data)

        return "Encryption and Compression Complete."
    except Exception as e:
        return "Error: " + str(e)

def generate_key_from_passphrase(passphrase):
    salt = b'#e4rD'  # Use the same salt for both encryption and decryption
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        iterations=100000,  # Adjust the number of iterations as needed
        salt=salt,
        length=32  # Specify the desired key length (32 bytes for Fernet)
    )
    key = base64.urlsafe_b64encode(kdf.derive(passphrase.encode()))
    return key

def check_data_integrity(original_file, decrypted_file):
    original_size = os.path.getsize(original_file)
    decrypted_size = os.path.getsize(decrypted_file)

    if original_size == decrypted_size:
        return f"Data Integrity Check: Data is preserved. Efficiency: 100.00%"
    else:
        data_loss = original_size - decrypted_size
        efficiency = (decrypted_size / original_size) * 100
        return f"Data Integrity Check: Data loss detected. Data Loss: {data_loss} bytes, Efficiency: {efficiency:.2f}%"

def log_activity(log_text, text_widget):
    text_widget.config(state="normal")
    text_widget.insert(tk.END, log_text + "\n")
    text_widget.config(state="disabled")
    text_widget.see(tk.END)

def compression_panel():
    panel_compression = tk.Toplevel(app)
    panel_compression.title("Compression Options")
    panel_compression.geometry("900x700")

    tk.Label(panel_compression, text="Enter Passphrase:").pack()
    entry_passphrase = tk.Entry(panel_compression, show="*")
    entry_passphrase.pack()
    button_padding = {'padx': 10, 'pady': 10}

    activity_text = tk.Text(panel_compression, height=10, state="disabled")
    activity_text.pack()

    def image_compression():
        log_activity("Image Compression in progress...", activity_text)
        try:
            original_file = filedialog.askopenfilename(title="Select the original image file")
            if not original_file:
                return
            compressed_image_path = "compressed_" + os.path.basename(original_file)
            compress_image(original_file)
            
            output_file = filedialog.asksaveasfilename(title="Save the compressed and encrypted image")
            if not output_file:
                return  
            passphrase = entry_passphrase.get()
             # Remove the unencrypted compressed image

            
            result = encrypt_and_compress_image(compressed_image_path, output_file, passphrase)
            os.remove(compressed_image_path)
            log_activity(result, activity_text)
            
            messagebox.showinfo("Result", "nice")
        except Exception as e:
            log_activity("Error: " + str(e), activity_text)

    def video_compression():
        log_activity("Video Compression in progress...", activity_text)
        try:
            original_file = filedialog.askopenfilename(title="Select the original video file")
            if not original_file:
                return
            
            compressed_video_path = "compressed_" + os.path.basename(original_file)
            compress_video(original_file, compressed_video_path)

            output_file = filedialog.asksaveasfilename(title="Save the compressed and encrypted video")
            if not output_file:
                return

            passphrase = entry_passphrase.get()
            result = encrypt_and_compress_video(compressed_video_path, output_file, passphrase)
            os.remove(compressed_video_path)
            log_activity(result, activity_text)
            messagebox.showinfo("Result", result)
        except Exception as e:
            log_activity("Error: " + str(e), activity_text)

    def text_compression():
        log_activity("Text Compression in progress...", activity_text)
        try:
            original_file = filedialog.askopenfilename(title="Select the original text file")
            if not original_file:
                return

            output_file = filedialog.asksaveasfilename(title="Save the compressed and encrypted text")
            if not output_file:
                return

            passphrase = entry_passphrase.get()
            result = encrypt_and_compress_file(original_file, output_file, passphrase)
            log_activity(result, activity_text)
            messagebox.showinfo("Result", result)
        except Exception as e:
            log_activity("Error: " + str(e), activity_text)

   
    def check_integrity():
        original_file = filedialog.askopenfilename(title="Select the original file for integrity check")
        if not original_file:
            return

        decrypted_file = filedialog.askopenfilename(title="Select the decrypted file for integrity check")
        if not decrypted_file:
            return

        efficiency = check_data_integrity(original_file, decrypted_file)
          # Ensure efficiency is a float
        log_activity(efficiency, activity_text)
    
    tk.Button(panel_compression, text="Compress Image", command=image_compression, padx=10, pady=10).pack()
    tk.Button(panel_compression, text="Compress Video", command=video_compression, padx=10, pady=10).pack()
    tk.Button(panel_compression, text="Compress Text", command=text_compression, padx=10, pady=10).pack()
    tk.Button(panel_compression, text="Show Integrity", command=check_integrity, padx=10, pady=10).pack()
    tk.Button(panel_compression, text="Back to Main", command=panel_compression.destroy, padx=10, pady=10).pack()
    
def decompression_panel():
    panel_decompression = tk.Toplevel(app)
    panel_decompression.title("Decompression Options")
    panel_decompression.geometry("900x700")

    tk.Label(panel_decompression, text="Enter Passphrase:").pack()
    entry_passphrase = tk.Entry(panel_decompression, show="*")
    entry_passphrase.pack()

    activity_text = tk.Text(panel_decompression, height=10, state="disabled")
    activity_text.pack()

    def decompress():
        log_activity("Decompression in progress...", activity_text)
        try:
            original_file = filedialog.askopenfilename(title="Select the encrypted file to decompress")
            if not original_file:
                return

            output_file = filedialog.asksaveasfilename(title="Save the decrypted and decompressed file")
            if not output_file:
                return

            passphrase = entry_passphrase.get()
            result = decrypt_and_decompress(original_file, output_file, passphrase)
            log_activity(result, activity_text)

            # Check data integrity and efficiency
            integrity_result = check_data_integrity(original_file, output_file)
            log_activity(integrity_result, activity_text)

            messagebox.showinfo("Result", result)
        except Exception as e:
            log_activity("Error: " + str(e), activity_text)

    tk.Button(panel_decompression, text="Decompress", command=decompress).pack()
    tk.Button(panel_decompression, text="Back to Main", command=panel_decompression.destroy).pack()

def exit_app():
    app.destroy()

app = tk.Tk()
app.title("File Processing Application")
app.geometry("1200x700")
app.configure(bg="midnight blue")

compression_button = tk.Button(app, text="Compression", command=compression_panel, padx=100, pady=10)
compression_button.pack(pady=80)
decompression_button = tk.Button(app, text="Decompression", command=decompression_panel, padx=100, pady=10)
decompression_button.pack(pady=80)
exit_button = tk.Button(app, text="Exit", command=exit_app, padx=140, pady=10)
exit_button.pack(pady=80)

app.mainloop()
