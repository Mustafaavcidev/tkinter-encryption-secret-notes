from tkinter import *
from tkinter import messagebox
from PIL import ImageTk, Image
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
import base64

window = Tk()
window.title("Secret Notes")
window.geometry("450x750")
window.config(pady=15,padx=15)
FONT = ("Arial", 12, "italic")
def clear_inputs():
    user_title_entry.delete(0,"end")
    user_secret_text.delete("1.0", "end")
    enter_key_Entry.delete(0,"end")
    user_title_entry.focus()
def derive_key(master_key):
    salt = b'some_salt'
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        iterations=100000,  # İterasyon sayısını ayarlayabilirsiniz
        salt=salt,
        length=32  # Anahtar uzunluğunu ayarlayabilirsiniz
    )
    key = base64.urlsafe_b64encode(kdf.derive(master_key.encode()))
    return key
def save_encrypt():
    title = user_title_entry.get()
    secret_text = user_secret_text.get("1.0", "end")
    master_key = enter_key_Entry.get()

    if title == "" or secret_text == "" or master_key == "":
        message_error = messagebox.showerror(
            title = "Error",
            message= "Please enter a value....!"
        )
    else:
        # Anahtar türetme
        derived_key = derive_key(master_key)
        cipher_suite = Fernet(derived_key)

        # Metni şifrele
        encrypted_text = cipher_suite.encrypt(secret_text.encode('utf-8'))

        # Encode edilmiş veriyi base64 ile dosyaya yaz
        encoded_text = base64.b64encode(encrypted_text).decode('utf-8')

        with open("info.txt", "a") as file:
            file.write(f"Title: {title}  \n")
            file.write(f"Text: {encoded_text}\n\n")

        message = messagebox.showinfo(
            title="İnfo",
            message="Saved and Encrypted"
        )
    clear_inputs()
def decrypt_text():
    master_key = enter_key_Entry.get()
    requested_title = user_title_entry.get()

    if master_key == "" or requested_title == "":
        message_error = messagebox.showerror(
            title="Error",
            message="Please enter the master key and title of the encrypted text....!"
        )
    else:
        encrypted_text = get_encrypted_text_from_file(requested_title)

        if encrypted_text:
            derived_key = derive_key(master_key)
            cipher_suite = Fernet(derived_key)
            decoded_text = base64.b64decode(encrypted_text)
            decrypted_text = cipher_suite.decrypt(decoded_text).decode('utf-8')

            messagebox.showinfo(
                title="Decrypted Text",
                message=f"Decrypted Text: {decrypted_text}"
            )
        else:
            messagebox.showerror(
                title="Error",
                message=f"No encrypted text found with the title '{requested_title}'."
            )
def get_encrypted_text_from_file(requested_title):
    encrypted_text = None
    with open("info.txt", "r") as file:
        lines = file.readlines()
        for line in lines:
            if line.startswith(f"Title: {requested_title}"):
                for next_line in lines[lines.index(line) + 1:]:
                    if next_line.startswith("Text: "):
                        encrypted_text = next_line.replace("Text: ", "").strip()
                        return encrypted_text
    return encrypted_text

#load image
image = Image.open("ımage.png")
image = ImageTk.PhotoImage(image)
image_label = Label(window, image=image,width=150,height=200)
image_label.pack() #label içerisinde tutabiliriz resmi.
title_label = Label(text="Enter your title",font=FONT,pady=15,padx=15)
title_label.pack()
user_title_entry = Entry(width=40)
user_title_entry.focus()
user_title_entry.pack()
secret_label = Label(text="Enter your secret", font=FONT,pady=15,padx=15)
secret_label.pack()
user_secret_text = Text(width=30,height=15)
user_secret_text.pack()
enter_key_label = Label(text="Enter master key", font=FONT,pady=15,padx=15)
enter_key_label.pack()
enter_key_Entry = Entry(width=40)
enter_key_Entry.pack()
save_button = Button(text="Save & Encrypt", font=FONT, pady=5, padx=5, command=save_encrypt)
save_button.pack()
decrypt_button = Button(text="Decrypt", font=FONT, pady=5, padx=5, command=decrypt_text)
decrypt_button.pack()
window.mainloop()

