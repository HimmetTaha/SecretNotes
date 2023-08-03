from tkinter import *
import customtkinter  # I used CustomTkinter for achieving a slightly modern appearance
from tkinter import messagebox
import base64

screen = customtkinter.CTk()
screen.title("Secret Notes")
screen.geometry("500x600")
screen.configure(bg="#EAE7E7")


# Vigenere chipper cryptography

def encode(key, clear):
    enc = []
    for i in range(len(clear)):
        key_c = key[i % len(key)]
        enc_c = chr((ord(clear[i]) + ord(key_c)) % 256)
        enc.append(enc_c)
    return base64.urlsafe_b64encode("".join(enc).encode()).decode()


def decode(key, enc):
    dec = []
    enc = base64.urlsafe_b64decode(enc).decode()
    for i in range(len(enc)):
        key_c = key[i % len(key)]
        dec_c = chr((256 + ord(enc[i]) - ord(key_c)) % 256)
        dec.append(dec_c)
    return "".join(dec)


# Save

def encrypt_save():
    title = entry1.get()
    message = secret_text.get("1.0", END)
    master_secret = secret_key_input.get()

    if len(title) == 0 or len(message) == 0 or len(master_secret) == 0:
        messagebox.showinfo(title="Error!", message="Please enter all information.")
    else:
        message_encrypted = encode(master_secret, message)

        try:
            with open("mysecret.txt", "a") as data_file:
                data_file.write(f'\n{title}\n{message_encrypted}')
        except FileNotFoundError:
            with open("mysecret.txt", "w") as data_file:
                data_file.write(f'\n{title}\n{message_encrypted}')
        finally:
            entry1.delete(0, END)
            secret_key_input.delete(0, END)
            secret_text.delete("1.0", END)


# Decrypt text

def decrypt():
    message_encrypted = secret_text.get("1.0", END)
    master_secret = secret_key_input.get()

    if len(message_encrypted) == 0 or len(master_secret) == 0:
        messagebox.showinfo(title="Error!", message="Please enter all information.")
    else:
        try:
            decrypted_message = decode(master_secret, message_encrypted)
            secret_text.delete("1.0", END)
            secret_text.insert("1.0", decrypted_message)
        except:
            messagebox.showinfo(title="Error!", message="Please make sure of encrypted info.")


# İnterface

# İmage

canvas = Canvas(height=200, width=200)
logo = PhotoImage(file="topsecret.png")
canvas.create_image(100, 100, image=logo)
canvas.pack()

# Label

title_label = customtkinter.CTkLabel(master=screen, text="Enter your title", font=("Verdena", 15, "normal"))
title_label.pack()

# Entry

entry1 = customtkinter.CTkEntry(master=screen, width=200)
entry1.pack()

# Label2

text_label = customtkinter.CTkLabel(master=screen, text="Enter your secret", font=("Verdena", 15, "normal"))
text_label.pack()

# Text

secret_text = customtkinter.CTkTextbox(master=screen, width=250, height=250)
secret_text.pack()

secret_key = customtkinter.CTkLabel(master=screen, text="Enter a master key", font=("Verdena", 15, "normal"))
secret_key.pack()

secret_key_input = customtkinter.CTkEntry(master=screen, width=200)
secret_key_input.pack()

save_button = customtkinter.CTkButton(master=screen, corner_radius=10, text="Save & Encrypt",
                                      command=encrypt_save)
save_button.pack(pady=15)

decrypt_button = customtkinter.CTkButton(master=screen, corner_radius=10, text="Decrypt", command=decrypt, )
decrypt_button.pack()

screen.mainloop()
