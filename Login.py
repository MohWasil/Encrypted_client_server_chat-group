# import modules

import math
import random
from tkinter import *
import json
import DataBase
import ast
import AES
import Ceaser
import DES
import Digital_sig
import Elgamal
import RSA
from client import ChatClient


# Designing window for registration


class GUI:
    def __init__(self):
        self.option = ''
        self.check = False
        self.msg_encrypted = None
        self.msg_decrypted = None
        self.chunk = ''
        self.user = ''
        self.register_screen = None
        self.email = None
        self.username = None
        self.password = None
        self.email_entry = None
        self.username_entry = None
        self.password_entry = None
        self.login_screen = None
        self.client = None
        self.username_login_entry = None
        self.email_login_entry = None
        self.password_login_entry = None
        self.username_verify = None
        self.email_verify = None
        self.password_verify = None
        self.login_success_screen = None
        self.chat_display = None
        self.entry = None
        self.send_button = None
        self.password_not_recognized_screen = None
        self.alg_type = None
        self.placeholder = 'Enter Text ...'

    # Registration page

    def register(self):
        self.register_screen = Toplevel(main_screen)
        self.register_screen.title("Register")
        self.register_screen.geometry("300x250")

        self.username = StringVar()
        self.password = StringVar()
        self.email = StringVar()

        Label(self.register_screen, text="Please enter details below").pack()
        Label(self.register_screen, text="").pack()
        username_label = Label(self.register_screen, text="Username * ")
        username_label.pack()
        self.username_entry = Entry(self.register_screen, textvariable=self.username)
        self.username_entry.pack()
        email_label = Label(self.register_screen, text='Email *')
        email_label.pack()
        self.email_entry = Entry(self.register_screen, textvariable=self.email)
        self.email_entry.pack()
        password_label = Label(self.register_screen, text="Password * ")
        password_label.pack()
        self.password_entry = Entry(self.register_screen, textvariable=self.password, show='*')
        self.password_entry.pack()
        Label(self.register_screen, text="").pack()
        Button(self.register_screen, text="Register", width=10, height=1, command=self.register_user).pack()

    # Designing window for login

    def login(self):
        self.login_screen = Toplevel(main_screen)
        self.login_screen.title("Login")
        self.login_screen.geometry("300x400")
        Label(self.login_screen, text="Please enter details below to login").pack()
        Label(self.login_screen, text="").pack()

        self.username_verify = StringVar()
        self.email_verify = StringVar()
        self.password_verify = StringVar()

        Label(self.login_screen, text="Username * ").pack()
        self.username_login_entry = Entry(self.login_screen, textvariable=self.username_verify)
        self.username_login_entry.pack()
        Label(self.login_screen, text="").pack()
        Label(self.login_screen, text='Email *').pack()
        self.email_login_entry = Entry(self.login_screen, textvariable=self.email_verify)
        self.email_login_entry.pack()
        Label(self.login_screen, text="").pack()
        Label(self.login_screen, text="Password * ").pack()
        self.password_login_entry = Entry(self.login_screen, textvariable=self.password_verify, show='*')
        self.password_login_entry.pack()
        Label(self.login_screen, text="").pack()
        Button(self.login_screen, text="Login", width=10, height=1, command=self.login_verify).pack()

    # Implementing event on register button

    def register_user(self):
        username_info = self.username.get()
        password_info = self.password.get()
        email_info = self.email.get()

        # Saving the data into Database

        DataBase.ob.insert(username_info, email_info, password_info)

        self.username_entry.delete(0, END)
        self.email_entry.delete(0, END)
        self.password_entry.delete(0, END)

        Label(self.register_screen, text="Registration Success", fg="green", font=("calibre", 11)).pack()

    # Verify the login

    def login_verify(self):
        self.user = self.username_verify.get()
        email1 = self.email_verify.get()
        password1 = self.password_verify.get()
        self.username_login_entry.delete(0, END)
        self.email_login_entry.delete(0, END)
        self.password_login_entry.delete(0, END)

        if DataBase.ob.checked(self.user, email1, password1):
            self.client = ChatClient('192.168.43.150', 12345)
            self.login_success()

        else:
            self.password_not_recognised()

    # Designing popup for login success

    def login_success(self):
        root = Tk()
        menu_btn = Menubutton(root, text='Select', relief=RAISED)
        root.geometry('400x400')
        menu_btn.menu = Menu(menu_btn, tearoff=0)
        menu_btn["menu"] = menu_btn.menu
        ceaser = IntVar()
        des = IntVar()
        aes = IntVar()
        sig = IntVar()
        rsa = IntVar()
        elgamal = IntVar()

        menu_btn.menu.add_checkbutton(label="Ceaser", variable=ceaser,
                                      command=lambda: self.check_display(root, "Ceaser"))
        menu_btn.menu.add_checkbutton(label="DES", variable=des, command=lambda: self.check_display(root, "DES"))
        menu_btn.menu.add_checkbutton(label="AES", variable=aes, command=lambda: self.check_display(root, "AES"))
        menu_btn.menu.add_checkbutton(label="Sig", variable=sig, command=lambda: self.check_display(root, "Sig"))
        menu_btn.menu.add_checkbutton(label="RSA", variable=rsa, command=lambda: self.check_display(root, "RSA"))
        menu_btn.menu.add_checkbutton(label="Elgamal", variable=elgamal,
                                      command=lambda: self.check_display(root, "Elgamal"))
        menu_btn.pack(padx=20, pady=20)

        menu_btn.mainloop()

    # Check the selected Algorythm

    def check_display(self, root, option):
        if self.check:
            self.destroy_current_page()

        if option == 'Ceaser':
            self.text_area(root, option)
        elif option == 'DES':
            self.text_area(root, option)
        elif option == 'AES':
            self.text_area(root, option)
        elif option == 'Sig':
            self.text_area(root, option)
        elif option == 'RSA':
            self.text_area(root, option)
        elif option == 'Elgamal':
            self.text_area(root, option)

    # Destroy the textbox if more then one item is selected

    def destroy_current_page(self):
        self.chat_display.destroy()
        self.entry.destroy()
        self.send_button.destroy()

    # Tkinter TextBox

    def text_area(self, root, option):
        root.title("Chat Application")

        self.chat_display = Text(root, height=10, width=40, state=DISABLED)
        self.chat_display.pack(pady=(10, 10))

        # Create an Entry widget for typing messages
        self.entry = Entry(root, width=40)

        # Creating Placeholder in message box

        self.entry.insert(0, self.placeholder)
        self.entry.bind("<FocusIn>", self.focus_in)
        self.entry.bind("<FocusOut>", self.focus_out)
        self.entry.pack()

        # Create a Send button

        self.send_button = Button(root, text="Send", command=lambda: self.encrypt_msg(option), width=10)
        self.send_button.pack(pady=(10, 10))

        self.check_for_message(root)

    # End Placeholder focusing

    def focus_in(self, event):
        if self.entry.get() == self.placeholder:
            self.entry.delete(0, END)

    # Start Placeholder focusing

    def focus_out(self, event):
        if not self.entry.get():
            self.entry.insert(0, self.placeholder)

    # Check for received message from server

    def check_for_message(self, root):
        if self.client.messages:
            for message in self.client.messages:
                self.decrypt_msg(message, root)
            self.client.messages = []
        main_screen.after(1000, self.check_for_message, root)

    # Encrypt entered message

    def encrypt_msg(self, option):
        self.check = True
        message = self.entry.get()
        if option == 'Ceaser':
            self.alg_type = 'Ceaser'
            self.msg_encrypted = Ceaser.MultiCeaser().encryption(message)
        elif option == 'DES':
            self.alg_type = 'DES'
            self.msg_encrypted = DES.Des().encryption(message.encode())
        elif option == 'AES':
            self.alg_type = 'AES'
            self.msg_encrypted = AES.Aes().encryption(message.encode())
        elif option == 'RSA':
            self.alg_type = 'RSA'
            self.msg_encrypted = RSA.RSA().encryption(message.encode())
        elif option == 'Sig':
            self.alg_type = 'Digital_sig'
            self.msg_encrypted = Digital_sig.Digital_signature().encryption(message.encode())
        elif option == 'Elgamal':
            self.alg_type = 'Elgamal'
            q = random.randint(int(math.pow(10, 20)), int(math.pow(10, 50)))
            g = random.randint(2, q)
            key = Elgamal.gen_key(q)
            h = Elgamal.power(g, key, q)
            self.msg_encrypted = Elgamal.encrypt(message, q, h, g, key)

        self.msg_encrypted.append(self.user)
        self.msg_encrypted.append(self.alg_type)
        self.alg_type = ''
        self.send_message(self.msg_encrypted)

    # Send the encrypted message to server

    def send_message(self, msg_encrypted: str):
        message = self.entry.get()
        if message:
            # Change list to string and convert into json format
            json_format = json.dumps(str(msg_encrypted))
            self.client.send(json_format.encode('utf-8'))

            self.chat_display.insert(END, "You: " + message + "\n")
            self.entry.delete(0, END)

    # Decrypt the received message

    def decrypt_msg(self, received_msg, root):
        received_list = list(json.loads(received_msg.decode('utf-8')))

        joi = ''.join(received_list)
        convert_to_str = ast.literal_eval(joi)
        name = convert_to_str[-2]

        if convert_to_str[-1] == 'Ceaser':
            self.msg_decrypted = Ceaser.MultiCeaser().decryption(convert_to_str[0], convert_to_str[1])
        elif convert_to_str[-1] == 'DES':
            self.msg_decrypted = DES.Des().decryption(convert_to_str[0], convert_to_str[1], convert_to_str[2])
        elif convert_to_str[-1] == 'AES':
            self.msg_decrypted = AES.Aes().decryption(convert_to_str[0], convert_to_str[1], convert_to_str[2])
        elif convert_to_str[-1] == 'RSA':
            self.msg_decrypted = RSA.RSA().decryption(convert_to_str[0])
        elif convert_to_str[-1] == 'Digital_sig':
            self.msg_decrypted = Digital_sig.Digital_signature().decryption(convert_to_str[0], convert_to_str[1])
        elif convert_to_str[-1] == 'Elgamal':
            self.msg_decrypted = Elgamal.decrypt(convert_to_str[0], convert_to_str[1], convert_to_str[2],
                                                 convert_to_str[3])

        root.after(0, self.display_msg_to_screen, self.msg_decrypted, name)

    # Display the message on tkinter interface

    def display_msg_to_screen(self, msg_decrypted, name):
        self.chat_display.config(state=NORMAL)
        self.chat_display.insert(END, f'{name}: ' + msg_decrypted + '\n')
        self.chat_display.config(state=DISABLED)

    # Designing popup for login invalid password

    def password_not_recognised(self):
        self.password_not_recognized_screen = Toplevel(self.login_screen)
        self.password_not_recognized_screen.title("Success")
        self.password_not_recognized_screen.geometry("150x100")
        Label(self.password_not_recognized_screen, text="Invalid Password or Email").pack()
        Button(self.password_not_recognized_screen, text="OK", command=self.delete_password_not_recognised).pack()

    # Deleting password or email or user not found

    def delete_password_not_recognised(self):
        self.password_not_recognized_screen.destroy()


# Designing Main(first) window
# from tkinter import Toplevel

ob = GUI()


def main_account_screen():
    main_screen.resizable(True, True)
    main_screen.geometry("300x250")
    main_screen.configure(bg='#F0F8FF')
    main_screen.title("Account Login")
    Label(text="Select Your Choice", width="300", height="2", font=("Calibre", 13)).pack()
    Label(text="").pack()
    Button(text="Login", height="2", width="30", command=ob.login, bg='white', borderwidth=0).pack()
    Label(text="").pack()
    Button(text="Register", height="2", width="30", command=ob.register, bg='white', borderwidth=0).pack()
    Label(text="").pack()
    Button(text="Quit", height="2", width="30", command=main_screen.destroy, bg='white', borderwidth=0).pack()
    main_screen.mainloop()


if __name__ == '__main__':
    main_screen = Tk()
    main_account_screen()
