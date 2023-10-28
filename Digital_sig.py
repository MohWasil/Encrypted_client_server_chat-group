import rsa


class Digital_signature:
    def __init__(self):
        self.sig = b''
        with open('public_key.pem', 'rb') as f:
            public_key = rsa.PublicKey.load_pkcs1(f.read())
        self.public_key = public_key

    def encryption(self, message):
        # public_key, private_key = rsa.newkeys(1024)
        with open('private_key.pem', 'rb') as f:
            private_key = rsa.PrivateKey.load_pkcs1(f.read())
        msg_encrypted = rsa.sign(message, private_key, 'SHA-512')
        # with open('signature', 'rb') as f:
        #     signature = f.read()
        self.sig = msg_encrypted
        return [message, self.sig]

    def decryption(self, message, sig):
        decrypted = rsa.verify(message, sig, self.public_key)
        return decrypted


if __name__ == '__main__':
    Digital_signature()





















# from tkinter import Tk, Menu, Menubutton, StringVar, IntVar, RAISED
#
# root = Tk()
# class YourClassName:
#     def __init__(self):
#         self.selected_option = StringVar()
#
#     def login_success(self):
#         global login_success_screen
#         menu_btn = Menubutton(root, text='Select', relief=RAISED)
#         root.geometry('400x400')
#         menu_btn.menu = Menu(menu_btn, tearoff=0)
#         menu_btn["menu"] = menu_btn.menu
#         Ceaser = IntVar()
#         DES = IntVar()
#         AES = IntVar()
#         Sig = IntVar()
#         RSA = IntVar()
#         Elgamal = IntVar()
#
#         menu_btn.menu.add_checkbutton(label="Ceaser", variable=Ceaser, command=lambda: self.set_selected_option("Ceaser"))
#         menu_btn.menu.add_checkbutton(label="DES", variable=DES, command=lambda: self.set_selected_option("DES"))
#         menu_btn.menu.add_checkbutton(label="AES", variable=AES, command=lambda: self.set_selected_option("AES"))
#         menu_btn.menu.add_checkbutton(label="Sig", variable=Sig, command=lambda: self.set_selected_option("Sig"))
#         menu_btn.menu.add_checkbutton(label="RSA", variable=RSA, command=lambda: self.set_selected_option("RSA"))
#         menu_btn.menu.add_checkbutton(label="Elgamal", variable=Elgamal, command=lambda: self.set_selected_option("Elgamal"))
#
#         menu_btn.pack(padx=20, pady=20)
#         root.mainloop()
#     def set_selected_option(self, option):
#         self.selected_option.set(option)
#         print(f"Selected option: {option}")
#
#
# # Create an instance of YourClassName
# app = YourClassName()
# app.login_success()
