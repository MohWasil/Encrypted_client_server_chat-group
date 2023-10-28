import rsa


class RSA:
    def __init__(self):
        # self.message = message.encode()
        self.msg_encrypted = b''
        self.msg_decrypted = b''

    def encryption(self, message):
        # public_key, private_key = rsa.newkeys(1024)
        # with open('private_key.pem', 'wb') as f:
        #     f.write(private_key.save_pkcs1('PEM'))
        #
        # with open('public_key.pem', 'wb') as f:
        #     f.write(public_key.save_pkcs1('PEM'))
        with open('public_key.pem', 'rb') as f:
            public_key = rsa.PublicKey.load_pkcs1(f.read())
        self.msg_encrypted += rsa.encrypt(message, public_key)
        print(self.msg_encrypted)
        return [self.msg_encrypted]

    def decryption(self, msg_encrypted):
        with open('private_key.pem', 'rb') as f:
            private_key = rsa.PrivateKey.load_pkcs1(f.read())
        msg_decrypted = rsa.decrypt(msg_encrypted, private_key)
        return msg_decrypted.decode()


if __name__ == '__main__':
    RSA()

