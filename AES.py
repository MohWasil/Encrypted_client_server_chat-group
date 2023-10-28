from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES


class Aes:
    def __init__(self, key=get_random_bytes(16)):
        # self.message = message.encode()
        self.key = key
        self.msg_encrypted = ''
        self.nonce = ''

    def encryption(self, message):
        encrypted = AES.new(self.key, AES.MODE_GCM)
        self.msg_encrypted = encrypted.encrypt(message)
        self.nonce = encrypted.nonce
        return [self.msg_encrypted, self.nonce, self.key]

    def decryption(self, msg_encrypted, nonce, key):
        encrypted = AES.new(key, AES.MODE_GCM, nonce)
        msg_decrypted = encrypted.decrypt(msg_encrypted)
        return msg_decrypted.decode()


if __name__ == '__main__':
    Aes()
# print(ob.encryption(b'Salaam Afghanistan'))
# print(ob.decryption())
