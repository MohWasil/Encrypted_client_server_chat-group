from Crypto.Cipher import DES
from Cryptodome.Random import get_random_bytes


class Des:
    def __init__(self, key=get_random_bytes(8)):
        self.key = key
        self.msg_encrypted = ''
        self.nonce = ''

    def encryption(self, message):
        cipher = DES.new(self.key, DES.MODE_EAX)
        self.msg_encrypted = cipher.encrypt(message)
        self.nonce = cipher.nonce
        return [self.msg_encrypted, self.nonce, self.key]

    def decryption(self, msg_encrypted, nonce, key):
        cipher = DES.new(key, DES.MODE_EAX, nonce)
        msg_decrypted = cipher.decrypt(msg_encrypted)
        return msg_decrypted.decode()


if __name__ == '__main__':
    Des()
