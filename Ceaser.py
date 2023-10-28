import random


class MultiCeaser:
    def __init__(self):
        self.key = random.randint(1, 1000)
        self.msgEncrypted = ''
        self.msgDecrypted = ''
        self.letterBasedOnNum = dict()
        self.letterBasedOnChr = dict()
        self.CoPrime = 0

        # Creating the characters in dictionary

        for num in range(52):
            if num <= 25:
                self.letterBasedOnChr[chr(num+65)] = num
                self.letterBasedOnNum[num] = chr(num+65)
            else:
                self.letterBasedOnChr[chr(num-26+97)] = num
                self.letterBasedOnNum[num] = chr(num-26+97)
        self.letterBasedOnChr[chr(32)] = 52
        self.letterBasedOnNum[52] = chr(32)

    # Creating the Co_prime key for decryption

    def multiplication_inverse_key(self, key):
        for num in range(1, 53):
            if (key * num) % 53 == 1:
                self.CoPrime = num
                return self.CoPrime

    def encryption(self, message):
        for let in message:
            self.msgEncrypted += self.letterBasedOnNum[(self.letterBasedOnChr[let] * self.key) % 53]
        return [self.msgEncrypted, self.multiplication_inverse_key(self.key)]

    def decryption(self, msg_encrypted, co_prime):
        for let in msg_encrypted:
            self.msgDecrypted += self.letterBasedOnNum[(self.letterBasedOnChr[let] * co_prime) % 53]
        print(self.msgDecrypted)
        return self.msgDecrypted


if __name__ == '__main__':
    MultiCeaser()
