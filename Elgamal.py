import random
from math import pow


def gcd(base_value, exponent_value):
    if base_value < exponent_value:
        return gcd(exponent_value, base_value)
    elif base_value % exponent_value == 0:
        return exponent_value
    else:
        return gcd(exponent_value, base_value % exponent_value)


# Generating large random numbers
def gen_key(prime_num):
    key = random.randint(int(pow(10, 20)), prime_num)
    while gcd(prime_num, key) != 1:
        key = random.randint(int(pow(10, 20)), prime_num)

    return key


# Modular exponentiation
def power(base_value, exponent_value, module_value):
    x = 1
    y = base_value

    while exponent_value > 0:
        if exponent_value % 2 != 0:
            x = (x * y) % module_value
        y = (y * y) % module_value
        exponent_value = int(exponent_value / 2)

    return x % module_value


# Asymmetric encryption
def encrypt(msg, prime_num, public_key, generator_val, key):
    en_msg = []

    k = gen_key(prime_num)  # Private key for sender
    s = power(public_key, k, prime_num)
    p = power(generator_val, k, prime_num)

    for i in range(0, len(msg)):
        en_msg.append(msg[i])

    # print("g^k used : ", p)
    # print("g^ak used : ", s)
    for i in range(0, len(en_msg)):
        en_msg[i] = s * ord(en_msg[i])

    return [en_msg, p, key, prime_num]


def decrypt(en_msg, exponentiation_result, key, prime_val):
    dr_msg = []
    h = power(exponentiation_result, key, prime_val)
    for i in range(0, len(en_msg)):
        dr_msg.append(chr(int(en_msg[i] / h)))

    return ''.join(dr_msg)


# Driver code
# def main():
#     msg = 'encryption'
#     print("Original Message :", msg)
#
#     q = random.randint(pow(10, 20), pow(10, 50))
#     g = random.randint(2, q)
#
#     key = gen_key(q)  # Private key for receiver
#     h = power(g, key, q)
#     print("g used : ", g)
#     print("g^a used : ", h)
#
#     en_msg, p, k, a = encrypt(msg, q, h, g, key)
#     dr_msg = decrypt(en_msg, p, key, q)
#     dmsg = ''.join(dr_msg)
#     print("Decrypted Message :", dmsg)
#
#
# if __name__ == '__main__':
#     main()
