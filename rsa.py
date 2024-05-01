import hashlib
import math
import timeit
from math import gcd
from bitness import generate_prime
from hash_alg import SHA1
from simple_hash import simple_hash


def modinv(a, m):
    m0, x0, x1 = m, 0, 1
    if m == 1:
        return 0
    while a > 1:
        # q is quotient
        q = a // m
        m, a = a % m, m
        x0, x1 = x1 - q * x0, x0
    if x1 < 0:
        x1 += m0
    return x1


def lcm(a, b):
    return abs(a * b) // math.gcd(a, b)


def hash_message(message):
    return hashlib.sha1(message.encode()).hexdigest()


class RSA:
    def __init__(self, bit_length):
        self.p = generate_prime(bit_length)
        self.q = generate_prime(bit_length)
        self.n = self.p * self.q
        self.lambda_n = lcm(self.p - 1, self.q - 1)
        self.e = self.find_e()
        self.d = self.find_d()
        # Зберігаємо обернені значення для КТЗ
        self.d_p = self.d % (self.p - 1)
        self.d_q = self.d % (self.q - 1)
        self.q_inv = modinv(self.q, self.p)  # обернене для q по модулю p

    def find_e(self):
        e = 3
        while math.gcd(e, self.lambda_n) != 1:
            e += 2
        return e

    def find_d(self):
        if self.e is None:
            raise ValueError("e was not set correctly")
        return modinv(self.e, self.lambda_n)

    def encrypt(self, message):
        return [pow(ord(char), self.e, self.n) for char in message]

    def chinese_remainder_theorem(self, c):
        m1 = pow(c, self.d_p, self.p)
        m2 = pow(c, self.d_q, self.q)
        # Застосовуємо КТЗ
        h = (self.q_inv * (m1 - m2)) % self.p
        message = (m2 + h * self.q) % self.n
        return message

    def decrypt(self, encrypted_message):
        # Розшифровуємо кожен символ за допомогою КТЗ
        return ''.join(chr(self.chinese_remainder_theorem(c)) for c in encrypted_message)

    def sign(self, message):
        # md4 = MD4()
        # md4.update(message)
        # message_hash = int(md4.hexdigest(), 16)
        # message_hash = int(hashlib.sha1(message.encode()).hexdigest(), 16)
        message_hash = simple_hash(message)
        # sha1 = SHA1()  # Створення екземпляра SHA1
        # sha1.update(message)  # Оновлення даних для обчислення хешу
        # message_hash = int(sha1.hexdigest(), 16)  # Перетворення хешу в ціле число
        # message_hash &= ((1 << bit_length) - 1)
        signature = pow(message_hash, self.d, self.n)
        return signature

    def verify(self, message, signature):
        # md4 = MD4()
        # md4.update(message)
        # message_hash = int(md4.hexdigest(), 16)
        # message_hash = int(hashlib.sha1(message.encode()).hexdigest(), 16)
        message_hash = simple_hash(message)
        # sha1 = SHA1()  # Створення екземпляра SHA1
        # sha1.update(message)  # Оновлення даних для обчислення хешу
        # message_hash = int(sha1.hexdigest(), 16)  # Перетворення хешу в ціле число
        # message_hash &= ((1 << bit_length) - 1)
        decrypted_hash = pow(signature, self.e, self.n)
        return message_hash == decrypted_hash


class User:
    def __init__(self, rsa, name):
        self.rsa = rsa
        self.name = name

    def send_message(self, message, recipient):
        print(f"{self.name} sends: {message}")
        encrypted_message = self.rsa.encrypt(message)
        signature = self.rsa.sign(message)
        recipient.receive_message(encrypted_message, signature, self.name)
        print("Encrypted message: ", encrypted_message)
        print("Signature: ", signature)

    def receive_message(self, encrypted_message, signature, sender_name):
        message = self.rsa.decrypt(encrypted_message)
        valid_signature = self.rsa.verify(message, signature)
        print(f"{self.name} received from {sender_name}: {message} - {'Signature valid.' if valid_signature else 'Signature invalid.'}")
        if valid_signature:
            print("Decrypted message: ", message)
            hash_of_message = hash_message(message)
            print("Hash of message: ", hash_of_message)


bit_length = 16
rsa = RSA(bit_length)

alice = User(rsa, "Alice")
bob = User(rsa, "Bob")

alice.send_message("Hello, Bob!", bob)
bob.send_message("Hi, Alice!", alice)
