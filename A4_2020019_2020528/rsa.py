import time
import socket
import json
from datetime import datetime
from cryptography.fernet import Fernet
import random
import math

class RSA:
    def is_prime(self,n):
        for i in range(2,int(math.sqrt(n))+1):
            if(n%i==0):
                return False
        return True

    def work(self):
        # Compute the product of p and q
        while True:
            p = random.randint(2, 1000)
            if self.is_prime(p):
                break
        self.p = p

        while True:
            q = random.randint(2, 1000)
            if self.is_prime(q) and p != q:
                break
        self.q = q
        self.n = p*q
        # Choose e such that gcd(e, phi_n) == 1.
        self.phi_n = (self.p - 1) * (self.q - 1)

        # choose e is randomly till e is coprime to phi_n.
        self.e = self.phi_n
        while math.gcd(self.e, self.phi_n) != 1:
            self.e = random.randint(2, self.phi_n - 1)

        # Choose d such that e * d % phi_n = 1.
        self.d = self.modular_inverse()

        return ((self.n,self.d),(self.n,self.e))

    def modular_inverse(self):
        # find the modular inverse of e using the rule taught in class
        # remainder
        R = []
        # quotient
        Q = []
        # inverse
        T = []
        
        # Initialization    
        R.append(self.phi_n)
        R.append(self.e)
        T.append(0)
        T.append(1)
        Q.append(0)
        Q.append(0)
        i = 1
        # iteratively moving till we get remainder  as 0
        while R[i] != 0:
            Q.append(R[i - 1] // R[i])
            R.append(R[i - 1] % R[i])
            T.append(T[i - 1] - Q[i + 1] * T[i])
            i += 1
        # return the modular inverse of e as the last element of T list modulo phi_n
        return T[i - 1] % self.phi_n

    def rsa_encrypt_text(self,plaintext,key):
        n, e = key
        #encrypting the plaintext
        encrypted = ''
        output = str(plaintext)
        for letter in output:
            encrypted = encrypted + chr(pow(ord(letter), e,n))
        return encrypted.encode()


    def rsa_decrypt_text(self,ciphertext,key):
        n, d = key
        ciphertext = ciphertext.decode()
        #decrypting the ciphertext
        decrypted = ''
        for letter in ciphertext:
            decrypted = decrypted + chr(pow(ord(letter),d,n))
        decrypted = decrypted[2:-1].encode().decode('unicode_escape').encode('latin1')
        return decrypted    


    def encrypt(self, message, public_key):
        n, e = public_key
        cipher = [pow(ord(char), e, n) for char in message]
        cipher = str(cipher).encode()
        return cipher
    
    def decrypt(self, cipher, private_key):
        n, d = private_key
        cipher = cipher.decode()
        cipher = cipher.strip('][').split(', ')
        cipher = [int(i) for i in cipher]
        plain = [chr(pow(char, d, n)) for char in cipher]
        plain = ''.join(plain)
        return plain
