import math
import random

class RSA:
    def work(self,p: int, q: int):
        # Compute the product of p and q
        self.p = p
        self.q = q
        self.n = p * q

        # Choose e such that gcd(e, phi_n) == 1.
        self.phi_n = (p - 1) * (q - 1)

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

    def rsa_encrypt_text(self,key, plaintext):
        n, e = key
        #encrypting the plaintext
        encrypted = ''
        output = str(plaintext)
        for letter in output:
            encrypted = encrypted + chr(pow(ord(letter), e,n))
        return encrypted


    def rsa_decrypt_text(self,key, ciphertext):
        n, d = key
        #decrypting the ciphertext
        decrypted = ''
        for letter in ciphertext:
            decrypted = decrypted + chr(pow(ord(letter),d,n))
        decrypted = decrypted[2:-1].encode().decode('unicode_escape').encode('latin1')
        return decrypted    

