# NSC Assignment 2
# Nakul Thureja - 2020528
# Akshat Saini - 2020019
class AES:
    def __init__(self, key):
        self.encrypt = False
        self.decrypt = False
        self.key = key
        self.plain_text = None
        self.cipher_text = None 
        self.key_size = len(key)
        self.nr = 10
        self.nk = 4
        self.s_box_string = '637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0b7fd9326363ff7cc34a5e5f171d8311504c723c31896059a071280e2eb27b27509832c1a1b6e5aa0523bd6b329e32f8453d100ed20fcb15b6acbbe394a4c58cfd0efaafb434d338545f9027f503c9fa851a3408f929d38f5bcb6da2110fff3d2cd0c13ec5f974417c4a77e3d645d197360814fdc222a908846eeb814de5e0bdbe0323a0a4906245cc2d3ac629195e479e7c8376d8dd54ea96c56f4ea657aae08ba78252e1ca6b4c6e8dd741f4bbd8b8a703eb5664803f60e613557b986c11d9ee1f8981169d98e949b1e87e9ce5528df8ca1890dbfe6426841992d0fb054bb16'
        self.s_box = bytearray.fromhex(self.s_box_string)
        self.inv_s_box_string = '52096ad53036a538bf40a39e81f3d7fb7ce339829b2fff87348e4344c4dee9cb547b9432a6c2233dee4c950b42fac34e082ea16628d924b2765ba2496d8bd12572f8f66486689816d4a45ccc5d65b6926c704850fdedb9da5e154657a78d9d8490d8ab008cbcd30af7e45805b8b34506d02c1e8fca3f0f02c1afbd0301138a6b3a9111414f67dcea97f2cfcef0b4e67396ac7422e7ad3585e2f937e81c75df6e47f11a711d29c5896fb7620eaa18be1bfc563e4bc6d279209adbc0fe78cd5af41fdda8338807c731b11210592780ec5f60517fa919b54a0d2de57a9f93c99cefa0e03b4dae2af5b0c8ebbb3c83539961172b047eba77d626e169146355210c7d'
        self.inv_s_box = bytearray.fromhex(self.inv_s_box_string)
    
    def xor_bytes(self,a, b):
        # function to XOR two byte strings
        l = []
        for (x, y) in zip(a, b):
            l.append(x ^ y)
        return bytes(l)

    def state_from_bytes(self,data):
        # Convert the byte string to a 4*4 matrix
        state = [data[i*4:(i+1)*4] for i in range(len(data) // 4)]
        return state

    def bytes_from_state(self, state):
        # Convert the state list to a byte string
        bytes_ = b''
        for i in range(len(state)):
            bytes_ += bytes(state[i])
        
        return bytes_

    def rcon(self, i):
        # Define a lookup table as a byte array, containing hexadecimal values
        rcon_lookup = bytearray.fromhex('01 02 04 08 10 20 40 80 1b 36'.replace(" ",""))
        # Retrieve the i-th value from the lookup table and append three zeros to create a byte array
        rcon_value = bytes([rcon_lookup[i-1], 0, 0, 0])
        # Return the byte array
        return rcon_value


    def sub_word(self,word):
        # function to substitute bytes in a word with s_box given the flag
        return bytes(self.s_box[i] for i in word)

    def key_expansion(self):
        # function to generate the round keys
        # convert initial key to 4*4 matrix
        w = self.state_from_bytes(self.key)

        # generate the rest of the keys
        for i in range(self.nk, self.nk * (self.nr + 1)):
            # performing operations of previous keys to generate new key
            temp = w[i-1]
            if i % self.nk == 0:
                temp = temp[1:] + temp[:1]
                temp = self.xor_bytes(self.sub_word((temp)), self.rcon(i // self.nk))
            elif self.nk > 6 and i % self.nk == 4:
                temp = self.sub_word(temp)
            temp = self.xor_bytes(temp, w[i - self.nk])
            w.append(temp)

        # return the round keys
        return [w[i:i+4] for i in range(0,len(w),4)]

    def add_round_key(self,state, round_key):
        # function to XOR the state with the round key
        for r in range(len(state)):
            l = []
            for j in range(len(state[0])):
                l.append(state[r][j] ^ round_key[r][j])
            state[r] = l


    def sub_bytes(self,state):
        # function to substitute bytes in state with s_box and inv_s_box given the flag
        if self.encrypt:
            for r in range(len(state)):
                state[r] = [self.s_box[state[r][c]] for c in range(len(state[0]))]
        if self.decrypt:
            for r in range(len(state)):
                state[r] = [self.inv_s_box[state[r][c]] for c in range(len(state[0]))]

    # returns transpose of a matrix
    def transpose(self,l1):
        l2 = []
        for i in range(len(l1[0])):
            row =[]
            for item in l1:
               row.append(item[i])
            l2.append(row)
        return l2

    def shift_rows(self,state):
        # shift rows by ith row i times
        state = self.transpose(state)
        if self.encrypt:
            for i in range(1, len(state)):
                state[i] = state[i][i:] + state[i][:i]
        if self.decrypt:
            for i in range(1, len(state)):
                state[i] = state[i][-i:] + state[i][:-i]
        state = self.transpose(state)
        return state


    def galois(self,a):
        # The first condition checks if the most significant bit of 'a' is zero (i.e., not set).
        if not a & 0x80:
            # If the most significant bit of 'a' is not set, the method multiplies 'a' by 2 and returns the result.
            return a << 1
        # If the most significant bit of 'a' is set, the method multiplies 'a' by 2 and XORs the result with the constant 0x1b.
        # The '&' operation is used to ensure that the result is truncated to 8 bits.
        return ((a << 1) ^ 0x1b) & 0xff
        
    def mix_column(self,col):
        c_0 = col[0]
        # 'all_xor' is initialized to the first byte of the input column.
        # The XOR operation is used to compute the result of XORing all the bytes in the input column.
        all_xor = col[0]
        all_xor = all_xor ^ col[1] 
        all_xor = all_xor ^ col[2]
        all_xor = all_xor ^ col[3]
        # The next 4 lines of code compute the result of multiplying the bytes in the input column with the matrix [2, 3, 1, 1; 1, 2, 3, 1; 1, 1, 2, 3; 3, 1, 1, 2].
        col[0] ^= all_xor ^ self.galois(col[1] ^ col[0])
        col[1] ^= all_xor ^ self.galois(col[2] ^ col[1])
        col[2] ^= all_xor ^ self.galois(col[3] ^ col[2])
        col[3] ^= all_xor ^ self.galois(col[3] ^ c_0)

    def mix_columns(self,state):
        for r in state:
            self.mix_column(r)

    def inv_mix_column(self,col):
        # The code to compute the inverse of the matrix [2, 3, 1, 1; 1, 2, 3, 1; 1, 1, 2, 3; 3, 1, 1, 2] for a single column.
        u_ = self.galois(col[2] ^ col[0])
        u = self.galois(u_)
        # The XOR operation is used to update the first and third bytes of the input column.
        col[0] ^= u
        col[2] ^= u
        v_ = self.galois(col[3] ^ col[1])
        v = self.galois(v_)        
        # The XOR operation is used to update the second and fourth bytes of the input column.
        col[1] ^= v
        col[3] ^= v

    def inv_mix_columns(self,state):
        for r in state:
            self.inv_mix_column(r)
            self.mix_column(r)

    def encrypter(self,plaintext):
        self.plaintext = plaintext
        # flags to set encrypt and decrypt
        self.encrypt = True
        self.decrypt = False

        # convert plaintext to state matrix 4*4
        state = self.state_from_bytes(self.plaintext)
        # generate key schedule
        self.key_schedule = self.key_expansion()

        # add round key
        self.add_round_key(state, self.key_schedule[0])

        for round in range(1, self.nr):
            # update state for each round performinf sub_bytes, shift_rows, mix_columns and add_round_key
            self.sub_bytes(state)
            state = self.shift_rows(state)
            self.mix_columns(state)
            self.add_round_key(state, self.key_schedule[round])
            self.cipher = self.bytes_from_state(state)
            if round == 1 or round == 9:
                print("After add Round Key: ", round," : ", end='')
                print(''.join(format(x, '02x') for x in self.cipher))
        
        # final round updating state with sub_bytes, shift_rows, add_round_key
        self.sub_bytes(state)
        state = self.shift_rows(state)
        self.add_round_key(state, self.key_schedule[self.nr])
        # convert state matrix to cipher text
        self.cipher = self.bytes_from_state(state)   
        return self.cipher
 
    def decrypter(self,cipher_text):
        self.cipher_text = cipher_text
        # flags to set encrypt and decrypt
        self.encrypt = False
        self.decrypt = True

        # convert ciphertext to state matrix 4*4
        state = self.state_from_bytes(self.cipher_text)
        # generate key schedule
        self.key_schedule = self.key_expansion()

        # add round key
        self.add_round_key(state,  self.key_schedule[self.nr])

        for round in range(self.nr-1, 0, -1):
            # update state for each round performinf inv_shift_rows, inv_sub_bytes, add_round_key and inv_mix_columns
            state = self.shift_rows(state)
            self.sub_bytes(state)
            if round == 1 or round == 9:
                print("Round", 10-round," Decryption: ", end='')
                print(''.join(format(x, '02x') for x in self.bytes_from_state(state)))

            self.add_round_key(state,self.key_schedule[round])
            self.inv_mix_columns(state)
            
        # final round updating state with inv_shift_rows, inv_sub_bytes, add_round_key
        state = self.shift_rows(state)
        self.sub_bytes(state)
        self.add_round_key(state,self.key_schedule[0])
        # convert state matrix to plain text
        plain = self.bytes_from_state(state)
        return plain

if  __name__ == "__main__":
    import random
    plaintext_hexes = ['0123456789abcdeffedcba9876543210','00112233445566778899aabbccddeeff']
    key_hexes = ['0f1571c947d9e8590cb7add6af7f6798','000102030405060708090a0b0c0d0e0f']
    ciphertext_hexes = ['ff0b844a0853bf7c6934ab4364148fb9','69c4e0d86a7b0430d8cdb78070b4c55a']

    for i in range(2):
        print("_____Test Case ",i+1,"_____")
        plaintext_hex = plaintext_hexes[i]
        plaintext = bytearray.fromhex(plaintext_hex)

        print("Plaintext : ", plaintext_hex)

        key_hex = key_hexes[i]
        key = bytearray.fromhex(key_hex)
        print("Key : ",key_hex)

        ciphertext = AES(key).encrypter(plaintext)
        ciphertext_hex = ''.join(format(x, '02x') for x in ciphertext)

        print("Ciphertext : ", ciphertext_hex)

        recovered_plaintext = AES(key).decrypter(ciphertext)
        print("Recovered Ciphertext : ", end='')
        print(''.join(format(x, '02x') for x in recovered_plaintext))
        assert (recovered_plaintext == plaintext)
        assert (ciphertext_hex == ciphertext_hexes[i])
        print()
    
