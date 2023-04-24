import hashlib
import sys

character_set = 'abcdefghijklmnopqrstuvwxyz'

def char_of_value(value):
    # Returns the character of the value
    return chr(value + ord('a'))

def value_of_char(char):
    # Returns the value of the character
    return ord(char) - ord('a')

def Hash(message):
    # Hashes the plaintext using the SHA-256 algorithm
    text = hashlib.sha256()
    text.update(message.encode())
    actual_hash = text.hexdigest()
    mod_hash = ''
    for i in actual_hash:
        if character_set.find(i) == -1:
            mod_hash += character_set[int(i)-1]
        else:
            mod_hash += i 
    return mod_hash

def key_extender(key, size):
    # Extends the key to the size of the plaintext
    while len(key) < size:
        key += key
    return key[:size]

def plaintext_validity_check(plaintext):
    # Checks if the plaintext is valid
    index = len(plaintext) - 256//4
    message = plaintext[:index]
    hash = plaintext[index:]
    if Hash(message) == hash:
        return message
    else:
        return "Invalid plaintext"    

def encrypt(message, key):
    # Encrypts the plaintext using poly-alphabetic substitution cipher
    plaintext = message + Hash(message)
    encoding_key = key_extender(key, len(plaintext)) 
    ciphertext = ""
    for i in range(len(plaintext)):
        char = (value_of_char(plaintext[i]) + value_of_char(encoding_key[i])) % 26
        ciphertext += char_of_value(char)
    return ciphertext

def decrypt(ciphertext, key):
    # Decrypts the ciphertext using poly-alphabetic substitution cipher
    encoding_key = key_extender(key, len(ciphertext))
    plaintext = ""
    for i in range(len(ciphertext)):
        char = (value_of_char(ciphertext[i]) - value_of_char(encoding_key[i]) + 26) % 26
        plaintext += char_of_value(char)
    return plaintext_validity_check(plaintext)

def check_property(plaintexts):
    # Checks if the property is satisfied     
    for i in range(len(plaintexts)):
        if (plaintexts[i] == "Invalid plaintext"):
            return False
    return True

def brute_force(ciphertexts,key_length = 4):
    # Brute forces the ciphertext
    file1 = open("brute_force_output.txt", "w")
    for i in range(26):
        key = char_of_value(i)
        for j in range(26):
            key += char_of_value(j)
            for k in range(26):
                key += char_of_value(k)
                for l in range(26):
                    key += char_of_value(l)
                    plaintexts = []
                    for ciphertext in ciphertexts:
                        plaintexts.append(decrypt(ciphertext, key))
                    if check_property(plaintexts) and len(key) == key_length:
                        file1.write("Discovered Key: " + key + "\n")
                        print("Brute Force Discovered Key: " + key + "\n")
                        for p in plaintexts:
                            file1.write("Decoded Plaintext: "+p + "\n")
                        return
                    key = key[:-1]
                key = key[:-1]
            key = key[:-1]
        key = key[:-1]

if __name__ == '__main__':
    
    #reading arguments from command line
    n = len(sys.argv)
    if n == 3:
        key = sys.argv[2]
        if len(key) != 4:
            print("Key length should be 4.")
            exit()
        file = open(sys.argv[1], "r")
        original_texts = []
        ciphertexts = []
        for line in file:
            if line != '\n':
                original_texts.append(line.strip())
        file.close()
        print("Key used: ", key,"\n")
        #sample run for encypytion and decryption
        for i in range(len(original_texts)):
            print("Original text "+str(i+1)+": ", original_texts[i])
            ciphertext = encrypt(original_texts[i], key)
            print("Ciphertext "+str(i+1)+": ", ciphertext)
            plaintext = decrypt(ciphertext, key)
            print("Decoded Plaintext "+str(i+1)+": ", plaintext)
            print()
            #storing the encypted texts in a list for brute force testing
            ciphertexts.append(ciphertext)

        #calling the brute force function upon the ciphertexts
        brute_force(ciphertexts, 4)
        
    else:
        print("Please enter the input file name followed by the key as an argument.")
