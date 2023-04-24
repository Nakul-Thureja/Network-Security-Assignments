import rsa
import time
import socket
import json
import os
import hashlib
from datetime import datetime
from cryptography.fernet import Fernet
import PKDC
my_private_key =  (53531, 44735)
rsa = rsa.RSA()
public_key_server = PKDC.Public_Keys["Server"]

def certificate_authority():
# get the hostname
    host = socket.gethostname()
    port = 5005  # initiate port no above 1024

    server_socket = socket.socket()  # get instance
    # look closely. The bind() function takes tuple as argument
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((host, port))  # bind host address and port together

    # configure how many client the server can listen simultaneously
    server_socket.listen(2)
    conn, address = server_socket.accept()  # accept new connection
    print("Connection from: " + str(address))
    while True:
        # receive data stream. it won't accept data packet greater than 1024 bytes
        data = conn.recv(200000).decode()
        if not data:
            # if data is not received break
            break

        print("from connected user: " + str(data))
        data = rsa.decrypt(data.encode("latin-1"),my_private_key)
        data = rsa.decrypt(data.encode("latin-1"),public_key_server)
        data = json.loads(data)
        
        if(time.time()-data["Time"]>data["Lifetime"]):
            print("Ticket Expired!!!!!!!!!!")
            exit()

        print(data)
        filename = data["Name"].replace(" ", "").lower()+"_"+data["Rollno"]+".pdf"
        f = open(filename, "rb")
        size = os.path.getsize(filename)
        pdf_data = f.read(size)
        hashed  = hashlib.sha256(pdf_data).digest()
        
        #print("\nHash: ",hashed,"\n")
        #print(pdf_data.decode("latin-1"))
        encrypted_hash = rsa.encrypt(hashed.decode("latin-1"),my_private_key)
        certificate = {"hash": encrypted_hash.decode("latin-1")}
      
        certificate = json.dumps(certificate)
        certificate = rsa.encrypt(certificate.encode("latin-1"),my_private_key)
        certificate = rsa.encrypt(certificate.encode("latin-1"),public_key_server)

        print("Size: ",len(certificate))
        conn.send(certificate)  # send data to the client
        f.close()
    conn.close()  # close the connection

if __name__ == '__main__':
    certificate_authority()
