import rsa
import time
import socket
import json
import os
import hashlib
from datetime import datetime
from cryptography.fernet import Fernet
import PKDC

my_private_key = (379241, 204061)
public_key_server = PKDC.Public_Keys["Server"]

shared_keys = {}
rsa = rsa.RSA()

def server_program():
    # get the hostname
    host = socket.gethostname()
    port = 5002  # initiate port no above 1024

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
        data = conn.recv(16384).decode()
        if not data:
            # if data is not received break
            break
        data = json.loads(data)
        print("Data Recieved from Client:\n",data)
        enc_ticket = data["Ticket"].encode()
        ticket = rsa.decrypt(enc_ticket,my_private_key)
        ticket = json.loads(ticket)
        
        if(time.time()-ticket["Time"]>ticket["Lifetime"]):
            print("Ticket Expired!!!!!!!!!!")
            exit()
        else: 
            print("Ticket Valid!!!!!!!!!!")

        key_c_server = ticket["Shared Key"]
        shared_keys["Client"] = key_c_server
        fernet = Fernet(key_c_server.encode())
        encAuthenticator = data["Authenticator"].encode()
        decAuthenticator = fernet.decrypt(encAuthenticator).decode()
        decAuthenticator = json.loads(decAuthenticator)

        print("Authenticator: ",decAuthenticator)
        if(ticket["ID1"]==decAuthenticator["ID"] and ticket["AD1"]==decAuthenticator["AD"] and ticket["ID2"]=="Server"):
            print("Client Verified!!!!!!")
        else:
            print("Client Unverified!!!!!!\nExiting Conversation")
            exit(0)
        
        message = {"Time": decAuthenticator["Time"]+1}
        message = fernet.encrypt(json.dumps(message).encode())
        decMessage = fernet.decrypt(message).decode()
        conn.send(message)  # send data to the client

    conn.close()  # close the connection

def certificate_authority():
# get the hostname
    host = socket.gethostname()
    port = 5003  # initiate port no above 1024

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
        fernet = Fernet(shared_keys["Client"].encode())
        data = fernet.decrypt(data.encode())
        data = data.decode()
        data = json.loads(data)
        
        # ticket = json.loads(ticket)
        
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
        certificate = {"data": pdf_data.decode("latin-1"), "hash": encrypted_hash.decode("latin-1")}
       # print("\ncert",certificate)
        certificate = json.dumps(certificate)
        certificate = fernet.encrypt(certificate.encode())
        print("Size: ",len(certificate))
        conn.send(certificate)  # send data to the client


    # break if the file size is reached or no more data is received
    


        # key_c_server = ticket["Shared Key"]
        # fernet = Fernet(key_c_server.encode())
        # encAuthenticator = data["Authenticator"].encode()
        # decAuthenticator = fernet.decrypt(encAuthenticator).decode()
        # decAuthenticator = json.loads(decAuthenticator)

        # print("Authenticator: ",decAuthenticator)
        # if(ticket["ID1"]==decAuthenticator["ID"] and ticket["AD1"]==decAuthenticator["AD"] and ticket["ID2"]=="Server"):
        #     print("Client Verified!!!!!!")
        # else:
        #     print("Client Unverified!!!!!!\nExiting Conversation")
        #     exit(0)
        
        # message = {"Time": decAuthenticator["Time"]+1}
        # message = fernet.encrypt(json.dumps(message).encode())
        # print("Size",message)
        # decMessage = fernet.decrypt(message).decode()
        # print(decMessage)
        # print(len(encrypted_data))
        # decrypted_data = rsa.decrypt(encrypted_data,private_key)
        # decrypted_data = json.loads(decrypted_data)
        # enc_ticket = decrypted_data["Ticket"].encode()
        # ticket = rsa.decrypt(enc_ticket,private_key_tgs)
        # conn.send(message)  # send data to the client

    conn.close()  # close the connection

if __name__ == '__main__':
    server_program()
    certificate_authority()
