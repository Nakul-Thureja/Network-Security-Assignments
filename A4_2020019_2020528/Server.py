import rsa
import time
import socket
import json
import os
import hashlib
from PyPDF2 import PdfFileReader, PdfFileWriter
from datetime import datetime
from cryptography.fernet import Fernet
import PKDC

my_private_key = (379241, 204061)
public_key_server = PKDC.Public_Keys["Server"]
public_key_server1 = PKDC.Public_Keys["Server1"]
public_key_server2 = PKDC.Public_Keys["Server2"]


shared_keys = {}
rsa = rsa.RSA()

def add_metadata(filename,signature):

    reader = PdfFileReader(filename) # load the PDF file
    writer = PdfFileWriter()
    writer.appendPagesFromReader(reader)
    metadata = reader.getDocumentInfo()
    writer.addMetadata(metadata)

# Write your custom metadata here:
    writer.addMetadata({"/sign": signature}) # replace /Some and Example with your field name and value

    with open(filename, "wb") as f:
        writer.write(f)

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



def send_message_Server(message,port,server_name):
    host = socket.gethostname()  # as both code is running on same pc
    client_socket = socket.socket()  # instantiate
    client_socket.connect((host, port))  # connect to the server
    client_socket.send(message)  # send message
    encrypted_data = client_socket.recv(200000) 
    decrypted_data = rsa.decrypt(encrypted_data,my_private_key)
    decrypted_data = rsa.decrypt(decrypted_data.encode("latin1"),PKDC.Public_Keys[server_name])
    decrypted_data = json.loads(decrypted_data)
    print("decrypted_data",decrypted_data)
    client_socket.close()  # close the connection
    return decrypted_data
    


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
        encrypted_data = rsa.encrypt(data.decode("latin-1"),my_private_key)
        encrypted_data1 = rsa.encrypt(encrypted_data.decode("latin-1"),public_key_server1)
        encrypted_data2 = rsa.encrypt(encrypted_data.decode("latin-1"),public_key_server2)
        
        server1 = send_message_Server(encrypted_data1,5004,"Server1")             
        server2 = send_message_Server(encrypted_data2,5005,"Server2")
        print("server1",server1)
        print("server2",server2)
        
        
        data = data.decode()
        data = json.loads(data)
        
        # ticket = json.loads(ticket)
        
        if(time.time()-data["Time"]>data["Lifetime"]):
            print("Ticket Expired!!!!!!!!!!")
            exit()
        else:
            print("Ticket Valid!!!!!!!!!!")

        print(data)
        filename = data["Name"].replace(" ", "").lower()+"_"+data["Rollno"]+".pdf"
        f = open(filename, "rb")
        size = os.path.getsize(filename)
        pdf_data = f.read(size)
        hashed  = hashlib.sha256(pdf_data).digest()
        
        #print("\nHash: ",hashed,"\n")
        #print(pdf_data.decode("latin-1"))
        # encrypted_hash = rsa.encrypt(hashed.decode("latin-1"),my_private_key)
        certificate = {"name":filename,"data": pdf_data.decode("latin-1"), "hash1": server1["hash"], "hash2": server2["hash"]}
       # print("\ncert",certificate)
        # received_hash = rsa.decrypt(encrypted_hash.decode("latin-1").encode("latin-1"),public_key_server).encode("latin-1")
        # if(received_hash == hashed):
        #     print("Hash Verified")

        certificate = json.dumps(certificate)
        certificate = fernet.encrypt(certificate.encode())
        print("Size: ",len(certificate))
        conn.send(certificate)  # send data to the client
        f.close()


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
