import rsa
import time
import socket
import json
import PKDC
from datetime import datetime
from cryptography.fernet import Fernet
my_private_key = (138953, 92371)
rsa = rsa.RSA()
public_key_tgs = PKDC.Public_Keys["TGS"]

def server_program():
    # get the hostname
    host = socket.gethostname()
    port = 5000  # initiate port no above 1024

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
        if(data["ID1"]=="Client" and data["ID2"]=="TGS"):
            print("Client Verified")
        
        key_c_tgs = Fernet.generate_key().decode()
        print("Shared Key generated b/w Client and TGS",key_c_tgs)
        Ticket = {"Shared Key": key_c_tgs,"ID1": "Client","AD1": "Client","ID2": "TGS","Time":time.time(),"Lifetime":5}
        data = {"Shared Key": key_c_tgs,"ID2": "TGS","Time":time.time(),"Lifetime":5,"Ticket":rsa.encrypt(json.dumps(Ticket),public_key_tgs).decode()}
        encrypted_data = rsa.encrypt(json.dumps(data),my_private_key)
        conn.send(encrypted_data)  # send data to the client

    conn.close()  # close the connection


if __name__ == '__main__':
    server_program()
