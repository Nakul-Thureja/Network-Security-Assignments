import rsa
import time
import socket
import json
from datetime import datetime
from cryptography.fernet import Fernet
import PKDC

my_private_key = (68681, 51241)
public_key_server = PKDC.Public_Keys["Server"]

rsa = rsa.RSA()

def server_program():
    # get the hostname
    host = socket.gethostname()
    port = 5001  # initiate port no above 1024

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

        key_c_tgs = ticket["Shared Key"]
        fernet = Fernet(key_c_tgs.encode())
        encAuthenticator = data["Authenticator"].encode()
        decAuthenticator = fernet.decrypt(encAuthenticator).decode()
        decAuthenticator = json.loads(decAuthenticator)

        print("Authenticator: ",decAuthenticator)
        if(ticket["ID1"]==decAuthenticator["ID"] and ticket["AD1"]==decAuthenticator["AD"] and ticket["ID2"]=="TGS"):
            print("Client Verified!!!!!!")
        else:
            print("Client Unverified!!!!!!\nExiting Conversation")

        key_c_s = Fernet.generate_key().decode()
        print("Shared Key generated b/w Client and Server",key_c_s)
        Ticket = {"Shared Key": key_c_s,"ID1": "Client","AD1": "Client","ID2":"Server","Time":time.time(),"Lifetime":5}
        message = {"Shared Key": key_c_s,"ID2": "Server","Time":time.time(),"Ticket":rsa.encrypt(json.dumps(Ticket),public_key_server).decode()}
        message = fernet.encrypt(json.dumps(message).encode())
        conn.send(message)  # send data to the client

    conn.close()  # close the connection


if __name__ == '__main__':
    server_program()
