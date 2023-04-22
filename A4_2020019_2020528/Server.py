import rsa
import time
import socket
import json
from datetime import datetime
from cryptography.fernet import Fernet

public_key, private_key = (260119,225911), (260119,109783)
public_key_tgs, private_key_tgs = (788131, 720581), (788131,62637)
public_key_server, private_key_server = (82993, 14849), (82993, 65857)

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
        print("from connected user: " + str(data))
        data = json.loads(data)
        enc_ticket = data["Ticket"].encode()
        ticket = rsa.decrypt(enc_ticket,private_key_server)
        ticket = json.loads(ticket)
        
        if(time.time()-ticket["Time"]>ticket["Lifetime"]):
            print("Ticket Expired!!!!!!!!!!")
            exit()

        print(ticket)
        print(data)
        
        key_c_server = ticket["Shared Key"]
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
        print("Size",message)
        decMessage = fernet.decrypt(message).decode()
        print(decMessage)
        # print(len(encrypted_data))
        # decrypted_data = rsa.decrypt(encrypted_data,private_key)
        # decrypted_data = json.loads(decrypted_data)
        # enc_ticket = decrypted_data["Ticket"].encode()
        # ticket = rsa.decrypt(enc_ticket,private_key_tgs)
        conn.send(message)  # send data to the client

    conn.close()  # close the connection


if __name__ == '__main__':
    server_program()
