import rsa
import time
import socket
import json
from datetime import datetime
from cryptography.fernet import Fernet

public_key, private_key = (260119,225911), (260119,109783)
rsa = rsa.RSA()
public_key_tgs, private_key_tgs = (788131, 720581), (788131,62637)

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
        print("from connected user: " + str(data))
        key = Fernet.generate_key().decode()
        print(key)
        Ticket = {"Shared Key": key,"ID1": "Client","AD1": "Client","ID2": "TGS","Time":time.time(),"Lifetime":5}
        print(json.dumps(Ticket))
        print(rsa.encrypt(json.dumps(Ticket),public_key_tgs).decode())
        data = {"Shared Key": key,"ID2": "TGS","Time":time.time(),"Lifetime":5,"Ticket":rsa.encrypt(json.dumps(Ticket),public_key_tgs).decode()}
        encrypted_data = rsa.encrypt(json.dumps(data),public_key)
        print(len(encrypted_data))
        decrypted_data = rsa.decrypt(encrypted_data,private_key)
        decrypted_data = json.loads(decrypted_data)
        enc_ticket = decrypted_data["Ticket"].encode()
        ticket = rsa.decrypt(enc_ticket,private_key_tgs)
        conn.send(encrypted_data)  # send data to the client

    conn.close()  # close the connection


if __name__ == '__main__':
    server_program()
