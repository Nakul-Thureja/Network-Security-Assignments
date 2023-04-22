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
sockets = {'P':5000, 'TGS':5001, 'AS':5002, 'VS':5003}
parties = {'5000': 'P', '5001': 'TGS', '5002': 'AS', '5003':'VS'}
tickets = {}
shared_keys = {}

def send_message_AS():
    message = {"ID1": "Client","ID2": "TGS","Time":time.time()}

    host = socket.gethostname()  # as both code is running on same pc
    port = 5000  # socket server port number

    client_socket = socket.socket()  # instantiate
    client_socket.connect((host, port))  # connect to the server

    client_socket.send(json.dumps(message).encode())  # send message
    encrypted_data = client_socket.recv(16384) 
    # receive response
    print(encrypted_data)
    decrypted_data = rsa.decrypt(encrypted_data,private_key)
    decrypted_data = json.loads(decrypted_data)
    enc_ticket = decrypted_data["Ticket"].encode()
    ticket = rsa.decrypt(enc_ticket,private_key_tgs)
    print(decrypted_data)
    print(ticket)
    tickets["TGS"] = enc_ticket
    shared_keys["TGS"] = decrypted_data["Shared Key"]
    client_socket.close()  # close the connection


def send_message_TGS():
    key_c_tgs = shared_keys["TGS"]
    Authenticator = {"ID": "Client","AD": "Client","Time":time.time()}
    fernet = Fernet(key_c_tgs.encode())
    encAuthenticator = fernet.encrypt(json.dumps(Authenticator).encode())
    message = {"ID1": "Server","Ticket": tickets["TGS"].decode(),"Authenticator":encAuthenticator.decode()}
    decAuthenticator = fernet.decrypt(encAuthenticator).decode()

    host = socket.gethostname()  # as both code is running on same pc
    port = 5001  # socket server port number

    client_socket = socket.socket()  # instantiate
    client_socket.connect((host, port))  # connect to the server

    client_socket.send(json.dumps(message).encode())  # send message
    encrypted_data = client_socket.recv(16384) 
    print(encrypted_data)
 
    decrypted_data = fernet.decrypt(encrypted_data).decode()
    decrypted_data = json.loads(decrypted_data)
    print(decrypted_data)
    enc_ticket = decrypted_data["Ticket"].encode()
    ticket = rsa.decrypt(enc_ticket,private_key_server)
    print(decrypted_data)
    print(ticket)
    tickets["Server"] = enc_ticket
    shared_keys["Server"] = decrypted_data["Shared Key"]

    client_socket.close()  # close the connection

def send_message_Server():
    key_c_server = shared_keys["Server"]
    Authenticator = {"ID": "Client","AD": "Client","Time":time.time()}
    fernet = Fernet(key_c_server.encode())
    encAuthenticator = fernet.encrypt(json.dumps(Authenticator).encode())
    message = {"Ticket": tickets["Server"].decode(),"Authenticator":encAuthenticator.decode()}
    decAuthenticator = fernet.decrypt(encAuthenticator).decode()

    host = socket.gethostname()  # as both code is running on same pc
    port = 5002  # socket server port number

    client_socket = socket.socket()  # instantiate
    client_socket.connect((host, port))  # connect to the server

    client_socket.send(json.dumps(message).encode())  # send message
    encrypted_data = client_socket.recv(16384) 
    print(encrypted_data)
 
    decrypted_data = fernet.decrypt(encrypted_data).decode()
    decrypted_data = json.loads(decrypted_data)
    print(decrypted_data)
    print(Authenticator)
    if(Authenticator['Time']+1 == decrypted_data["Time"]):
        print("Server Verified!!!!!!")
    else:
        print("Server Unverified!!!!!!\nExiting Conversation")
        exit(0)

    client_socket.close()  # close the connection

if __name__ == '__main__':
    send_message_AS()
    send_message_TGS()
    send_message_Server()