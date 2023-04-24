import rsa
import time
import socket
import json
import hashlib
from datetime import datetime
from cryptography.fernet import Fernet
import PKDC

my_private_key = (222637, 50373)
rsa = rsa.RSA()
tickets = {}
shared_keys = {}
public_key_as = PKDC.Public_Keys["AS"]
public_key_server = PKDC.Public_Keys["Server"]


def send_message_AS():
    message = {"ID1": "Client","ID2": "TGS","Time":time.time()}

    host = socket.gethostname()  # as both code is running on same pc
    port = 5000  # socket server port number

    client_socket = socket.socket()  # instantiate
    client_socket.connect((host, port))  # connect to the server

    client_socket.send(json.dumps(message).encode())  # send message
    encrypted_data = client_socket.recv(16384) 
    decrypted_data = rsa.decrypt(encrypted_data,public_key_as)
    decrypted_data = json.loads(decrypted_data)
    enc_ticket = decrypted_data["Ticket"].encode()
    print("Data Recieved From AS:\n",decrypted_data)
    tickets["TGS"] = enc_ticket
    shared_keys["TGS"] = decrypted_data["Shared Key"]
    client_socket.close()  # close the connection

def send_message_TGS():
    key_c_tgs = shared_keys["TGS"]
    Authenticator = {"ID": "Client","AD": "Client","Time":time.time()}
    fernet = Fernet(key_c_tgs.encode())
    encAuthenticator = fernet.encrypt(json.dumps(Authenticator).encode())
    message = {"ID1": "Server","Ticket": tickets["TGS"].decode(),"Authenticator":encAuthenticator.decode()}
    host = socket.gethostname()  # as both code is running on same pc
    port = 5001  # socket server port number
    client_socket = socket.socket()  # instantiate
    client_socket.connect((host, port))  # connect to the server
    client_socket.send(json.dumps(message).encode())  # send message
    encrypted_data = client_socket.recv(16384) 
    decrypted_data = fernet.decrypt(encrypted_data).decode()
    decrypted_data = json.loads(decrypted_data)
    print("\n\n Data Recieved From TGS\n",decrypted_data)
    enc_ticket = decrypted_data["Ticket"].encode()
    tickets["Server"] = enc_ticket
    shared_keys["Server"] = decrypted_data["Shared Key"]
    client_socket.close()  # close the connection

def send_message_Server():
    key_c_server = shared_keys["Server"]
    Authenticator = {"ID": "Client","AD": "Client","Time":time.time()}
    fernet = Fernet(key_c_server.encode())
    encAuthenticator = fernet.encrypt(json.dumps(Authenticator).encode())
    message = {"Ticket": tickets["Server"].decode(),"Authenticator":encAuthenticator.decode()}
    host = socket.gethostname()  # as both code is running on same pc
    port = 5002  # socket server port number
    client_socket = socket.socket()  # instantiate
    client_socket.connect((host, port))  # connect to the server
    client_socket.send(json.dumps(message).encode())  # send message
    encrypted_data = client_socket.recv(16384) 
    decrypted_data = fernet.decrypt(encrypted_data).decode()
    decrypted_data = json.loads(decrypted_data)
    print("\n\nData Recieved From Server\n",decrypted_data)
    if(Authenticator['Time']+1 == decrypted_data["Time"]):
        print("Server Verified!!!!!!")
    else:
        print("Server Unverified!!!!!!\nExiting Conversation")
        exit(0)
    client_socket.close()  # close the connection

def certificate_request():
    key_c_server = shared_keys["Server"]
    fernet = Fernet(key_c_server.encode())
    name = str(input("Enter your name: "))
    roll_no = str(input("Enter your roll number: "))
    message = {"Name": name,"Rollno":roll_no,"Time":time.time(), "Lifetime":5}
    encMessage = fernet.encrypt(json.dumps(message).encode())

    host = socket.gethostname()  # as both code is running on same pc
    port = 5003  # socket server port number

    client_socket = socket.socket()  #instantiate
    client_socket.connect((host, port))  #connect to the server

    client_socket.send(encMessage)  # send message
    encrypted_data = client_socket.recv(200000).decode()
    print("\n dec",len(encrypted_data))
    
    decrypted_data = fernet.decrypt(encrypted_data.encode()).decode()
    decrypted_data = json.loads(decrypted_data)
    hashed = hashlib.sha256(decrypted_data["data"].encode("latin-1")).digest()
    received_hash = rsa.decrypt(decrypted_data["hash"].encode("latin-1"),public_key_server).encode("latin-1")

    print("\nHash: ",hashed,"\n")
    print("\nReceived Hash: ",received_hash,"\n")

    if hashed == received_hash:
        print("Certificate Verified")
        f = open(decrypted_data["name"][:-4]+"recvd.pdf", "wb")
        f.write(decrypted_data["data"].encode("latin-1"))
        f.close()
    else:
        print("Certificate Not Verified")
        

    client_socket.close()  # close the connection

if __name__ == '__main__':
    send_message_AS()
    send_message_TGS()
    send_message_Server()
    certificate_request()