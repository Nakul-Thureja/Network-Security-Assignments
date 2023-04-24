from RSA_019_528 import *
import socket
import time
import pickle
import threading

class PKDA:
    def __init__(self, a, b):
        self.public_keys = {}
        self.name = 'PKDA'
        self.RSA = RSA()
        self.key = self.RSA.work(a, b)
        self.public_key = (self.key[1][0], self.key[1][1])
        self.private_key = (self.key[0][0], self.key[0][1])
        self.current_port = 1301
        self.known_users = {}
        print(self.name,'Public Key:',self.public_key)

    def socket_creation(self,host = '127.0.0.1'):
        #creating the sockets for communication
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.bind((host, self.current_port))
        self.socket.listen()

    def handle_client(self, client_socket,i):
        #thread function to handle the response to a client
        #receives the request for public key of a user
        data = client_socket.recv(4096)
        if len(data)>0:
            data_rcvd = pickle.loads(data)
            print('\nReceived Request for Public Key of',data_rcvd['request'])
        else:
            print('client disconnected')
            client_socket.close()
            return
        #encrypt and send the public key of the user if it is known
        if(data_rcvd['request'] in self.known_users):
            message = {'PU':self.known_users[data_rcvd['request']],'request': data_rcvd['request'], 'T':data_rcvd['T'], 'duration':data_rcvd['duration']}
            message = pickle.dumps(message)
            message = self.RSA.rsa_encrypt_text(self.private_key,message)
            client_socket.send(pickle.dumps(message))
            print("Public key sent.")
        else:
            print("User not found.")
            client_socket.close()
            return
    
    def accept_connections(self):
        i = 0
        while True:
            #create a thread for each client to handle the request
            conn, address = self.socket.accept()
            client_thread = threading.Thread(target=self.handle_client, args=(conn,i,))
            i+=1
            #start the thread
            client_thread.start()

    
    def issue_certificate(self,client_socket,i):
        #thread function to handle the response to a client
        #send its public key to the client
        message = {'id':'PKDA','key':self.public_key}
        client_socket.send(pickle.dumps(message))
        data = client_socket.recv(4096)
        if len(data)>0:
            #receive the public key of the client and store it
            data_rcvd = pickle.loads(data)
            self.known_users[data_rcvd['id']]= data_rcvd['key']
            print('\nReceived Public Key of',data_rcvd['id'])
        else:
            print('\nclient disconnected')
            client_socket.close()
            return
        
        client_socket.close()

    def issue_certificate_out(self,no_of_clients):
        i = 0
        while i<no_of_clients:
            #create a thread for each client to handle the request
            conn, address = self.socket.accept()
            client_thread = threading.Thread(target=self.issue_certificate, args=(conn,i,))
            i+=1
            #start the thread
            client_thread.start()

if __name__ == "__main__":
    try:
        #create a PKDA
        PKDA = PKDA(193,829)
        #create a socket for communication
        PKDA.socket_creation()
        #issue certificates to the clients
        PKDA.issue_certificate_out(2)
        #accept and service requests for public keys
        PKDA.accept_connections()

    except KeyboardInterrupt:
        #close the socket on keyboard interrupt
        print("\nExiting...")
        PKDA.socket.close()
        exit()