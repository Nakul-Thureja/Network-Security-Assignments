from RSA_019_528 import *
import socket
import time
import pickle
import hashlib

class client:
    def __init__(self,name, p, q):
        self.name = name
        self.RSA = RSA()
        self.key = self.RSA.work(p, q)
        self.public_key = (self.key[1][0], self.key[1][1])
        self.private_key = (self.key[0][0], self.key[0][1])
        self.known_public_keys = {}
        self.nonces = {}
        print(self.name,'Public Key:',self.public_key)


    def hash(self,nonce):
        #to send a response to the nonce by hashing the nonce using sha256
        m = hashlib.sha256()
        m.update(bytes(nonce,'utf-8'))
        return m.hexdigest()
    
    def generate_nonce(self,target):
        #to randomly generate a nonce
        nonce = random.randint(0,1000000)
        nonce = str(nonce)
        self.nonces[target] = nonce
        return nonce
    
    def responce_nonce(self,nonce):
        return self.hash(nonce)
    
    def check_valid_nonce(self,target,nonce):
        #to check if the nonce is valid or not
        if self.hash(self.nonces[target]) == nonce:
            return True
        else:
            return False
    

    def issue_certificate(self,port=0,host = '127.0.0.1'):
        #initialisation function
        #to get the public key of PKDA and also send its own public key to PKDA
        port = 1301
        try:
            #creating the socket
            self.PKDA_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.PKDA_socket.connect((host, port))
                      
            data = self.PKDA_socket.recv(4096)
            if len(data)>0:
                #receive the public key of PKDA
                data_rcvd = pickle.loads(data)
                self.known_public_keys[data_rcvd['id']] = data_rcvd['key']
                print("\nPublic key received from PKDA:",self.known_public_keys['PKDA'])
            else:
                print('client disconnected')
                self.PKDA_socket.close()
                return
            #send the public key of client to PKDA
            message = {'id':self.name,'key':self.public_key}
            self.PKDA_socket.send(pickle.dumps(message))
            self.PKDA_socket.close()
            return 

        except:
            print("Connection to PKDA failed. Trying again in 5 seconds.")

    def talking_to_client(self, target,sock, host = '127.0.0.1'):
        #function to test 3 message sharing between A and B
        for i in range(3):
            #send encrypted message to Client B
            message = {'id':self.name,'nonce':self.generate_nonce(target),'response_nonce':None,'T':time.strftime("%H:%M:%S", time.localtime()),'duration':10, 'message':'Hi'+str(i+1)}
            print("\nData Sent:",message)
            print('Message Sent:',message['message'])
            message = pickle.dumps(message)
            message = self.RSA.rsa_encrypt_text(self.known_public_keys[target],message)
            sock.send(pickle.dumps(message))
            data = sock.recv(4096)
            if len(data)>0:
                #receive the response from client B and decrypt it
                data_rcvd = pickle.loads(data)
                data_rcvd = self.RSA.rsa_decrypt_text(self.private_key,data_rcvd)
                data_rcvd = pickle.loads(data_rcvd)
                print("\nData Received",data_rcvd)
                print("Message Received:" ,data_rcvd['message'])            
            else:
                print('client disconnected')
                sock.close()
                return
            #check if the nonce response is valid or not
            if self.check_valid_nonce(target,data_rcvd['response_nonce']):
                print("Nonce is valid.")
            else:
                print("Nonce is not valid.")
                socket.close()
            time.sleep(1)
        sock.close()
    
    def start_communication(self, target, host = '127.0.0.1'):
        port = 1401
        try:
            self.target_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.target_socket.connect((host, port))
            #send the initial message to client B after encrypting it
            message = {'id':self.name,'nonce':self.generate_nonce(target),'response_nonce':None,'T':time.strftime("%H:%M:%S", time.localtime()),'duration':10, 'message':None}
            print("\nInitiated. Message sent: ",message)
            message = pickle.dumps(message)
            message = self.RSA.rsa_encrypt_text(self.known_public_keys[target],message)
            self.target_socket.send(pickle.dumps(message))
            while True:
                data = self.target_socket.recv(4096)
                if len(data)>0:
                    #receive the response from client B and decrypt it
                    data_rcvd = pickle.loads(data)
                    data_rcvd = self.RSA.rsa_decrypt_text(self.private_key,data_rcvd)
                    data_rcvd = pickle.loads(data_rcvd)
                    print("\nMessage received:",data_rcvd)
                    break
                else:
                    print('client disconnected')
                    self.target_socket.close()
                    return
            #check if the nonce response is valid or not
            if self.check_valid_nonce(target,data_rcvd['response_nonce']):
                print("Nonce is valid.")
                #send the response to client B after encrypting it
                message = {'id':self.name,'nonce':None,'response_nonce':self.responce_nonce(data_rcvd['nonce']),'T':time.strftime("%H:%M:%S", time.localtime()),'duration':10, 'message':None}
                print("\nMessage sent:",message)
                message = pickle.dumps(message)
                message = self.RSA.rsa_encrypt_text(self.known_public_keys[target],message)
                self.target_socket.send(pickle.dumps(message))
                self.talking_to_client(target,self.target_socket)
            else:
                print("Nonce not valid.")
                self.target_socket.close()
                return
        except:
            print("Connection to target failed. Trying again in 5 seconds.")

    def get_public_keys_from_PKDA(self,target,host = '127.0.0.1'):
        port = 1301
        self.PKDA_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.PKDA_socket.connect((host, port))
        #send public key request to PKDA
        message_dict = {'request':target,'T':time.strftime("%H:%M:%S", time.localtime()),'duration':10}
        message = pickle.dumps(message_dict)
        self.PKDA_socket.send(message)
        print("\nRequest sent to PKDA.",message_dict)
        data = self.PKDA_socket.recv(4096)
        if len(data)>0:
            #receive the public key from PKDA and decrypt it
            data_rcvd = pickle.loads(data)
            decrypted = self.RSA.rsa_decrypt_text(self.known_public_keys['PKDA'],data_rcvd)
            decrypted = pickle.loads(decrypted)
            #check if the public key received is still valid or not
            if (decrypted['request'] != message_dict['request']) or (decrypted['T'] != message_dict['T']):
                print("\nError in PKDA response.")
                return
            else:
                self.known_public_keys[decrypted['request']] = decrypted['PU']
                print("\nPublic key received from PKDA.",decrypted)
        else:
            print('client disconnected')
            self.PKDA_socket.close()
            return
        self.PKDA_socket.close()
        return 
              
    
if __name__ == "__main__":
    #create client A
    ClientA = client("ClientA",787,827)
    #get the public key of PKDA and send the public key of client B to PKDA
    ClientA.issue_certificate()
    #get the public key of client B from PKDA
    ClientA.get_public_keys_from_PKDA('ClientB')
    #start the communication with client B
    ClientA.start_communication('ClientB')
    