# ----------------------
# Name: Charuni Liyanage, Von Castro, Moshood Aromolaran
# File: client_enhanced.py
# Assignment: FINAL PROJECT
# Class: CMPT 361
# Instructor: Dr. Elmorsy
# ----------------------
# This is an example from "Computer Networking: A Top Down Approach" textbook chapter 2
import socket
import sys
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import time


def read_binary_file(file_name):
    # opens binary file and read its contents
    try:
        with open(file_name, 'rb') as file:
            line = file.read()
            return line
    except IOError as e:
        print("Error:", e)

def create_email_message(user):
    # Get the email destination clients usernames and email title
    destinations = input('Enter destinations (separated by ";"): ')
    title = input('Enter title: ')
    if len(title) > 100:
        print("Title exceeds the maximum length of 100 characters. Please retry.")
        return None

    # Get the message contents from the user or from a text file
    content_source = input('Would you like to load contents from a file? (Y/N) ')
    if content_source.upper() == "N":
        content = input('Enter message contents: ')
    elif content_source.upper() == "Y":
        filename = input('Enter filename: ')
        try:
            with open(f'{user}/{filename}', 'r') as file:
                content = file.read()
        except IOError:
            print("File not found. Please retry")
            return None
    else:
        print("Invalid option. Please retry.")
        return None

    if len(content) > 1000000:
        print("Content exceeds the maximum length of 1000000 characters. Please retry.")
        return None

    # Construct the email message
    message = f"From: {user}\nTo: {destinations}\nTitle: {title}\nContent Length: {len(content)}\nContent:\n{content}"
    return message

def client():
    # Server Information
    serverName = input('Enter the server IP or name: ')
    serverPort = 12000
    
    #Create client socket that useing IPv4 and TCP protocols 
    try:
        clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except socket.error as e:
        print('Error in client socket creation:',e)
        sys.exit(1)    
    
    try:
        #Client connect with the server
        clientSocket.connect((serverName,serverPort))
        
        # get server public key 
        server_pub = read_binary_file('server_public.pem')
        pubkey = RSA.import_key(server_pub)
        cipher_rsa_en = PKCS1_OAEP.new(pubkey)


        # Client.py asks the client to enter his/her username and password.
        user = input("Enter your username: ")
        passw = input("Enter your password: ")

        user_passw =  f"{user} {passw}"
        
        # encrypt username and password with server public key
        encrypt_userpass = cipher_rsa_en.encrypt(user_passw.encode('ascii'))

        # send to server
        clientSocket.send(encrypt_userpass)
        
        response = clientSocket.recv(2048)

        # Processing server responses accordingly
        if "Username".encode('ascii') in response:
            print("Username and/or password wrong\nTerminating.")
            clientSocket.close()

        elif "Invalid".encode('ascii') in response:
            response = int(response.split()[-1])
            print(f"Invalid username or password. You have {response} attempts' left until locked out\nTerminating.")
            clientSocket.close()
        elif "locked out".encode('ascii') in response:
            lock_time = int(response.split()[-1])
            print(f"Too many attempts. You have to wait {lock_time} seconds to try again.")
            for i in range(lock_time):
                time.sleep(1)
                print(f'Try again in {lock_time - i} seconds')
            print("Terminating.")
            clientSocket.close()

        elif "Currently".encode('ascii') in response:
            print("Currently in lock out mode\nTerminating")
            clientSocket.close()
               
        else:
            # decrypt and store symmetric key 
            client_priv = read_binary_file(f'{user}/{user}_private.pem')
            privkey = RSA.import_key(client_priv)
            cipher_rsa_dec = PKCS1_OAEP.new(privkey)
            
            
            sym_key = cipher_rsa_dec.decrypt(response)

            # Generate Cyphering Block
            cipher = AES.new(sym_key, AES.MODE_ECB)

            # encrypt OK with sym_key 
            encrypt_ok = cipher.encrypt(pad("OK".encode('ascii'),16))
            clientSocket.send(encrypt_ok)

            # receive and decrypt server menu msg using sym_key
            encrypt_menu = clientSocket.recv(2048)
            menu = unpad(cipher.decrypt(encrypt_menu), 16).decode('ascii')

            choice = input(menu)
           
            # encrypt choice send to server
            clientSocket.send(cipher.encrypt(pad(choice.encode('ascii'), 16)))

            while choice != '4':

                if choice == '1':
                    message = create_email_message(user)
                    if message is not None:
                        # Encrypt the message and send it to the server
                        encrypt_message = cipher.encrypt(pad(message.encode('ascii'), 16))
                        
                        # Send message length
                        message_length = str(len(encrypt_message))
                        print(message_length)
                        encrypt_message_length = cipher.encrypt(pad(message_length.encode('ascii'), 16))
                        clientSocket.send(encrypt_message_length)
                        clientSocket.recv(10)
                     
                        # Send message
                        clientSocket.sendall(encrypt_message)
                        print("The message is sent to the server")
                
                elif choice == '2':
                    # Get and print email list
                    content = clientSocket.recv(2048)
                    content = unpad(cipher.decrypt(content), 16).decode('ascii')
                    print(content)  

                elif choice == '3':
                    # Get and send the index to the server
                    email_index = input('Enter the email index you wish to view: ')
                    email_index = cipher.encrypt(pad(email_index.encode('ascii'), 16))
                    clientSocket.send(email_index)
                    
                    # Get the response from the server
                    content_length = clientSocket.recv(2048)
                    content_length = int(unpad(cipher.decrypt(content_length), 16).decode('ascii'))
                    bytes_at_a_time = 0
                    content   = b''
                    clientSocket.send(' '.encode('ascii'))
                    
                    # Ensure to recieve all bytes
                    while bytes_at_a_time <= content_length:
                        
                        content += clientSocket.recv(1000)
                        bytes_at_a_time += 1000
                        
                    # Print content
                    content = unpad(cipher.decrypt(content), 16).decode('ascii')
                    print(f'\n{content}')  

                # send choice again
                choice = input(menu)
                clientSocket.send(cipher.encrypt(pad(choice.encode('ascii'), 16)))
                    
            
            # Client terminate connection with the server
            clientSocket.close()
            print("The connection is terminated with the server.")
        
    except socket.error as e:
        print('An error occured:',e)
        clientSocket.close()
        sys.exit(1)

#----------
client()