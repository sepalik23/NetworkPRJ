# ----------------------
# Name: Charuni Liyanage, Von Castro, Moshood Aromolaran
# File: server.py
# Assignment: FINAL PROJECT
# Class: CMPT 361
# Instructor: Dr. Elmorsy
# ----------------------
import socket
import sys
import os
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import json
import datetime

def read_binary_file(file_name):
    # opens binary file and read its contents
    try:
        with open(file_name, 'rb') as file:
            line = file.read()
            return line
    except IOError as e:
        print("Error:", e)

def handle_email(encrypt_message, sym, cipher):
    message = unpad(cipher.decrypt(encrypt_message), 16).decode('ascii')
    lines = message.split('\n')
    from_client = lines[0].split(': ')[1]
    to_clients = lines[1].split(': ')[1]
    title = lines[2].split(': ')[1]
    content_length = int(lines[3].split(': ')[1])
    content = '\n'.join(lines[5:])

    print(f"An email from {from_client} is sent to {to_clients} has a content length of {content_length}")

    # Add the time and date of receiving the email
    now = datetime.datetime.now()
    timestamp_str = now.strftime("%Y-%m-%d %H:%M:%S.%f")
    message = f"From: {from_client}\nTo: {to_clients}\nTime and Date: {timestamp_str}\nTitle: {title}\nContent Length: {content_length}\nContent:\n{content}"

    # if no destination found print error message
    if not to_clients:
        print("No destination client found.")
        return

    # Save the email as a text file in each destination client directory
    for client in to_clients.split(';'):
        # prevents empty strings from being considered as a client
        if client:
            filename = f"{client}/{from_client}_{title}.txt"
        
            with open(filename, 'w') as file:
                file.write(message)

def display_email(client):
    inbox_list = []
    index = 1
    content = f'Index\tFrom\t  DateTime\t\t\tTitle\n'
    
    for file in os.listdir(client):
        
        # Skip the .pem files
        if '.txt' in file:
            inbox_list.append(file)

            # Read and grab the necessary metadata of each email in the clients folder
            with open(f'{client}/{file}') as f:
                From = f.readline().split(" ")[-1].replace('\n', '')
                f.readline()
                date_time = f.readline().replace('Time and Date: ', '').replace('\n', '')
                
                title     = f.readline().split(":")[-1].strip().replace('\n', '')
                    
            
            content += f'{index}\t{From}\t  {date_time}\t{title}\n'
            index   += 1
            
    return [content, inbox_list]

def server():
    # Server port
    serverPort = 12000

    # Create server socket that uses IPv4 and TCP protocols
    try:
        serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except socket.error as e:
        print('Error in server socket creation:', e)
        sys.exit(1)

    # Associate 12000 port number to the server socket
    try:
        serverSocket.bind(('', serverPort))
    except socket.error as e:
        print('Error in server socket binding:', e)
        sys.exit(1)

    print('The server is ready to accept connections')

    # The server can only have one connection in its queue waiting for acceptance
    serverSocket.listen(5)

    while 1:
        try:
            # Server accepts client connection
            connectionSocket, addr = serverSocket.accept()
            pid = os.fork()

            # If it is a client process
            if pid == 0:
                serverSocket.close()

                # get server private key
                server_priv = read_binary_file('server_private.pem')
                privkey = RSA.import_key(server_priv)
                cipher_rsa_dec = PKCS1_OAEP.new(privkey)

                # receiver username & password and decrypt
                encrypt_userpass = connectionSocket.recv(2048)
                decrypt_userpass = cipher_rsa_dec.decrypt(encrypt_userpass).decode('ascii').split(' ')
                
                # break the username and password
                client = decrypt_userpass[0]
                password = decrypt_userpass[1]

                # open json file
                with open('user_pass.json') as file:
                    # Parse the JSON data
                    data = json.load(file)

                
                if client in data and data[client] == password:
    
                    # open client folder and grab client_public key
                    client_pub = read_binary_file(f'{client}/{client}_public.pem')
                    pubkey = RSA.import_key(client_pub)
                    cipher_rsa_en = PKCS1_OAEP.new(pubkey)

                    # Generate Key and then encrypt with client public key
                    KeyLen = 256
                    sym = get_random_bytes(int(KeyLen/8))

                    # Generate Cyphering Block
                    encrypt_client_key = cipher_rsa_en.encrypt(sym)
        
                    connectionSocket.send(encrypt_client_key)

                    print(f'Connection Accepted and Symmetric Key Generated for client: {client}')
                    
                    cipher = AES.new(sym, AES.MODE_ECB)
                    # receive the client message "OK"
                    encrypt_ok = connectionSocket.recv(2048)
                    ok = unpad(cipher.decrypt(encrypt_ok), 16).decode('ascii')

                    print(ok)
                    # send menu encrypted with sym_key
                    menu = "\nSelect the operation:\n\t1) Create and send an email\n\t2) Display the inbox list\n\t3) Display the email contents\n\t4) Terminate the connection\n\n\tchoice: "
                    
                    encrypt_menu = cipher.encrypt(pad(menu.encode('ascii'), 16))
                    connectionSocket.send(encrypt_menu)

                    # receive choice
                    encrypt_choice = connectionSocket.recv(2048)
                    choice = unpad(cipher.decrypt(encrypt_choice), 16).decode('ascii')

                    while choice != '4':
                        if choice == '1':
                    
                            # Receive and handle the email
                            email_length    = connectionSocket.recv(2048)
                            email_length    = int(unpad(cipher.decrypt(email_length), 16).decode('ascii'))
                            bytes_at_a_time = 0
                            encrypt_email   = b''
                            connectionSocket.send(' '.encode('ascii'))
                            
                            # make sure bytes are received
                            while bytes_at_a_time <= email_length:
                                
                                encrypt_email += connectionSocket.recv(1000)
                                bytes_at_a_time += 1000

                                if bytes_at_a_time >= email_length:
                                    break
                            
                            handle_email(encrypt_email, sym, cipher)

                        elif choice == '2':
                            # Get the content by calling the display_email function
                            content = display_email(client)[0]
                            
                            # Encrypt and send content to the client
                            content = cipher.encrypt(pad(content.encode('ascii'), 16))
                            connectionSocket.send(content)
                        
                        elif choice == '3':
                            # Get the email index from the client
                            email_index = connectionSocket.recv(2048)
                            email_index = unpad(cipher.decrypt(email_index), 16).decode('ascii')
                            
                            # Send the email content to the client based on the email index
                            content = display_email(client)[1]
                            
                            # Ensure inbox is not empty and client doesnt send an invalid email index
                            if (content != []) and (int(email_index) <= len(content)):
                                file_name = content[int(email_index) - 1]
                                
                                with open(f'{client}/{file_name}', 'r') as f:
                                    file = f.read()
                                    content = cipher.encrypt(pad(file.encode('ascii'), 16))
                                    content_length = str(len(content))
                                    connectionSocket.send(cipher.encrypt(pad(content_length.encode('ascii'), 16)))
                                    connectionSocket.recv(10)
                                    connectionSocket.sendall(content)
                               
                            # Tell client if inbox is empty or email index is invalid     
                            else:
                                content = cipher.encrypt(pad('Empty email/Invalid index!'.encode('ascii'), 16))
                                content_length = str(len(content))
                                connectionSocket.send(cipher.encrypt(pad(content_length.encode('ascii'), 16)))
                                connectionSocket.recv(10)
                                connectionSocket.sendall(content)
                        
                        # receive choice again
                        encrypt_choice = connectionSocket.recv(2048)
                        choice = unpad(cipher.decrypt(encrypt_choice), 16).decode('ascii')
                    
                    print(f'Terminated connection with {client}')
                    connectionSocket.close()
                    return
                    
                else:
                    connectionSocket.send("Invalid username or password".encode('ascii'))
                    print(f"The received client information: {client} is invalid (Connection Terminated).")
                    print(f"Terminating connection with {client}.")
                    connectionSocket.close()
                    return
                
            # Parent doesn't need this connection
            connectionSocket.close()

        except socket.error as e:
            print('An error occurred:', e)
            serverSocket.close()
            sys.exit(1)
        except:
            serverSocket.close()
            sys.exit(0)


# ------
server()
