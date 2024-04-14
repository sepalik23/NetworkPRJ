# ----------------------
# Name: Charuni Liyanage, Von Castro, Moshood Aromolaran
# File: key_generator.py
# Assignment: FINAL PROJECT
# Class: CMPT 361
# Instructor: Dr. Elmorsy
# Purpose: This program generates public and private keys for the server and client  
# ----------------------

from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import PKCS1_OAEP

key = RSA.generate(2048)
private_key = key.export_key()
public_key = key.publickey().export_key()

with open(f'Server/server_private.pem', 'wb') as private, open(f'Server/server_public.pem', 'wb') as public, open(f'Client/server_public.pem', 'wb') as cs_public:
    private.write(private_key)  # Server private key inside of server folder
    public.write(public_key)    # Sever public key insided of server folder
    cs_public.write(public_key) # Server public key inside of client folder
    

# Generate public and private keys for client
for index in range (1, 6):
   
    # Handle the Server(folder) client folders for private keys
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    
    # Private keys
    with open(f'Client/client{index}/client{index}_private.pem', 'wb') as private:
        private.write(private_key)
    
    # Public keys
    with open(f'Client/client{index}/client{index}_public.pem', 'wb') as c_public, open(f'Server/client{index}/client{index}_public.pem', 'wb') as cs_public:
        c_public.write(public_key) # Add client public key to the client folder
        cs_public.write(public_key)
    




''' To do inside the server.py'''
# # Encryption
# pubkey = RSA.import_key(public_key)
# cipher_rsa_en = PKCS1_OAEP.new(pubkey)
# enc_data = cipher_rsa_en.encrypt(message.encode('ascii'))
# print(enc_data)

# # Decryption
# privkey = RSA.import_key(private_key)
# cipher_rsa_dec = PKCS1_OAEP.new(privkey)
# dec_data = cipher_rsa_dec.decrypt(enc_data)
# print(dec_data.decode('ascii'))