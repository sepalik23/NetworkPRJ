# Network Security Project 
## TEAM MEMBERS

Charuni Liyanage, Moshood Aromolaran, Von Castro 

# Objective: 
- Facilitates communication between a client and a server for exchanging emails. 
- The improved security measures implemented in the program files: server_enhanced and client_enhanced
serve as a safeguard against brute force attacks.

## How to run program

1. Generate public and private keys
    `python3 key_generator.py`

2. Run Server
    `python3 server.py`

3. Run Client
    `python3 client.py`

## How to run enhanced program
1. Generate public and private keys
    `python3 key_generator.py`

2.  Generate brute.json to keep track of attempts, lock out time and 
    whether the client is currently in lock out time
    `python3 security.py`

2. Run Server
    `python3 server_enhanced.py`

3. Run Client
    `python3 client_enhanced.py`
