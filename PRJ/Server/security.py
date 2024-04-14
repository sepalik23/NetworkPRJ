# ----------------------
# Name: Charuni Liyanage, Von Castro, Moshood Aromolaran
# File: security.py
# Assignment: FINAL PROJECT
# Class: CMPT 361
# Instructor: Dr. Elmorsy
# Purpose: This program generates json files in each client in the server folder to
#          keep track of the failed attempts, lock out time and to check if the client is 
#          still in lockout. 
# ----------------------
import json
import time

for i in range(1,6):
    with open(f"client{i}/brute.json", 'w') as fp:
       json.dump({"failed_attempts": 3, "lock_time": 120, "is_timeout":False}, fp) 


