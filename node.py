import blockchain
import socket
import time
import hashlib
import json
HOST="0.0.0.0"
PORT=10027
"""
if data['command']=="GET_JOB":
    conn.send(json.dumps(blockchain.give_job()).encode())
elif data['command']=="FOUND_BLOCK":
    blockchain.validate_block(block_hash=data['hash'],found_by=data['address'],nonce=data['nonce'])
    conn.send(json.dumps({'command':"GOOD"}).encode())
"""
while True:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST,PORT))
        s.listen()
        conn,addr=s.accept()
        with conn:
            print(f"Connected by {addr[1]}")
            while True:
                data = conn.recv(1024)
                if not data:
                    break   
                data=json.loads(data.decode())
                if data['command']=="GET_JOB":
                    conn.send(json.dumps(blockchain.give_job()).encode())
                elif data['command']=="FOUND_BLOCK":
                    blockchain.validate_block(block_hash=data['hash'],found_by=data['address'],nonce=data['nonce'])
                    conn.send(json.dumps({'command':"GOOD"}).encode())