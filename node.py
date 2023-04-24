import blockchain
import socket
import time
import hashlib
import json
HOST="0.0.0.0"
PORT=10025
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen(1)
    conn, addr = s.accept()
    while True:
        recv = conn.recv(1024).decode()
        if not recv:
            break
        data=json.loads(recv)
        if data['command']=="GET_JOB":
            conn.send(json.dumps(blockchain.give_job()).encode())
        elif data['command']=="FOUND_BLOCK":
            blockchain.validate_block(block_hash=data['hash'],found_by=data['address'],nonce=data['nonce'])
            conn.send(json.dumps({'command':"GOOD"}).encode())