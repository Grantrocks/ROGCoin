import blockchain
import socket
import time
import hashlib
import json
HOST="0.0.0.0"
PORT=10017
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen()
    conn, addr = s.accept()
    with conn:
        print(f"Connected by {addr}")
        while True:
            recv = conn.recv(1024).decode()
            if not recv:
                break
            data=json.loads(recv)
            if data['command']=="GET_JOB":
                conn.send(json.dumps(blockchain.give_job()).encode())
            