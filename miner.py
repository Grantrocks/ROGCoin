import hashlib
import json
import socket
while True:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect(("0.0.0.0", 10000))
        print("GETTING JOB")
        s.send(json.dumps({"command":"GET_JOB"}).encode())
        job = json.loads(s.recv(1024).decode())
        print(job)
        if job['command']=="JOB":
            txhashes=""
            for a in job['txdata']:
                txhashes+=a
            nonce=0
            target_int=int(job['blockheaders']['target'],16)
        s.close()
    while True:
        datastring=f"{job['blockheaders']['lastBlockHash']}{job['blockheaders']['created']}{job['blockheaders']['merkleRoot']}{job['blockheaders']['version']}{txhashes}{nonce}"
        bhash=hashlib.sha3_256(hashlib.sha3_256(datastring.encode()).digest()).hexdigest()
        hash_int=int(bhash,16)
        if hash_int<=target_int:
            with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as s:
                s.connect(("0.0.0.0",10000))
                s.send(json.dumps({"command":"FOUND_BLOCK","hash":bhash,"nonce":nonce,"address":"xWsMNc3qwQA3ifTuBSUxsNtYXvQFvguKJL"}).encode())
                s.close()
            break
        nonce+=1
