import hashlib
import json
import socket


with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect(("0.0.0.0", 10025))
    s.send(json.dumps({"command":"GET_JOB"}).encode())
    while True:
        job = json.loads(s.recv(1024).decode())
        if job['command']=="JOB":
            txhashes=""
            for a in job['txdata']:
                txhashes+=a
            nonce=0
            target_int=int(job['blockheaders']['target'],16)
            while True:
                datastring=f"{job['blockheaders']['lastBlockHash']}{job['blockheaders']['created']}{job['blockheaders']['merkleRoot']}{job['blockheaders']['version']}{txhashes}{nonce}"
                bhash=hashlib.sha3_256(hashlib.sha3_256(datastring.encode()).digest()).hexdigest()
                hash_int=int(bhash,16)
                if hash_int<=target_int:
                    s.send(json.dumps({"command":"FOUND_BLOCK","hash":bhash,"nonce":nonce,"address":"xWsMNc3qwQA3ifTuBSUxsNtYXvQFvguKJL"}).encode())
                    break
                nonce+=1
        elif job['command']=="GOOD":
            print(job)
            break    
print(f"Received {job}")