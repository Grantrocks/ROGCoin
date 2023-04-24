import hashlib
import json
import socket


with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect(("0.0.0.0", 10017))
    s.sendall(json.dumps({"command":"GET_JOB"}).encode())
    job = json.loads(s.recv(1024).decode())
    txhashes=""
    for a in job['txdata']:
        txhashes+=a

    datastring=f"{job['blockheaders']['lastBlockHash']}{job['blockheaders']['created']}{job['blockheaders']['merkleRoot']}{job['blockheaders']['version']}{txhashes}"

    nonce=0
    target_int=int(job['blockheaders']['target'],16)
    while True:
        datastring+=str(nonce)

        bhash=hashlib.sha3_256(hashlib.sha3_256(datastring.encode()).digest()).hexdigest()
        hash_int=int(bhash,16)
        if hash_int<=target_int:
            print(bhash)
            print(nonce)
            break
        if nonce%10000==0:
            print(bhash)
        nonce+=1
print(f"Received {job}")