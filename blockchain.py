import hashlib
import json
import time
import codecs
import ecdsa
import base58
import binascii
import os
import math
# External imports
import merkletools

class Config:
    ecdsaCurve=ecdsa.SECP256k1
    hashingAlgo=hashlib.sha3_256
    VERSION=1
    network_bytes="89"
    pub_key_bytes="03"
    mature_len=3
    coinbase_mature_len=20
    block_reward=10
    max_bytes=2000000
    expected_time=100*5*60
block_template={
        "header":{"lastBlockHash":"","created":0,"fees":0,"merkelRoot":"","version":"","target":"","nonce":0,"hash":"","next_block_hash":"","weight":0},
        "body":{"transactions":[],"totalSent":0,"totalTransactions":0},
        "footer":{"minedBy":"","minedAt":0,"timeDifference":""}# Going to contain information about the blocks miner.
        }
# VARIABLES
mempool={}
block=block_template

# Functions

def get_balance(address,start_block=0):
    """
    Scans the blockchain from the specified block or 0 and totals balance
    """
    blocks=os.listdir("blockchain")
    balance=0
    for a in range(start_block,len(blocks)):
        file=f"b{a}.json"
        with open(file) as f:
            block_d=json.load(f)
        for transaction in block_d['body']['transactions']:
            if transaction['in']['address']==address:
                balance-=transaction['total']
            elif transaction['out']['address']==address:
                balance+=transaction['out']['value']
    return balance

def create_client_transaction(sender,receiver,scriptSig,amount,fee,rtime):
    """
    Base Fee(per byte): 0.000000002

    Codes:
    0 - OK

    Error Codes:
    1 - ScriptSig hash160 and public key mismatch
    2 - Provided public key did not sign or correctly sign the signature
    """
    public_key=codecs.decode(scriptSig['pubKey'].encode(),"hex")
    sha256_bpk_digest = hashlib.sha3_256(public_key).digest()
    ripemd160_bpk_digest = hashlib.new("ripemd160",sha256_bpk_digest).digest()
    ripemd160_bpk_hex = Config.network_bytes+codecs.encode(ripemd160_bpk_digest, "hex").decode()
    public_key_bytes = codecs.decode(ripemd160_bpk_hex, "hex")
    sha256_nbpk_digest = hashlib.sha3_256(public_key_bytes).digest()
    sha256_2_nbpk = hashlib.sha3_256(sha256_nbpk_digest)
    sha256_2_nbpk_digest = sha256_2_nbpk.digest()
    sha256_2_hex = codecs.encode(sha256_2_nbpk_digest, "hex")
    checksum = sha256_2_hex[:8]
    non_base58=ripemd160_bpk_hex+checksum.decode()
    hash160d=codecs.encode(base58.b58decode(sender.encode()),"hex").decode()
    if not non_base58==hash160d:
        return 1
    verify_key=ecdsa.VerifyingKey.from_string(bytes.fromhex(scriptSig['pubKey'][2:]),curve=Config.ecdsaCurve,hashfunc=Config.hashingAlgo)
    timestamp=round(time.time())
    data=str(Config.VERSION)+scriptSig['pubKey']+str(amount)+sender+receiver+str(fee)+str(rtime)
    tx_hash=hashlib.sha3_256(hashlib.sha3_256(hashlib.sha3_256(data.encode()).digest()).digest()).hexdigest()
    try:
        verify_key.verify(bytes.fromhex(scriptSig['signature']), data.encode(), Config.hashingAlgo)
    except:
        return 2
    
    fee=fee+(len(data)*2)
    total=fee+amount



    transaction={
        "in_active_chain":False,
        "coinbase":False,
        "hex":binascii.hexlify(data.encode()).decode(),
        "size":len(data),
        "txid":tx_hash,
        "hash":tx_hash,
        "weight":len(data)*4,
        "fee":fee,
        "total":total,
        "in":{
            "scriptSig":data,
            "address":sender
        },
        "out":{
            "address":receiver,
            "value":amount
        },
        "confirmations":0,
        "blocktime":0,
        "time":timestamp,
        "blockhash":""
    }
    return transaction
def coinbase_transaction(amount,to):
    """
    Transactions made by the coinbase. No auth needed.
    """
    timestamp=time.time()
    data=f"{Config.VERSION}0{amount}Coinbase{to}0"
    tx_hash=hashlib.sha3_256(hashlib.sha3_256(hashlib.sha3_256(data.encode()).digest()).digest()).hexdigest()
    total=0+amount
    transaction={
        "in_active_chain":False,
        "coinbase":True,
        "hex":binascii.hexlify(data.encode()).decode(),
        "size":len(data),
        "txid":tx_hash,
        "hash":tx_hash,
        "weight":len(data)*4,
        "fee":0,
        "total":total,
        "in":{
            "scriptSig":data,
            "address":"Coinbase"
        },
        "out":{
            "address":to,
            "value":amount
        },
        "confirmations":0,
        "blocktime":0,
        "time":timestamp,
        "blockhash":""
    }
    return transaction
def add_transaction_to_block(tx):
    """
    Adds a transaction to the blocks body
    """
    block['body']['transactions'].append(tx)

def find_best_transactions():
    """
    Sorts mempool and then finds the transactions with the highest fee
    """
    total_bytes_used=0
    high_fee = sorted(mempool.items(), key=lambda item:item[1]['fee'],reverse=True)
    transactions_used=[]
    for a in high_fee:
        if total_bytes_used+a[1]['size']>=Config.max_bytes:
            break
        transactions_used.append(a[1])
        total_bytes_used+=a[1]['size']
    return transactions_used
def get_merkel_root(transactions):
    mt = merkletools.MerkleTools(hash_type="sha3_256")
    for a in transactions:
        mt.add_leaf(a['hash'])
    print(mt.get_leaf_count())
    mt.make_tree()
    return mt.get_merkle_root()
def calculate_new_difficulty(old_target,old_time_mined,new_time_mined):
    time_diff=new_time_mined-old_time_mined
    ratio=float(time_diff)/float(Config.expected_time)
    if ratio>4:
        ratio=4
    print(ratio)
    new_target=round(int(old_target,16)*ratio)
    new_target =(math.floor(math.log(new_target, 256)) + 1) * 0x1000000
    print(new_target)
    return str(hex(new_target))
print(calculate_new_difficulty("0000f00000000000000000000000000000000000000000000000000000000000",100000,2000000))