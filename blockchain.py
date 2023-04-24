import hashlib
import json
import time
import codecs
import ecdsa
import base58
import binascii
import os

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
        "header":{"height":0,"lastBlockHash":"","created":round(time.time(),2),"fees":0,"merkleRoot":"","version":Config.VERSION,"target":"0000f00000000000000000000000000000000000000000000000000000000000","nonce":0,"hash":"","weight":0},
        "body":{"transactions":[],"totalSent":0,"totalTransactions":0},
        "footer":{"minedBy":"","minedAt":0}# Going to contain information about the blocks miner.
        }
# VARIABLES
mempool={}
blocksfiles=os.listdir("blockchain")
with open("blockchain/"+blocksfiles[-1]) as f:
    latestb=json.load(f)
block=latestb
blockch_len=os.listdir("blockchain")
block['header']['height']=len(blockch_len)
block['header']['created']=round(time.time(),2)
block['header']['lastBlockHash']=block['header']['hash']
block['header']['hash']=""
block['header']['fees']=0
block['header']['merkleRoot']=""
block['header']['version']=Config.VERSION
block['header']['nonce']=0
block['header']['weight']=0
block['body']['transactions']=[]
block['body']['totalSent']=0
block['body']['totalTransactions']=0
block['footer']['minedBy']=""
block['footer']['minedAt']=0
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
def dump_to_mempool(txs:list):
    for a in txs:
        mempool[a['txid']]=a
def find_best_transactions():
    """
    Sorts mempool and then finds the transactions with the highest fee
    """
    total_bytes_used=0
    high_fee = sorted(mempool.items(), key=lambda item:item[1]['fee'],reverse=True)
    transactions_used=[]
    for a in mempool:
        tx=mempool[a]
        if tx['coinbase']:
            transactions_used.append(tx)
            total_bytes_used+=tx['size']
            break
    for a in high_fee:
        if total_bytes_used+a[1]['size']>=Config.max_bytes:
            break
        transactions_used.append(a[1])
        total_bytes_used+=a[1]['size']
    block['header']['merkleRoot']=get_merkel_root(transactions_used)
    return transactions_used
def get_merkel_root(transactions):
    """
    Returns the merkel root of all the provided transactions.
    """
    mt = merkletools.MerkleTools(hash_type="sha3_256")
    for a in transactions:
        mt.add_leaf(a['hash'])
    mt.make_tree()
    return mt.get_merkle_root()

def calculate_new_difficulty(old_target,old_time_mined,new_time_mined):
    """
    Calculates the new mining difficulty.
    """
    time_diff=new_time_mined-old_time_mined
    ratio=float(time_diff)/float(Config.expected_time)
    if ratio>5:
        ratio=5
    if ratio<0.0001:
        ratio=0.0001
    new_target=str(hex(round(int(old_target,16)*ratio)))[2:]
    missing=64-len(new_target)
    new_target=("0"*missing)+new_target
    return new_target
def add_block():
    """with open(f"blockchain/block{block['header']['height']-1}.json") as f:
        last_block=json.load(f)
    if last_block['header']['height']!=0:
        block['header']['lastBlockHash']=last_block['header']['hash']
    else:"""
    block['header']['lastBlockHash']="Im sitting here in my homeroom class at highschool programming my blockchain. Im 16 as of now and im having a good time."
    with open(f"blockchain/block{block['header']['height']}.json","w") as f:
        json.dump(block,f)
    blockch_len=os.listdir("blockchain")
    if len(blockch_len)>=200:
        if len(blockch_len)%200:
            block['header']['target']=evaluate_target(block['footer']['minedAt'])
    block['header']['height']=len(blockch_len)
    block['header']['created']=round(time.time(),2)
    block['header']['lastBlockHash']=block['header']['hash']
    block['header']['hash']=""
    block['header']['fees']=0
    block['header']['merkleRoot']=""
    block['header']['version']=Config.VERSION
    block['header']['nonce']=0
    block['header']['weight']=0
    block['body']['transactions']=[]
    block['body']['totalSent']=0
    block['body']['totalTransactions']=0
    block['footer']['minedBy']=""
    block['footer']['minedAt']=0
    print(block)
def validate_block(block_hash,nonce,found_by):
    block_hash_int=int(block_hash,16)
    block_target=int(block['header']['target'],16)
    if not block_hash_int<=block_target:
        return "BLOCK_HASH_NOT_IN_TARGET"
    txhashes=""
    job=give_job()
    for a in job['txdata']:
        txhashes+=a
    datastring=f"{job['blockheaders']['lastBlockHash']}{job['blockheaders']['created']}{job['blockheaders']['merkleRoot']}{job['blockheaders']['version']}{txhashes}{nonce}"
    check_block_hash=hashlib.sha3_256(hashlib.sha3_256(datastring.encode()).digest()).hexdigest()
    if not block_hash==check_block_hash:
        return "BLOCK_HASH_MISMATCH"
    block['header']['nonce']=nonce
    block['header']['hash']=block_hash
    fee_total=0
    total_transactions=0
    transaction_amount_total=0
    total_weight=0
    updated_txs=[]
    for a in block['body']['transactions']:
        fee_total+=a['fee']
        transaction_amount_total+=a['total']
        total_transactions+=1
        total_weight+=a['weight']
        a['in_active_chain']=True
        a['blocktime']=block['header']['created']
        a['blockhash']=block['header']['hash']
        updated_txs.append(a)
    block['body']['transactions']=updated_txs
    block['body']['totalSent']=transaction_amount_total
    block['body']['totalTransactions']=total_transactions
    block["header"]['weight']=total_weight
    block['footer']['minedBy']=found_by
    block['header']['fees']=fee_total
    block['footer']['minedAt']=round(time.time(),2)
    add_block()
    reward=coinbase_transaction(Config.block_reward,found_by)
    dump_to_mempool([reward])
    return block
def get_mempool():
    """
    Returns the variable mempool
    """
    return mempool
def give_job():
    txhashes=[]
    fill_block()
    for a in block['body']['transactions']:
        txhashes.append(a['hash'])        
    job={"command":"JOB","txdata":txhashes,"blockheaders":block['header']}
    return job
def fill_block():
    transactions=find_best_transactions()
    block['body']['transactions']=transactions
def evaluate_target(new_time):
    blocks_len=len(os.listdir("blockchain"))
    remainder=blocks_len%200
    print(remainder)
    if remainder==0:
        if blocks_len>=200:
            with open(f"blockchain/block{blocks_len-200}.json") as f:
                thb=json.load(f)
        else:
            with open(f"blockchain/block0.json") as f:
                thb=json.load(f)
        old_time=thb['footer']['minedAt']
        old_target=thb['header']['target']
        new_diff=calculate_new_difficulty(old_target=old_target,old_time_mined=old_time,new_time_mined=new_time)
        return new_diff