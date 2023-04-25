"""
Required modules for the wallet
"""
import hashlib
import secrets
import os
import base64
import json
import codecs
import socket

import base58
import ecdsa
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

class Config:
    """
        Specifiying all of the parameters for the wallet such as encrytion, colors, units etc.
    """
    ecdsaCurve=ecdsa.SECP256k1
    hashingAlgo=hashlib.sha3_256
    version=1
    fileDir=""
    network_bytes="89"
    pub_key_bytes="03"
class Wallet:
    """
        This is the wallet class and it stores all the needed info for the wallet
    """
    def __init__(self,private_key,wallet_name):
        self.private_key=private_key
        self.wallet_name=wallet_name
        self.address=None
    def generate_details(self):
        """
        Generates the details of the wallet.
        """
        key=self.private_key[2:]
        verifying_key=ecdsa.SigningKey.from_string(key,curve=Config.ecdsaCurve,hashfunc=Config.hashingAlgo).verifying_key
        print(codecs.encode(ecdsa.SigningKey.from_string(key,curve=Config.ecdsaCurve,hashfunc=Config.hashingAlgo).sign("103fcc143105ba838f06da93375c741bd5c5d97ca836feb8f10b3e7f27b5d66649c6c6aa46ca6d806af8fb109e9882e7c9afe950a37fd44c85357904a12896961ee1100xWsMNc3qwQA3ifTuBSUxsNtYXvQFvguKJL120101682133575.0096".encode()),"hex"))
        print(verifying_key.to_string())
        public_key=codecs.decode((Config.pub_key_bytes+codecs.encode(verifying_key.to_string(),"hex").decode()).encode(),"hex")
        print(Config.pub_key_bytes+codecs.encode(verifying_key.to_string(),"hex").decode())
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
        address=base58.b58encode(codecs.decode(non_base58.encode(),"hex")).decode()
        print(address)
        self.address=address
class ClientConnection:
    """
    Handles the wallets socket connections
    """
    def __init__(self,host,port):
        self.host=host
        self.port=port
        self.socket=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        self.socket.connect((host, port))
    def send(self,jdata):
        """
        Sends JSON data and returns the response from the node.
        """
        self.socket.send(json.dumps(jdata).encode())
        return self.socket.recv(1024).decode()
print(ClientConnection("0.0.0.0",10000).send({"command":"GET_BALANCE","address":"xWsMNc3qwQA3ifTuBSUxsNtYXvQFvguKJL"}))
def generate_key():
    """
        Generate a secure,random, key
    """
    return hex(secrets.randbits(128))



def create_wallet(wallet_name,password):
    """
    Takes in info from the user and makes a wallet file with fernet encryption
    """
    salt = codecs.encode(os.urandom(16),"hex")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA3_512,
        length=32,
        salt=salt,
        iterations=1000000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password))
    fernet_key = Fernet(key)
    wallet_private_key=generate_key()
    encrypted_key = fernet_key.encrypt(wallet_private_key.encode())
    with open(wallet_name+".json","w",encoding="utf-8") as f:
        json.dump({"pk":encrypted_key.decode(),"salt":salt.decode()},f)
def open_wallet(NAME,PASSWORD):
    """
    Take wallet name and password and return the wallets private key
    """
    with open(NAME+".json",encoding="utf8") as f:
        encrypted_private_key=json.load(f)
    salt = encrypted_private_key['salt'].encode()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA3_512,
        length=32,
        salt=salt,
        iterations=1000000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(PASSWORD))
    fernet_key = Fernet(key)
    private_key=fernet_key.decrypt(encrypted_private_key['pk'])
    return private_key

NAME="GrantsWallet"
PASSWORD="Grantrock1!".encode()

#create_wallet(NAME,PASSWORD)
private_key=open_wallet(NAME,PASSWORD)
wallet=Wallet(private_key,NAME)
wallet.generate_details()