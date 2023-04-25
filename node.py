import blockchain
import time
import hashlib
import json
HOST="0.0.0.0"
PORT=10000
"""
if data['command']=="GET_JOB":
    conn.send(json.dumps(blockchain.give_job()).encode())
elif data['command']=="FOUND_BLOCK":
    blockchain.validate_block(block_hash=data['hash'],found_by=data['address'],nonce=data['nonce'])
    conn.send(json.dumps({'command':"GOOD"}).encode())
"""             
import asyncio, socket

async def handle_client(reader, writer):
    request = None
    while True:
        request = (await reader.read(255)).decode('utf8')
        data=json.loads(request)
        if data['command']=="GET_JOB":
            print("GIVING JOB")
            writer.write(json.dumps(blockchain.give_job()).encode())
            break
        elif data['command']=="FOUND_BLOCK":
            print("BLOCK_FOUND")
            blockchain.validate_block(block_hash=data['hash'],found_by=data['address'],nonce=data['nonce'])
            writer.write(json.dumps({'command':"GOOD"}).encode())
            break
        elif data['command']=="GET_BALANCE":
            writer.write(json.dumps({"command":"BALANCE","value":blockchain.get_balance(data['address'])}).encode())
            break
        await writer.drain()
    writer.close()

async def run_server():
    server = await asyncio.start_server(handle_client, '0.0.0.0', 10000)
    async with server:
        await server.serve_forever()

asyncio.run(run_server())