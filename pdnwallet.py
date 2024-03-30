import sys
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
import asyncio
import hashlib
from binascii import hexlify, unhexlify

def wallet_address_from_public_key(public_key):
    try:
        bpublic_key = unhexlify(public_key)
        hash = hashlib.sha256(bpublic_key).digest()
        hash2 = hashlib.new('ripemd160', hash).digest()
        hash3 = hashlib.sha256(hash2).digest()
        hash4 = hashlib.sha256(hash3).digest()
        checksum = hash4[:4]
        address = b'' + hash2[:20] + checksum
        print(checksum)
        print(address)
        return '00' + hexlify(address).decode('utf-8').upper()
    except Exception as e:
        return False

async def initwallet(private_hex_key):
    private_key_bytes = bytes.fromhex(private_hex_key)
    private_key = ed25519.Ed25519PrivateKey.from_private_bytes(private_key_bytes[:32])
    public_key = private_key.public_key()
    public_key_hex = public_key.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw).hex()
    print('Public Key:', public_key_hex.upper())
    print('Address:', wallet_address_from_public_key(public_key_hex))

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 p.py private_key")
        sys.exit(1)

    private_hex_key = sys.argv[1]
    asyncio.run(initwallet(private_hex_key))
