#!/usr/bin/env bash
# gen_fake_wallets.sh
# Usage: ./gen_fake_wallets.sh [count]
# Generates fake bitcoin wallets (private key hex, WIF, pseudo-address, random balance)

COUNT="${1:-10}"

python3 - <<'PY'
import os, sys, hashlib, struct, random

ALPHABET = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

def b58encode(b: bytes) -> str:
    # Base58 encode
    n = int.from_bytes(b, 'big')
    out = bytearray()
    while n > 0:
        n, r = divmod(n, 58)
        out.append(ALPHABET[r])
    # leading zeros
    for c in b:
        if c == 0:
            out.append(ALPHABET[0])
        else:
            break
    return out[::-1].decode()

def base58check(payload: bytes) -> str:
    checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    return b58encode(payload + checksum)

def ripemd160(x):
    h = hashlib.new('ripemd160')
    h.update(x)
    return h.digest()

def make_wif(priv_bytes: bytes, compressed: bool = True) -> str:
    prefix = b'\x80'  # mainnet
    payload = prefix + priv_bytes + (b'\x01' if compressed else b'')
    return base58check(payload)

def make_pseudo_address_from_priv(priv_bytes: bytes) -> str:
    # NOT a real public-key-derived address. Deterministic fake address for testing.
    h1 = hashlib.sha256(priv_bytes).digest()
    h2 = ripemd160(h1)
    versioned = b'\x00' + h2  # version 0x00 (P2PKH mainnet)
    return base58check(versioned)

def rand_balance(max_btc=10.0):
    # random balance with 8 decimal places
    sat = random.randint(0, int(max_btc * 1e8))
    return f"{sat/1e8:.8f}"

count = int(os.environ.get('COUNT', '10'))  # fallback, not used normally
# But we'll read count from argv passed by heredoc if provided:
try:
    if len(sys.argv) > 1:
        count = int(sys.argv[1])
except:
    pass

# If the parent shell passed COUNT in environment, prefer it
try:
    count = int(os.environ.get('COUNT', count))
except:
    pass

print("privkey_hex,wif,pseudo_address,balance")
for _ in range(count):
    priv = os.urandom(32)
    priv_hex = priv.hex()
    wif = make_wif(priv, compressed=True)
    addr = make_pseudo_address_from_priv(priv)
    bal = rand_balance(10.0)
    print(f"{priv_hex},{wif},{addr},{bal}")
PY
