from pwn import *
from os import urandom
import json

io = remote('13.233.255.238',4001)
p = io.recvuntil(b'Enter token: ')

def is_valid_padding(message, io):
    io.sendline(message)
    resp = io.recvuntil(b'Enter token: ')
    #send = bytes(json.dumps(message),'utf-8')
    return '{"result": "Valid padding"}' in str(resp)

def xor(*args, **kwargs):
    strs = [s for s in args]

    length = kwargs.pop('length', 'max')
    if isinstance(length, int):
        length = length
    elif length == 'max':
        length = max(len(s) for s in strs)
    elif length == 'min':
        length = min(len(s) for s in strs)
    else:
        raise ValueError("Invalid value for length parameter")

    def xor_indices(index):
        b = 0
        for s in strs:
            b ^= s[index % len(s)]
        return b

    return bytes([xor_indices(i) for i in range(length)])

msg = p[343:-14].decode()

json_data = json.loads(msg)
message = json_data["ciphertext"]
iv1 = json_data["IV1"]
iv2 = json_data["IV2"]
message = bytes.fromhex(message)

#io.sendline(msg)
#resp = io.recvuntil(b"Enter token: ")
#print(resp)
#io.sendline(msg)
#print(io.recvuntil(b'Enter token: '))
#io.sendline(msg)
#print(io.recvuntil(b'Enter token: '))

ct_blocks = [message[i:i+16] for i in range(0, len(message), 16)]

pt = b''
state1 = bytes.fromhex(iv1)
state2 = bytes.fromhex(iv2)
for block in ct_blocks:
    iv_ok = urandom(16)
    keystream = b''
    for i in range(1, 17):
        for now in range(256):
            iv_nice = iv_ok[:16-i]
            iv = iv_nice + bytes([now]) + xor(bytes([i]), keystream, length=len(keystream))
            iv_hex = iv.hex()
            payload = '{"IV1": "' + iv_hex + '",' + '"IV2": "' + state2.hex() + '",' + '"ciphertext": "' + block.hex() + '"}'
            print(f"Payload: {payload}")
            if is_valid_padding(payload.encode(), io):
                print("Valid")
                keystream = bytes([now ^ i]) + keystream
                break
    pt += xor(keystream, state1)
    print(pt)
    state1= xor(block, state2)
    state2 = keystream

print(str(pt))
