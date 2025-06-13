from pwn import *
from utils import MT19937
import random
import secrets
import json
import sys

host = "127.0.0.1"
PORT = 9001
state = []

p = remote(host, PORT)
def set_state():
    print(p.recvuntil(b'placements:'))
    data = b'[[100,200,"V"],[300,400,"H"],[500,600,"V"],[700,800,"H"],[900,1000,"V"]]'
    p.sendline(data)
    p.recvline()

    for i in range(312):
        p.recvline()
        p.sendline(f"{i+1},{i+2}")
        p.recvline()
        cords = p.recvline()
        #print(cords)
        cords = cords.split()[3].decode()
        x,y= cords.split(",")
        state.append(int(y))
        state.append(int(x))
        print(f"{i}: {x}, {y}")
    #p.sendline(f"{i+1},{i+2}")


def untemper(y: int, consts: dict) -> int:
    size = consts['w']
    y = invert_right_transform(y, consts['l'], size)
    y = invert_left_transform(y, consts['t'], size, consts['c'])
    y = invert_left_transform(y, consts['s'], size, consts['b'])
    y = invert_right_transform(y, consts['u'], size, consts['d'])

    return y & ((1 << size) - 1)

def invert_right_transform(y1: int, shift: int, size: int, mask: int=0) -> int:
    mask = mask or ((1 << size) - 1)

    if shift >= size / 2:
        return y1 ^ ((y1 >> shift) & mask)
    else:
        y0 = (y1 >> (size - shift)) << (size - shift)
        for _ in range(shift, size, shift):
            y0 = y1 ^ ((y0 >> shift) & mask)
        return y0

def invert_left_transform(y1: int, shift: int, size: int, mask: int=0) -> int:
    mask = mask or ((1 << size) - 1)

    if shift >= size / 2:
        return y1 ^ ((y1 << shift) & mask)
    else:
        y0 = y1
        for _ in range(shift, size, shift):
            y0 = y1 ^ ((y0 << shift) & mask)
        return y0

def clone_MT19937():
    consts = MT19937.CONSTANTS_32
    cloned = MT19937.new(32)
    cloned.set_state(state)

    return cloned

def test_MT19937_cloning() -> bool:
    cloned = clone_MT19937()
    #cloned = MT19937.new(64, seed)

    print(p.recvline())
    print(p.recvline())
    p.sendline(b"try")
    print(p.recvuntil(b'placements:'))
    data = b'[[100,200,"V"],[300,400,"H"],[500,600,"V"],[700,800,"H"],[900,1000,"V"]]'
    p.sendline(data)
    p.recvline()
    #c1 = cloned.genrand_int()
    #print(c1)
    for _ in range(10):
        c1 = cloned.genrand_int()
        c2 = cloned.genrand_int()
        c3 = cloned.genrand_int()
        c4 = cloned.genrand_int()
        r = (((c3 >> 5) << 26) + (c4 >> 6)) / float(1 << 53)
        print(f"C1 {c1}")
        print(f"C2 {c2}")
        print(f"MR {r}")

    for _ in range(10):
        c1 = cloned.genrand_int()
        c2 = cloned.genrand_int()
        print(f"C1 {c1}")
        print(f"C2 {c2}")
        print(f"MR {r}")

    return True


def main():
    set_state()
    passed64 = test_MT19937_cloning()

if __name__ == '__main__':
    main()

