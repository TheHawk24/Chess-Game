from pwn import *
from utils import MT19937
import random
import secrets
import json
import sys

host = "challenge.ctf.uscybergames.com"
PORT = 42939
state = []

p = remote(host, PORT)


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

def set_state():
    print(p.recvuntil(b'placements:'))
    data = b'[[100,200,"V"],[300,400,"H"],[500,600,"V"],[700,800,"H"],[900,1000,"V"]]'
    p.sendline(data)
    p.recvline()
    consts = MT19937.CONSTANTS_32
    for i in range(312):
        print(f"Number {i}")
        print(p.recvline())
        print(p.sendline(f"{i+1},{i+2}"))
        print(p.recvline())
        cords = p.recvline()
        #print(cords)
        cords = cords.split()[3].decode()
        x,y= cords.split(",")
        state.append(untemper(int(x),consts))
        state.append(untemper(int(y),consts))
        #print(f"{i}: {x}, {y}")
    #p.sendline(f"{i+1},{i+2}")

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
    sizes = [5,4,3,3,2]
    shoot = []
    for i in range(5):
        c1 = cloned.genrand_int()
        c2 = cloned.genrand_int()
        c3 = cloned.genrand_int()
        c4 = cloned.genrand_int()
        r = (((c3 >> 5) << 26) + (c4 >> 6)) / float(1 << 53)
        d = 'H' if r < 0.5 else 'V'
        for c in range(sizes[i]):
            rr = c1 + c if d == 'V' else c1
            cc = c2 + c if d == 'H' else c2
            shoot.append((rr,cc))

    for i in range(312):
        flag = str(p.recvline())
        print(flag)
        if "Flag" in flag:
            print(flag)
            break
        #p.sendline(f"{i+1},{i+2}")
        a,b = i, i+1
        if i < len(shoot):
            a,b = shoot[i]
            p.sendline(f"{a},{b}")
        else:
            p.sendline(f"{a},{b}")
        p.recvline()
        p.recvline()
        #print(cords)
    

    print(p.recvline())
    return True


def main():
    set_state()
    passed64 = test_MT19937_cloning()

if __name__ == '__main__':
    main()

