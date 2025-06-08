from sage.all import *
from hashlib import sha256

# Given parameters
r = 79584715527429222300394963243955780588590439283664809009487053717365956402397
s = 9747486637346006265691896282757974942015335411487476382189998036117147915968
n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

# Compute hash
msg = b"Karmany-evadhikaras te ma phalesu kadacana ma karma-phala-hetur bhur ma te sango 'stv akarmani."
h = int(sha256(msg).hexdigest(), 16)

# Extract high 128 bits of h
Hh = h >> 128

# Compute t, a, b as described
t = (s * Hh - h) % n
a = (s - r * pow(2, 128, n)) % n
b = (-r) % n

# Build the lattice basis
B = Matrix(ZZ, [
    [n, 0, 0],
    [0, n, 0],
    [a, b, n // (1 << 128)]
])

# Target vector for CVP
target = vector([0, 0, t])

# Reduce the lattice
B_red = B.LLL()

# Brute-force through reduced vectors to find small (d1, d0)
for row in B_red.rows():
    x, y, _ = row
    d1 = int(x) % (1 << 128)
    d0 = int(y) % (1 << 128)
    d = d0 + (d1 << 128)
    if 0 < d < n:
        print(f"[+] Recovered private key d: {d}")
        print("Flag: bi0sCTF{" + sha256(str(d).encode()).hexdigest() + "}")
        break

