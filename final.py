from sage.all import *
from hashlib import sha256

# Given values from output
r = 79584715527429222300394963243955780588590439283664809009487053717365956402397
s = 9747486637346006265691896282757974942015335411487476382189998036117147915968

n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

h = int(sha256(b"Karmany-evadhikaras te ma phalesu kadacana ma karma-phala-hetur bhur ma te sango 'stv akarmani.").hexdigest(), 16)
Hh = h >> 128

t = (s * Hh - h) % n
a = (s - r * pow(2, 128, n)) % n
b = (-r) % n

# Create lattice
B = Matrix(ZZ, [
    [n, 0, 0],
    [0, n, 0],
    [a, b, n // (1 << 128)]
])

target = vector([0, 0, t])

# CVP
L = B.LLL()
for row in L.rows():
    if abs(row[0]) < (1 << 128) and abs(row[1]) < (1 << 128):
        d0 = int(row[1]) % (1 << 128)
        d1 = int(row[0]) % (1 << 128)
        d = d0 + (d1 << 128)
        print("Possible d:", d)
        print("sha256(str(d)) =", sha256(str(d).encode()).hexdigest())
        break

