from sage.all import *
from hashlib import sha256
from Crypto.Util.number import inverse

# Curve and params
p = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f
n = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
E = EllipticCurve(GF(p), [0, 7])
G = E(
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
)

# Given signature (r, s) and public key Q
r = 80579966808713918478983341659337122686432803335171267648218857969027921365312
s = 9637249776736120858979470480417669223128010872043427932627328970379020037984
Qx = 19836457990735130330213999822700142063448801916778065790294450904234220560040
Qy = 49778669195807242554238448965344582118838366164474820630207798339564201541294
Q = E(Qx, Qy)

# Hash of the message
h = int(sha256(b"Karmany-evadhikaras te ma phalesu kadacana ma karma-phala-hetur bhur ma te sango 'stv akarmani.").hexdigest(), 16)

# Constants
mask_128 = (1 << 128) - 1
h_high = h & (~mask_128)

# Build lattice to recover d
B = Matrix(ZZ, 3, 3)
B[0, 0] = n
B[1, 1] = 2**128
B[2, 0] = (s * h_high) % n
B[2, 1] = (s * 1) % n
B[2, 2] = r

# LLL reduction
B = B.LLL()

# Recover potential (high_d, low_d) from short vector
for row in B.rows():
    high_d = int(row[1])
    low_d = int(row[2])
    d = (high_d << 128) + low_d
    if d <= 0 or d >= n:
        continue
    # Verify if this is the correct key
    if d * G == Q:
        print(f"[+] Found private key d = {d}")
        flag = "bi0sCTF{" + sha256(str(d).encode()).hexdigest() + "}"
        print(flag)
        break

