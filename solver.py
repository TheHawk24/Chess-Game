from sage.all import *
from hashlib import sha256
from Crypto.Util.number import inverse
import secrets

# Curve and parameters
p = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f
E = EllipticCurve(GF(p), [0, 7])
G = E(0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
      0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)
n = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141

# Public key point Q and signature components (replace with actual values from your output)
Qx = 0x...   # <-- Replace with printed Q.x()
Qy = 0x...   # <-- Replace with printed Q.y()
r = 0x...    # <-- Replace with printed r
s = 0x...    # <-- Replace with printed s

Q = E(Qx, Qy)

# Message hash (known)
msg = b"Karmany-evadhikaras te ma phalesu kadacana ma karma-phala-hetur bhur ma te sango 'stv akarmani."
h = int(sha256(msg).hexdigest(), 16)
h_high = h & ~((1 << 128) - 1)

# Try brute-force over d_low (top 128 bits of private key)
for d_low in range(0, 1 << 20):  # Try increasing this bound if needed
    k = h_high + d_low
    try:
        r_calc = int((k * G).x()) % n
        if r_calc != r:
            continue
        k_inv = inverse(k, n)
        d = ((s * k - h) * inverse(r, n)) % n
        if d * G == Q:
            print("[+] Found private key d =", d)
            from hashlib import sha256
            flag = "bi0sCTF{" + sha256(str(d).encode()).hexdigest() + "}"
            print("[+] Flag:", flag)
            break
    except (ZeroDivisionError, ValueError):
        continue
else:
    print("[-] Failed to find the private key in given range.")

