#!/usr/bin/python

from Crypto.Cipher import AES
from Crypto import Random

import base64, hashlib, sys

def genOptimalKey():
    optimalSize = max(AES.key_size)
    return Random.new().read(optimalSize)

    
def keyFromText(text):
    return hashlib.sha256(__pad(text, AES.block_size)).digest()
    
def __pad(m, size):
    l = len(m)
    lp = size if l%size==0 else size - (l%size)
    
    return m + chr(lp)*lp
   
   
def __unpad(m):
    lp = ord(m[-1])
    
    return m[:-lp]
 
 
def encrypt(m, key, aes_mode = AES.MODE_CBC):
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(key, aes_mode, iv)
    
    return base64.b64encode(iv + cipher.encrypt(__pad(m, AES.block_size)))
 
 
def decrypt(m, key, aes_mode = AES.MODE_CBC):
    c = base64.b64decode(m)
    
    iv = c[:AES.block_size]
    cipher = AES.new(key, aes_mode, iv)
    
    return __unpad(cipher.decrypt(c[AES.block_size:]))
    

# FOR TESTING PURPOSES    
if __name__ == '__main__':
    
    key = genOptimalKey()
    
    print 'KEY = %s' % base64.b64encode(key)

    m = sys.argv[1]
    print 'M = "%s"' % sys.argv[1]

    e_m = encrypt(m, key)
    print 'E(M) = %s' % e_m

    d_e_m = decrypt(e_m, key)
    print 'D(E(M)) = "%s"' % d_e_m