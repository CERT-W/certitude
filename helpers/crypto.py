#!/usr/bin/env python
# -*- coding: UTF-8 -*-
'''
    CERTitude: the seeker of IOC
    Copyright (c) 2016 CERT-W
    
    Contact: cert@wavestone.com
    Contributors: @iansus, @nervous, @fschwebel
    
    CERTitude is under licence GPL-2.0:
    This program is free software; you can redistribute it and/or
    modify it under the terms of the GNU General Public License
    as published by the Free Software Foundation; either version 2
    of the License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
'''

from Crypto.Cipher import AES
from Crypto import Random
from pbkdf2 import PBKDF2

import base64, hashlib, sys

SALT_LENGTH=16 # 128-bits

# Random bytes generation
def randomBytes(size):
    return Random.new().read(size)
    
    
# Generate a new random key
# Size is the maximum available size for AES
def genOptimalKey():
    optimalSize = max(AES.key_size)
    return randomBytes(optimalSize)


# True KDF, fix #4
def keyFromText(text, salt):
    optimalSize = max(AES.key_size)
    return PBKDF2(text, salt).read(optimalSize)


# Pad a message to a multiple of size
# Repeats chr(X) X times at the end of the message (X>0)
def __pad(m, size):
    l = len(m)
    lp = size if l%size==0 else size - (l%size)

    return m + chr(lp)*lp


# well, unpad :)
def __unpad(m):
    lp = ord(m[-1])

    return m[:-lp]


# IV is stored at the beginning of the encrypted message
def encrypt(m, key, aes_mode = AES.MODE_CBC):
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(key, aes_mode, iv)

    return base64.b64encode(iv + cipher.encrypt(__pad(m, AES.block_size)))


# Retrieves IV from the beginning and uses it to decipher message
def decrypt(m, key, aes_mode = AES.MODE_CBC):
    c = base64.b64decode(m)

    iv = c[:AES.block_size]
    cipher = AES.new(key, aes_mode, iv)

    return __unpad(cipher.decrypt(c[AES.block_size:]))


# FOR TESTING PURPOSES, uncomment this section
# if __name__ == '__main__':

    # key = genOptimalKey()

    # print 'KEY = %s' % base64.b64encode(key)

    # m = sys.argv[1]
    # print 'M = "%s"' % sys.argv[1]

    # e_m = encrypt(m, key)
    # print 'E(M) = %s' % e_m

    # d_e_m = decrypt(e_m, key)
    # print 'D(E(M)) = "%s"' % d_e_m