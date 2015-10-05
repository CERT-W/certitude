#!/usr/bin/env python
# -*- coding: UTF-8 -*-
"""
CERTitude: The Seeker of IOC
CERT-Solucom cert@solucom.fr
"""

import logging
from hashlib import sha256, sha512
from config import INTERFACE_HASH_SALT


loggingserver = logging.getLogger('api')

def hashPassword(password):
    s = sha256()
    s.update(INTERFACE_HASH_SALT)
    s.update(password)

    return s.hexdigest()


def checksum(data):
    return sha512(data).hexdigest()


def verifyPassword(p):
    if len(p) < 12:
        return False

    MIN = False
    MAJ = False
    NUM = False
    SPEC = False

    for i in range(0, len(p)):
        c = ord(p[i])

        if not c in range(33, 127):
            continue

        if c in range(ord('a'), ord('z')+1):
            MIN = True
        elif c in range(ord('A'), ord('Z')+1):
            MAJ = True
        elif c in range(ord('0'), ord('9')+1):
            NUM = True
        else:
            SPEC = True

    return int(MIN)+int(MAJ)+int(NUM)+int(SPEC)>=3


