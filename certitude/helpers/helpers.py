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


import logging
import uuid
from hashlib import sha256, sha512
from config import INTERFACE_HASH_SALT

threadname = uuid.uuid4().hex[:6]
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


