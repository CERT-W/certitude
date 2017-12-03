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


from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from config import CERTITUDE_DATABASE
from results_models import Result, IOCDetection
from queue_models import Task
from misc_models import User, GlobalConfig, XMLIOC, ConfigurationProfile, WindowsCredential
from yara_models import YaraRule, YaraDetection
from helpers import hashPassword, checksum, verifyPassword
import crypto
import getpass
import base64

# CERTitude core
engine = create_engine(CERTITUDE_DATABASE, echo=False)

Result.metadata.create_all(engine)
Task.metadata.create_all(engine)
IOCDetection.metadata.create_all(engine)
User.metadata.create_all(engine)
GlobalConfig.metadata.create_all(engine)
XMLIOC.metadata.create_all(engine)
ConfigurationProfile.metadata.create_all(engine)
WindowsCredential.metadata.create_all(engine)
YaraRule.metadata.create_all(engine)
YaraDetection.metadata.create_all(engine)


engine = create_engine(CERTITUDE_DATABASE, echo=False)
session = sessionmaker(bind=engine)()

print '[+] Generating Master Key...'
MASTER_KEY = crypto.genOptimalKey()

print '[+] Creating "seeker" account...'

while True:
    password = getpass.getpass('Please enter "seeker" password: ')
    password2 = getpass.getpass('Repeat: ')

    if not verifyPassword(password):
        print '[x] Password is not complex enough'
        continue
    
    if password==password2:
        break

print '[+] Encrypting Master Key for "seeker"...'

KDFSalt = crypto.randomBytes(crypto.SALT_LENGTH)
keyFromPassword = crypto.keyFromText(password, KDFSalt)
EMK = crypto.encrypt(MASTER_KEY, keyFromPassword)

print '[+] Storing Master Key checksum...'
cksum = checksum(MASTER_KEY)
gc = GlobalConfig(
            key = 'master_key_checksum',
            value = cksum
            )
session.add(gc)

del MASTER_KEY

u = User(
            username = 'seeker',
            password = hashPassword(password),
            email = 'root@localhost',
            active = True,
            encrypted_master_key = EMK,
            b64_kdf_salt = base64.b64encode(KDFSalt)
        )

session.add(u)
session.commit()