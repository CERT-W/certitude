#!/usr/bin/env python
# -*- coding: UTF-8 -*-
"""
CERTitude: The Seeker of IOC
CERT-Solucom cert@solucom.fr
"""

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from config import BASE_DE_DONNEES_QUEUE
from results_models import Result, IOCDetection
from queue_models import Task
from misc_models import User, GlobalConfig, XMLIOC, ConfigurationProfile, WindowsCredential
from helpers import hashPassword, checksum
import crypto
import getpass

# CERTitude core
engine = create_engine(BASE_DE_DONNEES_QUEUE, echo=False)

Result.metadata.create_all(engine)
Task.metadata.create_all(engine)
IOCDetection.metadata.create_all(engine)
User.metadata.create_all(engine)
GlobalConfig.metadata.create_all(engine)
XMLIOC.metadata.create_all(engine)
ConfigurationProfile.metadata.create_all(engine)
WindowsCredential.metadata.create_all(engine)

# Modules
# for module in MODULES_CONSO:
    # result_module = getattr(
        # __import__(
            # "modules." + module + '.models',
            # fromlist=['Result']
        # ), 'Result')
    # result_module.metadata.create_all(engine)

engine = create_engine(BASE_DE_DONNEES_QUEUE, echo=False)
session = sessionmaker(bind=engine)()

print '[+] Generating Master Key...'
MASTER_KEY = crypto.genOptimalKey()

print '[+] Creating "seeker" account...'

while True:
    password = getpass.getpass('Please enter "seeker" password: ')
    password2 = getpass.getpass('Repeat: ')

    if password==password2:
        break

print '[+] Encrypting Master Key for "seeker"...'
keyFromPassword = crypto.keyFromText(password)
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
            encrypted_master_key = EMK
        )

session.add(u)
session.commit()