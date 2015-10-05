#!/usr/bin/env python
# -*- coding: UTF-8 -*-
"""
CERTitude: The Seeker of IOC
CERT-Solucom cert@solucom.fr
"""
'''
Fichier de configuration du coeur de CERTitude ainsi que de ses modules
'''

# Global
# ======
## passage en mode debug : log plus d'infos sur le déroulement
DEBUG = True
DOSSIER_LOG = '_log/'
FORMAT_LOGS = '%(asctime)s %(name)-14s %(levelname)-8s %(message)s'

# SSL configuration
USE_SSL = True
SSL_KEY_FILE = 'ssl\\server.pem.key'
SSL_CERT_FILE = 'ssl\\server.pem.cer'


INTERFACE_HASH_SALT = '' # nocommit
SECONDES_POUR_RESCAN = 300 # secondes mini entre un résultat et une nouvelle demande

SLEEP = 5 # nombre de secondes entre les interrogations de la base
SECONDES_ENTRE_TENTATIVES = 300 # secondes entre les essais sur une même IP
BASE_DE_DONNEES_QUEUE = "sqlite:///data.db"

# IOC Scanner
# ===========

IOC_MODE = 'flat'           # flat | logic ## DO NOT USE "logic" for now !!!
IOC_KEEPFILES = False       # True | False
IOC_CONFIDENTIAL_DIRECTORY = 'DR_PLUS' # \components\iocscan\DR_PLUS
IOC_COMPONENT_ROOT = 'components\\iocscan'
IOC_TEMP_DIR = 'components\\iocscan\\tmp'