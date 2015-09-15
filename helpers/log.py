#!/usr/bin/env python
# -*- coding: UTF-8 -*-
"""
CERTitude: The Seeker of IOC
CERT-Solucom cert@solucom.fr
"""

import logging
from os import path

from config import DEBUG, DOSSIER_LOG, FORMAT_LOGS


def init():
    try:
        chemin = path.dirname(path.abspath(__file__))
    except:
        chemin = "" # relatif
    

    logging.basicConfig(filename=path.join(chemin, '..', DOSSIER_LOG, 'certitude-core.log'), format=FORMAT_LOGS, filemode='a')
    formatter = logging.Formatter(FORMAT_LOGS)
    
    if DEBUG:
        logging.getLogger('').setLevel(logging.DEBUG)
    else:
        logging.getLogger('').setLevel(logging.INFO)

    # Base de données (SQLAlchemy)
    loggingdb = logging.getLogger('sqlalchemy.engine')
    loggingdb.setLevel(logging.WARNING)
    handler_logdb = logging.FileHandler(path.join(chemin, '..', DOSSIER_LOG, 'db.log'))
    handler_logdb.setFormatter(formatter)
    loggingdb.addHandler(handler_logdb)

    # Serveur de l'API
    loggingserver = logging.getLogger('api')
    handler_logapi = logging.FileHandler(path.join(chemin, '..', DOSSIER_LOG, 'api.log'))
    handler_logapi.setFormatter(formatter)
    loggingserver.addHandler(handler_logapi)

    # Scanners
    loggingscan = logging.getLogger('scanner')
    handler_logscan = logging.FileHandler(path.join(chemin, '..', DOSSIER_LOG, 'scanners.log'))
    handler_logscan.setFormatter(formatter)
    loggingscan.addHandler(handler_logscan)
    
    # IOCScanners
    loggingiocscan = logging.getLogger('iocscanner')
    handler_logiocscan = logging.FileHandler(path.join(chemin, '..', DOSSIER_LOG, 'iocscanners.log'))
    handler_logiocscan.setFormatter(formatter)
    loggingiocscan.addHandler(handler_logiocscan)

    # Consolidation
    loggingconso = logging.getLogger('conso')
    handler_logconso = logging.FileHandler(path.join(chemin, '..', DOSSIER_LOG, 'conso.log'))
    handler_logconso.setFormatter(formatter)
    loggingconso.addHandler(handler_logconso)


    # Double sortie vers la console aussi
    # define a Handler which writes INFO messages or higher to the sys.stderr
    console = logging.StreamHandler()
    console.setLevel(logging.INFO)
    # set a format which is simpler for console use
    formatter = logging.Formatter('%(name)-14s : %(levelname)-8s %(message)s')
    # tell the handler to use this format
    console.setFormatter(formatter)
    # add the handler to the root logger
    logging.getLogger('').addHandler(console)
