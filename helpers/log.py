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

    # IOCScanners
    loggingiocscan = logging.getLogger('iocscanner')
    handler_logiocscan = logging.FileHandler(path.join(chemin, '..', DOSSIER_LOG, 'iocscanners.log'))
    handler_logiocscan.setFormatter(formatter)
    loggingiocscan.addHandler(handler_logiocscan)
    
     # IOCScanners
    logginghashscan = logging.getLogger('hashscanner')
    handler_loghashscan = logging.FileHandler(path.join(chemin, '..', DOSSIER_LOG, 'hashscanners.log'))
    handler_loghashscan.setFormatter(formatter)
    logginghashscan.addHandler(handler_loghashscan)
    
    # Double sortie vers la console aussi
    # define a Handler which writes INFO messages or higher to the sys.stderr
    console = logging.StreamHandler()
    console.setLevel(logging.INFO)
    # set a format which is simpler for console use
    formatter = logging.Formatter('%(name)-20s : %(levelname)-8s %(message)s')
    # tell the handler to use this format
    console.setFormatter(formatter)
    # add the handler to the root logger
    logging.getLogger('').addHandler(console)
