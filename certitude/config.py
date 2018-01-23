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
import os

# Global
# ======

# Flask debug mode
DEBUG = True
CONSOLE_DEBUG_LEVEL = logging.DEBUG
LOG_DIRECTORY = '_log'
FORMAT_LOGS = '%(asctime)s %(name)-14s %(levelname)-8s %(message)s'


# Network configuration
LISTEN_ADDRESS = '127.0.0.1'
LISTEN_PORT = 5000
BOKEH_LISTEN_ADDRESS = '127.0.0.2'
BOKEH_LISTEN_PORT = 8000

# SSL configuration
USE_SSL = False
SSL_KEY_FILE = os.path.join(os.path.dirname(__file__), 'ssl', 'server.pem.key')
SSL_CERT_FILE = os.path.join(os.path.dirname(__file__), 'ssl', 'server.pem.cer')


INTERFACE_HASH_SALT = '' # nocommit
SLEEP = 5 # second interval between database poll
MIN_SUBMIT_INTERVAL = 300 # min second interval between two submissions of same IP address
MIN_RESCAN_INTERVAL = 300 # min second interval between two consecutive scans on same IP address
CERTITUDE_DATABASE = "sqlite:///%s" % os.path.join(os.path.dirname(__file__), 'data.db') 

# IOC Scanner
# ===========

IOC_MODE = 'flat'           # flat | logic ## DO NOT USE "logic" for now !!!
IOC_KEEPFILES = False       # True | False
IOC_CONFIDENTIAL_DIRECTORY = 'DR_PLUS'
IOC_COMPONENT_ROOT = os.path.join('components','scanner')
IOC_TEMP_DIR = os.path.join('components','scanner','tmp')
