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


# start.py (actuellement déprécié)
# ========
START_LANCEMENT_SERVER = True
START_LANCEMENT_CONSO = True
START_NOMBRE_SCANNERS = 2


# SSL configuration
USE_SSL = True
SSL_KEY_FILE = 'ssl\\server.pem.key'
SSL_CERT_FILE = 'ssl\\server.pem.cer'


# Serveur de l'API
# ================
# Port d'écoute de l'interface HTTP et de l'API
PORT_API = 8080
# ATTENTION, ne désactiver le SSL que lors de tests et couplé à une identification
# Backward compatibility
API_SSL = USE_SSL

INTERFACE_HASH_SALT = '' # nocommit
CREDENTIALS_INTERFACE = dict(
    USERNAME='',
    PASSWORD='')

PREFIXES_IP_GROUPE = ( # l'API n'autorisera le scan que des IP commençant par ces préfixes
    '172.',
    '192.168.',
)
NOMBRE_MAX_IP_PAR_REQUETE = 1024 # /22 en notation CIDR
SECONDES_POUR_RESCAN = 300 # secondes mini entre un résultat et une nouvelle demande

# Adresse du serveur des fichiers statiques
# peut être lancé grâce à un simple `python -m SimpleHTTPServer 8081` depuis le répertoire `static`
# ou en utilisant serveur_static.bat
ADRESSE_STATIC = 'https://localhost:8081/'


# liste des modules qui proposent une vue
MODULES_VUES = (
    'vue_xp',
    'vue_taches',
    'vue_certitude',
)


# Scanner
# =======
NMAP_EXE = "C:\\Program Files (x86)\\Nmap\\nmap.exe"
DOSSIER_OUTPUT = '_log/nmap_output/'
SLEEP = 10  # nombre de secondes entre les interrogations de la base
SECONDES_ENTRE_TENTATIVES = 300 # secondes entre les essais sur une même IP
SECONDES_AVANT_ABANDON = 600 # secondes avant de considérer qu'un scanner a failli à sa tâche et doit être remplacé
# local, pour dev
BASE_DE_DONNEES_QUEUE = "sqlite:///data.db"
# MACHINE
#BASE_DE_DONNEES_QUEUE = 'mssql+pyodbc://MACHINE/CERTitude'
MAX_QUEUE_WARNING = 20 # Au-delà de ce nombre d'IP en attente, le scanner émettera un warning
SERVEURS_DNS = ['10.0.0.0',]
SNMP_COMMUNITY = 'SNMP COMMUNITY'
PORTS = (
    ("137,139", "NetBIOS"),
    (445, "AD, partages"),
)


# IOC Scanner
# ===========

    # Credentials
IOC_LOGIN = 'Administrateur'
IOC_PASSWORD = '' # Nocommit
IOC_DOMAIN = ''

    # Switches
IOC_MODE = 'flat'           # flat | logic ## DO NOT USE "logic" for now !!!
IOC_CONFIDENTIAL = False    # True | False
IOC_KEEPFILES = False       # True | False
IOC_CONFIDENTIAL_DIRECTORY = 'DR_PLUS' # \components\iocscan\DR_PLUS
IOC_COMPONENT_ROOT = 'components\\iocscan'
IOC_TEMP_DIR = 'components\\iocscan\\tmp'

    # IOC location
# IOC_DIRECTORY = 'components\\iocscan\\ioc'
# IOC_EXTENSION = 'ioc'
# IOC_IOCLIST = []


# Consolidation
# =============

# liste des modules dans l'ordre d'appel
MODULES_CONSO = (
    'sep12',
    'cmdb',
    'landesk',
    'ad',
)

# Module SEP
BASE_DE_DONNEES_SEP_INDIC = 'mssql+pyodbc://MACHINE/Indic_AV'
BASE_DE_DONNEES_SEP = 'mssql+pyodbc://MACHINE/SymantecSEM5'

# Module CMDB
BASE_DE_DONNEES_CMDB = 'mssql+pyodbc://MACHINE/EVO_DATA50005'

# Module LANDesk
BASE_DE_DONNEES_LANDESK = 'mssql+pyodbc://MACHINE/Suivi_Parc'

# Module VUE XP
XP_JOURS = 31

# Module VUE TACHES
TACHES_NOMBRE = 100


# Visualisation
# ==============
IP_SCANNER = ('10.0.0.0',) # Pour les distinguer sur la représentation
