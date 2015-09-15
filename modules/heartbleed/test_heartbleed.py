import time
import BaseHTTPServer
import SocketServer
import ssl
import base64
import urlparse
import logging
from os import path
import json
import datetime
import urllib
try:
    import win32event
    import win32security
except:
    pass

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import DeclarativeMeta
from netaddr import IPNetwork

from config import PORT_API, CERT_FILE, API_SSL, BASE_DE_DONNEES_QUEUE, PORTS, TYPE_AUTH, IP_AUTORISEES, LOGIN_AUTORISES, PREFIXES_IP_GROUPE, NOMBRE_MAX_IP_PAR_REQUETE, SECONDES_POUR_RESCAN, ADRESSE_STATIC, MODULES_CONSO, MODULES_VUES
from config_droits import ADMINS, DROIT_LECTURE, DROIT_SCAN
from helpers.queue_models import Task
from helpers.results_models import *
from helpers.helpers import resolve


try:
    chemin = path.join(path.dirname(path.abspath(__file__)), '..', '..')
except:
    chemin = "" # relatif

loggingserver = logging.getLogger('api')

engine = create_engine(BASE_DE_DONNEES_QUEUE, echo=False)
session = sessionmaker(bind=engine)()



port = 5061

q = session.query(Result).filter(Result.os.contains('Linux')).join(Port).filter(Port.port == str(port), Port.status == 'open')
ips = []
results = []
for i, t in enumerate(q):
    if t.ip not in ips:
        ips.append(t.ip)
        results.append([t.ip, t.hostname, t.domaine])

print len(results)

import subprocess
ips_vulnerables = open('ips_vulnerables', 'w')

cibles = results
#cibles = [['150.164.51.112']]


for i, r in enumerate(cibles):
    if i%1 == 0: print unicode(str(i) + '/' + str(len(cibles)))
    log = open('logheartbleed.txt', 'w')
    try:
        o = subprocess.check_call('python heartbleed.py ' + r[0] + ' -p ' + str(port), stdout=log, shell=False)
    except Exception as e:
        print unicode('Attention, erreur avec ' + r[0])
        print unicode(e)
    log.close()
    log = open('logheartbleed.txt', 'r')
    resultat = ''.join(log.readlines())
    log.close()
    if 'server is vulnerable' in resultat:
        print unicode('==================================== TROUVE ====================================')
        print unicode(r[0])
        ips_vulnerables.writelines([r[0]])
