#!/usr/bin/env python
# -*- coding: UTF-8 -*-
"""
CERTitude: The Seeker of IOC
CERT-Solucom cert@solucom.fr
"""
import requests
import datetime
import re
import time

from pbs import tail


auth = ('USERNAME', 'PASSWORD')
batch = 'Vague+Delta' # URL encoded

print 'Surveillance du fichier de logs en cours...'
while 1:
    aujourdhui = datetime.datetime.now() - datetime.timedelta(minutes=2)
    #fichier_log = '"/cygdrive/y/Symantec/Symantec Endpoint Protection Manager/apache/logs/access-' + str(aujourdhui.strftime('%Y-%m-%d')) + '.log"'
    fichier_log = '"/cygdrive/x/Logs/Infra/BlueCoat-SG/BlueCoat-SG-Acces-' + str(aujourdhui.strftime('%Y-%m-%d-%H')) + 'h.log"'

    q = tail(fichier_log, '-n 10')
    m = re.findall(r"(?:[0-9]{1,3}\.){3}[0-9]{1,3}", str(q))
    for i in m:
        r = requests.get('https://MACHINE:8080/scan/?ip=' + i.strip() + '&essais=1&batch=' + batch, auth=auth, verify=False)
        if 'ajoutee au batch' in r.text and 're-essai' in r.text:
            print datetime.datetime.now(), i, '(re-essai)'
        elif 'ajoutee au batch' in r.text:
            print datetime.datetime.now(), i, '(ajout)'
    time.sleep(180)
