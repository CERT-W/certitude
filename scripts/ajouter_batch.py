#!/usr/bin/env python
# -*- coding: UTF-8 -*-
"""
CERTitude: The Seeker of IOC
CERT-Solucom cert@solucom.fr
"""
import requests
from netaddr import IPAddress, IPNetwork


# IMPORTANT : vérifier que l'authentification autorise ce script
# (par exemple, en identification par l'IP avec 127.0.0.1 autorisé)
domaine = 'https://127.0.0.1:8080'
auth = ("USERNAME", "PASSWORD")

f = open("cibles/Batch Beta/beta_down.txt", 'r')
for i, l in enumerate(f.readlines()):
    if i % 100 == 0: print 'Requete', i
    url = domaine + "/scan/?ip=" + l.strip() + '&essais=2&priorite=9&commentaire=Vague+Gamma&force=1'
    #print url
    if auth:
        reponse = requests.get(url, verify=False, auth=auth, proxies=None)
    else:
        reponse = requests.get(url, verify=False, proxies=None)
    #print reponse.status_code
    if reponse.status_code != 200:
        print 'Erreur dans la soumission de ' + l.strip()
    if IPAddress('10.84.0.52') in IPNetwork(l):
        print l
