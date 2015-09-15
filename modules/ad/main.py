#!/usr/bin/env python
# -*- coding: UTF-8 -*-
"""
CERTitude: The Seeker of IOC
CERT-Solucom cert@solucom.fr
"""
"""
Module CERTitude permettant l'interrogation d'un environnement Active Directory
à l'aide du binaire présent en outil
"""
import sys
from os import path
from subprocess import check_output, STARTUPINFO, STARTF_USESHOWWINDOW

from sqlalchemy import create_engine, text

from .models import Result

# version du module
version = "0.1.0"

# on effectue les initialisations hors de la fonction, pour ne les faire
# qu'une fois
try:
    cheminlocal = path.join(path.dirname(path.abspath(__file__)))
except:
    cheminlocal = "" # relatif


def run(cible, logger):
    """
    Le run() sera appelé pour chaque demande d'information au sujet d'une
    cible. Il recevra en arguments les resultats précédemment agrégés, sous
    forme d'un dictionnaire, et contenant notamment l'IP de la cible et son
    hostname, et le logger.
    
    La fonction retournera un objet SQLalchemy avec les attributs découverts.
    
    En cas d'exception, consigner si besoin avec le logger approprié et laisser
    remonter l'exception.
    """
    result = Result()

    # Recherche dans l'AD
    if not cible.get('hostname', None):
        logger.info('Pas de hostname pour recherche dans l\'AD')
        return None

    # on exécute sur le poste local un appel de dsquery en ligne de commande
    startupinfo = STARTUPINFO()
    startupinfo.dwFlags |= STARTF_USESHOWWINDOW
    verif_ad = unicode(check_output([path.join(cheminlocal, 'tools', 'dsquery.exe'), "computer", "forestroot", '-name', cible['hostname']], startupinfo=startupinfo).strip().strip('"').decode('cp850'))
    if verif_ad:
        logger.info('  Host présent dans l\'AD')
        result.presence = True
        result.dn = verif_ad
    else:
        result.presence = False
        logger.info('  Host inconnu dans l\'AD')

    result.result_id = cible['id']

    return result
