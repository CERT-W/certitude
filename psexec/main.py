#!/usr/bin/env python
# -*- coding: UTF-8 -*-
"""
Module Scanopy permettant l'interrogation d'une centrale Symantec Endpoint
Protection Manager (SEPM) dans sa version 12
Le principe est ici très simple : on interroge une base de données sur
laquelle on a un accès en lecture seule.
"""
import sys

from sqlalchemy import create_engine, text
from .models import Result
import psexec

# version du module
version = "0.1.0"

# on effectue les initialisations hors de la fonction, pour ne les faire
# qu'une fois

def run(cible, logger):
    """
    Le run() sera appelé pour chaque demande d'information au sujet d'une
    cible. Il recevra en arguments les resultats précédemment agrégés, sous
    forme d'un dictionnaire, et contenant notamment l'IP de la cible et son
    hostname, et le logger.
    
    La fonction retournera un objet SQLalchemy avec les attributs découverts.
    
    En cas d'exception, la consigner avec le logger approprié et retourner 1
    ou laisser remonter l'exception.
    """
    resultats = Result()
    # Recherche dans la base de SEPM
    logger.debug("Lancement de psexec...")
    psobject = psexec.PSEXEC("cmd.exe /c systeminfo", "c:\\windows\\system32\\", None, "445/SMB", username = 'Administrateur', password = 'Motdepassefaible')
    raw_result = psobject.run(cible["ip"])
    print raw_result
    psobject.kill();
    
    if True:
        logger.info('  IP présente dans la base de SEPM')
        resultats.presence = True
        resultats.os = "OS"
    else:
        resultats.presence = False
        logger.info('  IP inconnue dans SEPM')
    return resultats
