#!/usr/bin/env python
# -*- coding: UTF-8 -*-
"""
CERTitude: The Seeker of IOC
CERT-Solucom cert@solucom.fr
"""
"""
Module CERTitude permettant l'interrogation d'un serveur de télédistribution
LANDesk dans sa version 9.5
Le principe est ici très simple : on interroge une base de données sur
laquelle on a un accès en lecture seule.
"""

from sqlalchemy import create_engine, text

from config import BASE_DE_DONNEES_LANDESK
from .models import Result


# version du module
version = "0.1.0"

# on effectue les initialisations hors de la fonction, pour ne les faire
# qu'une fois
landesk_engine = create_engine(BASE_DE_DONNEES_LANDESK, echo=False)


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

    # Recherche dans LANDesk
    if not cible.get('hostname', None):
        logger.info('Pas de hostname pour recherche dans LANDesk')
        return None

    logger.debug("Requête de la base de LANDesk...")
    ordis = landesk_engine.execute(
        text(
            "SELECT DomaineNT, OSType \
            FROM Machines \
            WHERE Nom = :hostname"
        ), {'hostname': cible['hostname']})
    ordi_LANDESK = ordis.fetchone()
    if ordi_LANDESK:
        logger.info('  Host présent dans LANDesk')
        result.presence = True
        result.domaine = ordi_LANDESK[0]
        os_landesk = ordi_LANDESK[1] if ordi_LANDESK[1] else ""
        result.os = unicode(os_landesk.replace('\xa0', ' ').decode('cp850')) ; # bug LANDesk utilisant des espaces insécables
    else:
        result.presence = False
        logger.info('  Host inconnu dans LANDesk')

    result.result_id = cible['id']

    return result
