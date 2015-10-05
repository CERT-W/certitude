#!/usr/bin/env python
# -*- coding: UTF-8 -*-
"""
CERTitude: The Seeker of IOC
CERT-Solucom cert@solucom.fr
"""
"""
Module CERTitude permettant l'interrogation d'un système de gestion de parc
CMDB (solution EasyVista)
Le principe est ici très simple : on interroge une base de données sur
laquelle on a un accès en lecture seule.
"""
import sys

from sqlalchemy import create_engine, text

from config import BASE_DE_DONNEES_CMDB
from .models import Result

# version du module
version = "0.1.0"

# on effectue les initialisations hors de la fonction, pour ne les faire
# qu'une fois
cmdb_engine = create_engine(BASE_DE_DONNEES_CMDB, echo=False)


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

    # Recherche dans la CMDB
    if not cible.get('hostname', None):
        logger.info('Pas de hostname pour recherche dans la CMDB')
        return None

    logger.debug("Requête de la base de la CMDB...")
    serveurs = cmdb_engine.execute(
        text(
            "SELECT serveur, os, application, fonction, environnement, equipe, hote \
            FROM E_SYSTEMES WHERE serveur = :hostname"
        ), {'hostname': cible['hostname']})
    serveur_CMDB = serveurs.fetchone()
    ordis = cmdb_engine.execute(
        text(
            "SELECT ASSET_ID, NETWORK_IDENTIFIER, LAST_NAME \
            FROM [50005].[AM_ASSET] A INNER \
            JOIN [50005].[AM_EMPLOYEE] E \
                ON A.EMPLOYEE_ID = E.EMPLOYEE_ID \
            WHERE NETWORK_IDENTIFIER = :hostname \
            ORDER BY ASSET_ID DESC"
        ), {'hostname': cible['hostname']})
    ordi_CMDB = ordis.fetchone()
    if serveur_CMDB:
        logger.info('  Host présent dans la CMDB (serveurs)')
        result.presence = True
        result.os = serveur_CMDB[1]
        result.application = serveur_CMDB[2]
        result.fonction = serveur_CMDB[3]
        result.environnement = serveur_CMDB[4]
        result.equipe = serveur_CMDB[5]
        result.hote = serveur_CMDB[6]
    elif ordi_CMDB:
        logger.info('  Host présent dans la CMDB (postes)')
        result.presence = True
        result.proprietaire = ordi_CMDB[2]
    else:
        result.presence = False
        logger.info('  Host inconnu dans la CMDB')

    result.result_id = cible['id']

    return result
