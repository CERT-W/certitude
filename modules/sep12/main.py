#!/usr/bin/env python
# -*- coding: UTF-8 -*-
"""
CERTitude: The Seeker of IOC
CERT-Solucom cert@solucom.fr
"""
"""
Module CERTitude permettant l'interrogation d'une centrale Symantec Endpoint
Protection Manager (SEPM) dans sa version 12
Le principe est ici très simple : on interroge une base de données sur
laquelle on a un accès en lecture seule.
"""

from sqlalchemy import create_engine, text

from config import BASE_DE_DONNEES_SEP, BASE_DE_DONNEES_SEP_INDIC
from .models import Result

# version du module
version = "0.1.0"

# on effectue les initialisations hors de la fonction, pour ne les faire
# qu'une fois
sep_engine = create_engine(BASE_DE_DONNEES_SEP, echo=False)
sep_indic_engine = create_engine(BASE_DE_DONNEES_SEP_INDIC, echo=False)


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

    # Recherche dans la base de SEPM
    logger.debug("Requête de la base de SEPM...")
    machines_par_hostname = sep_indic_engine.execute(
        text(
            "SELECT ComputerName, IPADDR, ComputerOS \
            FROM vwIndic_VersionAVSEP12 \
            WHERE ComputerName = :hostname AND DELETED = 0"
        ), {'hostname': cible['hostname']})
    machines_par_ip = sep_indic_engine.execute(
        text(
            "SELECT ComputerName, IPADDR, ComputerOS \
            FROM vwIndic_VersionAVSEP12 \
            WHERE IPADDR = :ip AND DELETED = 0"
        ), {'ip': cible['ip']})
    machine_SEP = machines_par_hostname.fetchone()
    details_sep = sep_engine.execute(
        text(
            '''SELECT
                [COMPUTER_NAME]
                ,[ALERTDATETIME]
                ,[FILEPATH]
                ,[SOURCE]
                ,[VIRUSNAME]
                ,[USER_NAME]
                ,[FREE_DISK]
                ,[VERSION]
            FROM [SymantecSEM5].[dbo].[SEM_COMPUTER] AS c
                INNER JOIN [SymantecSEM5].[dbo].[V_ALERTS] AS a
                    ON c.COMPUTER_ID = a.COMPUTER_IDX
                INNER JOIN [SymantecSEM5].[dbo].[VIRUS] AS v
                    ON v.VIRUSNAME_IDX = a.VIRUSNAME_IDX
                INNER JOIN [SymantecSEM5].[dbo].[SEM_AGENT] AS ag
                    ON ag.COMPUTER_ID = c.COMPUTER_ID
                INNER JOIN [SymantecSEM5].[dbo].[PATTERN] AS p
                    ON p.PATTERN_IDX = ag.PATTERN_IDX
            WHERE COMPUTER_NAME = :hostname
            ORDER BY ALERTDATETIME DESC'''
        ), {'hostname': cible['hostname']}).fetchone()

    result.result_id = cible['id']
    if not machine_SEP:
        machine_SEP = machines_par_ip.fetchone()
    if machine_SEP:
        logger.info('  IP présente dans la base de SEPM')
        result.presence = True
        result.os = machine_SEP[2]
        if details_sep:
            result.derniere_alerte_date = details_sep[1]
            result.derniere_alerte_path = details_sep[2]
            result.derniere_alerte_source = details_sep[3]
            result.derniere_alerte_virus = details_sep[4]
            result.derniere_alerte_username = details_sep[5]
            result.espace_disque = details_sep[6]
            result.version = details_sep[7]
    else:
        result.presence = False
        logger.info('  IP inconnue dans SEPM')

    return result
