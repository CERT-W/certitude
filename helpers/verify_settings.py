#!/usr/bin/env python
# -*- coding: UTF-8 -*-
"""
CERTitude: The Seeker of IOC
CERT-Solucom cert@solucom.fr
"""
from os import path

import config
import logging


def verify():
    logger = logging.getLogger('')
    if config.DEBUG:
        logger.warning('Debug Mode')
    if config.PORT_API < 1024:
        logger.info('Port de l\API < 1024, des droits d\'administration seront nécessaires')
    if not config.USE_SSL:
        logger.warning('ATTENTION, SSL désactivé, ce qui est fortement déconseillé')
    if config.NOMBRE_MAX_IP_PAR_REQUETE < 1:
        logger.warning('ATTENTION, le NOMBRE_MAX_IP_PAR_REQUETE a une valeur erroné')
    if config.SECONDES_POUR_RESCAN < 120:
        logger.warning('ATTENTION, le nombre SECONDES_POUR_RESCAN de secondes entre les demandes de scans est inférieur à la valeur minimale conseillée de 120')
    if config.SLEEP < 1:
        logger.error('ERREUR, le nombre SLEEP de secondes entre les vérifications doit être au moins de 1')
        exit()
    if config.SLEEP < 10:
        logger.warning('ATTENTION, le nombre SLEEP de secondes entre les vérifications est inférieur à la valeur minimale conseillée de 10')
    if config.SECONDES_ENTRE_TENTATIVES < 120:
        logger.warning('ATTENTION, le nombre SECONDES_ENTRE_TENTATIVES de secondes entre les tentatives de scan est inférieur à la valeur minimale conseillée de 120')
    if len(config.SERVEURS_DNS) < 1:
        logger.warning('ATTENTION, aucun DNS renseigné')
    if len(config.PORTS) < 1:
        logger.warning('ATTENTION, aucun port renseigné pour le scan')
    for module in config.MODULES_CONSO:
        if not module.isalnum():
            logger.error('ERREUR, nom de module erroné (les noms doivent être alphanumériques)')
            exit()
