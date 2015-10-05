#!/usr/bin/env python
# -*- coding: UTF-8 -*-
"""
CERTitude: The Seeker of IOC
CERT-Solucom cert@solucom.fr
"""
"""
Module CERTitude proposant une interface de téléchargement des données pour la webif
"""
import datetime
import json
import re

from sqlalchemy import or_
from netaddr import IPNetwork

from config_droits import ADMINS, DROIT_VUE_CERTITUDE
from config import XP_JOURS
from helpers.helpers import uniq
from helpers.queue_models import Task
from helpers.results_models import Result
from modules.landesk.models import Result as LANDeskResult


# version du module
version = "0.0.1"

# path de la visualisation (sera préfixé par /vue/)
# ex. : 'xp' signifiera que la visualisation sera accessible à l'adresse /vue/xp/
name_in_path = 'certitude_networkmapping'

IP_REGEX = '(([0-9]|[1-9][0-9]|1[0-9]{2}|2([0-4][0-9]|5[0-5]))\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2([0-4][0-9]|5[0-5]))'

def has_right(user, args):
    """
    Attention, cette fonction est la police de la vue : elle doit importer les
    listes d'accès de la conf et les faire respecter en rejetant les
    utilisateurs indélicats.
    """
    return user in ADMINS + DROIT_VUE_CERTITUDE

def view(user, args, logger, session):
    """
    Le view() sera appelé lors d'un appel à la page associée à cette
    visualisation : le path de la visualisation sera préfixé par /vue/, par
    exemple : 'xp' signifiera que la visualisation sera accessible à
    l'adresse /vue/xp/.

    La fonction retournera un triplet [a, b, c] contenant :
    a : code HTTP de retour (par défaut : 200)
    b : Content-type HTTP de retour (par défaut : text/html)
    c : chaîne de caractère contenant le body à renvoyer au client (ex. HTML)

    En cas d'exception, consigner si besoin avec le logger approprié et laisser
    remonter l'exception.
    """

    logger.debug('Lancement du module d\'API pour CERTitude')
    getargs = args[1]

    regex = '^'+IP_REGEX+'(\/([1-9]|1[0-9]|2[0-9]|3[01]))?$'
        # Matches IP from 0.0.0.0 to 255.255.255.255
        # and allows (but not necessarily) masks from /1 to /31
    ip_donnee = getargs.split('=')[1]
    result = re.match(regex, ip_donnee) != None
    ips = IPNetwork(ip_donnee)
    logger.debug(ips)

    cibles_uniques = []
    for ip in ips:
        logger.debug('Requête en cours pour l\'ip ' + str(ip))
        cibles_uniques.append(session.query(Result).join(Task).filter(
                Result.ip == str(ip)
            ).order_by('finished DESC').first())

    donnees = []
    for c in cibles_uniques:
        if c:
            donnees.append([c.ip, c.os])

    reponse = json.dumps(donnees, indent=4)
    return [200, 'application/json', reponse]
