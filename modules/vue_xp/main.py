#!/usr/bin/env python
# -*- coding: UTF-8 -*-
"""
CERTitude: The Seeker of IOC
CERT-Solucom cert@solucom.fr
"""
"""
Module CERTitude permettant la récupération d'un tableau des Windows XP
"""
import datetime

from sqlalchemy import or_

from config_droits import ADMINS, DROIT_VUE_XP
from config import XP_JOURS
from helpers.helpers import uniq
from helpers.queue_models import Task
from helpers.results_models import Result
from modules.landesk.models import Result as LANDeskResult


# version du module
version = "0.1.0"

# path de la visualisation (sera préfixé par /vue/)
# ex. : 'xp' signifiera que la visualisation sera accessible à l'adresse /vue/xp/
name_in_path = 'xp'


def has_right(user, args):
    """
    Attention, cette fonction est la police de la vue : elle doit importer les
    listes d'accès de la conf et les faire respecter en rejetant les
    utilisateurs indélicats.
    """
    return user in ADMINS + DROIT_VUE_XP

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

    logger.debug('Lancement du module de visualisation des machines sous Windows XP')
    limite_affichage_vue_xp = datetime.datetime.now() - datetime.timedelta(0, 60*60*24*XP_JOURS)
    xp = session.query(Result).join(Task).filter(
            or_(
                Result.os.contains('Windows XP'),
                LANDeskResult.os.contains('Windows XP')
            ),
            Result.os != 'Microsoft Windows XP SP2 or Windows Server 2003 SP1 or SP2',
            Result.finished >= limite_affichage_vue_xp,
            Task.consolide == 1
        ).order_by('finished DESC')
    logger.debug(str(xp.count()) + ' scans de machines sous Windows XP sur la période')

    # TODO: à optimiser en 2, voire 1 requête

    hostnames = uniq((machine.hostname for machine in xp))
    xp_uniques = []
    logger.debug(str(len(hostnames)) + ' machines sous Windows XP recensées sur la période, affinage...')
    for i, hostname in enumerate(hostnames):
        logger.debug('Requête ' + str(i) + '/' + str(len(hostnames)) + ' en cours')
        xp_uniques.append(session.query(Result).join(Task).filter(
                or_(
                    Result.os.contains('Windows XP'),
                    LANDeskResult.os.contains('Windows XP')
                ),
                Result.hostname == hostname,
                Result.finished >= limite_affichage_vue_xp,
                Task.consolide == 1
            ).order_by('finished DESC').first())

    reponse = '''<html><body>
        <p><u>Desc :</u> liste non-exhaustive des Windows XP detectes sur le reseau depuis ''' + XP_JOURS + ''' jours</p>
        <p><u>Info :</u> pour ordonner ou filter, passer par Excel : ctrl+a, crtl+c puis ctrl+v dans Excel, puis utiliser la fonction "Mettre sous forme de tableau"</p>
        <table>'''
    reponse += '<thead><tr><th>IP</th><th>Nom d\'hote</th><th>OS selon LANDesk</th><th>OS detecte</th><th>Presence SEP 12</th><th>Date detection</th></tr></thead>'
    reponse += '<tbody>'
    for machine in xp_uniques:
        reponse += '<tr>'
        reponse += '<td>' + machine.ip + '</td>'
        reponse += '<td>' + str(machine.hostname) + '</td>'
        try:
            reponse += '<td>' + str(machine.landesk.os) + '</td>'
        except AttributeError, e:
            reponse += '<td>?</td>'
        reponse += '<td style="font-size: 90%;">' + (str(machine.os) if 'Cisco' not in str(machine.os) else '-') + '</td>'
        try:
            reponse += '<td>' + ('Oui' if machine.sep12.presence else '<span style="color: red;">Non</span>') + '</td>'
        except AttributeError, e:
            reponse += '<td>?</td>'
        reponse += '<td>' + str(machine.finished) + '</td>'
        reponse += '<tr>'
    reponse += '</tbody></table></body></html>'


    return [200, 'text/html', reponse]
