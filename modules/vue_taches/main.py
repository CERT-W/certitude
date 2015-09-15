#!/usr/bin/env python
# -*- coding: UTF-8 -*-
"""
Tango : cartographie réseau
Projet interne confidentiel par Fabien Schwebel (fabien.schwebel@solucom.fr)
"""
from config_droits import ADMINS, DROIT_VUE_TACHES
from config import TACHES_NOMBRE
from helpers.queue_models import Task


# version du module
version = "0.1.0"

# path de la visualisation (sera préfixé par /vue/)
# ex. : 'xp' signifiera que la visualisation sera accessible à l'adresse /vue/xp/
name_in_path = 'taches'


def has_right(user, args):
    """
    Attention, cette fonction est la police de la vue : elle doit importer les
    listes d'accès de la conf et les faire respecter en rejetant les
    utilisateurs indélicats.
    """
    return user in ADMINS + DROIT_VUE_TACHES

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

    logger.debug('Lancement du module de visualisation des dernières tâches')
    taches = session.query(Task).order_by('id DESC').limit(TACHES_NOMBRE)

    reponse = '''<html><body>
        <p><u>Desc :</u> liste des ''' + str(TACHES_NOMBRE) + ''' dernieres taches</p>
        <p><u>Info :</u> pour ordonner ou filter, passer par Excel : ctrl+a, crtl+c puis ctrl+v dans Excel, puis utiliser la fonction "Mettre sous forme de tableau"</p>
        <table>'''
    champs = (
        'id',
        'ip',
        'ip_demandeur',
        'commentaire',
        'batch',
        'date_soumis',
        'date_debut',
        'done',
        'priorite',
        'reserve',
        'consolide',
        'essais_restants',
        'dernier_essai',
    )
    reponse += '<thead><tr>'
    for i in champs:
        reponse += '<th>' + i + '</th>'
    reponse += '</tr></thead>'
    reponse += '<tbody>'
    for tache in taches:
        reponse += '<tr>'
        for i in champs:
            reponse += '<td>' + str(getattr(tache, i)) + '</td>'
        reponse += '<tr>'
    reponse += '</tbody></table></body></html>'

    return [200, 'text/html', reponse]
