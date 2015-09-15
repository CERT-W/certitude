#!/usr/bin/env python
# -*- coding: UTF-8 -*-
"""
CERTitude: The Seeker of IOC
CERT-Solucom cert@solucom.fr
"""
if __name__ == "__main__" and __package__ is None:
    raise Exception(
        'Erreur : lancez le script depuis main.py et non directement')

import time
import logging
import re
from os import path
from subprocess import check_output, STARTUPINFO, STARTF_USESHOWWINDOW
try:
    import win32event
except:
    pass

from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from config import BASE_DE_DONNEES_QUEUE, SLEEP, MODULES_CONSO
from helpers.results_models import Result as Result_certitude
from helpers.queue_models import Task
from helpers.helpers import row2dict


try:
    chemin = path.join(path.dirname(path.abspath(__file__)), '..')
except:
    chemin = "" # relatif

loggingconso = logging.getLogger('conso')

engine = create_engine(BASE_DE_DONNEES_QUEUE, echo=False)
session = sessionmaker(bind=engine)()


def consolidation(tache):
    # On va requêter dans les bases de prod avec l'IP de la cible, vérifions donc à nouveau sa bonne forme (double sécurité)
    # deuxième couche de sécurité (utilisation sécurisée, présente vérification)
    if not re.match("^[0-9a-fA-F\.\:]*$", tache.ip):
        loggingconso.error('Format de l\'IP non valide', exc_info=True)
        raise Exception('ERREUR CRITIQUE ! Format de l\'IP non valide : ' + tache.ip)

    # On récupère le résultat associé
    try:
        resultat = session.query(Result_certitude).filter_by(tache_id=tache.id).order_by('id DESC')[0]
    except:
        loggingconso.error('Impossible de trouver le résultat associé à la tâche', exc_info=True)
        raise Exception('Erreur : la tâche n\'a pas été effectuée')

    # On va exécuter une commande avec le hostname en argument, vérification de sa forme (double sécurité)
    # same, deuxième couche de sécurité (utilisation sécurisée, présente vérification)
    if resultat.hostname and not re.match("^[0-9a-zA-Z- _]*$", resultat.hostname):
        raise Exception('ERREUR CRITIQUE ! Format du hostname non valide : ' + resultat.hostname)

    cible = {
        'id': resultat.id,
        'ip': tache.ip,
        'hostname': resultat.hostname,
    }

    results = []
    for module in MODULES_CONSO:
        loggingconso.debug('Lancement du module ' + str(module))
        run_module = getattr(
            __import__(
                "modules." + module + '.main',
                fromlist=['run']
            ), 'run')
        try:
            # Appel à la fonction run() des modules
            result = run_module(cible, loggingconso)
            results.append(result)
        except Exception, e:
            loggingconso.error('Erreur lors de la conso !', exc_info=True)
            session.rollback()
            time.sleep(1)

    for result in results:
        try:
            loggingconso.debug(row2dict(result))
        except:
            pass
        # Sauvegarde des résultats des modules
        if result:
            session.add(result)
            session.commit()

    if not resultat.hostname:
        loggingconso.info('  Pas de hostname pour soumettre aux modules')

    tache.consolide = True
    session.commit()
    return


def demarrer_conso(hWaitStop=None):
    loggingconso.info('Lancement de la consolidation')
    try:
        try:
            # On ne souhaite pas surcharger les bases de prod consultées, donc on
            # limite à 1 instance (uniquement possible si librairie tendo disponible)
            from tendo import singleton
            try:
                singleton = singleton.SingleInstance()
            except:
                loggingconso.error('Script de consolidation lancé en double')
                raise Exception(
                    'Erreur : une seule instance de ce script doit tourner à la fois')
        except:
            loggingconso.warning("Attention, il est préférable de ne pas lancer plus d'une instance de ce script")

        # Boucle principale
        while True:
            halt = False

            # Récupération des IPs à scanner
            queue = session.query(Task).filter_by(discovered=True, consolide=False)

            for tache in queue.all():
                loggingconso.debug('=================================================')
                loggingconso.debug('Eveil ! Le consolidateur a des tâches à accomplir')
                loggingconso.debug('=================================================')
                loggingconso.info('Taille des consolidations en attente : ' + str(queue.count()))
                loggingconso.info('  Consolidation de la tache numero ' + str(tache.id) + ' concernant l\'IP ' + tache.ip)
                consolidation(tache)
                try:
                    # si on est lancé en tant que service
                    halt = (win32event.WaitForSingleObject(hWaitStop, 2000) == win32event.WAIT_OBJECT_0)
                except:
                    pass
                if halt:
                    # Stop signal encountered
                    loggingconso.info('Fermeture du consolidateur')
                    break
            if halt:
                break

            loggingconso.debug('(Conso en sommeil pour ' + str(SLEEP) + ' secondes...)')
            time.sleep(SLEEP)
    except Exception, e:
        loggingconso.error('Erreur !', exc_info=True)


if __name__ == '__main__':
    demarrer_conso()
