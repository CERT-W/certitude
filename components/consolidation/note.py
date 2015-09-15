#!/usr/bin/env python
# -*- coding: UTF-8 -*-
"""
CERTitude: The Seeker of IOC
CERT-Solucom cert@solucom.fr
"""
if __name__ == "__main__" and __package__ is None:
    raise Exception(
        'Erreur : lancez le script depuis main.py et non directement')

import re
from os import path

from sqlalchemy import create_engine, func, distinct, or_
from sqlalchemy.orm import sessionmaker

from config import BASE_DE_DONNEES_QUEUE
from queue_models import Task
from results_models import Result, Port


try:
    chemin = path.join(path.dirname(path.abspath(__file__)), '..')
except:
    chemin = "" # relatif

engine = create_engine(BASE_DE_DONNEES_QUEUE, echo=False)
session = sessionmaker(bind=engine)()

OS_PDT = (
    'Windows 7 Entreprise',
    'Windows 7 Professionnel',
    'Windows XP Professional',
    'Microsoft Windows XP SP2',
    'Microsoft Windows XP SP3',
    'Microsoft Windows XP Professional SP3',
    'Windows XP Tablet PC Edition',
    'Windows 8 Entreprise',
    'Windows 8.1 Professionnel',
    'Microsoft Windows Vista SP1 - SP2'
)

def demarrer_note(hWaitStop=None):

    def categoriser(os):
        categorie = None
        if 'server' in os:
            if 'windows' in os:
                categorie = 'serveur windows'
            else:
                categorie = 'serveur linux'
        elif 'printer' in os:
            categorie = 'imprimante'
        elif os in (x.lower() for x in OS_PDT):
            categorie = 'poste de travail'
        elif 'ilo' in os or 'remote management' in os:
            categorie = 'ilo'
        elif any(item in os for item in ('firewall', 'router', 'switch', 'bridge', 'load', 'adsl', 'modem', 'openwrt')):
            categorie = 'reseau'
        #elif any(item in os for item in ('voip', 'pbx', 'pabx', 'phone', 'voice', 'webcam', 'camera')):
        elif any(item in os for item in ('voip', 'pbx', 'pabx', 'phone', 'voice', 'camera')):
            categorie = 'voip'
        elif 'pda' in os or os == 'Microsoft Windows Mobile 2003 PocketPC'.lower():
            categorie = 'pda'
        elif 'windows' in os:
            categorie = 'windows'
        return categorie

    def noter(resultat):
        zone = 'noire'

        ports = [int(p.port) for p in resultat.ports]
        hostname = str(resultat.hostname)
        if not resultat.categorie:
            pass
        elif resultat.categorie == 'poste de travail':
            landesk = 9593 in ports
            tal = 9003 in ports
            nom_conforme = re.match('^(OP|SR|CV|ST)\d\d[WY].+', hostname)
            if all([landesk, tal, nom_conforme]):
                zone = 'blanche'
            elif any([landesk, tal, nom_conforme]):
                zone = 'grise'
        elif resultat.categorie == 'serveur windows' or resultat.categorie == 'serveur linux':
            nom_conforme = re.match('^(OP|SR|CV|ST).+', hostname)
            if resultat.cmdb and nom_conforme:
                zone = 'blanche'
            elif any([resultat.cmdb, nom_conforme]):
                zone = 'grise'
        elif resultat.categorie == 'windows':
            nom_conforme = re.match('^(OP|SR|CV|ST)\d\d.+', hostname)
            if nom_conforme:
                zone = 'grise'
        elif resultat.categorie == 'ilo':
            nom_conforme = re.match('^ILO(OP|SR|CV|ST)\d\d.+', hostname)
            if nom_conforme:
                zone = 'blanche'
            else:
                zone = 'grise'
        elif resultat.categorie in ['imprimante', 'reseau', 'voip', 'pda', 'industriel']:
            zone = 'grise'
        return zone

    # Récupération des IPs à catégoriser et noter
    queue = session.query(Result).filter(Result.up == 1, Result.categorie == None).join(Task).filter(Task.commentaire=="Vague Beta")
    #queue = session.query(Result).filter(Result.up == 1)
    #queue = session.query(Result).filter_by(categorie=None).filter(Result.os_landesk != None, Result.os != None)
    #queue = session.query(Result).filter(Result.up == 1, Result.categorie == "windows")
    #queue = session.query(Result).filter(Result.up == 1, Result.categorie == None).join(Task).filter(Task.commentaire=="Vague Beta")
    compte = queue.count()
    print '-> ' + str(compte) + ' cibles vont être catégorisées'
    fait = 0
    pas_trouve = 0

    SIMULATION = False

    if not SIMULATION:
        for resultat in queue.all():
            print str(fait + 1) + '/' + str(compte)
            categorie = None
            if resultat.ip.startswith('10.18'):
                categorie = 'industriel'
            else:
                if resultat.os_landesk:
                    categorie = categoriser(resultat.os_landesk.lower())
                if resultat.os:
                    oss = re.split(' or |, ', resultat.os.lower())
                    if not categorie:
                        categorie = categoriser(oss[0])
                    if not categorie and len(oss) > 1:
                        categorie = categoriser(oss[1])

            print 'Traitement du résultat n°' + str(resultat.id)
            print '  OS détecté : ' + str(resultat.os)
            #print '  OS LANDesk : ' + str(resultat.os_landesk)
            #print '  Catégorie : ' + str(categorie)
            #time.sleep(1)
            resultat.categorie = categorie
            if not categorie:
                pas_trouve += 1

            zone = noter(resultat)
            resultat.zone = zone
            fait += 1

        print 'commit en cours...'
        session.commit()
        print 'commit terminé'

    print '================================'
    travail = session.query(func.count(distinct(Result.ip))).join(Task).filter(Task.commentaire=="Vague Beta")
    print "Profils d'OS différents sur le réseau : " + str(session.query(func.count(distinct(Result.os))).join(Task).filter(Task.commentaire=="Vague Beta")[0][0])
    print "Taches encore non categorisees : " + str(session.query(Result).filter_by(up=1, categorie=None).join(Task).filter(Task.commentaire=="Vague Beta").count())
    print "Taches categorisees : " + str(session.query(Result).filter(Result.up==1, Result.categorie!=None).join(Task).filter(Task.commentaire=="Vague Beta").count())
    print "Taches categorisees et notees à l'instant : " + str(compte - pas_trouve)
    print "Taches dont la categorisation a echoue : " + str(pas_trouve)
    print "Catégories :"
    categories = ('serveur windows', 'serveur linux', 'imprimante', 'poste de travail', 'windows', 'ilo', 'reseau', 'voip', 'pda', 'industriel', )
    for categorie in categories:
        print " " + unicode(categorie) + " : " + str(session.query(Result).join(Task).filter(Task.commentaire=="Vague Beta", Result.categorie==categorie).count())
    print "Nombre d'IP : " + str(session.query(func.count(Result.ip)).join(Task).filter(Task.commentaire=="Vague Beta")[0][0])
    print "Nombre d'IP distinctes : " + str(travail[0][0])

    print "Nombre d'IP scannees : " + str(session.query(Task).filter(Task.commentaire=="Vague Beta").count())

    print '================================'
    print "Nombre dans LANDesk uniquement : " + str(travail.filter(Result.landesk == 1, Result.sep == 0, Result.ad == 0)[0][0])
    print "Nombre dans SEPM uniquement : "    + str(travail.filter(Result.landesk == 0, Result.sep == 1, Result.ad == 0)[0][0])
    print "Nombre dans l'AD uniquement : "    + str(travail.filter(Result.landesk == 0, Result.sep == 0, Result.ad == 1)[0][0])
    print "Nombre dans LANDesk et SEPM : "    + str(travail.filter(Result.landesk == 1, Result.sep == 1, Result.ad == 0)[0][0])
    print "Nombre dans LANDesk et l'AD : "    + str(travail.filter(Result.landesk == 1, Result.sep == 0, Result.ad == 1)[0][0])
    print "Nombre dans SEPM et l'AD : "       + str(travail.filter(Result.landesk == 0, Result.sep == 1, Result.ad == 1)[0][0])
    print "Nombre dans les trois : "          + str(travail.filter(Result.landesk == 1, Result.sep == 1, Result.ad == 1)[0][0])
    print "Nombre dans aucun : "              + str(travail.filter(Result.landesk == 0, Result.sep == 0, Result.ad == 0, Result.hostname != None)[0][0])
    print '================================'
    print "Total :"
    print "Zone blanche : " + str(travail.filter(Result.zone == 'blanche')[0][0])
    print "Zone grise : " + str(travail.filter(Result.zone == 'grise')[0][0])
    print "Zone noire : " + str(travail.filter(Result.zone == 'noire')[0][0])
    print "Pdt :"
    travail_actu = travail.filter(Result.categorie == 'poste de travail')
    print "Zone blanche : " + str(travail_actu.filter(Result.zone == 'blanche')[0][0])
    print "Zone grise : " + str(travail_actu.filter(Result.zone == 'grise')[0][0])
    print "Zone noire : " + str(travail_actu.filter(Result.zone == 'noire')[0][0])

    print 'Serveurs :'
    travail_actu = travail.filter(or_(Result.categorie == 'serveur windows', Result.categorie == 'serveur linux'))
    print "Zone blanche : " + str(travail_actu.filter(Result.zone == 'blanche')[0][0])
    print "Zone grise : " + str(travail_actu.filter(Result.zone == 'grise')[0][0])
    print "Zone noire : " + str(travail_actu.filter(Result.zone == 'noire')[0][0])

    print 'Catégories selon le service réseau : cas de LANDesk'
    for c in categories:
        print str(c) + ' : ' + str(session.query(Result).join(Task).filter(Task.commentaire=="Vague Beta", Result.up==1, Result.categorie==c).join(Port).filter(Port.port==9593, Port.status=='open').count())

if __name__ == '__main__':
    demarrer_note()
