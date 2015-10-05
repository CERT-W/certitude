#!/usr/bin/env python
# -*- coding: UTF-8 -*-
"""
CERTitude: The Seeker of IOC
CERT-Solucom cert@solucom.fr
"""
if __name__ == "__main__" and __package__ is None:
    raise Exception('Erreur : lancez le script depuis main.py et non directement')

import subprocess
import socket
import time
import datetime
import logging
import re
import uuid
from os import path
try:
    import win32event
except:
    pass

threadname = uuid.uuid4().hex[:6]

from sqlalchemy import create_engine, or_, func
from sqlalchemy.orm import sessionmaker
from lxml import objectify

from config import DOSSIER_LOG, BASE_DE_DONNEES_QUEUE, NMAP_EXE, DOSSIER_OUTPUT, SLEEP, MAX_QUEUE_WARNING, SERVEURS_DNS, SECONDES_ENTRE_TENTATIVES, SECONDES_AVANT_ABANDON, SNMP_COMMUNITY, PORTS
from helpers.queue_models import Task
from helpers.results_models import Result, Port, Link


try:
    chemin = path.join(path.dirname(path.abspath(__file__)), '..', '..')
except:
    chemin = "" # relatif

loggingscan = logging.getLogger('scanner.' + threadname)

engine = create_engine(BASE_DE_DONNEES_QUEUE, echo=False)
session = sessionmaker(bind=engine)()
logfile = open(path.join(chemin, DOSSIER_LOG,'nmap.log'), 'a')

# Ajout manuel d'IP pour tests
#unetache = Task(ip='10.80.0.240')
#unetache = Task(ip='192.168.0.104')
# session.add(unetache)
# session.commit()


def scan(id, ip):
    # Scan avec NMAP
    nom_fichier_resultat = "output_" + str(id) + "_" + ip + ".xml"
    # Définition de la commande NMAP et de ses paramètres
    commande = [NMAP_EXE,
                # Détection de l'OS
                "-O",
                # limitation des ports scannés
                "-p",
                "".join([str(i[0]) + ',' for i in PORTS]),
                "-oX",
                path.join(chemin, DOSSIER_OUTPUT, nom_fichier_resultat),
                ip]
    #logfile = open(os.devnull, 'w')
    subprocess.check_call(commande, stdout=logfile, shell=True)

    fichier_resultat = open(path.join(chemin, DOSSIER_OUTPUT, nom_fichier_resultat))
    return fichier_resultat


def analyse(fichier_resultat, tache):
    root = objectify.fromstring(fichier_resultat.read())
    runstats = root.runstats

    # Exploitation des résultats du scan et sauvegarde
    up = (runstats.hosts.get("up") == '1')
    elapsed = runstats.finished.get("elapsed")
    resultats_brut = {}


    if up:
        # Hack pour ne pas détecter un refus du firewall comme un host up
        osmatch = root.host.xpath("os/osmatch/@name")
        if osmatch and osmatch[0] == "Cisco ASA 5510 firewall (PIX OS 8.2)":
            loggingscan.warning('  ' + tache.ip + " est derrière le firewall, qui cache la vue !")
            blocked = True
        else:
            blocked = False
            loggingscan.info('  ' + tache.ip + " est en ligne")

        host = root.host

        # MAC
        mac_path = host.xpath("address[@addrtype='mac']")
        mac_nbstat = host.xpath("hostscript/script[@id='nbstat']/@output")
        mac = None
        mac_vendor = None
        if mac_path:
            mac = mac_path[0].get('addr')
            mac_vendor = mac_path[0].get('vendor')

        if not mac_path and mac_nbstat:
            rgx = re.compile('.*(([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}).*')
            test_mac = rgx.match(mac_nbstat[0])
            if test_mac:
                mac = test_mac.group(1)

        # Hostname
        # On essaye par le reverse DNS en priorité...
        hostname_long_path_dns = host.xpath("hostnames/hostname/@name")
        # ... sinon, par les scripts
        hostname_long_path_samba = host.xpath("hostscript/script[@id='smb-os-discovery']/elem[@key='fqdn']")
        hostname = None
        hostname_long = None
        hostname_long_path = hostname_long_path_dns if hostname_long_path_dns else hostname_long_path_samba
        if hostname_long_path:
            hostname_long = str(hostname_long_path[0])
            hostname = hostname_long.split(".", 1)[0].upper()


        domain = host.xpath(
            "hostscript/script[@id='smb-os-discovery']/elem[@key='domain']")
        resultats_brut = {
            'blocked': blocked,
            'ip': host.xpath("address[@addrtype='ipv4']/@addr")[0],
            'mac': mac,
            'mac_vendor': mac_vendor,
            'hostname_long': hostname_long,
            'hostname': hostname,
            'os': osmatch[0] if osmatch else None,
            'domaine': unicode(domain[0]) if domain else None,
        }
        tache.discovered = True
    else:
        loggingscan.info('  ' + tache.ip + " n'est PAS joignable...")
        if tache.retries_left_discovery > 0:
            # On remet l'entrée en jeu dans la queue
            tache.discovered = False
            tache.retries_left_discovery -= 1
            tache.last_retry = datetime.datetime.now()
            tache.priority -= 1
            tache.date_debut = None
        else:
            tache.discovered = True

    tache.reserved_discovery = False
    session.commit()

    r = Result(
        up=up,
        elapsed=elapsed,
        tache_id=tache.id,
        **resultats_brut
    )
    session.add(r)
    loggingscan.debug('  ' + str(resultats_brut))
    session.commit()

    if up:
        for port in host.xpath("ports/port"):
            p = Port(result_id=r.id, port=port.get(
                'portid'), status=port.state.get('state'))
            session.add(p)
        session.commit()

        # initialisation de ip_precedent : ip de l'hôte du scanner
        ip_precedent = socket.gethostbyname(socket.gethostname())
        for hop in host.xpath("trace/hop"):
            hopip = hop.get('ipaddr')
            l = Link(result_id=r.id, ipaddr1=ip_precedent, ipaddr2=hopip)
            session.add(l)
            ip_precedent = hopip
        session.commit()

    loggingscan.info('  ' + tache.ip + " a ete scanne")

def demarrer_scanner(hWaitStop=None):
    loggingscan.info('Lancement d\'une instance du scanner : ' + threadname)

    # Boucle principale
    while True:
        try:
            halt = False
            # Récupération des IPs à scanner
            queue = session.query(Task).filter_by(discovered=False, reserved_discovery=False).filter(Task.retries_left_discovery > 0)
            taille_queue = queue.count()

            # Récupération des IPs papsées depuis longtemps (10 min) et non encore scannées
            date_abandon = datetime.datetime.now() - datetime.timedelta(0, SECONDES_AVANT_ABANDON)
            queue_abandonnee = session.query(Task).filter_by(discovered=False, reserved_discovery=True).filter(Task.date_debut < date_abandon)
            taille_abandonnee = queue_abandonnee.count()

            # calcul de l'instant à partir duquel on retente un scan échoué
            limite_a_reessayer = datetime.datetime.now() - datetime.timedelta(0, SECONDES_ENTRE_TENTATIVES)
            a_scanner = queue.filter(or_(Task.last_retry <= limite_a_reessayer, Task.last_retry == None)).union(queue_abandonnee)
            taille_a_scanner = a_scanner.count()

            while taille_a_scanner > 0:
                priority_max = a_scanner.order_by(Task.priority.desc()).first().priority
                taches_priority_max = a_scanner.filter(Task.priority==priority_max)
                nbre_taches_priority_max = taches_priority_max.count()
                if BASE_DE_DONNEES_QUEUE.startswith('sqlite'):
                    tache = taches_priority_max.order_by(func.random()).first()
                else:
                    tache = taches_priority_max.order_by(func.newid()).first()
                # On lock la tâche pour qu'un autre scanner ne la prenne pas
                tache.reserved_discovery = True
                tache.date_debut = datetime.datetime.now()
                session.commit()

                loggingscan.debug('===============================================================================')
                loggingscan.debug('Eveil ! Le scanner a des tâches à accomplir')
                loggingscan.info('Taille de la queue : ' + str(taille_queue + taille_abandonnee) + ', dont ' + str(taille_a_scanner) + ' à scanner, dont ' + str(nbre_taches_priority_max) + ' de priorité maximale (' + str(priority_max) + ')')
                if taille_a_scanner > MAX_QUEUE_WARNING:
                    loggingscan.warning('ATTENTION, le scanner n\'arrive pas à suivre la demande : ' + str(taille_a_scanner) + ' cibles à scanner')

                loggingscan.debug('  --------------------------------')
                loggingscan.info('         Lancement de NMAP        ')
                loggingscan.info('        Cible : ' + str(tache.ip))
                loggingscan.debug('  --------------------------------')
                # Inverser le commentaire des 2 lignes suivantes pour
                # réanalyser un rapport de scan
                fichier_resultat = scan(tache.id, tache.ip)
                #fichier_resultat = open('output\output_94_10.80.234.58.xml')
                analyse(fichier_resultat, tache)

                # màj de la taille de queue à scanner pour la boucle
                taille_a_scanner = a_scanner.count()

                try:
                    # si on est lancé en tant que service
                    halt = (win32event.WaitForSingleObject(hWaitStop, 2000) == win32event.WAIT_OBJECT_0)
                except:
                    pass
                if halt:
                    # Stop signal encountered
                    loggingscan.info('Fermeture d\'une instance du scanner : ' + threadname)
                    break

            if halt:
                break
            loggingscan.debug('(Scanner en sommeil pour ' + str(SLEEP) + ' secondes...)' \
                + (' (' + str(taille_queue) + ' en attente)' if taille_queue > 0 else ''))
            time.sleep(SLEEP)
        except Exception, e:
            loggingscan.error('Erreur !', exc_info=True)
            session.rollback()
            time.sleep(1)

if __name__ == '__main__':
    demarrer_scanner()
