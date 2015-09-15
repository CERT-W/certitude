#!/usr/bin/env python
# -*- coding: UTF-8 -*-
"""
CERTitude: The Seeker of IOC
CERT-Solucom cert@solucom.fr
"""
if __name__ == "__main__" and __package__ is None:
    raise Exception('Erreur : lancez le script depuis main.py et non directement')


# From CERTitude orchestrator
import base64
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

from config import DOSSIER_LOG, BASE_DE_DONNEES_QUEUE, SLEEP, SECONDES_ENTRE_TENTATIVES, MAX_QUEUE_WARNING
from config import IOC_LOGIN, IOC_PASSWORD, IOC_DOMAIN, IOC_MODE, IOC_CONFIDENTIAL, IOC_KEEPFILES
from config import IOC_CONFIDENTIAL_DIRECTORY, IOC_COMPONENT_ROOT, IOC_TEMP_DIR
from helpers.queue_models import Task
from helpers.results_models import Result, IOCDetection
from helpers.misc_models import ConfigurationProfile, WindowsCredential, XMLIOC, Batch, GlobalConfig, User
from helpers.helpers import hashPassword, checksum
import helpers.crypto as crypto
import getpass

try:
    chemin = path.join(path.dirname(path.abspath(__file__)), '..', '..')
except:
    chemin = ""

loggingiocscan = logging.getLogger('iocscanner.' + threadname)

engine = create_engine(BASE_DE_DONNEES_QUEUE, echo=False)
session = sessionmaker(bind=engine)()
logfile = open(path.join(chemin, DOSSIER_LOG,'nmap.log'), 'a')

# From certitude.py

import openioc.openiocparser as openiocparser
import openioc.ioc as ioc

import remotecmd
from threading import Lock
from optparse import OptionParser
import  time, logging, os, sys, json

# from targethandler.py

# Evaluators

import helpers.iocscan_modules as ioc_modules

DR_PLUS_DIR = 'DR_PLUS'

# File droplist

dropList = [
    [os.path.join('resources','gzip.exe'), 'gzip.exe'],
    [os.path.join('resources','tar.exe'), 'tar.exe'],
    [os.path.join('resources','collecte.tar.gz'), 'collecte.tar.gz'],
    [os.path.join('resources','import_sql.tar.gz'), 'import_sql.tar.gz'],
    [os.path.join('resources','rmtar.bat'), 'rmtar.bat'],
]


# Commands executed at startup (after files being dropped)
StartCommandList = [
    'gzip -d -k collecte.tar.gz',
    'gzip -d -k import_sql.tar.gz',
    'tar xf collecte.tar',
    'tar xf import_sql.tar',
]

# Commands executed at the end (after files being dropped)
# 0 = do not execute if keep files
EndCommandList = [
    ['rmtar.bat collecte.tar',0],
    ['rmtar.bat import_sql.tar',0],
]

# Ajout manuel d'IP pour tests
#unetache = Task(ip='10.80.0.240')
#unetache = Task(ip='192.168.0.104')
# session.add(unetache)
# session.commit()


def scan(targetObject, IOCObjects, hostConfidential):

    HANDLER_NAME = '%s@%s' % (targetObject['login'], targetObject['ip'])

    # Init PsExec tunnel to targer
    try:
        RemCom = remotecmd.RemoteCmd(loggingiocscan,
                                        targetObject['ip'],
                                        targetObject['login'],
                                        targetObject['password'],
                                        domain = targetObject['domain'],
                                        rootDir = IOC_COMPONENT_ROOT
                                     )
        loggingiocscan.info('Handler %s has been succesfully created' % HANDLER_NAME)
    # too bad, error in connection
    except Exception, e:
        loggingiocscan.error('Handle '+HANDLER_NAME+' could not be created : '+str(e).decode('cp1252'))
        return None

    drive = RemCom.setNet()

    # Drop files
    for local, remote in dropList:

        if RemCom.fileExists(remote):
            RemCom.deleteFile(remote)
        RemCom.dropFile(local, remote)

    # Start commands
    for command in StartCommandList:
        RemCom.execCommand(command, drive)

    # Confidential
    hostConfidential_LOCALNAME = os.path.join(IOC_CONFIDENTIAL_DIRECTORY, HANDLER_NAME)
    if hostConfidential:
        os.makedirs(os.path.join(IOC_COMPONENT_ROOT, hostConfidential_LOCALNAME))

    # TMP query file
    if not os.path.isdir(IOC_TEMP_DIR):
        os.makedirs(IOC_TEMP_DIR)
    TEMP_FILE = os.path.join(IOC_TEMP_DIR, '%s.tmp' % threadname)

    # <analysis>

    result = {}
    raw_results = {}
    initFilesPresent = []

    if IOC_MODE == 'flat':

        for IOCid, IOCObject in IOCObjects.items():
            loggingiocscan.info('Searching for IOC %s (id=%d)' % (IOCObject['name'], IOCid))

            leaves = IOCObject['tree'].getLeaves()

            # IOC Tree evaluation
            for uid, leaf in leaves.items():
                if uid not in result.keys():
                    if leaf.document in ioc_modules.flatEvaluatorList.keys():
                        localFullname = os.path.join(IOC_COMPONENT_ROOT, hostConfidential_LOCALNAME)
                        evlt = ioc_modules.flatEvaluatorList[leaf.document](loggingiocscan, leaf, RemCom, drive, IOC_KEEPFILES, hostConfidential, localFullname)
                        newFiles = evlt.createInitFiles(initFilesPresent)

                        for newFile in newFiles:
                            initFilesPresent.append(newFile)

                            if hostConfidential:
                                RemCom.getFile(newFile, os.path.join(hostConfidential_LOCALNAME, newFile))

                        res = evlt.eval(TEMP_FILE)

                    else:
                        loggingiocscan.info('Setting result=UNDEFINED for '+leaf.document)
                        res = ioc_modules.FlatEvltResult.UNDEF

                    result[uid] = ioc_modules.FlatEvltResult._str(res)

                raw_results[leaf.id] = {'res':result[uid], 'iocid':IOCid}

            loggingiocscan.info('Research for %s has ended' % IOCObject['name'])

        if not IOC_KEEPFILES or hostConfidential:
            for remoteFile in initFilesPresent:
                RemCom.deleteFile(remoteFile)


    else:#if IOC_MODE == 'logic':
        raise NotImplementedError

    # </analysis>

    # TMP query file
    if os.path.exists(TEMP_FILE):
        os.unlink(TEMP_FILE)

    # End commands
    for command in EndCommandList:
        if (not IOC_KEEPFILES or hostConfidential) or command[1]!=0:
            RemCom.execCommand(command[0], drive)

    if not IOC_KEEPFILES or hostConfidential:
        for local, remote in dropList:
            RemCom.deleteFile(remote)
            
    if hostConfidential and not IOC_KEEPFILES:
        loggingiocscan.info('Wiping local data')
        os.popen('del /q %s\\*' % os.path.join(IOC_COMPONENT_ROOT, hostConfidential_LOCALNAME)).read()
        a = os.popen('rmdir %s' % os.path.join(IOC_COMPONENT_ROOT, hostConfidential_LOCALNAME)).read()

    RemCom.unsetNet()

    loggingiocscan.info('Handler %s has gracefully ended' % HANDLER_NAME)

    return raw_results

def analyse(resultats_scan, tache):

    smbreachable = True

    if resultats_scan is None :
        tache.retries_left_ioc -= 1

        if tache.retries_left_ioc > 0:
            tache.iocscanned = False
            tache.last_retry = datetime.datetime.now()
            tache.priority -= 1
        else:
            tache.iocscanned = True

        smbreachable = False
    else:
        tache.iocscanned = True

    tache.reserved_ioc = False
    session.commit()

    r  = session.query(Result).filter_by(tache_id = tache.id).first()
    
    if r is None:
        r = Result(
                    smbreachable = smbreachable,
                    tache_id=tache.id,
                    )
    else:
        r.smbreachable = smbreachable

    session.add(r)
    session.commit()

    if smbreachable:

        for ioc_id, dic in resultats_scan.items():
            if dic['res']!='True':
                continue

            id = IOCDetection(result_id = r.id, indicator_id = ioc_id, xmlioc_id = dic['iocid'])
            session.add(id)

        session.commit()


def demarrer_scanner(hWaitStop=None, batch=None):
    loggingiocscan.info('Starting an IOC scanner instance : ' + threadname)
    
    print ''
    print '\tPlease log in to launch scan'
    print ''
    username = raw_input('Username: ')
    password = getpass.getpass('Password: ')
    print ''
    
    u = session.query(User).filter_by(username = username).first()
    
    if not u or hashPassword(password) != u.password:
        loggingiocscan.critical('Username or password incorrect, shutting down...')
        raw_input()
        sys.exit(1)
        
    keyFromPassword = crypto.keyFromText(password)
    MASTER_KEY = crypto.decrypt(u.encrypted_master_key, keyFromPassword)
    
    mk_cksum = session.query(GlobalConfig).filter_by(key = 'master_key_checksum').first()
    
    if not mk_cksum:
        loggingiocscan.critical('Database is broken, please create a new one !')
        del MASTER_KEY
        raw_input()
        sys.exit(1)
        
    if checksum(MASTER_KEY)!=mk_cksum.value:
        loggingiocscan.critical('MASTER_KEY may have been altered')
        del MASTER_KEY
        raw_input()
        sys.exit(1)

    loggingiocscan.info('Login successful !')
    # INITIALIZATION

    # TODO : initialise all IOCs in DB, then link them to CP
    
    all_xmliocs = session.query(XMLIOC).order_by(XMLIOC.name.asc())
    all_cp = session.query(ConfigurationProfile).order_by(ConfigurationProfile.name.asc())
    
    ioc_by_cp = {cp.id:[int(e) for e in cp.ioc_list.split(',')] for cp in all_cp}
    tree_by_ioc = {}
    
    FLAT_MODE = (IOC_MODE == 'flat')
    allowedElements = {}
    evaluatorList = ioc_modules.flatEvaluatorList if FLAT_MODE else ioc_modules.logicEvaluatorList
    
    for name, classname in evaluatorList.items():
        allowedElements[name] = classname.evalList
    
    for xmlioc in all_xmliocs:
        
        content = base64.b64decode(xmlioc.xml_content)
        oip = openiocparser.OpenIOCParser(content, allowedElements, FLAT_MODE, fromString=True)
        oip.parse()
        iocTree = oip.getTree()

        # Trees may be stripped from non valid elements
        if iocTree is not None:
            tree_by_ioc[xmlioc.id] = {'name':xmlioc.name, 'tree':iocTree}
                        
    tree_by_cp = {cpid: {i:tree_by_ioc[i] for i in ioclist} for (cpid, ioclist) in ioc_by_cp.items()}
            
    halt = False
    tache = None
    batchquery = None
    
    if batch is not None:
        loggingiocscan.info('Filtering for batch "%s"' % batch)
        batchquery = session.query(Batch).filter( Batch.name == batch).first()
        
        if batchquery is None:
            loggingiocscan.error('Unknown batch "%s" ...' % batch)
            halt = True
            
    # TODO: remove and continue dev'
            
    # LAUNCH

    # Boucle principale
    while not halt:
        try:

            # Récupération des IPs à scanner
            queue = session.query(Task).filter_by(discovered=True, iocscanned=False, reserved_ioc=False).filter(Task.retries_left_ioc > 0)
            
            
            if batchquery is not None:        
                queue = queue.filter_by(batch_id = batchquery.id)
                
            taille_queue = queue.count()

            # Récupération des IPs papsées depuis longtemps (10 min) et non encore scannées
            # date_abandon = datetime.datetime.now() - datetime.timedelta(0, SECONDES_AVANT_ABANDON)
            # queue_abandonnee = session.query(Task).filter_by(done=False, reserve=True).filter(Task.date_debut < date_abandon)
            # taille_abandonnee = queue_abandonnee.count()

            # calcul de l'instant à partir duquel on retente un scan échoué
            limite_a_reessayer = datetime.datetime.now() - datetime.timedelta(0, SECONDES_ENTRE_TENTATIVES)
            a_scanner = queue.filter(or_(Task.last_retry <= limite_a_reessayer, Task.last_retry == None))
            taille_a_scanner = a_scanner.count()


            while taille_a_scanner > 0:
                priorite_max = a_scanner.order_by(Task.priority.desc()).first().priority
                taches_priorite_max = a_scanner.filter(Task.priority==priorite_max)
                nbre_taches_priorite_max = taches_priorite_max.count()
                if BASE_DE_DONNEES_QUEUE.startswith('sqlite'):
                    tache = taches_priorite_max.order_by(func.random()).first()
                else:
                    tache = taches_priorite_max.order_by(func.newid()).first()

                # On lock la tâche pour qu'un autre scanner ne la prenne pas
                tache.reserved_ioc = True
                tache.date_debut = datetime.datetime.now()
                session.commit()

                loggingiocscan.debug('===============================================================================')
                loggingiocscan.debug('Wake up, there is work to do !')
                loggingiocscan.info('Queue size : ' + str(taille_queue) + ', including ' + str(taille_a_scanner) + ' to scan, including ' + str(nbre_taches_priorite_max) + ' at top priority (' + str(priorite_max) + ')')
              
                loggingiocscan.debug('  --------------------------------')
                loggingiocscan.info('         Starting IOC Scan')
                loggingiocscan.info('        Target : ' + str(tache.ip))
                loggingiocscan.debug('  --------------------------------')

                batch = session.query(Batch).filter_by(id = tache.batch_id).first()
                wc = session.query(WindowsCredential).filter_by(id = batch.windows_credential_id).first()
                cp = session.query(ConfigurationProfile).filter_by(id = batch.configuration_profile_id).first()
                
                if not wc:
                    raise Exception('WindowsCredential %d does not exist' % tache.windows_credential_id)
                    
                if not cp:
                    raise Exception('ConfigurationProfile %d does not exist' % tache.configuration_profile_id)

                targetPassword = crypto.decrypt(wc.encrypted_password, MASTER_KEY)
                targetObject = {'ip':       tache.ip,
                                'login':    wc.login,
                                'password': targetPassword,
                                'domain':   wc.domain,
                                }

                if cp.host_confidential:
                    loggingiocscan.info('"High confidentiality" mode enabled')
                    testdir = os.path.join(IOC_COMPONENT_ROOT, IOC_CONFIDENTIAL_DIRECTORY)
                    if not os.path.isdir(testdir):
                        loggingiocscan.info('Creating confidential directory %s' % testdir)
                        os.makedirs(testdir)

                                
                resultats_scan = scan(targetObject, tree_by_cp[cp.id], cp.host_confidential)
                analyse(resultats_scan, tache)

                # màj de la taille de queue à scanner pour la boucle
                taille_a_scanner = a_scanner.count()

                try:
                    # si on est lancé en tant que service
                    halt = (win32event.WaitForSingleObject(hWaitStop, 2000) == win32event.WAIT_OBJECT_0)
                except:
                    pass
                if halt:
                    # Stop signal encountered
                    break

            if halt:
                loggingiocscan.info('Stopping IOC scanner : ' + threadname)
                break
            loggingiocscan.debug('(IOC scanner sleeping for ' + str(SLEEP) + ' seconds...)' \
                + (' (' + str(taille_queue) + ' waiting)' if taille_queue > 0 else ''))
            time.sleep(SLEEP)
        except KeyboardInterrupt:
            halt = True
        except Exception, e:
            halt = True
            loggingiocscan.error('Error : %s' % str(e))
            session.rollback()
            if tache is not None:
                tache.reserved_ioc = False
                tache.retries_left_ioc = max(0,tache.retries_left_ioc - 1)
            session.commit()


if __name__ == '__main__':
    demarrer_scanner()
