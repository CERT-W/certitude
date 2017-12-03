#!/usr/bin/env python
# -*- coding: UTF-8 -*-
'''
    CERTitude: the seeker of IOC
    Copyright (c) 2016 CERT-W
    
    Contact: cert@wavestone.com
    Contributors: @iansus, @nervous, @fschwebel
    
    CERTitude is under licence GPL-2.0:
    This program is free software; you can redistribute it and/or
    modify it under the terms of the GNU General Public License
    as published by the Free Software Foundation; either version 2
    of the License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
'''

if __name__ == "__main__" and __package__ is None:
    raise Exception('Error: you have to launch this script from main.py')


# SYS MODULES
import base64
import datetime
import getpass
import json
import logging
from lxml import objectify
from optparse import OptionParser
import os
import re
import subprocess
from sqlalchemy import create_engine, or_, func
from sqlalchemy.orm import sessionmaker
import sys
import socket
import time
from threading import Lock
import traceback
import uuid

# USER MODULES
from config import CERTITUDE_DATABASE, SLEEP, MIN_RESCAN_INTERVAL
from config import IOC_MODE, IOC_KEEPFILES
from config import IOC_CONFIDENTIAL_DIRECTORY, IOC_COMPONENT_ROOT, IOC_TEMP_DIR
import helpers.crypto as crypto
from helpers.helpers import hashPassword, checksum, threadname
import helpers.iocscan_modules as scan_modules
from helpers.misc_models import ConfigurationProfile, WindowsCredential, XMLIOC, Batch, GlobalConfig, User
from helpers.queue_models import Task
from helpers.results_models import Result, IOCDetection
import openioc.openiocparser as openiocparser
import openioc.ioc as ioc
import remotecmd
import shutil

loggingscan = logging.getLogger('iocscanner.' + threadname)

engine = create_engine(CERTITUDE_DATABASE, echo=False)
session = sessionmaker(bind=engine)()

# File droplist

dropList = [
    [os.path.join('resources','gzip.exe'), 'gzip.exe'],
    [os.path.join('resources','tar.exe'), 'tar.exe'],
    [os.path.join('resources','collecte.tar.gz'), 'collecte.tar.gz'],
    [os.path.join('resources','import_sql.tar.gz'), 'import_sql.tar.gz'],
    [os.path.join('resources','rmtar.bat'), 'rmtar.bat'],
    [os.path.join('resources','getresults.bat'), 'getresults.bat'],
    [os.path.join('resources','hash.cfg'), 'hash.cfg'],
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

def iocDict_from_trees(ioc_trees):
    iocDictionary = {}

    for ioc_id, ioc_object in ioc_trees.items():
        leaves = ioc_object['tree'].getLeaves()

        # IOC Tree evaluation
        for uid, ioc in leaves.items():
            # Do we know how to search for that ?
            if ioc.document in scan_modules.flatEvaluatorList.keys():
                # Getting the dictionary for that category, or creating it
                if not ioc.document in iocDictionary.keys():
                    iocDictionary[ioc.document] = []

                ioc.db_ioc_id = ioc_id
                iocDictionary[ioc.document].append(ioc)

    return iocDictionary


# Scans the target defined by taregtObject
# IOCObjects represents the set of IOC trees to be searche on the workstation
# HostConfidential is a boolean that triggers data retrieval or remote database querying
#
def scanTarget(targetObject, IOCObjects, hostConfidential):

    HANDLER_NAME = '%s@%s' % (targetObject['login'], targetObject['ip'])

    # Init PsExec tunnel to target
    try:
        remoteSystem = remotecmd.RemoteCmd(threadname,
                                        targetObject['ip'],
                                        targetObject['login'],
                                        targetObject['password'],
                                        domain = targetObject['domain'],
                                        rootDir = IOC_COMPONENT_ROOT
                                     )
        loggingscan.info('Handler %s has been succesfully created' % HANDLER_NAME)
        
        remoteSystem.setup()
    # too bad, error in connection
    except Exception, e:
        loggingscan.error(HANDLER_NAME+' startup error: '+str(e).encode(sys.stdout.encoding))
        return None

        
    try:
        # Drop files
        for local, remote in dropList:
            if remoteSystem.fileExists(remote):
                remoteSystem.deleteFile(remote)
            remoteSystem.dropFile(local, remote)

        # Start commands
        for command in StartCommandList:
            remoteSystem.execute(command, True)

        # Confidential
        hostConfidentialLocalName = os.path.join(IOC_CONFIDENTIAL_DIRECTORY, HANDLER_NAME)
        localFullname = os.path.join(IOC_COMPONENT_ROOT, hostConfidentialLocalName)
        if hostConfidential:
            os.makedirs(os.path.join(IOC_COMPONENT_ROOT, hostConfidentialLocalName))

        # TMP query file
        if not os.path.isdir(IOC_TEMP_DIR):
            os.makedirs(IOC_TEMP_DIR)
        TEMP_FILE = os.path.join(IOC_TEMP_DIR, '%s.tmp' % threadname)

        # <analysis>

        result = {}
        rawResults = {}
        initFilesPresent = []

        if IOC_MODE == 'flat':

            iocDict = iocDict_from_trees(IOCObjects)

            for category, ioc_list in iocDict.items():
                evlt = scan_modules.flatEvaluatorList[category](loggingscan, None, remoteSystem, IOC_KEEPFILES,
                                                                    hostConfidential, localFullname)

                # Retrieves created file so we don't create them again (speed++)
                newFiles = evlt.createInitFiles(initFilesPresent)
                for newFile in newFiles:
                    initFilesPresent.append(newFile)

                    if hostConfidential:
                        remoteSystem.getFile(newFile, os.path.join(hostConfidentialLocalName, newFile))

                categoryResults = evlt.eval(TEMP_FILE, ioc_list)
                rawResults.update(categoryResults)

                loggingscan.info('Research for %s has ended' % category)

            # Remove files if not explicitly told to keep them
            # In the latter case, they are kept on the analyst computer, so erase them from the remote
            if not IOC_KEEPFILES or hostConfidential:
                for remoteFile in initFilesPresent:
                    remoteSystem.deleteFile(remoteFile)


        else:#if IOC_MODE == 'logic':
            raise NotImplementedError

        # </analysis>
    except Exception, e:
        loggingscan.error(HANDLER_NAME+' scan error: '+str(e).encode(sys.stdout.encoding))
        return None
    
        
    try:
        # TMP query file
        if os.path.exists(TEMP_FILE):
            os.unlink(TEMP_FILE)

        # End commands
        for command in EndCommandList:
            if (not IOC_KEEPFILES or hostConfidential) or command[1]!=0:
                remoteSystem.execute(command[0], True)

        if not IOC_KEEPFILES or hostConfidential:
            for local, remote in dropList:
                remoteSystem.deleteFile(remote)

        # If data has been retrieved, erase it if not instructed otherwise
        if hostConfidential and not IOC_KEEPFILES:
            loggingscan.info('Wiping local data')
            shutil.rmtree(os.path.join(IOC_COMPONENT_ROOT, hostConfidentialLocalName))

        remoteSystem.cleanup()
        loggingscan.info('Handler %s has gracefully ended' % HANDLER_NAME)
        
    except Exception, e:
        loggingscan.error(HANDLER_NAME+' cleanup error: '+str(e).encode(sys.stdout.encoding))

        
    return rawResults



# Uses scan results to build the "Result" row in the database
# If analysis has failed for some reason, decrements priority and retries count
#
def analyzeResults(scanResults, task):

    loggingscan.info('Begin IOC analysis for host %s' % task.ip)
    smbreachable = True

    # Scan not completed
    if scanResults is None :
        task.retries_left_ioc -= 1

        # Still got some retries left
        if task.retries_left_ioc > 0:
            task.iocscanned = False
            task.last_retry_ioc = datetime.datetime.now()
            task.priority_ioc -= 1
        else:
            task.iocscanned = True

        smbreachable = False
    else:
        task.iocscanned = True

    task.reserved_ioc = False
    session.commit()

    r  = session.query(Result).filter_by(tache_id = task.id).first()

    # No result for now
    if r is None:
        r = Result(
                    smbreachable = smbreachable,
                    tache_id=task.id,
                    )
    else:
        r.smbreachable = smbreachable

    session.add(r)
    session.commit()

    # If scan has been completed, add the detections to the database
    if smbreachable:

        for ioc_id, dic in scanResults.items():
            if dic['res']!='True':
                continue

            id = IOCDetection(result_id = r.id, indicator_id = ioc_id, indicator_data = json.dumps(dic['data']), xmlioc_id = dic['iocid'])
            session.add(id)

        session.commit()

    loggingscan.info('End IOC analysis for host %s' % task.ip)

    
def rollbackTask(task):
    session.rollback()
    if task is not None:
        task.reserved_ioc = False
        task.retries_left_ioc = max(0,task.retries_left_ioc - 1)
        task.last_retry_ioc = datetime.datetime.now()
        
    session.commit()
    

# MAIN function launched by the scheduler
# "batch" is used to scan only targets for a specific batch
def startScanner(hWaitStop=None, batch=None):
    loggingscan.info('Starting an IOC scanner instance : ' + threadname)

    print ''
    print '\tPlease log in to launch scan'
    print ''
    username = raw_input('Username: ')
    password = getpass.getpass('Password: ')
    print ''

    # Get user
    u = session.query(User).filter_by(username = username).first()

    # No user or bad password
    if not u or hashPassword(password) != u.password:
        loggingscan.critical('Username or password incorrect, stopping the initialization, press a key...')
        raw_input()
        return

    # Get KEY and decrypt MASTER_KEY
    keyFromPassword = crypto.keyFromText(password, base64.b64decode(u.b64_kdf_salt))
    MASTER_KEY = crypto.decrypt(u.encrypted_master_key, keyFromPassword)

    masterKeyChecksum = session.query(GlobalConfig).filter_by(key = 'master_key_checksum').first()

    # No checksum in config ???
    if not masterKeyChecksum:
        loggingscan.critical('Database is broken, please create a new one, stopping the initialization...')
        del MASTER_KEY
        raw_input()
        return

    # Someone has been playing with the database !
    if checksum(MASTER_KEY)!=masterKeyChecksum.value:
        loggingscan.critical('MASTER_KEY may have been altered, stopping the initialization...')
        del MASTER_KEY
        raw_input()
        return

    loggingscan.info('Login successful !')
    # INITIALIZATION

    # TODO : initialise all IOCs in DB, then link them to CP

    allXmlIocs = session.query(XMLIOC).order_by(XMLIOC.name.asc())
    allConfigurationProfiles = session.query(ConfigurationProfile).order_by(ConfigurationProfile.name.asc())

    iocByConfigurationProfile = {}
    for configurationProfile in allConfigurationProfiles:
        if configurationProfile.ioc_list == '':
            loggingscan.warning('No IOC defined for profile "%s"' % cp.name)
            continue

        iocByConfigurationProfile[configurationProfile.id] = []
        for e in configurationProfile.ioc_list.split(','):
            iocByConfigurationProfile[configurationProfile.id].append(int(e))

    treeByIoc = {}

    # Retrieves evaluators for current mode
    FLAT_MODE = (IOC_MODE == 'flat')
    allowedElements = {}
    evaluatorList = scan_modules.flatEvaluatorList if FLAT_MODE else scan_modules.logicEvaluatorList

    for name, classname in evaluatorList.items():
        allowedElements[name] = classname.evalList

    # Parse XML Ioc into IOC trees according to what we can do
    for xmlioc in allXmlIocs:

        content = base64.b64decode(xmlioc.xml_content)
        oip = openiocparser.OpenIOCParser(content, allowedElements, FLAT_MODE, fromString=True)
        oip.parse()
        iocTree = oip.getTree()

        # Trees may be stripped from non valid elements
        if iocTree is not None:
            treeByIoc[xmlioc.id] = {'name':xmlioc.name, 'tree':iocTree}

    # Each configuration profile has a set of trees
    tree_by_cp = {cpid: {i:treeByIoc[i] for i in ioclist} for (cpid, ioclist) in iocByConfigurationProfile.items()}

    halt = False
    task = None
    batchquery = None

    # Batch filtering
    if batch is not None:
        loggingscan.info('Filtering for batch "%s"' % batch)
        batchquery = session.query(Batch).filter( Batch.name == batch).first()

        if batchquery is None:
            loggingscan.error('Unknown batch "%s" ...' % batch)
            halt = True

    # LAUNCH
    # Main loop
    while not halt:
        try:

            # Get targets to be scanned
            # and that are not currently being scanned
            # or that don't have any retry left
            taskQueue = session.query(Task).filter_by(iocscanned=False, reserved_ioc=False, reserved_hash=False).filter(Task.retries_left_ioc > 0)

            # Batch filtering
            if batchquery is not None:
                taskQueue = taskQueue.filter_by(batch_id = batchquery.id)

            taskQueueSize = taskQueue.count()

            # Compute the time after which targets are still recovering from last scan
            # Gets target which last retry is NULL or before that time
            retryLimit = datetime.datetime.now() - datetime.timedelta(0, MIN_RESCAN_INTERVAL)
            taskScanList = taskQueue.filter(or_(Task.last_retry_ioc <= retryLimit, Task.last_retry_ioc == None))
            taskScanListSize = taskScanList.count()

            # Reads this list
            while taskScanListSize > 0:

                # Max priority
                maxPriority = taskScanList.order_by(Task.priority_ioc.desc()).first().priority_ioc
                maxPriorityTasks = taskScanList.filter(Task.priority_ioc==maxPriority)
                nbre_maxPriorityTasks = maxPriorityTasks.count()
                if CERTITUDE_DATABASE.startswith('sqlite'):
                    task = maxPriorityTasks.order_by(func.random()).first()
                else:
                    task = maxPriorityTasks.order_by(func.newid()).first()

                # Mutex on the task
                task.reserved_ioc = True
                task.date_debut = datetime.datetime.now()
                session.commit()

                loggingscan.debug('===============================================================================')
                loggingscan.debug('Wake up, there is work to do !')
                loggingscan.info('taskQueue size : ' + str(taskQueueSize) + ', including ' + str(taskScanListSize) + ' to scan, including ' + str(nbre_maxPriorityTasks) + ' at top priority (' + str(maxPriority) + ')')
                loggingscan.debug('  --------------------------------')
                loggingscan.info('         Starting IOC Scan')
                loggingscan.info('        Target : ' + str(task.ip))
                loggingscan.debug('  --------------------------------')

                # Recover Windows Credential and Configuration Profile from Batch
                batch = session.query(Batch).filter_by(id = task.batch_id).first()
                wc = session.query(WindowsCredential).filter_by(id = batch.windows_credential_id).first()
                cp = session.query(ConfigurationProfile).filter_by(id = batch.configuration_profile_id).first()

                if not wc:
                    raise Exception('WindowsCredential %d does not exist' % task.windows_credential_id)

                if not cp:
                    raise Exception('ConfigurationProfile %d does not exist' % task.configuration_profile_id)

                # Decrypt password using MASTER_KEY and create target object
                targetPassword = crypto.decrypt(wc.encrypted_password, MASTER_KEY)
                targetObject = {'ip':       task.ip,
                                'login':    wc.login,
                                'password': targetPassword,
                                'domain':   wc.domain,
                                }

                # If high confidentiality is enabled, create local directory if needed
                if cp.host_confidential:
                    loggingscan.info('"High confidentiality" mode enabled')
                    testdir = os.path.join(IOC_COMPONENT_ROOT, IOC_CONFIDENTIAL_DIRECTORY)
                    if not os.path.isdir(testdir):
                        loggingscan.info('Creating confidential directory %s' % testdir)
                        os.makedirs(testdir)

                # Let the scan begin

                if cp.id in tree_by_cp.keys():
                    scanResults = scanTarget(targetObject, tree_by_cp[cp.id], cp.host_confidential)

                else:
                    loggingscan.warning('No IOC to scan (profile=%s)' % cp.name)
                    scanResults = {}

                if scanResults is not None:
                    analyzeResults(scanResults, task)
                    
                else:
                    rollbackTask(task)

                # Update taskQueue size
                taskScanListSize = taskScanList.count()

                if halt:
                    # Stop signal encountered
                    break

            if halt:
                loggingscan.info('Stopping IOC scanner : ' + threadname)
                break
            loggingscan.debug('(IOC scanner sleeping for ' + str(SLEEP) + ' seconds...)' \
                + (' (' + str(taskQueueSize) + ' waiting)' if taskQueueSize > 0 else ''))
            time.sleep(SLEEP)

        except KeyboardInterrupt:
            halt = True


        except Exception, e:

            exc_type, exc_obj, exc_tb = sys.exc_info()
            loggingscan.error('Exception caught:')
            for line in traceback.format_exc(exc_tb).splitlines():
                loggingscan.error(line)

            # Cancel changes and unreserve task
            rollbackTask(task)


if __name__ == '__main__':
    demarrer_scanner()
