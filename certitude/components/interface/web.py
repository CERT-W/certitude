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
    raise Exception('Erreur : lancez le script depuis main.py et non directement')

# Imports
# Lots of them...
#
import atexit
import base64
import datetime
import json
import logging
import os
import ssl
import subprocess
import sys

try:
    import win32event
    import win32security
except:
    pass

from flask import Flask, render_template, request, session, redirect, url_for, Response, abort, escape
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
import netaddr

from config import LISTEN_ADDRESS, LISTEN_PORT, BOKEH_LISTEN_ADDRESS, BOKEH_LISTEN_PORT
from config import IOC_MODE, DEBUG, USE_SSL, SSL_KEY_FILE, SSL_CERT_FILE, CERTITUDE_DATABASE, MIN_SUBMIT_INTERVAL
from helpers.queue_models import Task
from helpers.results_models import Result, IOCDetection
from helpers.misc_models import User, ConfigurationProfile, WindowsCredential, XMLIOC, Batch, GlobalConfig
from helpers.yara_models import YaraRule
from helpers.helpers import hashPassword, checksum, verifyPassword
import helpers.crypto as crypto

import components.scanner.openioc.openiocparser as openiocparser
import helpers.iocscan_modules as ioc_modules
import helpers.hashscan_modules as hash_modules
import xml.etree.ElementTree as ET
from functools import wraps

# Bokeh future
# from bokeh.embed import autoload_server
# from bokeh.client import pull_session

from plyara.plyara import PlyaraParser

# Set up logger
loggingserver = logging.getLogger('api')

# Create database
engine = create_engine(CERTITUDE_DATABASE, echo=False)
dbsession = sessionmaker(bind=engine)()


def genCSRFToken():
    return base64.b64encode(crypto.randomBytes(20)).replace('=', '').replace('+', '').replace('/', '')


CSRF_TOKEN_INDEX = '_csrft'
STATIC_ENDPOINT = os.path.join(os.path.dirname(__file__), 'static')
TEMPLATES_FOLDER = os.path.join(os.path.dirname(__file__), 'templates')

def getCSRFToken():
    if not CSRF_TOKEN_INDEX in session:
        session[CSRF_TOKEN_INDEX] = genCSRFToken()

    return session[CSRF_TOKEN_INDEX]


''' APPLICATION CONFIGURATION '''

app = Flask(__name__, static_folder=STATIC_ENDPOINT, template_folder=TEMPLATES_FOLDER)
app.secret_key = os.urandom(24)

app.jinja_env.globals['csrf_token'] = getCSRFToken
app.jinja_env.globals['csrf_token_name'] = CSRF_TOKEN_INDEX

app.config['UPLOAD_FOLDER'] = 'upload'
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 5 * 60
ALLOWED_EXTENSIONS = ['txt']
app.config['IOCS_FOLDER'] = os.path.join('components', 'iocscan', '.', 'ioc')
app.config['RESULT_FILE'] = os.path.join('components', 'interface', 'static', 'data', 'results.csv')
app.config['CERTITUDE_OUTPUT_FOLDER'] = 'results'
app.config['PROCESSED_FOLDER'] = 'processed'
RESULT_FILE_HEADER = 'Title:HostId,Title:Hostname,Lookup:Success,Lookup:IOCScanned,Lookup:HashScanned,Lookup:IP,Lookup:Subnet,Malware,Compromise'

IP_REGEX = '(([0-9]|[1-9][0-9]|1[0-9]{2}|2([0-4][0-9]|5[0-5]))\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2([0-4][0-9]|5[0-5]))'


# ''' Decorator for auth '''
def requires_auth(f):
    """
        Wrapper to check on each page the user authentication
    """

    @wraps(f)
    def decorated(*args, **kwargs):
        if 'logged_in' in session:
            return f(*args, **kwargs)
        else:
            return redirect(app.jinja_env.globals['url_for']('login'))

    return decorated

# ''' Bokeh configuration '''

bokeh_process = None

# Preventing Flask from running Bokeh twice
# source : https://stackoverflow.com/questions/9449101/how-to-stop-flask-from-initialising-twice-in-debug-mode
if not DEBUG or os.environ.get('WERKZEUG_RUN_MAIN') == 'true':
    cmd = [
        'bokeh', 
        'serve', "%s" % os.path.abspath(os.path.join(__file__, '../../../crossbokeh.py')), 
        '--address', BOKEH_LISTEN_ADDRESS, 
        '--port', str(BOKEH_LISTEN_PORT),
        '--allow-websocket-origin', '%s:%d' % (BOKEH_LISTEN_ADDRESS, BOKEH_LISTEN_PORT),
    ]
    bokeh_process = subprocess.Popen(cmd, stdout=subprocess.PIPE)

@atexit.register
def kill_server():
    if bokeh_process is not None:
        bokeh_process.kill()


# ''' CSRF Protection '''

@app.before_request
def csrf_protect():
    if request.method == 'POST':
        token = None if CSRF_TOKEN_INDEX not in session else session[CSRF_TOKEN_INDEX]
        arg = request.form.get(CSRF_TOKEN_INDEX)

        if not token or token != arg:
            print 'Received %s, expected %s' % (arg, token)
            abort(400)



            # -############################-#
            # Pages routing and controlers #
            # -############################-#

            # INDEX


@app.route('/')
@requires_auth
def index():
    return redirect(app.jinja_env.globals['url_for']('scan'))


    # SESSION MANAGEMENT


@app.route('/login', methods=['GET', 'POST'])
def login():
    error = ''
    if request.method == 'POST':

        # Get user from username
        userList = dbsession.query(User).filter_by(username=request.form['username']).limit(1)
        matchingUser = userList.first()

        # Check password
        if (matchingUser is not None) and (matchingUser.password == hashPassword(request.form['password'])):

            # Since there is an "active" status...
            if matchingUser.active:
                session['logged_in'] = True
                session['user_id'] = matchingUser.id

                return redirect(app.jinja_env.globals['url_for']('index'))
            else:
                return render_template('session-login.html', error='User account is disabled')
        error = 'User might not exist or password is incorrect'

    return render_template('session-login.html', errors=error)


@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    return redirect(app.jinja_env.globals['url_for']('index'))


    # USER MANAGEMENT


# Lists users
@app.route('/users')
@requires_auth
def users():
    allUsers = dbsession.query(User).order_by(User.id.asc())
    return render_template('user-list.html', users=allUsers)


# {En,Dis}ables an account
@app.route('/users/<int:userid>/switchactive')
@requires_auth
def userSwitchActive(userid):
    u = dbsession.query(User).filter_by(id=userid).first()

    if u is None:
        return redirect(app.jinja_env.globals['url_for']('users'))

    u.active = not u.active
    dbsession.commit()

    return redirect(app.jinja_env.globals['url_for']('users'))


# Add a new user
# MASTER_KEY is encrypted for the new user
# Clear text MASTER_KEY is retrieved using the current use's credentials
#
@app.route('/user/add', methods=['GET', 'POST'])
@requires_auth
def userAdd():
    if request.method == 'GET':
        return render_template('user-add.html')
    else:
        success = True
        errors = []

        user_password = request.form['user_password']
        user = dbsession.query(User).filter_by(id=session['user_id']).first()

        # Checks current user password
        if user is None or hashPassword(user_password) != user.password:
            success = False
            errors.append('Your password is incorrect')

        # Someone has messed with the database
        if success:
            mk_cksum = dbsession.query(GlobalConfig).filter_by(key='master_key_checksum').first()
            if not mk_cksum:
                success = False
                errors.append('Database is broken, please create a new one !')

        if success:
            keyFromPassword = crypto.keyFromText(user_password, base64.b64decode(user.b64_kdf_salt))
            MASTER_KEY = crypto.decrypt(user.encrypted_master_key, keyFromPassword)

            # Someone changed the master key...
            if checksum(MASTER_KEY) != mk_cksum.value:
                errors.append('MASTER_KEY may have been altered')
                del MASTER_KEY
                success = False

        # Now check the new user password...
        if success:
            password1, password2 = request.form['password'], request.form['password2']
            if password1 != password2:
                success = False
                errors.append('New user passwords do not match')

        # ... including complexity
        if success:
            if not verifyPassword(password1):
                success = False
                errors.append(
                    'Password is not complex enough (l > 12 and at least three character classes between lowercase, uppercase, numeric and special char)')

        # Encrypt the MASTER_KEY for the user
        if success:
            new_kdf_salt = crypto.randomBytes(crypto.SALT_LENGTH)
            keyFromPassword = crypto.keyFromText(password1, new_kdf_salt)
            emk = crypto.encrypt(MASTER_KEY, keyFromPassword)
            del MASTER_KEY  # safer ?

            u = User(
                username=request.form['username'],
                password=hashPassword(password1),
                email=request.form['email'],
                active=True,
                encrypted_master_key=emk,
                b64_kdf_salt=base64.b64encode(new_kdf_salt))

        if len(request.form['username']) <= 0 or len(request.form['email']) <= 0:
            success = False
            errors.append('No empty fields allowed.')

        if success:
            dbsession.add(u)
            dbsession.commit()
            return redirect(app.jinja_env.globals['url_for']('users'))
        else:
            return render_template('user-add.html', username=request.form['username'], email=request.form['email'],
                                   errors='\n'.join(errors))


# Delete a user
@app.route('/user/<int:userid>/delete', methods=['POST'])
@requires_auth
def userDelete(userid):
    u = dbsession.query(User).filter_by(id=userid).first()

    if u is None:
        return redirect(app.jinja_env.globals['url_for']('users'))

    dbsession.delete(u)
    dbsession.commit()

    return redirect(app.jinja_env.globals['url_for']('users'))



    # CONFIGURATION, IOCs & PROFILES MANAGEMENT


# Configuration homepage
@app.route('/config', )
@requires_auth
def config():
    configuration_profiles = dbsession.query(ConfigurationProfile).order_by(ConfigurationProfile.name.asc())
    windows_credentials = dbsession.query(WindowsCredential).order_by(WindowsCredential.domain.asc(),
                                                                      WindowsCredential.login.asc())
    xmliocs = dbsession.query(XMLIOC).order_by(XMLIOC.date_added.desc())
    yararules = dbsession.query(YaraRule).order_by(YaraRule.date_added.desc())

    iocref = {}
    for xmlioc in xmliocs:
        iocref[str(xmlioc.id)] = xmlioc.name + ' - ' + str(xmlioc.date_added)

    yararef = {}
    for yararule in yararules:
        yararef[str(yararule.id)] = yararule.name + ' - ' + str(yararule.date_added)

    iocdesclist = {}
    for cp in configuration_profiles:
        if len(cp.ioc_list) == 0:
            iocdesclist[cp.id] = ''
            continue
        iocdesclist[cp.id] = '||'.join([iocref[str(id)] for id in cp.ioc_list.split(',')])

    yaradesclist = {}
    for cp in configuration_profiles:
        if len(cp.yara_list) == 0:
            yaradesclist[cp.id] = ''
            continue
        yaradesclist[cp.id] = '||'.join([yararef[str(id)] for id in cp.yara_list.split(',')])

    return render_template('config-main.html',
                           yararules=yararules,
                           xmliocs=xmliocs,
                           windows_credentials=windows_credentials,
                           configuration_profiles=configuration_profiles,
                           iocdesclist=iocdesclist,
                           yaradesclist=yaradesclist)


    # DELETIONS


@app.route('/config/wincredz/<int:wincredid>/delete', methods=['POST'])
@requires_auth
def wincredDelete(wincredid):
    wc = dbsession.query(WindowsCredential).filter_by(id=wincredid).first()

    if wc is None:
        return redirect(app.jinja_env.globals['url_for']('config'))

    dbsession.delete(wc)
    dbsession.commit()

    return redirect(app.jinja_env.globals['url_for']('config'))


@app.route('/config/xmlioc/<int:xmliocid>/delete', methods=['POST'])
@requires_auth
def xmliocDelete(xmliocid):
    xi = dbsession.query(XMLIOC).filter_by(id=xmliocid).first()

    if xi is None:
        return redirect(app.jinja_env.globals['url_for']('config'))

    cps = dbsession.query(ConfigurationProfile).all()
    
    for cp in cps:
        ioclist = map(int, cp.ioc_list.split(','))
        if xi.id in ioclist:
            ioclist.remove(xi.id)
            
        cp.ioc_list = ','.join(map(str, ioclist))
        dbsession.add(cp)
        
    dbsession.delete(xi)
    dbsession.commit()

    return redirect(app.jinja_env.globals['url_for']('config'))


@app.route('/config/profile/<int:profileid>/delete', methods=['POST'])
@requires_auth
def profileDelete(profileid):
    p = dbsession.query(ConfigurationProfile).filter_by(id=profileid).first()

    if p is None:
        return redirect(app.jinja_env.globals['url_for']('config'))

    dbsession.delete(p)
    dbsession.commit()

    return redirect(app.jinja_env.globals['url_for']('config'))


    # ADDITIONS


# Adds a new credential
# uses current user's password to decipher MASTER_KEY
#
@app.route('/config/wincredz/add', methods=['GET', 'POST'])
@requires_auth
def wincredAdd():
    if request.method == 'GET':
        return render_template('config-wincred-add.html')
    else:
        success = True
        errors = []

        user_password = request.form['user_password'].encode(sys.stdout.encoding)
        user = dbsession.query(User).filter_by(id=session['user_id']).first()

        # Password incorrect
        if user is None or hashPassword(user_password) != user.password:
            success = False
            errors.append('Your password is incorrect')

        # Database altered
        if success:
            mk_cksum = dbsession.query(GlobalConfig).filter_by(key='master_key_checksum').first()
            if not mk_cksum:
                success = False
                errors.append('Database is broken, please create a new one !')

        # MASTER_KEY altered
        if success:
            keyFromPassword = crypto.keyFromText(user_password, base64.b64decode(user.b64_kdf_salt))
            MASTER_KEY = crypto.decrypt(user.encrypted_master_key, keyFromPassword)

            if checksum(MASTER_KEY) != mk_cksum.value:
                errors.append('MASTER_KEY may have been altered')
                del MASTER_KEY
                success = False

        if success:
            account_password = request.form['password'].encode(sys.stdout.encoding)
            encrypted_account_password = crypto.encrypt(account_password, MASTER_KEY)
            del MASTER_KEY

            # Encrypt Windows Credential's password
            wc = WindowsCredential(
                domain=request.form['domain'].encode(sys.stdout.encoding),
                login=request.form['login'].encode(sys.stdout.encoding),
                encrypted_password=encrypted_account_password)

            dbsession.add(wc)
            dbsession.commit()

        if success:
            return redirect(app.jinja_env.globals['url_for']('config'))
        else:
            return render_template('config-wincred-add.html',
                                   errors='\n'.join(errors),
                                   domain=request.form['domain'],
                                   login=request.form['login'],
                                   password=request.form['password'])


@app.route('/config/xmlioc/add', methods=['GET', 'POST'])
@requires_auth
def xmliocAdd():
    if request.method == 'GET':
        return render_template('config-xmlioc-add.html')
    else:
        success = True
        errors = []

        xml_content = request.files['xml_content'].stream.read()

        ioc_name = request.form['name']
        xi = XMLIOC(
            name=ioc_name,
            xml_content=base64.b64encode(xml_content))

        if len(ioc_name) <= 0:
            success = False
            errors.append("IOC name cannot be empty.")
        else:
            existing_ioc = dbsession.query(XMLIOC).filter_by(name=ioc_name).first()
            if existing_ioc is not None:
                success = False
                errors.append("IOC name already exists.")

        if len(xml_content) <= 0:
            success = False
            errors.append("You must specify a file.")

        if success:
            dbsession.add(xi)
            dbsession.commit()
            return redirect(app.jinja_env.globals['url_for']('config'))
        else:
            return render_template('config-xmlioc-add.html', errors='\n'.join(errors), name=ioc_name)


@app.route('/config/profile/add', methods=['GET', 'POST'])
@requires_auth
def profileAdd():
    xi = dbsession.query(XMLIOC).order_by(XMLIOC.name.asc())
    yr = dbsession.query(YaraRule).order_by(YaraRule.name.asc())

    if request.method == 'GET':
        return render_template('config-profile-add.html', xmliocs=xi, yararules=yr)
    else:
        success = True
        errors = []

        hc = True if 'host_confidential' in request.form else False

        profile_name = request.form['name']
        ioc_selected_list = ','.join(request.form.getlist('ioc_list'))
        yara_selected_list = ','.join(request.form.getlist('yara_list'))
        cp = ConfigurationProfile(
            name=profile_name,
            host_confidential=hc,
            ioc_list=ioc_selected_list,
            yara_list=yara_selected_list)

        if len(profile_name) <= 0:
            success = False
            errors.append("Profile name cannot be empty.")
        else:
            existing_profile_name = dbsession.query(ConfigurationProfile).filter_by(name=profile_name).first()
            if existing_profile_name is not None:
                success = False
                errors.append("Profile name already exists.")

        if success:
            dbsession.add(cp)
            dbsession.commit()
            return redirect(app.jinja_env.globals['url_for']('config'))
        else:
            return render_template('config-profile-add.html', errors='\n'.join(errors), host_confidential=hc,
                                   name=request.form['name'], xmliocs=xi)


            # MISC. VIEWS


@app.route('/config/profile/<int:profileid>/popupview')
@requires_auth
def profilePopupView(profileid):
    return render_template('config-profile-popupview.html')

    # CAMPAIGN RESULTS


@app.route('/campaignvisualizations')
@requires_auth
def campaignvisualizations():
    batches = dbsession.query(Batch).order_by(Batch.name.asc())

    return render_template('campaign-visualizations.html', batches=batches)


@app.route('/campaignvisualizations/<int:batchid>')
@requires_auth
def campaignvisualizationbatch(batchid):
    batch = dbsession.query(Batch).filter_by(id=batchid).first()

    if batch is None:
        return redirect(app.jinja_env.globals['url_for']('campaignvisualizations'))
    else:
        return render_template('campaign-visualizations-batch.html', batch=batch)

@app.route('/massvisualizations/<int:batchid>')
@requires_auth
def massvisualizationbatch(batchid):
    batch = dbsession.query(Batch).filter_by(id=batchid).first()

    if batch is None:
        return redirect(app.jinja_env.globals['url_for']('campaignvisualizations'))
    else:
        csv_url = url_for('static', filename='data/results.csv/' + str(batch.id))

        iframe = '<iframe src="http://%s:%d/crossbokeh?batchid=%s" style="width:900px; height: 1000px; margin: 0 auto; display:block;" frameborder="0" scrolling="no" marginheight="0" marginwidth="0"></iframe>' % (BOKEH_LISTEN_ADDRESS, BOKEH_LISTEN_PORT, batchid)

        return render_template('mass-visualizations-batch.html', bokeh_script=iframe, batch=batch)


@app.route('/ioc/<int:iocid>')
@requires_auth
def iocvizu(iocid):
    return render_template('ioc-vizualisation.html', iocid=iocid)


# IOC.json
# File describing an IOC for previsualization in config
#
@app.route('/static/data/ioc.json/<int:iocid>')
@requires_auth
def iocjson(iocid):
    # if 'logged_in' in session:

    response = ''

    # get the IOC
    ioc = dbsession.query(XMLIOC).filter_by(id=iocid).first()

    if ioc is None:
        return Response(status=404, response='This IOC does not exist', content_type='text/plain')

    FLAT_MODE = (IOC_MODE == 'flat')
    allowedElements = {}
    IOCevaluatorList = ioc_modules.flatEvaluatorList if FLAT_MODE else ioc_modules.logicEvaluatorList
    HASHevaluatorList = hash_modules.flatEvaluatorList if FLAT_MODE else hash_modules.logicEvaluatorList

    evaluatorList = dict(IOCevaluatorList.items() + HASHevaluatorList.items())

    for name, classname in evaluatorList.items():
        allowedElements[name] = classname.evalList

    content = base64.b64decode(ioc.xml_content)

    # Parse it, filtering on allowed elements
    oip = openiocparser.OpenIOCParser(content, allowedElements, FLAT_MODE, fromString=True)
    oip.parse()

    # Get the tree
    tree = oip.getTree()

    return Response(status=200, response=json.dumps(tree.json2(), indent=4), content_type='application/json')
    # else:
    # return redirect(app.jinja_env.globals['url_for']('login'))


@app.route('/host-result/<int:hostid>')
@requires_auth
def hostresult(hostid):
    return render_template('host-result-vizualisation.html', hostid=hostid)


# HOST.json
# Result of the scan on a specific host
@app.route('/static/data/host.json/<int:hostid>')
@requires_auth
def hostjson(hostid):
    # if 'logged_in' in session:

    response = ''

    # Get the result
    task, result = dbsession.query(Task, Result).filter(Result.id == hostid).join(Result,
                                                                                  Task.id == Result.tache_id).first()
    if task is None or result is None:
        return Response(status=404, response='This host does not exist', content_type='text/plain')

    # if not reachable, display error on the graph
    if not result.smbreachable:
        tab = {'name': task.ip, 'infected': True,
               'children': [{'name': 'This host could not be joined', 'infected': True}]}
        return Response(status=200, response=json.dumps(tab), content_type='application/json')

    # Get batch
    batch = dbsession.query(Batch).filter_by(id=task.batch_id).first()

    # Then profile
    cp = dbsession.query(ConfigurationProfile).filter_by(id=batch.configuration_profile_id).first()

    # The IOC list
    if cp.ioc_list == '':
        ioc_list = []
    else:
        ioc_list = [int(e) for e in cp.ioc_list.split(',')]

    # And IOC detections
    ioc_detections = dbsession.query(IOCDetection).filter_by(result_id=result.id).all()

    # list of GUID per IOC
    guids = {i: {} for i in ioc_list}
    for iocd in ioc_detections:
        if iocd.indicator_data is None:
            ioc_data = []
            
        else:
            jdata = json.loads(iocd.indicator_data)

            if jdata is not None:
                ioc_data = [str(escape(d)) for d in jdata]
            else:
                ioc_data = []
            
        guids[iocd.xmlioc_id][iocd.indicator_id] = ioc_data
        # guids[iocd.xmlioc_id][iocd.indicator_id] = str(escape(iocd.indicator_data))

    tree = {'name': task.ip, 'children': [], 'infected': False}

    for iocid in ioc_list:

        ioc = dbsession.query(XMLIOC).filter_by(id=iocid).first()

        FLAT_MODE = (IOC_MODE == 'flat')
        allowedElements = {}
        IOCevaluatorList = ioc_modules.flatEvaluatorList if FLAT_MODE else ioc_modules.logicEvaluatorList
        HASHevaluatorList = hash_modules.flatEvaluatorList if FLAT_MODE else hash_modules.logicEvaluatorList

        evaluatorList = dict(IOCevaluatorList.items() + HASHevaluatorList.items())

        for name, classname in evaluatorList.items():
            allowedElements[name] = classname.evalList

        content = base64.b64decode(ioc.xml_content)

        # Parse IOC
        oip = openiocparser.OpenIOCParser(content, allowedElements, FLAT_MODE, fromString=True)
        oip.parse()

        # Build tree and infect it with the IOC detections
        tmp = oip.getTree()
        tmp.infect(guids[iocid])
        tmp = tmp.json2()

        tmptree = {'name': ioc.name, 'children': [tmp], 'infected': tmp['infected']}
        tree['children'].append(tmptree)

        # Get the infection up
        tree['infected'] |= tmp['infected']

    return Response(status=200, response=json.dumps(tree, indent=4), content_type='application/json')


def getInfosFromXML(content):
    c = base64.b64decode(content)
    r = {'guids': {}, 'totalguids': 0}

    xml = ET.fromstring(c)
    openiocparser.removeNS(xml)

    for indic in xml.iter('IndicatorItem'):
        guid = indic.attrib['id']

        context = indic.findall('Context')[0]
        search = context.attrib['search']

        content = indic.findall('Content')[0]
        value = content.text

        r['guids'][guid] = {'search': search, 'value': value}
        r['totalguids'] += 1

    return r


@app.route('/static/data/results.csv/<int:batchid>')
@requires_auth
def resultscsv(batchid):
    response = 'Title:HostId,Title:Hostname-IP,Lookup:Success,Lookup:IOCScanned,Lookup:HashScanned,Lookup:Subnet,Malware,Compromise'

    # Get Batch
    batch = dbsession.query(Batch).filter_by(id=batchid).first()
    if batch is None:
        return Response(status=404)

    # Get all IOCs
    cp = dbsession.query(ConfigurationProfile).filter_by(id=batch.configuration_profile_id).first()
    if cp.ioc_list == '':
        ioc_list = []
    else:
        ioc_list = [int(e) for e in cp.ioc_list.split(',')]
    iocs = dbsession.query(XMLIOC).filter(XMLIOC.id.in_(ioc_list)).all()

    # Complete first line & assoc ioc.id => ioc
    all_iocs = {}
    for ioc in iocs:
        all_iocs[ioc.id] = ioc
        response += ',%s' % ioc.name
    response += '\n'

    all_tasks_results = dbsession.query(Task, Result).filter(Task.batch_id == batchid).join(Result,
                                                                                            Task.id == Result.tache_id).all()

    # Get total indicator items / IOC
    total_by_ioc = {}
    for ioc in iocs:
        infos = getInfosFromXML(ioc.xml_content)
        total_by_ioc[ioc.id] = infos['totalguids']

    for task, result in all_tasks_results:
        ioc_detections = dbsession.query(IOCDetection).filter_by(result_id=result.id).all()

        response += '%d,%s,%s,%s,%s,%s' % (
        result.id, task.ip, result.smbreachable, task.iocscanned, task.hashscanned, task.commentaire)
        result_for_host = {e: 0 for e in ioc_list}

        # Sum IOC detections
        for ioc_detection in ioc_detections:
            result_for_host[ioc_detection.xmlioc_id] += 1

        # Compute n in [0,1] = % of detection
        result_for_host = {id: round(val * 100. / total_by_ioc[id]) / 100 for id, val in result_for_host.items()}

        # Get max
        mval, mid = 0, -1
        for id, val in result_for_host.items():
            if val > mval:
                mval, mid = val, id

        # Complete max compromise
        mname = "None" if mid == -1 else all_iocs[mid].name
        response += ',%s,%.2f' % (mname, mval)

        # Complete detection / IOC
        for id in all_iocs:
            response += ',%.2f' % result_for_host[id]
        response += '\n'

    return Response(status=200, response=response, content_type='text/plain')



    # CAMPAIGN PLANIFICATION


@app.route('/scan/', methods=['GET', ])
@requires_auth
def scan():
    batches = dbsession.query(Batch).order_by(Batch.name.asc())

    return render_template('scan-planification.html', batches=batches)


@app.route('/scan/batch/add', methods=['GET', 'POST'])
@requires_auth
def scanbatchAdd():
    cp = dbsession.query(ConfigurationProfile).order_by(ConfigurationProfile.name.asc())
    wc = dbsession.query(WindowsCredential).order_by(WindowsCredential.domain.asc(), WindowsCredential.login.asc())

    if request.method == 'GET':
        return render_template('scan-planification-batch-add.html', configuration_profiles=cp, windows_credentials=wc)
    else:
        success = True
        errors = []

        batch_name = request.form['name']
        batch = Batch(
            name=batch_name,
            configuration_profile_id=request.form['profile'],
            windows_credential_id=request.form['credential'])

        if len(batch.name) <= 0:
            success = False
            errors.append("Batch name cannot be empty.")
        else:
            existing_batch = dbsession.query(Batch).filter_by(name=batch_name).first()
            if existing_batch is not None:
                success = False
                errors.append("Batch name already exists.")

        if success:
            dbsession.add(batch)
            dbsession.commit()
            return redirect(app.jinja_env.globals['url_for']('scan'))
        else:
            return render_template('scan-planification-batch-add.html', errors='\n'.join(errors),
                                   configuration_profiles=cp, windows_credentials=wc)


@app.route('/scan/task/<int:taskid>/delete')
@requires_auth
def scantaskDelete(taskid):
    task = dbsession.query(Task).filter_by(id=taskid).first()
    dbsession.delete(task)
    dbsession.commit()

    return redirect(url_for('progress'))


@app.route('/scan/batch/<int:batchid>/delete')
@requires_auth
def scanbatchDelete(batchid):
    batch = dbsession.query(Batch).filter_by(id=batchid).first()

    dbsession.delete(batch)
    dbsession.commit()

    return redirect(url_for('scan'))


@app.route('/scan/batch/<int:batchid>', methods=['GET', ])
@requires_auth
def scanbatch(batchid):
    batch = dbsession.query(Batch).filter_by(id=batchid).first()
    cp = dbsession.query(ConfigurationProfile).filter_by(id=batch.configuration_profile_id).first()
    wc = dbsession.query(WindowsCredential).filter_by(id=batch.windows_credential_id).first()

    return render_template('scan-planification-batch.html', batch=batch, configuration_profile=cp,
                           windows_credential=wc)


@app.route('/api/scan/', methods=['POST'])
@requires_auth
def api_json():
    def getCible(param):
        param_list = param.get('ip_list', None)
        param_ip = param.get('ip', None)
        param_hostname = param.get('hostname', None)

        list = []

        if param_list is not None and param_list != '':
            liste = param_list.replace('\r\n', '\n')
            ips = liste.split('\n')
            list += [(e, 'ipl') for e in ips]

        if param_ip is not None and param_ip != '':
            list.append((param_ip, 'ipn'))

        if param_hostname is not None and param_hostname != '':
            list.append((param_hostname, 'host'))

        return list

    loggingserver.debug('Scan request incoming ')
    param = request.form

    # param = urlparse.parse_qs(args[1])
    # Target IP(s)
    ip_list = getCible(param)
    if len(ip_list) > 0:

        # Priority IOC
        try:
            priority_ioc = int(param.get('priority_ioc'))
        except:
            priority_ioc = 10
        if not priority_ioc > 0:
            priority_ioc = 10

        # Priority HASH
        try:
            priority_hash = int(param.get('priority_hash'))
        except:
            priority_hash = 10
        if not priority_hash > 0:
            priority_hash = 10

        # Priority Yara
        try:
            priority_yara = int(param.get('priority_yara'))
        except:
            priority_yara = 10
        if not priority_yara > 0:
            priority_yara = 10

        # Retries count (IOC)
        essais_ioc = param.get('retries_ioc')
        if essais_ioc is not None:
            try:
                assert 0 < int(essais_ioc) <= 10
                retries_left_ioc = int(essais_ioc)
            except:
                retries_left_ioc = 10
        else:
            retries_left_ioc = 10

        # Retries count (hash)
        essais_hash = param.get('retries_hash')
        if essais_hash is not None:
            try:
                assert 0 < int(essais_hash) <= 10
                retries_left_hash = int(essais_hash)
            except:
                retries_left_hash = 10
        else:
            retries_left_hash = 10

        # Retries count (yara)
        essais_yara = param.get('retries_yara')
        if essais_yara is not None:
            try:
                assert 0 < int(essais_yara) <= 10
                retries_left_yara = int(essais_yara)
            except:
                retries_left_yara = 10
        else:
            retries_left_yara = 10

        subnet = 'n/a'
        subnetp = param.get('subnet', None)
        if subnetp is not None:
            subnet = subnetp

        batchp = param.get('batch', None)
        if batchp is not None:
            batch = batchp

        reponse = {}
        reponse['code'] = 200
        reponse['ips'] = {}

        # Ajout à la queue...
        nb_ip, nb_ip_ok = 0, 0
        for ip, iptype in ip_list:
            actualise = False

            # try:
            # ip_int = int(ip)
            # except ValueError,e:
            # try:
            # ipn = IPNetwork(ip)
            # ip_int = int(ipn[0])
            # except Exception, e:
            # if iptype=='ip':
            # reponse['ips'][str(ip)] = 'invalid IP address'
            # continue
            # ip_int=0

            try:

                if iptype[:2] == 'ip':
                    ipn = netaddr.IPNetwork(ip)
                else:
                    ipn = [ip]

                ipSubnet = str(ip) if iptype == 'ipl' else subnet

                for ipa in ipn:
                    nb_ip += 1

                    if param.get('force', None) is None:
                        limite_avant_nouvel_essai = datetime.datetime.now() - datetime.timedelta(0,
                                                                                                 MIN_SUBMIT_INTERVAL)
                        if dbsession.query(Result).filter(Result.ip == str(ipa),
                                                          Result.finished >= limite_avant_nouvel_essai).count() > 0:
                            reponse['ips'][str(ipa)] = 'already scanned a few moments ago...'
                            continue
                        elif dbsession.query(Task).filter(Task.ip == str(ipa), Task.batch_id == batch,
                                                          Task.date_soumis >= limite_avant_nouvel_essai).count() > 0:
                            reponse['ips'][str(ipa)] = 'already requested a few moments ago'
                            continue

                    nb_ip_ok += 1
                    tache = Task(
                        ip=str(ipa),
                        priority_ioc=priority_ioc,
                        priority_hash=priority_hash,
                        priority_yara=priority_yara,
                        reserved_ioc=False,
                        reserved_hash=False,
                        reserved_yara=False,
                        iocscanned=False,
                        hashscanned=False,
                        yarascanned=False,
                        ip_demandeur=request.remote_addr,
                        retries_left_ioc=retries_left_ioc,
                        retries_left_hash=retries_left_hash,
                        retries_left_yara=retries_left_yara,
                        commentaire=ipSubnet,
                        batch_id=batch
                    )
                    dbsession.add(tache)

                if batch and len(batch) > 0 and not actualise:
                    reponse['ips'][str(ip)] = 'added to batch ' + batch
                elif batch and len(batch) > 0 and actualise:
                    reponse['ips'][str(ip)] = 'added to batch ' + batch + ' for retry'
                else:
                    reponse['ips'][str(ip)] = 'added to queue'

                reponse['ips'][str(ip)] += ' (%d tries for iocscan, %d tries for hashscan)' % (
                retries_left_ioc, retries_left_hash)

            except netaddr.core.AddrFormatError:
                reponse['ips'][str(ip)] = ' not added to batch ' + batch + ': bad formatting)'

        reponse['message'] = 'Requested scan of %d IP addresses, %d were OK' % (nb_ip, nb_ip_ok)
        dbsession.commit()
        return Response(
            status=200,
            response=json.dumps(
                reponse,
                indent=4
            ),
            content_type='application/json'
        )

    else:
        return APIscan()

        # YARA


@app.route('/config/yara/add', methods=['GET', 'POST'])
@requires_auth
def yaraAdd():
    if request.method == 'GET':
        return render_template('config-yara-add.html')
    else:
        success = True
        errors = []

        content = request.files['content'].stream.read()
        yp = PlyaraParser()
        rules = yp.parseString(content)
        rules = [e['rule_name'] for e in rules]

        name = request.form['name']
        yr = YaraRule(
            name=name,
            content=base64.b64encode(content),
            rules=','.join(rules))

        if len(name) <= 0:
            success = False
            errors.append("Rule name cannot be empty.")

        else:
            existing_rule = dbsession.query(YaraRule).filter_by(name=name).first()
            if existing_rule is not None:
                success = False
                errors.append("Rule name already exists.")

        if len(content) <= 0:
            success = False
            errors.append("You must specify a file.")

        if success:
            dbsession.add(yr)
            dbsession.commit()
            return redirect(app.jinja_env.globals['url_for']('config'))
        else:
            return render_template('config-yara-add.html', errors='\n'.join(errors), name=name)


@app.route('/config/yara/<int:yaraid>/delete', methods=['POST'])
@requires_auth
def yaraDelete(yaraid):
    yi = dbsession.query(YaraRule).filter_by(id=yaraid).first()

    if yi is None:
        return redirect(app.jinja_env.globals['url_for']('config'))

    cps = dbsession.query(ConfigurationProfile).all()
    
    for cp in cps:
        yaralist = map(int, cp.yara_list.split(','))
        if yi.id in ioclist:
            ioclist.remove(yi.id)
            
        cp.yaralist_list = ','.join(map(str, yaralist))
        dbsession.add(cp)
        
    dbsession.delete(yi)
    dbsession.commit()

    return redirect(app.jinja_env.globals['url_for']('config'))


    # SCAN PROGRESS


@app.route('/progress', methods=['GET', ])
@requires_auth
def progress():
    headers = (
        'id',
        'ip',
        'commentaire',
        'batch_id',
        'date_soumis',
        'date_debut',
        'iocscanned',
        'hashscanned',
        'yarascanned',
        'reserved_ioc',
        'reserved_hash',
        'reserved_yara',
        'retries_left_ioc',
        'retries_left_hash',
        'retries_left_yara',
    )
    tasks = dbsession.query(Task).order_by(Task.id.desc()).limit(50)
    tasks_data = [[getattr(t, h) for h in headers] for t in tasks]
    return render_template('scan-progress.html', headers=headers, tasks_data=tasks_data)


    # SERVER LAUNCH


def run_server():
    context = None

    if USE_SSL and os.path.isfile(SSL_KEY_FILE) and os.path.isfile(SSL_CERT_FILE):
        context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
        context.load_cert_chain(SSL_CERT_FILE, SSL_KEY_FILE)
        loggingserver.info('Using SSL, open interface in HTTPS')

    loggingserver.info('Web interface starting')
    app.run(
        host=LISTEN_ADDRESS,
        port=LISTEN_PORT,
        debug=DEBUG,
        ssl_context=context
    )


if __name__ == '__main__':
    run_server()
