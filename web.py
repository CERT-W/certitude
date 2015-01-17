from flask import Flask, render_template, request, session, redirect, url_for, Markup, jsonify
from flask.ext.login import LoginManager, login_required, login_user, logout_user, flash

import os
import re #Regular expressions 
import subprocess, sys

import sqlite3

import json
from werkzeug import secure_filename

''' APPLICATION CONFIGURATION '''

app = Flask(__name__)
app.secret_key = os.urandom(24)
app.config.update(dict(
	USERNAME='seeker',
	PASSWORD='certitude'))

app.config['UPLOAD_FOLDER'] = 'upload'
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0
ALLOWED_EXTENSIONS = ['txt']
app.config['IOCS_FOLDER'] = os.path.join('.','ioc')
app.config['RESULT_FILE'] = os.path.join('static','data','results.csv')
app.config['CERTITUDE_OUTPUT_FOLDER'] = 'results'
app.config['PROCESSED_FOLDER'] = 'processed'
RESULT_FILE_HEADER = 'Title:HostId,Title:Hostname,Lookup:Success,Lookup:IP,Lookup:Subnet,Malware,Compromise'

''' CONSTANTS '''

IP_REGEX = '(([0-9]|[1-9][0-9]|1[0-9]{2}|2([0-4][0-9]|5[0-5]))\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2([0-4][0-9]|5[0-5]))'

''' DATABASE STUFF '''

def init_db_structure(cur, con):

	try:
		cur.execute('DROP TABLE ioc')
	except sqlite3.OperationalError, e:
		pass
		
	try:
		cur.execute('DROP TABLE host')
	except sqlite3.OperationalError, e:
		pass
		
	try:
		cur.execute('DROP TABLE result')
	except sqlite3.OperationalError, e:
		pass
		
	cur.execute('CREATE TABLE ioc ( ioc_id INTEGER PRIMARY KEY AUTOINCREMENT, ioc_name VARCHAR(255) ) ');
	cur.execute('CREATE TABLE host ( host_id INTEGER PRIMARY KEY AUTOINCREMENT, host_ip VARCHAR(255), host_subnet VARCHAR(255), host_username VARCHAR(255) ) ');
	cur.execute('CREATE TABLE result ( result_id INTEGER PRIMARY KEY AUTOINCREMENT, host_id INT, json_result TEXT, success INT ) ');
	con.commit()

	

con = sqlite3.connect( os.path.join( 'db', 'analysis.db' ) )
cur = con.cursor()
try:
	cur.execute('SELECT 1 FROM host')
	cur.execute('SELECT 1 FROM ioc')
	cur.execute('SELECT 1 FROM result')
except sqlite3.OperationalError, e:
	init_db_structure(cur, con)

con.close()


# Page routing

@app.route('/')
def index():

	con = sqlite3.connect( os.path.join( 'db', 'analysis.db' ) )
	cur = con.cursor()

	if 'logged_in' in session:
		cur.execute('SELECT COUNT(*) FROM host')
		data = cur.fetchone()

		if data[0] > 1:
			ret=redirect('campaignresults')
		else:
			ret=redirect('campaignplan')
	else:
		ret=redirect('login')
		
	con.close()
	return ret

@app.route('/login', methods=['GET', 'POST'])
def login():
	if request.method == 'POST':
		if ( request.form['username'] != app.config['USERNAME'] or
			 request.form['password'] != app.config['PASSWORD'] ):
			flash('Invalid username/password combination')
		else:
			session['logged_in'] = True
			flash('Logged in')
			return redirect(request.args.get('next') or url_for('index'))
	return render_template('login.html')

@app.route('/logout')
def logout():
	session.pop('logged_in', None)
	flash('Logged out')
	return redirect(url_for('index'))

@app.route('/campaignresults')
def campaignresults():
	if 'logged_in' in session:
		return render_template('campaignresults.html')
	else:
		return redirect(url_for('login'))

def res2html(iocresult, indent=0):

	ret = ''

	for (k, c) in iocresult.items():
		if type(c) is list:
			ret += '<div style="padding-left:%dpx"><li><b>%s</b></li></div>\n' % (indent*25, k)
			for e in c:
				ret += res2html(e, indent+1)
		else:
			colors = {'True':'red', 'False':'#333333', 'Undefined':'orange'}
			ret += '<div style="padding-left:%dpx"><li>%s&nbsp;<span style="color:%s">[%s</li></div>\n' % (indent*25,  k.split('[')[0], colors[c], ''.join(k.split('[')[1:]))
	return ret
		
@app.route('/campaignresults/<int:host>')
def hostresult(host):
	if 'logged_in' in session:
	
		con = sqlite3.connect( os.path.join( 'db', 'analysis.db' ) )
		con.row_factory = sqlite3.Row
		cur = con.cursor()
		
		cur.execute('SELECT result_id, host_id, json_result, success FROM result WHERE host_id=%d'%host)
		data = cur.fetchone()
		
		cur.execute('SELECT host_ip, host_subnet, host_username FROM host WHERE host_id=%d'%host)
		data_host = cur.fetchone()
		host = data_host['host_username']+'@'+data_host['host_ip']+' (in subnet '+data_host['host_subnet']+')'
		
		if data['success']==0:
			html_result = '<h3 style="color:red"><b>Analysis results cannot be displayed for this host since it could not have been reached.</b></h3>'
		else:
		
			json_result = json.loads(data['json_result'])
			
			
			html_result = []
			
			for (ioc, iocresult) in json_result.items():
				ioc = os.path.split(ioc)[1].replace('.ioc','')
				html_result.append('<h3><a href="#" onClick="javascript:switchDisplay(\'div_%s\')">+</a> Result for IOC <i>%s</i></h3>' % (ioc,ioc))
				html_result.append('<div id="div_%s" style="display:none">' % ioc)
				html_result.append(res2html(iocresult))
				html_result.append('</div>')
				html_result.append('')
				
			html_result = '<br />'.join(html_result)
	
		return render_template('hostresult.html', host=host , html_result=html_result)
	else:
		return redirect(url_for('login'))

@app.route('/campaignplan',methods=['GET','POST'])
def campaignplan():
	if 'logged_in' in session:
		if request.method=='GET':
			iocs = [os.path.splitext(f)[0] for f in os.listdir(app.config['IOCS_FOLDER']) if re.match('^.*\.ioc$',f)]
			return render_template('plan.html',iocs = iocs)
		else:
			clean_db()
			con = sqlite3.connect( os.path.join( 'db', 'analysis.db' ) )
			cur = con.cursor()
			args = [os.path.join('.','python.bat'),os.path.join('.','certitude.py')]
			args.append('-f')
			#Handle target file upload
			targetfile = request.files['target']
			if targetfile and allowed_file(targetfile.filename):
				name = 'anon-campaign' if 'name' not in request.form else request.form['name']
				targetfilename = name.replace('/','_').replace('\\','_').replace(' ', '_').replace('&','_') + '-target.txt'
				targetfilepath = os.path.join(app.config['UPLOAD_FOLDER'],targetfilename)
				targetfile.save(targetfilepath)
				
				with open(targetfilepath,'r') as t:
					for line in t:
						content = line.split('\t')
						ip, subnet, username, password = content[:4]
						domain = content[4] if len(content)>4 else ''
						username = domain+'\\'+username

						cur.execute('INSERT INTO host (host_ip, host_subnet, host_username) VALUES ("%s", "%s", "%s");'%(ip, subnet, username))
					con.commit()
					
			#Define target files
			args.append('-t')
			args.append(targetfilepath)
			#Confidential
			if 'confidential' in request.form:
				args.append('-c')
			#Nb of threads
			args.append('-n')
			args.append(request.form['nbthreads'])
			#Results
			args.append('-o')
			args.append('results')
			#Monitoring?
			args.append('-vvvv')

			
			#IoCs
			
			selected_iocs = request.form.getlist('iocs')
			iocs = sorted(selected_iocs)
			csv_text = RESULT_FILE_HEADER
			for ioc in iocs:
				iocpath = os.path.join(app.config['IOCS_FOLDER'],ioc+'.ioc')
				if os.path.isfile(iocpath):
					#We create the IoC in the DB
					cur.execute('INSERT INTO ioc (ioc_name) VALUES ("%s");' % ioc)
					#We add the IoC in the args list (for the Python command)
					args.append(iocpath)
					#We add the IoC name to the CSV file (for the D3js diplay)
					csv_text += ','+ioc
					
			con.commit()

			csv_text += '\n'
			with open(app.config['RESULT_FILE'],'w') as res:
				res.write(csv_text)
			
			#Let's empty the processed folder (from previous analyzes)
			processed_dir = os.path.join(app.config['CERTITUDE_OUTPUT_FOLDER'],'processed')
			for f in os.listdir(processed_dir):
				if f!='.empty':
					os.remove(os.path.join(processed_dir,f))
			
			#BANZAAAAAAAAAIIIIIIIIIIIIIIIIIIIIIIIIIIIII
			p = subprocess.Popen(args)
			con.close()
			#return render_template('test.html',data = args)
			return redirect(url_for('campaignresults'))
	else:
		return redirect(url_for('login'))

def allowed_file(filename):
	return '.' in filename and filename.rsplit('.',1)[1] in ALLOWED_EXTENSIONS

def clean_db():
	con = sqlite3.connect( os.path.join( 'db', 'analysis.db' ) )
	cur = con.cursor()
	cur.execute('DELETE FROM host')
	cur.execute('DELETE FROM ioc')
	cur.execute('DELETE FROM result')
	try:
		cur.execute('DELETE FROM sqlite_sequence WHERE name="host" OR name="ioc" OR name="result"')
	except sqlite3.OperationalError,e :
		pass
	con.commit()

def browse_tree(node):
	nb_atoms = 0
	nb_positive = 0
	nb_undefined = 0
	if type(node) == dict:
		for i in node.values():
			#result += ' 1 ' + browse_tree(i)
			nba,nbp,nbi = browse_tree(i)
			nb_positive += nbp
			nb_atoms += nba
			nb_undefined += nbi
	elif type(node) == list or type(node) == tuple:
		for i in node:
			#result += ' 2 ' + browse_tree(i)
			nba,nbp,nbi = browse_tree(i)
			nb_positive += nbp
			nb_atoms += nba
			nb_undefined += nbi
	else: #type(node) == str
		#result += '3' + node
		nb_atoms +=1
		if node == 'True':
			nb_positive +=1
		elif node == 'Undefined':
			nb_undefined += 1
	
	return (nb_atoms,nb_positive,nb_undefined)


@app.route('/process')
def process():
                     
	con = sqlite3.connect( os.path.join( 'db', 'analysis.db' ) )
	con.row_factory = sqlite3.Row
	cur = con.cursor()
					 
	files_processed = 0
	files=[f for f in os.listdir(app.config['CERTITUDE_OUTPUT_FOLDER'] ) if not os.path.isdir(os.path.join(app.config['CERTITUDE_OUTPUT_FOLDER'] ,f))]
	for f in files:
	
		filename = os.path.join(app.config['CERTITUDE_OUTPUT_FOLDER'] ,f)

		if f[0] == '_':
			ip_regex = re.match(r'^_.*\@(?P<ip_address>.+)\.txt', f)
			ip = ip_regex.group('ip_address')
			
			cur.execute('SELECT host_id, host_subnet, host_username FROM host WHERE host_ip = "%s"' % ip)
			data = cur.fetchone()
			
			csv = ','.join([str(data['host_id']), ip, 'No', ip, data['host_subnet'], 'N/A', '-1'])+'\n'
			with open(app.config['RESULT_FILE'],'a') as f1:
				f1.write(csv)
				
			cur.execute('INSERT INTO result (host_id, json_result, success) VALUES (%d, "", 0)' % data['host_id'])
			con.commit()
			
			os.popen('move "%s" "%s"' % (filename, os.path.join(app.config['CERTITUDE_OUTPUT_FOLDER'], app.config['PROCESSED_FOLDER'], f)))
			files_processed += 1 
			continue
			
		
		# We extract the host's IP address
		ip_regex = re.match(r'.*\@(?P<ip_address>.+)\.txt', filename)
		ip = ip_regex.group('ip_address')
		#We retrieve the host from the DB 
		cur.execute("SELECT host_id FROM host WHERE host_ip = '%s'"%ip)
		data = cur.fetchone()

		if data != None: 
			infections = dict()

			with open(filename,'r') as f1:
				raw_iocs = f1.read()
			#We dump the raw result of the analysis in the DB:
			
			cur.execute('INSERT INTO result (host_id, json_result, success) VALUES (?, ?, 1)',(data['host_id'], raw_iocs))
			con.commit()
			host_id = data['host_id']
			
			#'Title:Hostname,Lookup:success,Lookup:IP,Lookup:Subnet,Malware,Compromise,'
			cur.execute('SELECT host_ip, host_subnet FROM host WHERE host_id=%d'% host_id)
			data = cur.fetchone()
			
			iocs = json.loads(raw_iocs)
			maxrate, maxioc = -1, None
			rates = []
			
			csv = ','.join( [ str(host_id), ip, 'Yes', ip, data['host_subnet']] )
			
			for k,v in iocs.iteritems():
			
				v_json = json.dumps(v)
				nb_atoms = v_json.count('": "') # IMPROVE THIS !!!
				nb_true = v_json.count('": "True') # IMPROVE THIS !!!
				rate = int(100*float(nb_true)/nb_atoms)
				rates.append(str(rate))
				
				if rate > maxrate:
					maxrate, maxioc = rate, k
							
			maxioc = os.path.split(maxioc)[1].replace('.ioc','')
			csv += ','.join( [ '',maxioc, str(maxrate)] + rates) + '\n'
			with open(app.config['RESULT_FILE'],'a') as f1:
				f1.write(csv)
                                   
		con.commit()
		#Finally, we move the processed file to the the "processed" dir 
		#(as we don't want to process it again...)
		os.popen('move "%s" "%s"' % (filename, os.path.join(app.config['CERTITUDE_OUTPUT_FOLDER'], app.config['PROCESSED_FOLDER'], f)))
		files_processed += 1 
	
	con.close()
	return jsonify({ 'files_processed' : str(files_processed) })           
	#return render_template('test.html',data=str(files_processed)+' file(s) processed   ')# + str(ioc_names))

		
		
@app.route('/prepare')
def prepare():
	result = ''
	
	return render_template('test.html',data=result)


@app.route('/dashboard')
def dashboard():
	if 'logged_in' in session:
		return render_template('dashboard.html')
	else:
		return redirect(url_for('login'))



@app.route('/targetcreation', methods=['GET', 'POST'])
def targetcreation():
	if 'logged_in' in session:
		if request.method=='GET':
			return render_template('targetcreation.html')
		else: #POST
			#os.listdir('.')	
			regex = '^'+IP_REGEX+'(\/([1-9]|1[0-9]|2[0-9]|3[01]))?$'
				# Matches IP from 0.0.0.0 to 255.255.255.255
				# and allows (but not necessarily) masks from /1 to /31
			result = re.match(regex,request.form['ip_1']) != None
			if result:
				elts = re.split('\/',request.form['ip_1'])
				if len(elts)==2:
					mask_dec = int(elts[1])
					mask_bin = '0b'
					for i in range(mask_dec):
						mask_bin += '1'
					for i in range(32-mask_dec):
						mask_bin += '0'
					ip_fragments = re.split('\.',elts[0])
					ip_dec = 0
					mul = 1
					for f in ip_fragments:
						ip_dec += int(f)*mul
						mul *= 256
					ip_bin = bin(ip_dec)
					subnet_bin = bin(int(ip_bin,2) & int(mask_bin,2))
					subnet_dec = int(subnet_bin,2)
					
					ip_max = '0b1'
					for i in range(32-mask_dec):
						ip_max += '0'
					ip_max = int(ip_max,2)
					addresses = list()
					for i in range(1,ip_max-1): #We don-t want the bcast nor the subnet addresses
						addresses.append(subnet_dec+i)
					
		return render_template('test.html',data=addresses)
	
	else:	#Not logged in
		return redirect(url_for('login'))

		




# Let's run the application

if __name__ == '__main__':
	app.run(debug=False)


