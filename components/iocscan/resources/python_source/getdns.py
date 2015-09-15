#!/usr/bin/python

import os, re

IP_PATTERN = r'^(25[0-5]|2[0-4][0-9]|[1-9][0-9]{2}|[1-9][0-9]|[0-9]\.){3}25[0-5]|2[0-4][0-9]|[1-9][0-9]{2}|[1-9][0-9]|[0-9]$'

def getDNSEntries():

	ret = []
	commandOutput = os.popen('ipconfig/displaydns').read()
	
	lines = commandOutput.split('\n')
	for i in range(0,3):
		lines.pop(0)
	
	lines = [re.sub(r' +', r' ', e).strip() for e in lines]
	ID=1
	
	previous, c = '', 0
	RNAME, RTYPE, TTL, DATALEN, RD_HOST, RD_IPV4 = None, None, None, None, None, None
	
	for line in lines:
		
		if line=='':
			continue
		
		if line=='----------------------------------------':
			DOMAIN = previous
			c=0
			
		else:
		
			if c==6:
				ret.append( [ ID, RNAME, RTYPE, TTL, DATALEN, RD_HOST, RD_IPV4 ] )
				ID += 1
				continue
				
			if not ':' in line:
				continue
			
			value = line.split(':')[1].strip()
			
			if c==0:
				RNAME = value
				
			if c==1:
				TTL = value
				
			if c==2:
				TTL = value
				
			if c==3:
				DATALEN = value
				
			if c==5:
				RD_HOST, RD_IPV4 = ['-', value] if re.search(IP_PATTERN, value) else [value, '-']
			
			c+=1
		
		
		previous = line
		
	return ret
	
def main():

	dnsentries = getDNSEntries()
	
	print '\n'.join(['\t'.join([str(f) for f in e]) for e in dnsentries])
    
if __name__=='__main__':
    main()