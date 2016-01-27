#!/usr/bin/python

import os, re

def getConnections():

    # Command netstat -ano
	ret = []
	commandOutput = os.popen('netstat -ano').read()
	
	lines = commandOutput.split('\n')
	for i in range(0,4):
		lines.pop(0)
	lines.pop()
		
    # MSFT, please use tabs...
	lines = [re.sub(r' +', r' ', e).strip() for e in lines]
	ID=1
	
    # Parse output
	for line in lines:
		PROTOCOL = line.split(' ')[0]
		
		if PROTOCOL=='TCP':
			PROTOCOL, LOCAL_COMB, REMOTE_COMB, STATUS, PID = line.split(' ')
		else:
			PROTOCOL, LOCAL_COMB, REMOTE_COMB, PID = line.split(' ')
			STATUS = 'UNKNOWN'
			
		LOCAL_PORT = LOCAL_COMB.split(':')[-1]
		REMOTE_PORT = REMOTE_COMB.split(':')[-1]
		
        # IPv4/IPv6 trick
		LOCAL_IP = LOCAL_COMB.split(']')[0][1:] if LOCAL_COMB[0] == '[' else LOCAL_COMB.split(':')[0]
		REMOTE_IP = REMOTE_COMB.split(']')[0][1:] if REMOTE_COMB[0] == '[' else REMOTE_COMB.split(':')[0]
		
		ret.append( [ ID, PROTOCOL, LOCAL_IP, LOCAL_PORT, REMOTE_IP, REMOTE_PORT, STATUS, PID ] )
		ID += 1
				
	return ret
	
def main():

	connexions = getConnections()
	
	print '\n'.join(['\t'.join([str(f) for f in e]) for e in connexions])

if __name__=='__main__':
    main()