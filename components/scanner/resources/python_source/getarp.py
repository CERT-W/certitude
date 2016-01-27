#!/usr/bin/python

import os, re

def getARPTable():

    # Command is arp -a
	ret = []
	commandOutput = os.popen('arp -a').read()

	lines = commandOutput.split('\n')
	lines = [e for e in lines if (not 'ress' in e)]

	ACTIVE_IFACE = None
	ID=1

    # Parse output
	for line in lines:
		
		if line=='':
			continue

		if line[:9]=='Interface':
			ACTIVE_IFACE = line.split(' ')[1]
			
		else:
			if ACTIVE_IFACE is None:
				continue
				
			line = re.sub(r' +', r' ', line).strip()
			IPV4, PHYSICAL, CACHE_TYPE = line.split(' ')

            # Lnaguage trick
            # French is "dynamique" and English is "dynamic"
			CACHE_TYPE = 'dynamic' if CACHE_TYPE[:4]=='dyna' else 'static'
			
			ret.append([ID, ACTIVE_IFACE, IPV4, PHYSICAL, CACHE_TYPE])
			ID += 1
			
	return ret
	
def main():

	ARPEntries = getARPTable()
	
	print '\n'.join(['\t'.join([str(f) for f in e]) for e in ARPEntries])

if __name__=='__main__':
    main()