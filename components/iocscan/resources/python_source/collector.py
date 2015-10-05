#!/usr/bin/python

import sys

# Dynamic import does not work with
# pyinstaller (easy to undesrtsand why)...
import getarp
import getdns
import getfiles
import getport
import getprefetch
import getprocess
import getservices

collectors = {
    'getarp':getarp,
    'getdns':getdns,
    'getfiles':getfiles,
    'getport':getport,
    'getprefetch':getprefetch,
    'getprocess':getprocess,
    'getservices':getservices,
        }

if __name__=='__main__':

    if len(sys.argv)<2:

        sys.stderr.write('Usage: %s <action>\n' % sys.argv[0])
        sys.stderr.write('Actions:\n')
        for collector in collectors.keys() :
            sys.stderr.write('\t- %s\n' % collector)

        sys.exit(1)

    name = sys.argv[1]
    if name not in collectors.keys():
        sys.stderr.write('Err: Collector %s does not exist' % name)
        sys.exit(2)

    collectors[name].main()