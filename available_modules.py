#!/usr/bin/python

import helpers.iocscan_modules as A
import helpers.hashscan_modules as B

print '*** IOCSCAN ***'

for k,v in A.flatEvaluatorList.items():
    print '%s\t%s' % (k, ', '.join(v.evalList))
    
print '\n'
print '*** HashSCAN ***'

for k,v in B.flatEvaluatorList.items():
    print '%s\t%s' % (k, ', '.join(v.evalList))
    
print '\n'
