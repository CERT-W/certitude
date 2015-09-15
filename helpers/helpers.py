#!/usr/bin/env python
# -*- coding: UTF-8 -*-
"""
CERTitude: The Seeker of IOC
CERT-Solucom cert@solucom.fr
"""
from socket import gethostbyname
from socket import gaierror
import logging

from hashlib import sha256, sha512
import dns.resolver
import dns

from config import SERVEURS_DNS, INTERFACE_HASH_SALT


loggingserver = logging.getLogger('api')

my_resolver = dns.resolver.Resolver()
my_resolver.timeout = 1

def resolve(name):
    # Serveurs DNS de la conf
    ip = None
    for d in SERVEURS_DNS:
        loggingserver.debug('Résolution de ' + name + ' auprès de ' + d)
        my_resolver.nameservers = [gethostbyname(d),]
        try:
            # requête type DNS
            answer = my_resolver.query(name, 'A')
            ips = [a.address for a in answer]
            loggingserver.debug('IPs trouvée : ' + str(ips))
            ip = answer[0].address
        except (dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
            try:
                # requête type WINS
                answer = my_resolver.query(name + '.wins.MACHINE.fr', 'A')
                ips = [a.address for a in answer]
                loggingserver.debug('IPs trouvée : ' + str(ips))
                ip = answer[0].address
            except (dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
                pass # domaine inexistant
    # Serveur DNS de l'hôte
    if not ip:
        try:
            ip = gethostbyname(name)
        except gaierror:
            pass
    if ip:
        loggingserver.debug('IP renvoyée : ' + str(ip))
        return ip
    else:
        return None

def row2dict(row):
    d = {}
    for column in row.__table__.columns:
        d[column.name] = getattr(row, column.name)

    return d

def uniq(seq):
    # dédoublonnage
    # http://www.peterbe.com/plog/uniqifiers-benchmark
    # order preserving
    def idfun(x): return x
    seen = {}
    result = []
    for item in seq:
       marker = idfun(item)
       if marker in seen: continue
       seen[marker] = 1
       result.append(item)
    return result
    
def hashPassword(password):
    s = sha256()
    s.update(INTERFACE_HASH_SALT)
    s.update(password)
    
    return s.hexdigest()

    
def checksum(data):
    return sha512(data).hexdigest()
    

def verifyPassword(p):
    if len(p) < 12:
        return False
        
    MIN = False
    MAJ = False
    NUM = False
    SPEC = False
    
    for i in range(0, len(p)):
        c = ord(p[i])
        
        if not c in range(33, 127):
            continue
        
        if c in range(ord('a'), ord('z')+1):
            MIN = True
        elif c in range(ord('A'), ord('Z')+1):
            MAJ = True
        elif c in range(ord('0'), ord('9')+1):
            NUM = True
        else:
            SPEC = True
            
    return int(MIN)+int(MAJ)+int(NUM)+int(SPEC)>=3
        
    
    