#!/usr/bin/env python
# -*- coding: UTF-8 -*-
"""
CERTitude: The Seeker of IOC
CERT-Solucom cert@solucom.fr
"""
from datetime import datetime

from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey
from sqlalchemy.orm import relationship

from queue_models import Base


class Result(Base):
    __tablename__ = 'resultats'

    id = Column(Integer, primary_key=True)
    tache_id = Column(Integer, ForeignKey('queue.id'))
    finished = Column(DateTime, default=datetime.now)

    up = Column(Boolean)
    blocked = Column(Boolean)
    ip = Column(String)
    elapsed = Column(String)
    mac = Column(String)
    mac_vendor = Column(String)
    hostname = Column(String)
    hostname_long = Column(String)
    os = Column(String)
    domaine = Column(String)
    os_simple = Column(String)
    tal = Column(String)
    zone = Column(String)
    typeequipement = Column(String)
    categorie = Column(String)
    smbreachable = Column(Boolean)


class Port(Base):
    __tablename__ = 'ports'

    id = Column(Integer, primary_key=True)
    result_id = Column(Integer, ForeignKey('resultats.id'))
    resultat = relationship(Result,
        backref='ports',)

    port = Column(Integer)
    status = Column(String)


class Link(Base):
    __tablename__ = 'links'

    id = Column(Integer, primary_key=True)
    result_id = Column(Integer, ForeignKey('resultats.id'))

    ipaddr1 = Column(String)
    ipaddr2 = Column(String)


class IOCDetection(Base):
    __tablename__ = 'iocdetections'

    id = Column(Integer, primary_key=True)
    result_id = Column(Integer, ForeignKey('resultats.id'))
    resultat = relationship(Result,
        backref='iocdetections',)
    xmlioc_id = Column(Integer)
    indicator_id = Column(String) # Length should be 62
