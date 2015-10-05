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
    hostname = Column(String)
    smbreachable = Column(Boolean)


class IOCDetection(Base):
    __tablename__ = 'iocdetections'

    id = Column(Integer, primary_key=True)
    result_id = Column(Integer, ForeignKey('resultats.id'))
    resultat = relationship(Result,
        backref='iocdetections',)
    xmlioc_id = Column(Integer)
    indicator_id = Column(String) # Length should be 62
