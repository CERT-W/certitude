#!/usr/bin/env python
# -*- coding: UTF-8 -*-
"""
CERTitude: The Seeker of IOC
CERT-Solucom cert@solucom.fr
"""
from datetime import datetime

from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Column, Integer, BigInteger, String, DateTime, Boolean


Base = declarative_base()


class Task(Base):
    __tablename__ = 'queue'

    id = Column(Integer, primary_key=True)
    ip = Column(String(64))
    ip_int = Column(BigInteger)
    ip_demandeur = Column(String(64))
    commentaire = Column(String(100))
    date_soumis = Column(DateTime, default=datetime.now)
    date_debut = Column(DateTime)

    # From here, in english
    iocscanned = Column(Boolean, default=False)
    priority = Column(Integer)
    reserved_ioc = Column(Boolean, default=False)
    consolidated = Column(Boolean, default=False)
    retries_left_ioc = Column(Integer, default=0)
    last_retry = Column(DateTime)

    # Runtime configuration
    batch_id = Column(Integer)
