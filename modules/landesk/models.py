#!/usr/bin/env python
# -*- coding: UTF-8 -*-
"""
CERTitude: The Seeker of IOC
CERT-Solucom cert@solucom.fr
"""
"""
Fichier déclarant le modèle des résultats que va remonter le module CERTitude
Le nom du fichier est une constante
"""
from datetime import datetime

from sqlalchemy.ext.declarative import declarative_base

from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey, BigInteger
from sqlalchemy.orm import relationship, backref

from helpers.queue_models import Base
from helpers.results_models import Result


class Result(Base):
    __tablename__ = 'landesk'

    id = Column(Integer, primary_key=True)
    result_id = Column(Integer, ForeignKey('resultats.id'))
    resultat = relationship(Result,
        backref=backref('landesk', uselist=False),)

    presence = Column(Boolean)
    os = Column(String)
    domaine = Column(String)
