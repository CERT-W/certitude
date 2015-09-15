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
    __tablename__ = 'sep12'

    id = Column(Integer, primary_key=True)
    result_id = Column(Integer, ForeignKey('resultats.id'))
    resultat = relationship(Result,
        backref=backref('sep12', uselist=False),)

    presence = Column(Boolean)
    os = Column(String(42))
    derniere_alerte_date = Column(DateTime)
    derniere_alerte_path = Column(String(420))
    derniere_alerte_source = Column(String(42))
    derniere_alerte_virus = Column(String(420))
    derniere_alerte_username = Column(String(42))
    espace_disque = Column(BigInteger)
    version = Column(String)
