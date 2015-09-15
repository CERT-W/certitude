#!/usr/bin/env python
# -*- coding: UTF-8 -*-
"""
Fichier déclarant le modèle des résultats que va remonter le module Scanopy
Le nom du fichier est une constante
"""
from datetime import datetime

from sqlalchemy.ext.declarative import declarative_base
# pour illustration des possibilités
from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey


Base = declarative_base()


class Result(Base):
    __tablename__ = 'forensics'

    id = Column(Integer, primary_key=True)
    # tache_id à ne pas garder pour l'instant, injection de dépendance à étudier
    #tache_id = Column(Integer, ForeignKey('results.id'))
    date = Column(DateTime, default=datetime.now)

    os = Column(String)
    nom_machine = Column(String)
    dernier_heartbeat = Column(DateTime)
