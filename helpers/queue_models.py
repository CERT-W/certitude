#!/usr/bin/env python
# -*- coding: UTF-8 -*-
'''
    CERTitude: the seeker of IOC
    Copyright (c) 2016 CERT-W
    
    Contact: cert@wavestone.com
    Contributors: @iansus, @nervous, @fschwebel
    
    CERTitude is under licence GPL-2.0:
    This program is free software; you can redistribute it and/or
    modify it under the terms of the GNU General Public License
    as published by the Free Software Foundation; either version 2
    of the License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
'''

from datetime import datetime

from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Column, Integer, BigInteger, String, DateTime, Boolean


Base = declarative_base()


class Task(Base):
    __tablename__ = 'queue'

    id = Column(Integer, primary_key=True)
    ip = Column(String(64))
    ip_demandeur = Column(String(64))
    commentaire = Column(String(100))
    date_soumis = Column(DateTime, default=datetime.now)
    date_debut = Column(DateTime)

    # From here, in english
    iocscanned = Column(Boolean, default=False)
    hashscanned = Column(Boolean, default=False)
    yarascanned = Column(Boolean, default=False)
    priority_ioc = Column(Integer)
    priority_hash = Column(Integer)
    priority_yara = Column(Integer)
    reserved_ioc = Column(Boolean, default=False)
    reserved_hash = Column(Boolean, default=False)
    reserved_yara = Column(Boolean, default=False)
    retries_left_ioc = Column(Integer, default=0)
    retries_left_hash = Column(Integer, default=0)
    retries_left_yara = Column(Integer, default=0)
    last_retry_ioc = Column(DateTime)
    last_retry_hash = Column(DateTime)
    last_retry_yara = Column(DateTime)

    # Runtime configuration
    batch_id = Column(Integer)
