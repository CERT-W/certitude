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


class User(Base):
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True)
    username = Column(String)
    password = Column(String)
    email = Column(String)
    active = Column(Boolean)
    encrypted_master_key = Column(String)


class XMLIOC(Base):
    __tablename__ = 'xmliocs'

    id = Column(Integer, primary_key=True)
    name = Column(String)
    date_added = Column(DateTime, default=datetime.now)
    xml_content = Column(String)


class Batch(Base):
    __tablename__ = 'batches'

    id = Column(Integer, primary_key = True)
    name = Column(String)
    configuration_profile_id = Column(Integer)
    windows_credential_id = Column(Integer)

class ConfigurationProfile(Base):
    __tablename__ = 'configuration_profiles'

    id = Column(Integer, primary_key=True)
    name = Column(String)
    host_confidential = Column(Boolean, default=False)
    ioc_list = Column(String)


class WindowsCredential(Base):
    __tablename__ = 'windows_crendentials'

    id = Column(Integer, primary_key=True)
    domain = Column(String)
    login = Column(String)
    encrypted_password = Column(String)

class GlobalConfig(Base):
    __tablename__ = 'global_config'

    id = Column(Integer, primary_key=True)
    key = Column(String)
    value = Column(String)