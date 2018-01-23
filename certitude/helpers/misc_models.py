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
    b64_kdf_salt = Column(String)


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
    yara_list = Column(String)


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