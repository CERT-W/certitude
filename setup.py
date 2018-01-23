#!/usr/bin/env python
# -*- coding: utf-8 -*-

from setuptools import setup, find_packages

setup(name='certitude',
      version='1.0',
      description='The Seeker of IOC',
      long_description=open('certitude/README.md').read(),
      url='https://github.com/CERT-W/certitude',
      author='CERT-W',
      author_email='cert@wavestone.com',
      license='GPL',
      classifiers=[
        'Topic :: Security',
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Information Technology',
        'License :: OSI Approved :: GNU Library or Lesser General Public License (LGPL)',
      ],
      keywords='cert-w certitude scan ioc seeker',
      packages=find_packages(),
      python_requires='<3',
      install_requires=['plyara',
                        'bokeh',
                        'dnspython',
                        'flask',
                        'flask-login',
                        'impacket',
                        'lxml',
                        'netaddr',
                        'pandas',
                        'pbkdf2',
                        'ply',
                        'pyasn1',
                        'pycryptodome',
                        'pyopenssl',
                        'sqlalchemy'],
      dependency_links=['git+https://github.com/8u1a/plyara.git#egg=plyara'],
      entry_points = {
        'console_scripts': ['certitude=certitude.main:main'],
      },
      include_package_data=True)