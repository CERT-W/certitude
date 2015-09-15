#!/usr/bin/python

FALSE = 0
UNDEF = 1
TRUE = 2

def _str(res):
	_strings = { FALSE:'False', TRUE:'True', UNDEF:'Undefined'}
	return _strings[res]