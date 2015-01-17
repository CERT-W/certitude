#!/usr/bin/python
#encoding:utf-8

import sha, random
from logictree import LogicTree, getClass

########
#
#	Logic Tree which leaves are IOC
#
class IOCTree():

	def __init__(self, name, children=[]):
		self.name = name
		self.isLeaf = (children==[])   
		self.nodes = children
		

	#########
	#
	#	The documents are the different types of elements
	#	(ServiceItem, FileItem...) present within the subleaves
	#
	def getDocuments(self):
		if self.isLeaf:
			return [self.name.document]
		else:
			ret = []
			for c in self.nodes:
				ret += c.getDocuments()
			return list(set(ret))

	#######
	#
	#	Return the leaves relatively to the current root
	#
	def getLeaves(self):

		if self.isLeaf:
			return {self.name.uid:self.name}
		else:
			ret = {}
			for node in self.nodes:
				for uid, name in node.getLeaves().items():
					ret[uid] = name
		return ret
	
	def __str__(self):
		return self.disp()
	
	# Does not need to be explained
	def disp(self, values={}, indent=''):
	
		ret = str(self.name)

		if not self.isLeaf:
			cnt=0
			l = len(self.nodes)
			for c in self.nodes:
				ret += '\n'+indent+'|'
				if cnt==(l-1):
					ret += '\n'+indent+'+--'+c.disp(values, indent+'   ')
				else:
					ret += '\n'+indent+'+--'+c.disp(values, indent+'|  ')
				cnt += 1
		else:
			ioc = self.name
			if ioc.uid in values.keys():
				ret += ' => '+values[ioc.uid]
			
		return ret
		
	def json(self, values={}):
		
		if self.isLeaf:
			ioc = self.name
			if ioc.uid in values.keys():
				return {str(ioc):values[ioc.uid]}
		else:
			children = []
			for c in self.nodes:
				children.append(c.json(values))
			return {str(self.name):children}
	
	##########
	#
	#	Only for logic evaluation
	#	Build the SQL query associated with the logic
	#	structure of the tree
	#
	def buildWhereClause(self, conditionList, escapeValueFun):
		
		if self.isLeaf:
			ioc = self.name
			condition =  conditionList[ioc.condition] % escapeValueFun(ioc.value) if ioc.condition != 'regex' else conditionList[ioc.condition] % ioc.value
			category = ioc.search.replace('%s/'%ioc.document, '')
			
			return '(`%(index)s` %(clause)s)' % {'index' : category, 'clause': (condition)}
		else:
			return '('+(' %s ' % self.name).join([n.buildWhereClause(conditionList, escapeValueFun) for n in self.nodes])+')'
			

class IOC:

	TYPE_LIST = ['string', 'int', 'date', 'sha256', 'md5', 'sha1', 'dateTime']

	documentPrefixes = {
		'ServiceItem' : 'SERVICE'
	}
	
	def __init__(self, condition, document, search, eltType, value):
		
		self.condition = condition
		self.document = document
		self.search = search.replace(document+'/', '')
		self.eltType = eltType
		self.value = value
		self.uid = sha.new(condition+document+search+value).hexdigest()[:8]

	def __repr__(self):
		return self.__str__()
		
	def __str__(self):
		return self.document+'/'+self.search+'['+self.condition+'='+self.value+']'#-'+self.uid
		

########
#
#	Transforms an IOC Tree into a logic tree
#	which leaves are IOC trees
#
def IOC2LogicTree(it, isRoot = True):
	if it.isLeaf:
		return it
	else:
		docs = it.getDocuments()
		if len(docs) == 1:
			if isRoot:
				return LogicTree('OR', [LogicTree(it)])
			else:
				return it
		else:
			treatNow = dict()
			newNodes = []
			for n in it.nodes:
				subDocs = n.getDocuments()
				if len(subDocs)==1:
					if subDocs[0] not in treatNow.keys():
						treatNow[subDocs[0]] = []
					treatNow[subDocs[0]].append(n)
				else:
					newNodes.append(IOC2LogicTree(n))
			
			for doc, nds in treatNow.items():
				toInsert = IOCTree(it.name, nds)
				if toInsert.name=="AND":
					toInsert = IOCTree('OR', [toInsert])
					
				new = LogicTree(toInsert)
				newNodes.append(new)
				
			ret = LogicTree(it.name, newNodes)
				
			return ret
