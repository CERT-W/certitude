#!/usr/bin/python
#encoding:utf-8

import xml.etree.ElementTree as ET
import ioc
import sys,logging

FORMAT = logging.Formatter('%(asctime)-15s\t%(name)s\t%(levelname)s\t%(message)s')
sh = logging.StreamHandler()
sh.setFormatter(FORMAT)

logger = logging.getLogger('OpenIOCParser')
logger.addHandler(sh)

######
#
#	FUNCTION removeNS
#	ElementTree inserts the namespace and/or xmnls in tag name, between braces {}
#	Goal is to remove it to have clear tags
#
def removeNS(root):
	tag = root.tag
	root.tag = tag[tag.find('}')+1:] if tag[0]=='{' else tag

	for child in root:
		removeNS(child)


######
#
#	FUNCTION printTree
#	Debug function.
#	Prints ElementTree tree with increasing number of tabulations
#
def printTree(root, level=0):

	print ("\t"*level)+root.tag
	for child in root:
		printTree(child, level+1)


''' Custom exception '''
class OpenIOCParserException(Exception):
	pass


''' CLASS OpenIOCParser
	Parser of OpenIOC XML files built around ElementTree

	Attributes:
		filename:   filename of the OpenIOC file
		tree:	   ElementTree recovered after parsing
		atomicIOC:  Exhaustive list of all atomic IOC present in the tree (=leaves). Discriminated by IndicatorItem[id]
'''
class OpenIOCParser:

	@staticmethod
	def setDebugLevel(level):
		logger.setLevel(level)

	def __init__(self, filename, allowedElements, flatMode):

		self.filename = filename
		self.allowedElements = allowedElements
		self.flatMode = flatMode

	''' METHOD parse
		Sets attribute __tree to the LogicTree (nodes are AND/OR) version of the OpenIOC file
	'''
	def parse(self):
	
		self.__normalTree = None
		self.__reductedTree = None
		self.__atomicIOC = {}
		self.__differentTree = False
		
		XMLTree = ET.parse(self.filename)
		XMLRoot = XMLTree.getroot()

		removeNS(XMLRoot)
		if XMLRoot.tag!='ioc':
			raise Exception('Le fichier XMl fourni est n\'est pas au format OpenIOC')

		definition = list(XMLRoot.findall('definition'))
		if definition==[]:
			raise OpenIOCParserException('Aucune definition n\'est presente')
		definition = definition[0]

		IOCTreeRoot = list(definition.findall('Indicator'))
		if IOCTreeRoot==[] or IOCTreeRoot[0].attrib['operator']!='OR':
			raise OpenIOCParserException('La racine doit etre un element OR')
		IOCTreeRoot = IOCTreeRoot[0]

		if self.flatMode:
			self.__reductedTree = self.createIOCTree(IOCTreeRoot)
		else:
			self.__reductedTree = self.createIOCTree(IOCTreeRoot, True)
		
		if self.__differentTree:
			if self.__reductedTree is None:
				logger.log(logging.WARNING, 'L\'IOC %s n\'a pas pu etre ajoute car aucun de ses elements ne peut etre evalue' % self.filename)
			else:
				logger.log(logging.WARNING, 'L\'IOC %(fn)s a du etre modifie pour etre interprete, voir le fichier %(fn)s.modified' % {'fn':self.filename})
				nfn = self.filename + '.modified'
				normalTree = self.createIOCTree(IOCTreeRoot)
				
				f = open(nfn, 'w')
				f.write('Arbre normal :\n\n')
				f.write(str(normalTree))
				f.write('\n\nArbre modifie :\n\n')
				f.write(str(self.__reductedTree))
				f.close()
				

	''' METHOD createIOCTree - recursive
		creates LogicTree from ElementTree root
		All IndicatorItem must ave an attribute 'id'
	'''
	def createIOCTree(self, root, reducted=False):

		children = []
		
		for indicatorItemChild in root.findall('IndicatorItem'):
			newIOC = self.__createIOC(indicatorItemChild)
			if (not reducted) or ((newIOC.document in self.allowedElements.keys()) and (newIOC.search in self.allowedElements[newIOC.document])):
				children.append(ioc.IOCTree(newIOC))
			else:
				logger.log(logging.WARNING, 'L\'element suivant ne peut etre evalue avec les capacites actuelles : %s/%s' % (newIOC.document, newIOC.search))
				self.__differentTree = True

		for indicatorChild in root.findall('Indicator'):
			newTree = self.createIOCTree(indicatorChild, reducted)
			if newTree is not None:
				children.append(newTree)

		ret = ioc.IOCTree(root.attrib['operator'], children) if children!=[] else None
		
		return ret

	''' GETTER getTree '''
	def getTree(self):
		return self.__reductedTree

	''' METHOD __addAtomicIOC
		Adds an ElementTree IndicatorItem to the current list of
		IOC as an IOC object
	'''
	def __createIOC(self, iocE):
		
		condition = iocE.attrib['condition']
		context = list(iocE.findall('Context'))
		content = list(iocE.findall('Content'))

		if context==[] or content==[]:
			raise OpenIOCParserException('No content or context available for this IndicatorItem')
		context = context[0]
		content = content[0]

		document = context.attrib['document']
		search = context.attrib['search']
		eltType = content.attrib['type']
		value = content.text

		return ioc.IOC(condition, document, search, eltType, value)

	''' GETTER getAtomicIOC '''
	def getAtomicIOC(self):
		return self.__atomicIOC
		

		
############# MAIN #############


if __name__=='__main__':
	
	pass
