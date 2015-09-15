#!/usr/bin/python
#encoding:utf-8

import sha, random

def getClass(obj):
	return str(obj.__class__).split('.')[-1]

######
#
#	Custom exception
#
class LogicTreeException(Exception):
	pass


######
#
#	CLASS LogicTree
# 	Tree with n children. Nodes are subtrees or leaves.
#
# 	Attributes:
# 	name:       Name of the node. Special names are '__AND__' or '__OR__'
# 	isLeaf:     Set if current node is a leaf
# 	nodes:      child nodes of current node
# 	scenarios:  list of all test scenarios of the current node. Only set by a call to evalTree()
class LogicTree:

	def __init__(self, name, children=[]):

		self.name = name
		self.isLeaf = (children==[])   
		self.nodes = children
		self.uid = sha.new(str(random.random())).hexdigest()

		self.scenarios = None

	######
	#
	#	METHOD getLeaves - recursive
	#	returns the leaves beneath current node
	#
	def getLeaves(self):

		if self.isLeaf:
			return {self.uid:self.name}
		else:
			ret = {}
			for node in self.nodes:
				for uid, name in node.getLeaves().items():
					ret[uid] = name
		return ret


	######
	#
	#	METHOD evalTree
	#	evaluate the scenarios of the tree according to the leaves value
	#
	def eval(self, leavesValue):
		if self.isLeaf:
			if not self.uid in leavesValue.keys():
				raise Exception('Missing value for '+self.uid)
			else:
				return leavesValue[self.uid]
		else:
			if self.name == 'OR':
				for n in self.nodes:
					if n.eval(leavesValue):
						return True
				return False
			else:
				for n in self.nodes:
					if not n.eval(leavesValue):
						return False
				return True
	
	######
	#
	#	toString()
	#
	def __str__(self):
		return self.disp()
		
	######
	#
	#	Display the logic tree.
	#	toString is applied on the leaves
	#
	def disp(self, indent=''):
	
		ret = getClass(self)+'_'+str(self.name)

		if not self.isLeaf:
			cnt=0
			#print self.nodes
			l = len(self.nodes)
			for c in self.nodes:
				ret += '\n'+indent+'|'
				if cnt==(l-1):
					ret += '\n'+indent+'+--'+c.disp(indent+'   ')
				else:
					ret += '\n'+indent+'+--'+c.disp(indent+'|  ')
				cnt += 1
			
		return ret

############# MAIN #############

if __name__=='__main__':

	treeA = LogicTree('Filename is iansus.exe')
	treeB = LogicTree('Right is +s')
	treeC = LogicTree('Right is +x')
	treeD = LogicTree('Owner is root')
	treeE = LogicTree('Owner is admin')

	treeDE = LogicTree('__OR__4', [treeD, treeE])
	treeCDE = LogicTree('__AND__3', [treeC, treeDE])
	treeBCDE = LogicTree('__OR__2', [treeB, treeCDE])
	treeABCDE = LogicTree('__AND__1', [treeA, treeBCDE])
	tree = LogicTree('__OR__0', [treeABCDE])

	values = {}
	
	for uid, elt in tree.getLeaves().items():
		values[uid] = True
		
	print tree.eval(values)
	
