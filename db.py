from pymongo import MongoClient

Class DBManager():
    def __init__():
        self.client = MongoClient()
        self.db = self.client.certitude
        self.users = self.db.users
        self.users.ensure_index('username', unique=True)
        self.iocs = self.db.iocs
        self.results = self.db.results

    def getIOCList():
        return self.iocs

#    def insertResult():
#        return t

#    def insertIOC():
#        return t

    def loadResult():
        return self.results

    def getUsers():
        return self.users
