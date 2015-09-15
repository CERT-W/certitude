#!/usr/bin/python

import openioc.openiocparser as openiocparser
import openioc.ioc as ioc

from flatevaluators.template import EvaluatorInterface as FLETemplate
from logicevaluators.template import EvaluatorInterface as LOETemplate

import remotecmd
from threading import Lock
from optparse import OptionParser
import  time, logging, os, sys, json

import targethandler

# Logging options

FORMAT = logging.Formatter('%(asctime)-15s\t%(name)s\t%(levelname)s\t%(message)s')
sh = logging.StreamHandler()
sh.setFormatter(FORMAT)

logger = logging.getLogger('CERTitude')
logger.addHandler(sh)

######
#
#    Returns a list that is the intersection of the
#    two input lists
#
def ListIntersection(a, b):
    return list(set(a) & set(b))

######
#
#    Main class
#
class Certitude:

    @staticmethod
    def setDebugLevel(level):
        logger.setLevel(level)

    # Init function
    def __init__(self, targetList, IOCFilenameList, nthreads=1, rootDir=".", flatMode=False, confidential=False, keepFiles=False):

        # Other init stuff

        self.__nthreads = nthreads
        self.__lock = Lock()
        self.__handlers = []
        self.__handlerCount = 0
        self.__trees = {}
        self.__outputDir = None
        self.__flatMode = flatMode
        self.__keepFiles = keepFiles
        self.__confidential = confidential
        self.rootDir = rootDir
        leaves = {}

        logger.log(logging.INFO, 'Demarrage de CERTitude a %d threads sur %d cibles' % (nthreads, len(targetList)))
        
                # Selection of evaluator according to the search mode
        allowedElements = {}
        evaluatorList = targethandler.flatEvaluatorList if flatMode else targethandler.logicEvaluatorList

        for name, classname in evaluatorList.items():
            allowedElements[name] = classname.evalList

        # IOC Parsing for each one of the files
        for filename in IOCFilenameList:
            oip = openiocparser.OpenIOCParser(filename, allowedElements, self.__flatMode)
            oip.parse()
            iocTree = oip.getTree()

            # Trees may be stripped from non valid elements
            if iocTree is not None:
                self.__trees[filename] = iocTree

            del oip

        # If there is no valid tree anymore
        if self.__trees == {}:
            logger.log(logging.CRITICAL, 'Aucun IOC valide a evaluer, fermeture du programme')
            sys.exit(1)

        # Handler list creation
        for target in targetList:
            if ListIntersection(['ip','login','password'], target.keys())!=[]:

                priority = remotecmd.PRIORITY_NORMAL if not 'priority' in target.keys() else target['priority']
                domain = '' if not 'domain' in target.keys() else target['domain']

                if flatMode:
                    h = targethandler.FlatTargetHandler(target['ip'], target['login'], target['password'], domain, priority, self.__trees, self.rootDir, self.__confidential, self.__keepFiles)
                else:
                    h = targethandler.LogicTargetHandler(target['ip'], target['login'], target['password'], domain, priority, self.__trees, self.rootDir, self.__confidential, self.__keepFiles)

                self.__handlers.append(h)

    #######
    #
    #    Method to launch the scans
    #
    def launch(self):

        if self.__confidential:
            logger.log(logging.INFO, 'Mode "Haute confidentialite" active')
            drPlusDir = os.path.join( self.rootDir, targethandler.DR_PLUS_DIR )
            if not os.path.isdir( drPlusDir ):
                os.popen('mkdir "'+drPlusDir+'"')
    
        logger.log(logging.INFO, 'Instance demarree, en ecoute de %d handlers' % len(self.__handlers))
        activeList = []    # List of active scans

        while True:

            isNone = False

            # If there is not enough active threads
            if len(activeList) < self.__nthreads:
                next = self.__getNextHandler()

                # If there are still scans to perform
                if next is not None:
                    logger.log(logging.INFO,'Tentative de contact du handler "%s"' % next.getName())
                    next.start()
                    activeList.append(next)
                else:
                    isNone = True

            delIdx = []

            # Run through the active list to get rid of ended scans
            for hdl in activeList:
                if hdl.finished:
                    if hdl.isOk:
                        logger.log(logging.INFO, 'Le handler "%s" a renvoye les resultats de l\'analyse' % hdl.getName())
                        self.__printResults(hdl.getName(), hdl.result)
                    else:
                        self.__printResultError(hdl.getName())

                    activeList.remove(hdl)

            # If no active scan and no more scan to perform
            if isNone and len(activeList)==0:
                logger.log(logging.INFO, 'Tous les handlers ont termine !')
                break
                
        if self.__confidential and not self.__keepFiles:
            os.popen('rmdir /s /q "'+drPlusDir+'"')

    #######
    #
    #    Selects scan output directory
    #
    def setOutputDir(self, dirname):

        if not os.path.isdir(dirname):
            logger.log(logging.WARNING, 'Le repertoire de sortie n\'existe pas et sera donc cree automatiquement')
            os.popen('mkdir '+dirname)

        self.__outputDir = dirname


    ######
    #
    #    Prints results for OK scans
    #
    def __printResults(self, name, results):


        if self.__flatMode:
            jsonresults = {}

            for filename, tree in self.__trees.items():
                # s+= '====='+filename+'=====\n\n'
                # s+= tree.disp(results)
                # s+= '\n\n'
                jsonresults[filename] = tree.json(results)
            s = json.dumps(jsonresults, sort_keys=True, indent=4, separators=(',', ': '))
                
        else:
            s = '['+name+']\n\n'

            for filename, tree in self.__trees.items():
                s+= filename+'='+results[filename]+'\n'

            s+'\n\n'

        if self.__outputDir is not None:
            f = open(os.path.join(self.__outputDir, name + '.txt'), 'wb')
            f.write(s)
            f.close()
        else:
            print s


    #######
    #
    #    Prints results for not OK scans
    #
    def __printResultError(self, name):

        if self.__outputDir is not None:
            f = open(os.path.join (self.__outputDir, '_' + name + '.txt'), 'wb')
            f.close()
        else:
            pass


    ######
    #
    #    Returns the next handler in the list or None if no more handlers
    #
    def __getNextHandler(self):
        if self.__handlerCount == len(self.__handlers):
            return None
        else:
            self.__handlerCount += 1
            return self.__handlers[self.__handlerCount - 1]


    ########
    #
    #    Lock stuff
    #    Might be completely useless, dunno...
    #
    def acquireLock(self):
        self.__lock.acquire()

    def releaseLock(self):
        self.__lock.release()


if __name__=='__main__':

    # Options definition

    op = OptionParser(usage='usage: %prog [options] ioc_file_1 [ioc_file_2 [ioc_file_n] ]', add_help_option=False)

    op.add_option('-t', '--target-file', dest='target', metavar='TARGET_FILE', action='store', help='Fichier de description de la cible. Chaque ligne est sous la forme "IP<TAB>Utilisateur<TAB>MotDePasse[<TAB>Domaine[<TAB>Priorite d\'execution]]". Priorite est facultatif')
    op.add_option('-v', dest='verbose', action='count', help='Rendre le programme verbeux (-v -vv -vvv -vvvv)')
    op.add_option('-f', '--flat-analysis', dest='flat', action='store_true', help='Effectuer une recherche plate', default=False)
    op.add_option('-k', '--keep-files', dest='keep', action='store_true', help='Garder les fichiers apres analyse', default=False)
    op.add_option('-o', '--output-dir', dest='output', action='store', help='Specifier un dossier de sortie')
    op.add_option('-R', '--root-dir', dest='root', action='store', help='Specifier le dossier racine de CERTitude')
    op.add_option('-n', '--nthreads', dest='nthreads', type='int', action='store', help='Nombre de threads a utiliser, par defaut 1', default=1)
    op.add_option('-h', '--help', action='help', help='Affiche ce menu d\'aide')
    op.add_option('-c', '--confidential', dest='confidential', action='store_true', help='Mode "Haute confidentialite" = IOC non envoye sur le poste distant. Tres gourmand en ressources reseau', default=False)


    # Options verification

    opts, iocs = op.parse_args()

    if len(iocs) < 1:
        op.print_help()
        sys.exit(1)

    if not opts.target:
        print 'Option -t manquante !\n'
        op.print_help()
        sys.exit(1)

    if opts.nthreads < 1:
        print 'Le nombre de threads a utiliser doit etre superieur ou egal a 1 !\n'
        op.print_help()
        sys.exit(1)

    try:
        target = open(opts.target, 'rb')
    except IOError:
        print 'Le fichier %s n\'existe pas !' % opts.target
        sys.exit(1)

    # Options exploitation & CERTitude init

    targetList = []

    for line in target.read().replace('\r', '').split('\n'):
        if not line:
            continue
        s = line.split('\t')
        d = {'ip':s[0], 'login':s[2], 'password':s[3]}
        if len(s)>4:
            d['domain'] = s[4]
        if len(s)>5:
            d['priority'] = s[5]

        targetList.append(d)


    # Debug level stuff
    debugLevels = {
        0: logging.CRITICAL,
        1: logging.ERROR,
        2: logging.WARNING,
        3: logging.INFO,
        4: logging.DEBUG,
    }

    debugLevel = debugLevels.get(opts.verbose, logging.CRITICAL)

    Certitude.setDebugLevel(debugLevel)
    openiocparser.OpenIOCParser.setDebugLevel(debugLevel)
    FLETemplate.setDebugLevel(debugLevel)
    LOETemplate.setDebugLevel(debugLevel)
    remotecmd.RemoteCmd.setDebugLevel(debugLevel)

    if opts.root:
        rootDir = opts.root
    else:
        rootDir = "."
    
    # Launch it !
    c = Certitude(targetList, iocs, opts.nthreads, rootDir, opts.flat, opts.confidential, opts.keep)
    
    if opts.output:
        c.setOutputDir(opts.output)

    # Time Analysis

    t1 = time.time()
    results = c.launch()
    t2 = time.time()

    logger.log(logging.INFO, 'L\'analyse s\'est terminee en %fs' % (t2-t1))
