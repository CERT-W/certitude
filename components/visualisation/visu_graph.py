#!/usr/bin/env python
# -*- coding: UTF-8 -*-
"""
CERTitude: The Seeker of IOC
CERT-Solucom cert@solucom.fr
"""
if __name__ == "__main__" and __package__ is None:main.py et non directement')

import matplotlib.pyplot as plt
import networkx as nx
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from config import BASE_DE_DONNEES_QUEUE, IP_SCANNER
from results_models import Link, Result
from queue_models import Task


#GRAPH = 'teamviewer'
#GRAPH = 'SEP'
#GRAPH = 'zone'
GRAPH = 'categorie'


def lanl_graph():
    """ Return the lanl internet view graph from lanl.edges
    """
    try:
        fh=open('lanl_routes.edgelist','r')
    except IOError:
        print "lanl.edges not found"
        raise

    G=nx.Graph()

    time={}
    time[0]=0 # assign 0 to center node
    for line in fh.readlines():
        (head,tail,rtt)=line.split()
        G.add_edge(int(head),int(tail))
        time[int(head)]=float(rtt)

    # get largest component and assign ping times to G0time dictionary
    G0=nx.connected_component_subgraphs(G)[0]
    G0.rtt={}
    for n in G0:
        G0.rtt[n]=time[n]

    return G0


def graph():
    # ouverture de la base de données
    engine = create_engine(BASE_DE_DONNEES_QUEUE, echo=False)
    session = sessionmaker(bind=engine)()

    # récupération des éléments
    liens_reseau = session.query(Link).order_by(Task.id).join(Result).join(Task).filter(Task.commentaire == 'Vague Beta', Result.categorie!='industriel').all()
    # formattage des arcs
    liens = [(str(l.ipaddr1) if l.ipaddr1 not in IP_SCANNER else 'Scanner ' + str(l.ipaddr1), str(l.ipaddr2))
             for l in liens_reseau]
    print str(len(liens)) + ' liens affichés'

    G = nx.Graph()
    G.add_edges_from(liens)

    # mise en cache des données pertinentes en 1 requête
    data = {}
    for r in session.query(Result).filter(Result.up==1, Result.categorie!='industriel').join(Task).filter(Task.commentaire=='Vague Beta').all():
        data[r.ip] = (r.id, r.hostname, r.os, r.sep, r.zone, r.categorie)
    colors = []
    sizes = []
    labels = {}
    nombre_nodes = str(len(G.node))
    print '=== ' + nombre_nodes + ' nodes à représenter ==='
    for i, node in enumerate(G.node):
        print '-- traitement du node n°' + str(i + 1) + '/' + nombre_nodes
        size = 50
        color = 'black'
        label = ''
        if node.startswith('Scanner'):
            #ip = node.split(' ')[1]
            color = 'yellow'
            size = 200
        else:
            # sans mise en cache
            #results = session.query(Result).filter(Result.ip==node)
            #if results.count() > 0:
                #r = results[0]

            # avec mise en cache
            results = data.get(node)
            if results:
                r = Result(
                    id = results[0],
                    hostname = results[1],
                    os = results[2],
                    sep = results[3],
                    zone = results[4],
                    categorie = results[5],
                )

                if GRAPH == 'categorie':
                    if r.categorie:
                        print r.categorie
                        if r.categorie == 'poste de travail':
                            color = 'blue'
                        elif r.categorie == 'reseau':
                            color = 'white'
                            #size = 200
                        elif r.categorie == 'voip':
                            color = 'orange'
                        elif r.categorie == 'ilo':
                            color = 'red'
                        elif r.categorie == 'pda':
                            color = 'violet'
                        elif r.categorie == 'imprimante':
                            color = 'brown'
                        elif 'serveur' in r.categorie:
                            color = 'green'
                        else:
                            color = 'black'
                    else:
                        color = 'black'
                elif GRAPH == 'zone':
                    if r.zone:
                        print r.zone
                        if r.zone == 'blanche':
                            color = 'white'
                        elif r.zone == 'grise':
                            color = 'gray'
                        elif r.zone == 'noire':
                            color = 'black'
                        else:
                            color = 'black'
                    else:
                        color = 'black'
                elif GRAPH == 'SEP':
                    print r.sep
                    if r.sep:
                        color = 'white'
                    elif not r.sep and r.categorie and r.categorie == 'reseau':
                        color = 'white'
                    else:
                        color = 'black'
                elif GRAPH == 'teamviewer':
                    teamviewer = False
                    if r.ports:
                        for p in r.ports:
                            if p.port == 5938 and p.status == 'open':
                                teamviewer = True
                    if not teamviewer:
                        color = 'white'
            else:
                color = 'white'
            #A0CBE2
        if color == 'black':
            label = node
            try:
                hostname = session.query(Result).filter(Result.ip==node)[0].hostname
                if hostname:
                    label = hostname
            except:
                pass
        label = ''
        print node
        print color
        colors.append(color)
        sizes.append(size)
        labels[node] = label


    # Positionnement des points
    ## Graphe classique
    pos = nx.graphviz_layout(G, root=0)
    ## Graphe circulaire
    #pos = nx.graphviz_layout(G, prog="twopi", root=0)
    
    nx.draw(
        G,
        pos,
        node_color=colors,
        font_size=6,
        font_color='gray',
        with_labels=False,
        alpha=0.7,
        node_size=sizes,
        edge_color='grey',
        width=0.4,
    )
    nx.draw_networkx_labels(
        G,
        pos,
        labels,
    )
    #nx.draw_spectral(G, node_color=colors)

    #plt.savefig("simple_path.png")  # save as png
    plt.show()

if __name__ == '__main__':
    graph()
