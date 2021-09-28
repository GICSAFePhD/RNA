
from RailML.XML_tools import *

#%%%
def RNA(RML,INPUT_FILE,OUTPUT_FILE,test = False):
    
    if test:
        print("#"*20+" Starting Railway Network Analyzer "+"#"*20)
    
    if test:
        print("Reading .railML file")
    root = load_xml(INPUT_FILE)   #A RELATIVE PATH DOESN'T WORK FOR PREVIEW!
    
    if test:
        print("Creating railML object")
    get_branches(RML,root,test = False)
    
    if test:
        print("Analyzing railML object")
    analyzing_object(RML)
    
    
    #print(dir(RML.Common.Positioning.GeometricPositioningSystems.GeometricPositioningSystem))
            
    #x = RML.Infrastructure.Topology.Networks.Network[0]
    #y = get_attributes(x)
    #print(x,y)
    #for i in y:
    #    z = getattr(x,i)
    #    if z != None:
    #        print(i,z)   

    if test:
        print("Exporting .railML file")
    with open(OUTPUT_FILE, "w") as f:        
        f.write('<?xml version="1.0" encoding="UTF-8"?>\n')
        f.write('<railML xmlns="https://www.railml.org/schemas/3.1" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:gml="http://www.opengis.net/gml/3.2/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="https://www.railml.org/schemas/3.1 https://www.railml.org/schemas/3.1/railml3.xsd" version="3.1">\n')

        save_xml(RML,f)
        
        f.close()


#%%%
def analyzing_graph(netElements,netRelations):
    netElementsId = []
    netRelationsId = []
    
    for netElement in netElements:
        netElementsId.append(netElement.Id)
    print(f'  Nodes: {len(netElementsId)} | {netElementsId}')
    
    for netRelation in netRelations:
        netRelationsId.append(netRelation.Id)
    print(f'  Edges: {len(netRelationsId)}')
    
    neighbours = {}
    switches = {}
    
    for i in netElementsId:
        neighbours[i] = []
    
    for netElement in netElements:
        for i in netElement.Relation:
            [begin, end, name] = identify_relations(i.Ref)
            
            if name not in switches.keys():
                switches[name] = []
            
            if end not in neighbours[begin]:
                neighbours[begin].append(end)
                
            if begin not in neighbours[end]:
                neighbours[end].append(begin)
                
            if begin not in switches[name]:
                switches[name].append(begin)
            
            if end not in switches[name]:
                switches[name].append(end)
    
    print(f'  Swtiches: {len(switches)} | {[i for i in switches]}')
    
    
    limits = []
    
    for j in switches:
        for i in switches[j]:
        
            if i in limits:
                limits.remove(i)
            else:
                limits.append(i)
        
        
    print(f'  Limits: {len(limits)} | {limits}')
    
    
    
    
    for i in neighbours:
        print(f'  Node {i} has {len(neighbours[i])} neighbours: {neighbours[i]}')
    
    for i in switches:
        print(f'  Switch {i} touches {len(switches[i])} nodes: {switches[i]}')
    
    
    
    
def identify_relations(reference):
    
    begin = end = name = ""

    reference = reference.replace('nr_','')
    
    begin = reference[0:reference[1:].find('ne')+1]
    
    reference = reference.replace(begin,'')
    
    end = reference[0:reference[1:].find('_')+1]
    
    name = reference.replace(end+'_','')
    
    return [begin,end,name]
    
    

#%%%
def analyzing_object(object):
    
    topology = object.Infrastructure.Topology
    netElements = topology.NetElements.NetElement
    netRelations = topology.NetRelations.NetRelation


    print(" Analyzing graph")
    analyzing_graph(netElements,netRelations)
    
    
    