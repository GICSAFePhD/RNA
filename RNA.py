
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
    
    if test:
        print("Exporting .railML file")
    with open(OUTPUT_FILE, "w") as f:        
        f.write('<?xml version="1.0" encoding="UTF-8"?>\n')
        f.write('<railML xmlns="https://www.railml.org/schemas/3.1" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:gml="http://www.opengis.net/gml/3.2/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="https://www.railml.org/schemas/3.1 https://www.railml.org/schemas/3.1/railml3.xsd" version="3.1">\n')

        save_xml(RML,f)
        
        f.close()

#%%
def add_sections(graph,node,zones):
    zones_number = len(zones)
    zones_number += 1
    zones[zones_number] = []
    zones[zones_number].append(node)
    zones[zones_number].extend(graph[node])
    
    return zones_number
#%%%
def analyze_connectedness(neighbours):
    zones = {}
    zones_number = len(zones)

    for node in neighbours:
        if zones_number == 0:
            zones_number = add_sections(neighbours,node,zones)
        #print(f'Node:{node}')
        
        for zone in zones:
            new_zone = True
            #print(f'Zone_{zone}:{zones[zone]}')
            
            if node in zones[zone]:
                new_zone = False
                continue
            
            if list(set(neighbours[node]) & set(zones[zone])):
                zones[zones_number].append(node)
                zones[zones_number].extend([x for x in neighbours[node] if (x not in zones[zone])])
                new_zone = False
        
        if new_zone: 
            zones_number = add_sections(neighbours,node,zones)
            #print(f'Zone_{zones_number}:{zones[zones_number]}')
        
    #print(f'Zones:{zones}')
    if len(zones) > 1:
        return False
    else:
        return True


#%%%
def analyzing_graph(netElements,netRelations):
        
    netElementsId = get_nodes(netElements)
    netRelationsId = get_relations(netRelations)
    neighbours,switches = get_neighbours_and_switches(netElements) 
    limits = get_limits(switches)
    
    x = '' if (analyze_connectedness(neighbours)) else ('not')

    print(f' The network is {x}connected')

    return netElementsId,neighbours,switches,limits

#%%%   
def get_nodes(netElements):
    netElementsId = []
    
    for netElement in netElements:
        netElementsId.append(netElement.Id)
        
    return netElementsId  

def get_relations(netRelations):
    netRelationsId = []
    
    for netRelation in netRelations:
        netRelationsId.append(netRelation.Id)
        
    return netRelationsId  

def get_neighbours_and_switches(netElements):
    neighbours = {}
    switches = {}
    
    netElementsId = get_nodes(netElements)
    
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
                
    return neighbours, switches

def get_limits(switches):
    
    limits = []
    
    for j in switches:
        for i in switches[j]:
        
            if i in limits:
                limits.remove(i)
            else:
                
                limits.append(i)
    
    return limits
    
def identify_relations(reference):
    
    begin = end = name = ""

    reference = reference.replace('nr_','')
    
    begin = reference[0:reference[1:].find('ne')+1]
    
    reference = reference.replace(begin,'')
    
    end = reference[0:reference[1:].find('_')+1]
    
    name = reference.replace(end+'_','')
    
    return [begin,end,name]
    
def detect_borders(infrastructure):
    borders = {}
    
    for i in infrastructure.Borders[0].Border:
        if i.Id not in borders.keys():
            borders[i.SpotLocation[0].NetElementRef] = {"Id":i.Id,"isOpenEnd":i.IsOpenEnd,"Type":i.Type}
    
    return borders    

def detect_bufferStops(infrastructure):
    bufferStops = {}
    
    for i in [infrastructure.BufferStops[0].BufferStop]:
        if i.Id not in bufferStops.keys():
            bufferStops[i.SpotLocation[0].NetElementRef] = {"Id":i.Id,"Type":i.Type}
    
    return bufferStops

def detect_signalsIS(infrastructure):
    signalsIS = {}
    
    for i in infrastructure.SignalsIS[0].SignalIS:
        if i.Id not in signalsIS.keys():
            signalsIS[i.Name[0].Name] = {"Node":i.SpotLocation[0].NetElementRef,
                                        "Direction":i.SpotLocation[0].ApplicationDirection,
                                        "Position":i.SignalConstruction[0].PositionAtTrack}
    
    return signalsIS

def detect_switchesIS(infrastructure):
    switchesIS = {}
        
    for i in infrastructure.SwitchesIS[0].SwitchIS:
        if i.Id not in switchesIS.keys():
            switchesIS[i.Name[0].Name] = {"Node":i.SpotLocation[0].NetElementRef,"ContinueCourse":i.ContinueCourse,
                                        "BranchCourse":i.BranchCourse,"Direction":i.SpotLocation[0].ApplicationDirection,
                                        "LeftBranch":i.LeftBranch[0].NetRelationRef,"RightBranch":i.RightBranch[0].NetRelationRef}
    
    return switchesIS

def detect_tracks(infrastructure):
    tracks = {}
    
    for i in infrastructure.Tracks[0].Track:
        if i.Id not in tracks.keys():
            tracks[i.Name[0].Name] = {"Node":i.LinearLocation[0].AssociatedNetElement[0].NetElementRef}
    
    return tracks


def detect_trainDetectionElements(infrastructure):
    trainDetectionElements = {}
    
    #print(infrastructure.SwitchesIS[0].SwitchIS)
    
    for i in infrastructure.TrainDetectionElements[0].TrainDetectionElement:
        #print(i.Name[0].Name)
        if i.Id not in trainDetectionElements.keys():
            trainDetectionElements[i.Name[0].Name] = {"Node":i.SpotLocation[0].NetElementRef}
    
    return trainDetectionElements


def analyzing_infrastructure(infrastructure):
    
    # borders
    borders = detect_borders(infrastructure)

    # bufferStops
    bufferStops = detect_bufferStops(infrastructure)
    
    # signalsIS
    signalsIS = detect_signalsIS(infrastructure)

    # switchesIS
    switchesIS = detect_switchesIS(infrastructure)

    # tracks
    tracks = detect_tracks(infrastructure)
    
    # trainDetectionElements
    trainDetectionElements = detect_trainDetectionElements(infrastructure)

    return borders,bufferStops,signalsIS,switchesIS,tracks,trainDetectionElements

#%%%
def export_analysis(file,netElementsId,neighbours,borders, bufferStops,signalsIS,switchesIS,tracks,trainDetectionElements):
    
    with open(file, "w") as f:        
        f.write(f'Nodes: {len(netElementsId)} | Switches: {len(switchesIS)} | Signals: {len(signalsIS)} | Detectors: {len(trainDetectionElements)} | Ends: {len(borders)+len(bufferStops)}\n')
        
        for i in netElementsId:
            f.write(f'Node {i}:\n')
            for j in tracks:
                if i == tracks[j]["Node"]:
                    f.write(f'\tTrack = {j}\n')
            for j in trainDetectionElements:
                if i == trainDetectionElements[j]["Node"]:
                    f.write(f'\tTrainDetectionElements = {j}\n')        
                    
            if i in borders:
                f.write(f'\tType = Border --> {borders[i]["Id"]}\n')
            if i in bufferStops:
                f.write(f'\tType = BufferStop --> {bufferStops[i]["Id"]}\n')
                
            f.write(f'\tNeighbours = {len(neighbours[i])} --> {neighbours[i]}\n')
            
            for j in signalsIS:
                if i == signalsIS[j]["Node"]:
                    f.write(f'\tSignals -> {j}\n')
                    f.write(f'\t\tDirection -> {signalsIS[j]["Direction"]}\n')
                    f.write(f'\t\tPosition -> {signalsIS[j]["Position"]}\n')
            
            for j in switchesIS:
                if i == switchesIS[j]["Node"]:
                    f.write(f'\tSwitches = {j}\n')
                    
                    left = identify_relations(switchesIS[j]["LeftBranch"])[:-1]
                    right = identify_relations(switchesIS[j]["RightBranch"])[:-1]
                    left.remove(i)
                    right.remove(i)
                    
                    if switchesIS[j]["ContinueCourse"] == "right":
                        f.write(f'\t\tContinueCourse -> right -> {right[0]}\n')
                        f.write(f'\t\tBranchCourse -> left -> {left[0]}\n')
                    else:
                        f.write(f'\t\tContinueCourse -> left -> {left[0]}\n')
                        f.write(f'\t\tBranchCourse -> right -> {right[0]}\n')
        f.close()
#%%%
def analyzing_object(object):
    
    topology = object.Infrastructure.Topology
    netElements = topology.NetElements.NetElement
    netRelations = topology.NetRelations.NetRelation
    infrastructure = object.Infrastructure.FunctionalInfrastructure

    print(" Analyzing graph --> Graph.RNA")
    netElementsId,neighbours,switches,limits = analyzing_graph(netElements,netRelations)
        
    print(" Analyzing infrastructure --> Infrastructure.RNA")
    borders, bufferStops,signalsIS,switchesIS,tracks,trainDetectionElements = analyzing_infrastructure(infrastructure)
    
    export_analysis("F:\PhD\RailML\\Graph.RNA",netElementsId,neighbours,borders, bufferStops,signalsIS,switchesIS,tracks,trainDetectionElements)
    