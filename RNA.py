
from RailML.XML_tools import *

#%%%
def RNA(RML,INPUT_FILE,OUTPUT_FILE,auto = True, test = False):
    
    if test:
        print("#"*20+" Starting Railway Network Analyzer "+"#"*20)
    
    if test:
        print("Reading .railML file")
    
    root = load_xml(INPUT_FILE)   #A RELATIVE PATH DOESN'T WORK FOR PREVIEW!
    
    if auto:
        ignore = {None}
    else:
        ignore = {"SignalsIS","SignalsIL","Routes"}
        
    if test:
        print("Creating railML object")
    get_branches(RML,root,ignore = ignore,test = False )
    
    if test:
        print("Analyzing railML object")
    analyzing_object(RML)
    
    if test:
        print("Exporting .railML file")
    with open(OUTPUT_FILE, "w") as f:        
        f.write('<?xml version="1.0" encoding="UTF-8"?>\n')
        f.write('<railML xmlns="https://www.railml.org/schemas/3.1" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:gml="http://www.opengis.net/gml/3.2/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="https://www.railml.org/schemas/3.1 https://www.railml.org/schemas/3.1/railml3.xsd" version="3.1">\n')

        save_xml(RML,f,ignore = ignore, test = False)
        
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
        #print(f'Node:{node}|{neighbours[node]}')
        
        for zone in zones:
            new_zone = True
            #print(f'Zone_{zone}:{zones[zone]}')
            
            if node in zones[zone]:
                new_zone = False
                zones[zone].extend([x for x in neighbours[node] if (x not in zones[zone])])
                continue
            
            if list(set(neighbours[node]) & set(zones[zone])):
                zones[zones_number].append(node)
                zones[zones_number].extend([x for x in neighbours[node] if (x not in zones[zone])])
                new_zone = False
        
        if new_zone: 
            zones_number = add_sections(neighbours,node,zones)
        #print(f'Zones:{zones}')
    
    # Combine zones with common nodes
    for zone in range(1,len(zones)+1):
        if zone+1 <= len(zones):
            if list(set(zones[zone]) & set(zones[zone+1])):
                zones[zone].extend([x for x in zones[zone+1] if (x not in zones[zone])])
                del zones[zone+1]
    
    print(f' Zones:{zones}')
    
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
    
    x = '' if (analyze_connectedness(neighbours)) else ('not ')

    print(f' The network is {x}connected')

    return netElementsId,neighbours,switches,limits

#%%%   
def get_nodes(netElements):
    netElementsId = []
    
    for netElement in netElements:
        if (netElement.Id[2].isdigit()):        # Only MICRO
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
        #print(netElement.AssociatedPositioningSystem)
        if netElement.Relation != None:
            for i in netElement.Relation:
                
                if (not netElement.Id[2].isdigit()): 
                    continue
                
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
    
    #return borders 
    
    if infrastructure.Borders != None:
        for i in infrastructure.Borders[0].Border:
            if i.Id not in borders.keys():
                borders[i.Id] = {"Node":i.SpotLocation[0].NetElementRef,"IsOpenEnd":i.IsOpenEnd,"Type":i.Type}
    
    return borders 

def detect_bufferStops(infrastructure):
    bufferStops = {}
    
    if infrastructure.BufferStops != None:
        for i in [infrastructure.BufferStops[0].BufferStop]:
            if i.Id not in bufferStops.keys():
                bufferStops[i.SpotLocation[0].NetElementRef] = {"Id":i.Id,"Type":i.Type}
    
    return bufferStops

def detect_derailersIS(infrastructure):
    derailersIS = {} 

    if infrastructure.DerailersIS != None:
        for i in infrastructure.DerailersIS[0].DerailerIS:
            if i.Id not in derailersIS.keys():
                derailersIS[i.SpotLocation[0].NetElementRef] = {"Id":i.Id,"Side":i.DerailSide}

    return derailersIS

def detect_levelCrossingsIS(infrastructure):
    levelCrossingsIS = {}

    if infrastructure.LevelCrossingsIS != None:
        for i in infrastructure.LevelCrossingsIS[0].LevelCrossingIS:
            if i.Id not in levelCrossingsIS.keys():
                levelCrossingsIS[i.SpotLocation[0].NetElementRef] = {"Id":i.Id,"Lights":i.Protection[0].Lights,"Acoustic":i.Protection[0].Acoustic,"Protection":i.Protection[0].HasActiveProtection,"Barriers":i.Protection[0].Barriers}
    
    return levelCrossingsIS

def detect_lines(infrastructure):
    lines = {}

    if infrastructure.Lines != None:
        for i in infrastructure.Lines[0].Line:
            if i.Id not in lines.keys():
                lines[i.SpotLocation[0].NetElementRef] = {"Id":i.Id,"Type":i.LineType}
    
    return lines

def detect_operationalPoints(infrastructure):
    operationalPoints = {}
    
    return operationalPoints    #IGNORE! IT IS FOR MACRO LEVEL!

    if infrastructure.BufferStops != None:
        for i in [infrastructure.BufferStops[0].BufferStop]:
            if i.Id not in operationalPoints.keys():
                operationalPoints[i.SpotLocation[0].NetElementRef] = {"Id":i.Id,"Type":i.Type}
    
    return operationalPoints

def detect_platforms(infrastructure):
    platforms = {}

    if infrastructure.Platforms != None:
        for i in infrastructure.Platforms[0].Platform:
            if i.Id not in platforms.keys():
                platforms[i.LinearLocation[0].AssociatedNetElement[0].NetElementRef] = {"Id":i.Id,"Side":i.LinearLocation[0].AssociatedNetElement[0].LinearCoordinateBegin.LateralSide}
    
    return platforms

def detect_signalsIS(infrastructure):
    signalsIS = {}

    if infrastructure.SignalsIS != None:
        for i in infrastructure.SignalsIS[0].SignalIS:
            if i.Id not in signalsIS.keys():
                signalsIS[i.Name[0].Name] = {"Node":i.SpotLocation[0].NetElementRef,
                                            "Direction":i.SpotLocation[0].ApplicationDirection,
                                            "Position":i.SignalConstruction[0].PositionAtTrack}
    
    return signalsIS

def detect_switchesIS(infrastructure):
    switchesIS = {}

    if infrastructure.SwitchesIS != None:
        for i in infrastructure.SwitchesIS[0].SwitchIS:
            if i.Id not in switchesIS.keys():
                switchesIS[i.Name[0].Name] = {"Node":i.SpotLocation[0].NetElementRef,"ContinueCourse":i.ContinueCourse,
                                            "BranchCourse":i.BranchCourse,"Direction":i.SpotLocation[0].ApplicationDirection,
                                            "LeftBranch":i.LeftBranch[0].NetRelationRef,"RightBranch":i.RightBranch[0].NetRelationRef}
    
    return switchesIS

def detect_tracks(infrastructure):
    tracks = {}

    if infrastructure.Tracks != None:
        for i in infrastructure.Tracks[0].Track:
            if i.Id not in tracks.keys():
                tracks[i.Name[0].Name] = {"Node":i.LinearLocation[0].AssociatedNetElement[0].NetElementRef}
    
    return tracks

def detect_trainDetectionElements(infrastructure):
    trainDetectionElements = {}
    
    if infrastructure.TrainDetectionElements != None:
        for i in infrastructure.TrainDetectionElements[0].TrainDetectionElement:
            if i.Id not in trainDetectionElements.keys():
                if i.SpotLocation[0].LinearCoordinate != None:
                    trainDetectionElements[i.Id] = {"Node":i.SpotLocation[0].NetElementRef,"Type":i.Type,"Side":i.SpotLocation[0].LinearCoordinate[0].LateralSide}
                else:
                    trainDetectionElements[i.Id] = {"Node":i.SpotLocation[0].NetElementRef,"Type":i.Type}
    
    return trainDetectionElements

def analyzing_infrastructure(infrastructure):
    
    # borders
    try:
        borders = detect_borders(infrastructure)
    except:
        print("Error with borders")
        borders = {}
        
    # bufferStops
    try:
        bufferStops = detect_bufferStops(infrastructure)
    except:
        print("Error with bufferStops")
        bufferStops = {}
        
    # derailersIS
    derailersIS = detect_derailersIS(infrastructure)
    
    # levelCrossingsIS
    levelCrossingsIS = detect_levelCrossingsIS(infrastructure)
    
    # lines
    lines = detect_lines(infrastructure)
    
    # operationalPoints
    operationalPoints = detect_operationalPoints(infrastructure)    # TODO FOR MESO
    
    # platforms
    platforms = detect_platforms(infrastructure)
    
    # signalsIS
    signalsIS = detect_signalsIS(infrastructure)

    # switchesIS
    switchesIS = detect_switchesIS(infrastructure)

    # tracks
    tracks = detect_tracks(infrastructure)
    
    # trainDetectionElements
    trainDetectionElements = detect_trainDetectionElements(infrastructure)

    return borders,bufferStops,derailersIS,levelCrossingsIS,lines,operationalPoints,platforms,signalsIS,switchesIS,tracks,trainDetectionElements
#%%%
def export_analysis(file,netElementsId,neighbours,borders,bufferStops,derailersIS,levelCrossingsIS,lines,operationalPoints,platforms,signalsIS,switchesIS,tracks,trainDetectionElements):
    
    #print(trainDetectionElements)
    with open(file, "w") as f:        
        f.write(f'Nodes: {len(netElementsId)} | Switches: {len(switchesIS)} | Signals: {len(signalsIS)} | Detectors: {len(trainDetectionElements)} | Ends: {len(borders)+len(bufferStops)}\n')
        
        for i in netElementsId:
            f.write(f'Node {i}:\n')
            for j in lines:
                f.write(f'\tLines -> {lines[j]["Id"]}\n')
            for j in tracks:
                if i == tracks[j]["Node"]:
                    f.write(f'\tTrack = {j}\n')
            
            for j in trainDetectionElements:
                if i == trainDetectionElements[j]["Node"]:
                    f.write(f'\tTrainDetectionElements -> {j}\n')        
                    f.write(f'\t\tType -> {trainDetectionElements[j]["Type"]}\n')
                    if "Side" in trainDetectionElements[j]:
                        f.write(f'\t\tSide -> {trainDetectionElements[j]["Side"]}\n')
                    
            for j in derailersIS:
                if i == j:
                    f.write(f'\tDerailer -> {derailersIS[i]["Id"]}\n')
                    f.write(f'\t\t Side -> {derailersIS[i]["Side"]}\n')
                    
            for j in borders:
                if i == borders[j]["Node"]:
                    f.write(f'\tType = Border -> {j}\n')
                    f.write(f'\t\tType -> {borders[j]["Type"]}\n')
                    f.write(f'\t\tIsOpenEnd -> {borders[j]["IsOpenEnd"]}\n')
            
                
            if i in bufferStops:
                f.write(f'\tType = BufferStop -> {bufferStops[i]["Id"]}\n')
                
            f.write(f'\tNeighbours = {len(neighbours[i])} -> {neighbours[i]}\n')
            
            for j in platforms:
                if i == j:
                    f.write(f'\tPlatform  -> {platforms[j]["Id"]}\n')
                    f.write(f'\t\tSide -> {platforms[j]["Side"]}\n')
            
            for j in levelCrossingsIS:
                if i == j:
                    f.write(f'\tLevel crossing -> {levelCrossingsIS[j]["Id"]}\n')
                    f.write(f'\t\tProtection -> {levelCrossingsIS[j]["Protection"]}\n')
                    f.write(f'\t\tBarriers -> {levelCrossingsIS[j]["Barriers"]}\n')
                    f.write(f'\t\tLights -> {levelCrossingsIS[j]["Lights"]}\n')
                    f.write(f'\t\tAcoustic -> {levelCrossingsIS[j]["Acoustic"]}\n')
                    
            for j in signalsIS:
                if i == signalsIS[j]["Node"]:
                    f.write(f'\tSignals -> {j}\n')
                    f.write(f'\t\tDirection -> {signalsIS[j]["Direction"]}\n')
                    f.write(f'\t\tPosition -> {signalsIS[j]["Position"]}\n')
            
            for j in switchesIS:
                if i == switchesIS[j]["Node"]:
                    f.write(f'\tSwitches -> {j}\n')
                    
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
    netRelations = topology.NetRelations.NetRelation if topology.NetRelations != None else []  
    infrastructure = object.Infrastructure.FunctionalInfrastructure

    print(" Analyzing graph --> Graph.RNA")
    netElementsId,neighbours,switches,limits = analyzing_graph(netElements,netRelations)
        
    print(" Analyzing infrastructure --> Infrastructure.RNA")
    borders,bufferStops,derailersIS,levelCrossingsIS,lines,operationalPoints,platforms,signalsIS,switchesIS,tracks,trainDetectionElements = analyzing_infrastructure(infrastructure)

    #export_analysis("F:\PhD\RailML\\Graph.RNA",netElementsId,neighbours,borders,bufferStops,derailersIS,levelCrossingsIS,lines,operationalPoints,platforms,signalsIS,switchesIS,tracks,trainDetectionElements)