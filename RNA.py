
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
    
    # Create new signalling
    
    
    if test:
        print("Exporting .railML file")
    with open(OUTPUT_FILE, "w" , encoding="utf-8") as f:        
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
    netPaths = get_relations(netRelations)
    neighbours,switches = get_neighbours_and_switches(netElements) 
    limits = get_limits(switches)
    
    x = '' if (analyze_connectedness(neighbours)) else ('not ')
    print(f' The network is {x}connected')

    return netElementsId,neighbours,switches,limits,netPaths

#%%%   
def get_nodes(netElements):
    netElementsId = []
    
    for netElement in netElements:
        if (netElement.Id[2].isdigit()):        # Only MICRO
            netElementsId.append(netElement.Id)
        
    return netElementsId  

def get_relations(netRelations):
    netPaths = {}
    
    for netRelation in netRelations:
        [begin_net, end_net, name] = identify_relations(netRelation.Id)
        
        #print(begin_net,end_net, netRelation.Navigability)
        if netRelation.Navigability == "Both":
            if begin_net not in netPaths:
                netPaths[begin_net] = {"Next":[]}
            elif "Prev" in netPaths[begin_net] and "Next" not in netPaths[begin_net]:
                netPaths[begin_net] |= {"Next":[]}
            
            if end_net not in netPaths:
                netPaths[end_net] = {"Prev":[]}
            elif "Next" in netPaths[end_net]  and "Prev" not in netPaths[end_net]:
                netPaths[end_net] |= {"Prev":[]}
        
        #print(netPaths)
        
            if end_net not in netPaths[begin_net]["Next"]:
                netPaths[begin_net]["Next"].append(end_net)
            if begin_net not in netPaths[end_net]["Prev"]:
                netPaths[end_net]["Prev"].append(begin_net)
        #print(netPaths)   
    
    #print("Paths: ",netPaths)
    return netPaths  

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

def detect_nodes(topology):
    nodes = {}
    
    #return nodes 
    
    if topology.NetElements != None:
    
        for i in topology.NetElements.NetElement:
            if i.Id not in nodes.keys():
                nodes[i.Id] = {"Begin":[int(i.AssociatedPositioningSystem[0].IntrinsicCoordinate[0].GeometricCoordinate[0].X[:-4]),-int(i.AssociatedPositioningSystem[0].IntrinsicCoordinate[0].GeometricCoordinate[0].Y[:-4])],
                            "End":[int(i.AssociatedPositioningSystem[0].IntrinsicCoordinate[-1].GeometricCoordinate[0].X[:-4]),-int(i.AssociatedPositioningSystem[0].IntrinsicCoordinate[-1].GeometricCoordinate[0].Y[:-4])],
                            "Lines":len(i.AssociatedPositioningSystem[0].IntrinsicCoordinate)-1}
    
    return nodes 
    
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
        for i in infrastructure.BufferStops[0].BufferStop:
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

def detect_switchesIS(infrastructure,visualization):
    switchesIS = {}

    if infrastructure.SwitchesIS != None:
        for i in infrastructure.SwitchesIS[0].SwitchIS:
            if i.Id not in switchesIS.keys():
                switchesIS[i.Name[0].Name] = {"Node":i.SpotLocation[0].NetElementRef,"ContinueCourse":i.ContinueCourse,
                                            "BranchCourse":i.BranchCourse,"Direction":i.SpotLocation[0].ApplicationDirection,
                                            "LeftBranch":i.LeftBranch[0].NetRelationRef,"RightBranch":i.RightBranch[0].NetRelationRef
                                            }
    
    if visualization.Visualization != None:
        for i in  visualization.Visualization[0].SpotElementProjection:
            if "Sw" in i.Name[0].Name:
                switchesIS[i.Name[0].Name] |= {"Position":[int(i.Coordinate[0].X[:-4]),-int(i.Coordinate[0].Y[:-4])]}

    return switchesIS

def detect_tracks(infrastructure):
    tracks = {}

    if infrastructure.Tracks != None:
        for i in infrastructure.Tracks[0].Track:
            if i.Id not in tracks.keys():
                tracks[i.Name[0].Name] = {"Node":i.LinearLocation[0].AssociatedNetElement[0].NetElementRef}
    
    return tracks

def detect_trainDetectionElements(infrastructure,visualization):
    trainDetectionElements = {}
    
    if infrastructure.TrainDetectionElements != None:
        for i in infrastructure.TrainDetectionElements[0].TrainDetectionElement:
            if i.Id not in trainDetectionElements.keys():
                if i.SpotLocation[0].LinearCoordinate != None:
                    trainDetectionElements[i.Id] = {"Node":i.SpotLocation[0].NetElementRef,"Name":i.Name[0].Name,"Coordinate":i.SpotLocation[0].IntrinsicCoord,"Type":i.Type,"Side":i.SpotLocation[0].LinearCoordinate[0].LateralSide}
                else:
                    trainDetectionElements[i.Id] = {"Node":i.SpotLocation[0].NetElementRef,"Name":i.Name[0].Name,"Coordinate":i.SpotLocation[0].IntrinsicCoord,"Type":i.Type}
    
    if visualization.Visualization != None:
        for i in visualization.Visualization[0].SpotElementProjection:
            if "tde" in i.RefersToElement: 
                if "J" == i.Name[0].Name[0]:
                    trainDetectionElements[i.RefersToElement] |= {"Position":[int(i.Coordinate[0].X[:-4]),-int(i.Coordinate[0].Y[:-4])]}

    #print(trainDetectionElements)
    return trainDetectionElements

def analyzing_infrastructure(topology,infrastructure,visualization):
    
    # nodes
    try:
        nodes = detect_nodes(topology)
    except:
        print("Error with nodes")
        nodes = {}
        
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
    switchesIS = detect_switchesIS(infrastructure,visualization)

    # tracks
    tracks = detect_tracks(infrastructure)
    
    # trainDetectionElements
    trainDetectionElements = detect_trainDetectionElements(infrastructure,visualization)

    return nodes,borders,bufferStops,derailersIS,levelCrossingsIS,lines,operationalPoints,platforms,signalsIS,switchesIS,tracks,trainDetectionElements
#%%%
def export_analysis(file,netElementsId,neighbours,borders,bufferStops,derailersIS,levelCrossingsIS,lines,operationalPoints,platforms,signalsIS,switchesIS,tracks,trainDetectionElements):
    
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

def detect_danger(file,nodes,netPaths,switchesIS,trainDetectionElements):
    
    with open(file, "w") as f: 
        #f.write(f'Dangers> Switches:{len(switchesIS)}+Level crossings:NaN+Borders:NaN\n\n')
        
        semaphores = {}
        
        railJoint = create_railJoint(trainDetectionElements)
        #print(railJoint)
        
        source = analyze_switches(nodes,netPaths,switchesIS,railJoint)
        
        print(source)
        
        
        for i in switchesIS:
            
            danger_spot = switchesIS[i]
            start_node = danger_spot["Node"]
            
            continue_course = danger_spot["ContinueCourse"][0].upper() + danger_spot["ContinueCourse"][1:]
            branch_course = danger_spot["BranchCourse"][0].upper() + danger_spot["BranchCourse"][1:]
            
            continue_nodes = danger_spot[continue_course+"Branch"]
            continue_node = identify_relations(continue_nodes)[:-1]
            continue_node.remove(start_node)
            continue_node = continue_node[0]
            
            branch_nodes = danger_spot[branch_course+"Branch"]
            branch_node = identify_relations(branch_nodes)[:-1]
            branch_node.remove(start_node)
            branch_node = branch_node[0]
            
            #print(start_node,continue_node,branch_node)
            
            pos_sw          = switchesIS[i]["Position"]
            pos_start       = nodes[start_node]["Begin"] if switchesIS[i]["Position"] == nodes[start_node]["End"] else nodes[start_node]["End"]
            pos_continue    = nodes[continue_node]["Begin"] if switchesIS[i]["Position"] == nodes[continue_node]["End"] else nodes[continue_node]["End"]
            pos_branch      = nodes[branch_node]["Begin"] if switchesIS[i]["Position"] == nodes[branch_node]["End"] else nodes[branch_node]["End"]
            
            n_start = nodes[start_node]["Lines"]
            n_continue = nodes[continue_node]["Lines"]
            n_branch = nodes[branch_node]["Lines"] 
            
            #print(pos_start,pos_continue,pos_branch)
            
            continue_straight, branch_straight = calculate_angle(pos_sw,pos_start,pos_continue,pos_branch,n_continue,n_branch)
            
            semaphore_source = {'Node':i,"Switch":pos_sw,'Start':[start_node,pos_start,n_start],'Continue':[continue_node,pos_continue,n_continue,continue_straight],'Branch':[branch_node,pos_branch,n_branch,branch_straight]}
            
            #print(semaphore_source)
            create_semaphore(semaphores,semaphore_source,railJoint) 
            
            f.write(f'{i} @ ({pos_sw[0]},{pos_sw[1]})\n')
            f.write(f'\tStart: {start_node} @ ({pos_start[0]},{pos_start[1]}) > ({pos_sw[0]},{pos_sw[1]})\n')
            f.write(f'\tContinue > {continue_course} [{n_continue} {"--" if continue_straight else "/"} ] : {continue_node} @ ({pos_sw[0]},{pos_sw[1]}) > ({pos_continue[0]},{pos_continue[1]})\n')
            f.write(f'\tBranch > {branch_course} [{n_branch} {"--" if branch_straight else "/"} ] : {branch_node} @ ({pos_sw[0]},{pos_sw[1]}) > ({pos_branch[0]},{pos_branch[1]})\n')
        
        f.close()

    #print(semaphores)
    return semaphores

def analyze_switches(nodes,netPaths,switchesIS,railJoint):
    switches_data = {}
    node_sw = {}
    
    print(netPaths)
    
    for switch in switchesIS:
        # Find the switch info
        sw_info = switchesIS[switch]
        # Find the swithc position
        sw_position = sw_info["Position"]
        # Find the start node
        start_node = sw_info["Node"]
        start_position = nodes[start_node]["Begin"] if sw_position == nodes[start_node]["End"] else nodes[start_node]["End"]
        # Attach switch to node
        node_sw[sw_info["Node"]] = switch
        # Find the continue course
        continue_course = sw_info["ContinueCourse"].capitalize()
        # Find the branch course
        branch_course = sw_info["BranchCourse"].capitalize()
        
        # Find the continue node
        continue_relation = sw_info[continue_course+"Branch"]
        continue_node = identify_relations(continue_relation)[:-1]
        continue_node.remove(start_node)
        continue_node = continue_node[0]
        continue_position = nodes[continue_node]["Begin"] if sw_position == nodes[continue_node]["End"] else nodes[continue_node]["End"]
        
        # Find the branch node
        branch_relation = sw_info[branch_course+"Branch"]
        branch_node = identify_relations(branch_relation)[:-1]
        branch_node.remove(start_node)
        branch_node = branch_node[0]
        branch_position = nodes[branch_node]["Begin"] if sw_position == nodes[branch_node]["End"] else nodes[branch_node]["End"]
        
        # Find the start rail joint
        rail_joint_found = False
        start_candidate_node = start_node
        
        while (rail_joint_found == False):  
            if start_candidate_node in railJoint:
                start_rail_joint_data = railJoint[start_candidate_node]
                rail_joint_found = True
            else:
                # If start position before switch
                if start_position[0] < sw_position[0]:
                    if ("Prev" in netPaths[start_candidate_node] and len(netPaths[start_candidate_node]["Prev"]) == 1):
                        start_candidate_node = netPaths[start_candidate_node]["Prev"][0]
                    else:
                        break
                else: # If start position after switch
                    if ("Next" in netPaths[start_candidate_node] and len(netPaths[start_candidate_node]["Next"]) == 1):
                        start_candidate_node = netPaths[start_candidate_node]["Next"][0]
                    else:
                        break
        
        if rail_joint_found == True:
            start_rail_joint_data = railJoint[start_candidate_node]
            rail_joint_index = find_closest_coordinate(start_rail_joint_data["Position"],sw_position)
            start_rail_joint_position = start_rail_joint_data["Position"][rail_joint_index]
            start_rail_joint = start_rail_joint_data["Joint"][rail_joint_index]
            
            sw_candidate_position = switchesIS[node_sw[start_candidate_node]]["Position"]
            start_candidate_position = nodes[start_candidate_node]["Begin"] if  sw_candidate_position == nodes[start_candidate_node]["End"] else nodes[start_candidate_node]["End"]
            # Calculate the signal position in the same line as the switch and node, before the joint
            start_signal_position = calculate_position(start_candidate_position,sw_candidate_position,start_rail_joint_position)    # TODO LIMIT THE POSITION IF THE LINE ENDS IN A BUFFER
        else:
            if nodes[start_candidate_node]["Lines"] > 1:
                # Calculate the signal position before the curve before the switch node
                start_candidate_position = start_position
                sw_candidate_position = sw_position
                start_rail_joint_position = None
                start_signal_position = [0,0]
            else:
                # Calculate the signal position in the same line as the switch and node, at 30% of the switch position
                start_candidate_position = start_position
                sw_candidate_position = sw_position
                start_rail_joint_position = None
                start_signal_position = [1,1] # TODO FIND A POINT IN THE NETPATH
        
        print(switch,start_node,start_candidate_position,sw_candidate_position,start_rail_joint_position,start_signal_position)
        
        
    #print(nodes)
    
    return switches_data

# Calculate the signal position in the same line as the switch and node, before the joint
def calculate_position(start_candidate_position,sw_candidate_position,start_rail_joint_position):
    signal_position = [None,None]
    
    # calculate coordinate between two points
    m = (sw_candidate_position[1] - start_candidate_position[1]) / (sw_candidate_position[0] - start_candidate_position[0])
    c = start_candidate_position[1] - m * start_candidate_position[0]
    
    d = 0.075
    
    signal_position_a = [start_rail_joint_position[0]*(1+d),start_rail_joint_position[1]*(1+d)*m+c]
    signal_position_b = [start_rail_joint_position[0]*(1-d),start_rail_joint_position[1]*(1-d)*m+c]
    
    distance_a = (signal_position_a[0]-sw_candidate_position[0])**2 + (signal_position_a[1]-sw_candidate_position[1])**2
    distance_b = (signal_position_b[0]-sw_candidate_position[0])**2 + (signal_position_b[1]-sw_candidate_position[1])**2
    
    if distance_a > distance_b:
        signal_position = signal_position_a
    else:
        signal_position = signal_position_b
    
    return signal_position

# Find the closest joint to the switch position
def find_closest_coordinate(joint_positions,sw_position):
    index = -1
    distance = -1
    
    for joint in joint_positions:
        new_distance_sq = (joint[0]-sw_position[0])**2 + (joint[1]-sw_position[1])**2
        if distance == -1:
            distance = new_distance_sq
            index = joint_positions.index(joint)
        if new_distance_sq < distance:
            distance = new_distance_sq
            index = joint_positions.index(joint)
    
    #print(index)
    return index

def create_railJoint(trainDetectionElements):
    railJoint = {}
    for joint in trainDetectionElements:
            
            if trainDetectionElements[joint]["Node"] not in railJoint.keys():
                railJoint[trainDetectionElements[joint]["Node"]] = {}
            
            if "Position" not in railJoint[trainDetectionElements[joint]["Node"]]:
                railJoint[trainDetectionElements[joint]["Node"]]["Position"] = []
                
            if "Joint" not in railJoint[trainDetectionElements[joint]["Node"]]:
                railJoint[trainDetectionElements[joint]["Node"]]["Joint"] = []
            
            if trainDetectionElements[joint]["Type"] == "insulatedRailJoint":    
                railJoint[trainDetectionElements[joint]["Node"]]["Position"].append(trainDetectionElements[joint]["Position"])
                railJoint[trainDetectionElements[joint]["Node"]]["Joint"].append(trainDetectionElements[joint]["Name"])
    return railJoint

def export_semaphores(file,semaphores):

    with open(file, "w") as f: 
        #print(semaphores)
        for sig in semaphores:
            f.write(f'Sig{str(sig).zfill(2)}:\n')
            f.write(f'\tNet: {semaphores[sig]["Net"]}\n')
            f.write(f'\tType: {semaphores[sig]["Type"]}\n')
            f.write(f'\tDirection: {semaphores[sig]["Direction"]} \n')
            f.write(f'\tPosition: {semaphores[sig]["Position"]}\n')
            f.write(f'\tCoordinate: {semaphores[sig]["Coordinate"]}\n')
        f.close()
        
def create_semaphore(semaphores,semaphore_source,railJoint):

    n = len(semaphores)+1
    
    #print(railJoint)
    
    continue_straight = semaphore_source["Continue"][3]
    branch_straight = semaphore_source["Branch"][3]
    start_x = semaphore_source["Start"][1][0]
    continue_x = semaphore_source["Continue"][1][0]
    branch_x = semaphore_source["Branch"][1][0]
    sw_x = semaphore_source["Switch"][0]
    
    #Start to Continue
    type = "Straight" if continue_straight else "Maneuver"
    net = semaphore_source["Start"][0]
    direction, position = ("Normal","Left") if start_x < continue_x else ("Reverse","Right")
    coordinate = 0.33 if start_x < sw_x else 0.66
    
    semaphores[n] = {'Id':'sig'+str(n),'Net':net,'Type':type,'Direction':direction,'Position':position,'Coordinate':coordinate}
    #print(f'  Creating a {type} semaphore[{n}] @{net} in {coordinate}|{semaphore_source}')
    
    #Start to Branch
    type = "Straight" if branch_straight else "Maneuver"
    net = semaphore_source["Start"][0]
    direction, position = ("Normal","Left") if start_x < branch_x else ("Reverse","Right")
    coordinate = 0.33 if start_x < sw_x else 0.66
    
    semaphores[n+1] = {'Id':'sig'+str(n+1),'Net':net,'Type':type,'Direction':direction,'Position':position,'Coordinate':coordinate}
    #print(f'  Creating a {type} semaphore[{n+1}] @{net} in {coordinate}|{semaphore_source}')
    
    # Continue To Start
    type = "Straight" if continue_straight else "Maneuver"
    net = semaphore_source["Continue"][0]
    direction, position = ("Normal","Left") if start_x > continue_x else ("Reverse","Right")
    coordinate = 0.33 if continue_x > sw_x else 0.66
    
    semaphores[n+2] = {'Id':'sig'+str(n+2),'Net':net,'Type':type,'Direction':direction,'Position':position,'Coordinate':coordinate}
    #print(f'  Creating a {type} semaphore[{n+2}] @{net} in {coordinate}|{semaphore_source}')
    
    #Branch To Start
    type = "Straight" if branch_straight else "Maneuver"
    net = semaphore_source["Branch"][0]
    direction, position = ("Normal","Left") if start_x > branch_x else ("Reverse","Right")
    coordinate = 0.33 if branch_x > sw_x else 0.66
    
    semaphores[n+3] = {'Id':'sig'+str(n+3),'Net':net,'Type':type,'Direction':direction,'Position':position,'Coordinate':coordinate}
    #print(f'  Creating a {type} semaphore[{n+3}] @{net} in {coordinate}|{semaphore_source}')
    
def calculate_angle(pos_sw,pos_start,pos_continue,pos_branch,n_continue,n_branch):        
    
    continue_straight = False
    branch_straight = False
    
    #print(pos_sw,pos_start,pos_continue,pos_branch)

    x1 = pos_start[0]
    y1 = pos_start[1]
    x2 = pos_sw[0]
    y2 = pos_sw[1]
    x3 = pos_continue[0]
    y3 = pos_continue[1]
    
    #print(f'[{x1},{y1}] > [{x2},{y2}] > [{x3},{y3}]')
    
    continue_straight = ((y1 - y2) * (x1 - x3) == (y1 - y3) * (x1 - x2)) & (n_continue == 1)
    
    x3 = pos_branch[0]
    y3 = pos_branch[1]
    
    #print(x1,y1,x2,y2,x3,y3)
    # TODO ADD ALL THE POINTS, NOT ONLY BEGIN-END 
    
    # Because it is a branch!
    branch_straight = False #((y1 - y2) * (x1 - x3) == (y1 - y3) * (x1 - x2)) & (n_branch == 1)
    
    #print(pos_continue["Lines"],((y1 - y2) * (x1 - x3) == (y1 - y3) * (x1 - x2)),pos_branch["Lines"],((y1 - y2) * (x1 - x3) == (y1 - y3) * (x1 - x2)))
    
    return continue_straight, branch_straight
#%%%
def analyzing_object(object):
    topology = object.Infrastructure.Topology
    netElements = topology.NetElements.NetElement
    netRelations = topology.NetRelations.NetRelation if topology.NetRelations != None else []  
    infrastructure = object.Infrastructure.FunctionalInfrastructure
    visualization = object.Infrastructure.InfrastructureVisualizations
    
    
    print(" Analyzing graph")
    netElementsId,neighbours,switches,limits,netPaths = analyzing_graph(netElements,netRelations)   # TODO IF THE NET WAS NOT CREATING IN ORDER THERE IS A FAIL
        
    print(" Analyzing infrastructure --> Infrastructure.RNA")
    nodes,borders,bufferStops,derailersIS,levelCrossingsIS,lines,operationalPoints,platforms,signalsIS,switchesIS,tracks,trainDetectionElements = analyzing_infrastructure(topology,infrastructure,visualization)
    
    export_analysis("F:\PhD\RailML\\Infrastructure.RNA",netElementsId,neighbours,borders,bufferStops,derailersIS,levelCrossingsIS,lines,operationalPoints,platforms,signalsIS,switchesIS,tracks,trainDetectionElements)
    
    print(" Detecting Danger --> Signalling.RNA")
    
    semaphores = detect_danger("F:\PhD\RailML\\Dangers.RNA",nodes,netPaths,switchesIS,trainDetectionElements)
    
    export_semaphores("F:\PhD\RailML\\Signalling.RNA",semaphores)
    
    print(" Analyzing danger zones --> Danger.RNA")
# %%
