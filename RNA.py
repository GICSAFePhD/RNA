import re
import xml.etree.cElementTree as ET

from RailML import railML
from RailML.Common import Metadata
from RailML.Common import Common
from RailML.Infrastructure import Infrastructure
from RailML.Interlocking import Interlocking
from RailML import aRailML

IGNORE = {None}

#%%%
def RNA(RML,INPUT_FILE,OUTPUT_FILE):
    print("#"*20+" Starting Railway Network Analyzer "+"#"*20)
    
    print("Reading .railML file")
    root = load_xml(INPUT_FILE)   #A RELATIVE PATH DOESN'T WORK FOR PREVIEW!
    print("Creating railML object")
    get_branches(RML,root,test = False)
    
    #print(dir(RML.Common.Positioning.GeometricPositioningSystems.GeometricPositioningSystem))
    
    
        
    #x = RML.Infrastructure.Topology.Networks.Network[0]
    #y = get_attributes(x)
    #print(x,y)
    #for i in y:
    #    z = getattr(x,i)
    #    if z != None:
    #        print(i,z)   


    
    print("Exporting .railML file")
    with open(OUTPUT_FILE, "w") as f:        
        f.write('<?xml version="1.0" encoding="UTF-8"?>\n')
        f.write('<railML xmlns="https://www.railml.org/schemas/3.1" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:gml="http://www.opengis.net/gml/3.2/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="https://www.railml.org/schemas/3.1 https://www.railml.org/schemas/3.1/railml3.xsd" version="3.1">\n')

        save_xml(RML,f)
        
        f.close()
#%%%        
def load_xml(file):
    tree = ET.parse(file)
    root = tree.getroot()
    return root
#%%%
def save_xml(object,f,name = "",level = 0, test = False):
    
    all_attributes = get_attributes(object)
    
    if name == "":
        tag = get_name(object)[0].lower()+get_name(object)[1:]
    else:
        tag = name[0].lower()+name[1:]
        
    attributes = []
    nodes = []
    
    for i in all_attributes:
        next_object = getattr(object, i)
        if next_object != None:
            (nodes, attributes)[ type(next_object) == str ].append(i)    
    
    if test:
        print(' '*(level)+f'<{tag}> | {attributes} & {nodes}')
    
    if attributes == []:
        if tag != "railML":
            f.write('\t'*(level)+f'<{tag}>\n')
    else:
        attr = ""
        for i in attributes:
            
            attr += i[0].lower()+i[1:]+"=\""+getattr(object,i)+"\""
            if i != attributes[-1]:
                attr += " "
        
        if name == "Metadata":
            f.write('\t'*(level)+f'<{tag}>\n')
            for i in attributes:
                next_object = getattr(object,  i) 
                f.write('\t'*(level+1)+f'<dc:{i.lower()}>{next_object}</dc:{i.lower()}>\n')
            f.write('\t'*(level)+f'</{tag}>\n') 
        else:
            if nodes == []:
                f.write('\t'*(level)+f'<{tag} {attr}/>\n') 
            else:
                f.write('\t'*(level)+f'<{tag} {attr}>\n')        
        #print(attr)
    
    for i in nodes:
        next_object = getattr(object,  i)  
        if next_object != None:
            #print(' '*(level)+f'--{i} -> {next_object}')
            
            if (type(next_object) == list):
                #if len(next_object) > 1:
                #    print(len(next_object))
                for j in next_object:
                    save_xml(j,f,i,level+1)         
            else:
                save_xml(next_object,f,i,level+1)
                
    if nodes != []:    
        if test:    
            print(' '*(level)+f'<\{tag}>')
        f.write('\t'*(level)+f'</{tag}>\n')
#%%%
def get_leaves(root):
    leaves = []
    leaf = []
    text = []
    #ns_leaf = '{'+tag+'}'
    
    for i in root:  # HERE I CAN DO IT GENERIC
        ns = re.match(r'{.*}', i.tag).group(0)
        leaves.append(i.tag[len(ns):])
        leaf.append(i)
        
        if i.text and i.text[0] != '\n':
            text.append(i.text)
    
    return [leaf,leaves,text]   
#%%%
def get_attributes(object):
    try:
        attribute_inherated = []
        for i in type(object).mro()[:-1]:
            attribute_inherated += [j for j in i.__dict__ if not j.startswith('__') and not j.startswith('create') and j[0].isupper()]
        #print(attribute_inherated) 
        return attribute_inherated
    except:
        pass
    return [i for i in type(object).__dict__.keys() if not i.startswith('__') and not i.startswith('create')]
#%%%
def set_text(object,tag,text):
    setattr(object,tag,text)
#%%%
def get_name(object):
    return object.__class__.__name__
#%%%
def get_branches(current_object, xml_node, level = 0, idx = "", idx_txt = 0, test = False):
    a = 0
    # xml_node: the old-tree
    # child[i]: the new-tree

    if (type(current_object) != list and current_object != None):    
        if (xml_node.attrib):    
            #print(xml_node.attrib)         
            for tag_i in [*xml_node.attrib]:
                attribute_tag = tag_i[0].upper()+tag_i[1:]
                #print(f'{current_object}|{attribute_tag} : {xml_node.attrib[tag_i]}')
                setattr(current_object,attribute_tag,xml_node.attrib[tag_i]) 
                
    [xml_child,xml_tag,xml_text] = get_leaves(xml_node)
    #print(xml_child,xml_tag,xml_text)
    object_attributes = get_attributes(current_object)
    #print(f'Attributes:{object_attributes}')
    #if xml_tag:
    #    print(f'Tags:{xml_tag}')

    size_xml_tag = len(xml_tag)

    for xml_tag_i in range(size_xml_tag):
        capitalized_tag = xml_tag[xml_tag_i][0].upper() + xml_tag[xml_tag_i][1:]
        
        if capitalized_tag in IGNORE:
            continue
        
        #print(f'{capitalized_tag}|{capitalized_tag in object_attributes}')
        if (capitalized_tag in object_attributes):
            next_attribute_position = object_attributes.index(capitalized_tag)
            next_attribute = object_attributes[next_attribute_position]
            
            next_xml_child = xml_child[xml_tag_i] 
            #print(f'Next_child:{next_xml_child}')
            
            if test:          
                print('>'*(level+1)+f'{xml_tag[xml_tag_i]}[{xml_tag_i+1} de {size_xml_tag}]') 
            if xml_text:
                #print(f'{text}|{text[idx_txt]}')
                constructors[xml_tag[xml_tag_i]](current_object,capitalized_tag,xml_text[idx_txt])
                idx_txt = idx_txt + 1
            else:
                #print(f'TRYING:{xml_tag[xml_tag_i]}|{xml_tag[xml_tag_i] in constructors}')
                if xml_tag[xml_tag_i] in constructors:    
                    constructors[xml_tag[xml_tag_i]](current_object)
            #print(f'Constructor:{xml_tag_i}')
            #print(f'Next: {current_object.__class__.__name__}.{getattr(current_object, next_attribute)}')
            
            next_object = getattr(current_object,  next_attribute)
            #print(f'NEXT:{next_object}|||{xml_tag_i}')
            
            if(type(next_object) == list):
                if size_xml_tag == 1:
                    get_branches(next_object[0],next_xml_child,level+1, test = test)
                if xml_tag_i < size_xml_tag and 1 < size_xml_tag:
                    #print(f'----------------INCREMENTANDO:{xml_tag_i}[{idx}->{idx+1}]') 
                    #idx = idx + 1
                    get_branches(next_object[-1],next_xml_child,level+1, test = test)
            else:
                get_branches(next_object,next_xml_child,level+1,idx_txt=idx_txt, test = test)
        else:
            print(f'{capitalized_tag} doesn\'t exists! in {object_attributes}')
#%%%
def print_leaves(root,leaf,tag):
    print('-'*20+ leaf +'-'*20)
    ns = re.match(r'{.*}', root.tag).group(0)
    if leaf != '':
        leaves = root.find(f"{ns}"+leaf)
    else:
        leaves = root
        
    ns_leaf = '{'+tag+'}'
    for child in leaves:
        print(f'{child.tag[len(ns_leaf):]} | {child.attrib} | {child.text}')
#%%%
def get_leaves(root):
    leaves = []
    leaf = []
    text = []
    #ns_leaf = '{'+tag+'}'
    
    for i in root:  # HERE I CAN DO IT GENERIC
        ns = re.match(r'{.*}', i.tag).group(0)
        leaves.append(i.tag[len(ns):])
        leaf.append(i)
        
        if i.text and i.text[0] != '\n':
            text.append(i.text)
    
    return [leaf,leaves,text]
#%%%
def network_connection(object):
    
    topology = object.Infrastructure.Topology
    netElements = topology.NetElements.NetElement
    netRelations = topology.NetRelations.NetRelation

    netElementsId = []
    netRelationsId = []
    
    for netElement in netElements:
        netElementsId.append(netElement.Id)
    print(f'Nodes:{netElementsId}')
    
    for netRelation in netRelations:
        netRelationsId.append(netRelation.Id)
    print(f'Edges:{netRelationsId}')
    
    
    
constructors = {'metadata':railML.railML.create_metadata,'common':railML.railML.create_common,'infrastructure':railML.railML.create_infrastructure,'interlocking':railML.railML.create_interlocking, # RailML
                'title':set_text,'date':set_text,'creator':set_text,'source':set_text,'identifier':set_text,'subject':set_text,'format':set_text,'description':set_text,'publisher':set_text,   # Metadata
                
                'electrificationSystems':railML.Common.Common.create_ElectrificationSystems,'organizationalUnits':railML.Common.Common.create_OrganizationalUnits,'speedProfiles':railML.Common.Common.create_SpeedProfiles,'positioning':railML.Common.Common.create_PositioningSystems,  # Common
                'electrificationSystem':railML.Common.ElectrificationSystems.ElectrificationSystems.create_ElectrificationSystem, # ElectrificationSystems
                'tVoltageVolt':railML.Common.ElectrificationSystems.ElectrificationSystem.ElectrificationSystem.create_tVoltageVolt,'frequencyHertz':railML.Common.ElectrificationSystems.ElectrificationSystem.ElectrificationSystem.create_tFrequencyHertz, # ElectrificationSystem              
                'infrastructureManager':railML.Common.OrganizationalUnits.OrganizationalUnits.create_InfrastructureManager,'vehicleManufacturer':railML.Common.OrganizationalUnits.OrganizationalUnits.create_VehicleManufacturer,'vehicleOperator':railML.Common.OrganizationalUnits.OrganizationalUnits.create_VehicleOperator,'customer':railML.Common.OrganizationalUnits.OrganizationalUnits.create_Customer,'railwayUndertaking':railML.Common.OrganizationalUnits.OrganizationalUnits.create_RailwayUndertaking,'operationalUndertaking':railML.Common.OrganizationalUnits.OrganizationalUnits.create_OperationalUndertaking,'concessionaire':railML.Common.OrganizationalUnits.OrganizationalUnits.create_Concessionaire,'contractor':railML.Common.OrganizationalUnits.OrganizationalUnits.create_Contractor, # OrganizationalUnits  
                'speedfprofiles':railML.Common.SpeedProfiles.SpeedProfiles.create_SpeedProfile, # SpeedProfiles
                'speedProfileTilting':railML.Common.SpeedProfiles.SpeedProfile.SpeedProfile.create_SpeedProfileTilting,'speedProfileLoad':railML.Common.SpeedProfiles.SpeedProfile.SpeedProfile.create_SpeedProfileLoad,'speedProfileBraking':railML.Common.SpeedProfiles.SpeedProfile.SpeedProfile.create_SpeedProfileBraking,'speedProfileTrainType':railML.Common.SpeedProfiles.SpeedProfile.SpeedProfile.create_SpeedProfileTrainType, # SpeedProfile
                'geometricPositioningSystems':railML.Common.Positioning.Positioning.create_GeometricPositioningSystems,'linearPositioningSystems':railML.Common.Positioning.Positioning.create_LinearPositioningSystems,'screenPositioningSystems':railML.Common.Positioning.Positioning.create_ScreenPositioningSystems, # PositioningSystems
                'geometricPositioningSystem':railML.Common.Positioning.GeometricPositioningSystems.GeometricPositioningSystems.create_GeometricPositioningSystem, # GeometricPositioningSystems
                'linearPositioningSystem':railML.Common.Positioning.LinearPositioningSystems.LinearPositioningSystems.create_LinearPositioningSystem, # LinearPositioningSystem
                'screenPositioningSystem':railML.Common.Positioning.ScreenPositioningSystems.ScreenPositioningSystems.create_ScreenPositioningSystem, # ScreenPositioningSystems
                'name':railML.Common.Positioning.GeometricPositioningSystems.GeometricPositioningSystem.GeometricPositioningSystem.create_Name,'isValid':railML.Common.Positioning.GeometricPositioningSystems.GeometricPositioningSystem.GeometricPositioningSystem.create_IsValid, # GeometricPositioningSystem

                'topology':railML.Infrastructure.Infrastructure.create_Topology,'geometry':railML.Infrastructure.Infrastructure.create_Geometry,'functionalInfrastructure':railML.Infrastructure.Infrastructure.create_FunctionalInfrastructure,'physicalFacilities':railML.Infrastructure.Infrastructure.create_PhysicalFacilities,'infrastructureVisualizations':railML.Infrastructure.Infrastructure.create_InfrastructureVisualizations,'infrastructureStates':railML.Infrastructure.Infrastructure.create_InfrastructureStates, # Infrastructure
                'netElements':railML.Infrastructure.Topology.Topology.create_NetElements, 'netRelations':railML.Infrastructure.Topology.Topology.create_NetRelations,'networks':railML.Infrastructure.Topology.Topology.create_Networks, # Topology
                'netElement':railML.Infrastructure.Topology.NetElements.NetElements.create_NetElement, # NetElements
                'tLengthM':railML.Infrastructure.Topology.NetElements.NetElement.NetElement.create_tLengthM,'associatedPositioningSystem':railML.Infrastructure.Topology.NetElements.NetElement.NetElement.create_AssociatedPositioningSystem,'elementCollectionOrdered':railML.Infrastructure.Topology.NetElements.NetElement.NetElement.create_ElementCollectionOrdered,'elementCollectionUnordered':railML.Infrastructure.Topology.NetElements.NetElement.NetElement.create_ElementCollectionUnordered,'isValid':railML.Infrastructure.Topology.NetElements.NetElement.NetElement.create_IsValid,'name':railML.Infrastructure.Topology.NetElements.NetElement.NetElement.create_Name,'relation':railML.Infrastructure.Topology.NetElements.NetElement.NetElement.create_Relation, # NetElement
                'positioningSystemRef':railML.Infrastructure.Topology.NetElements.NetElement.AssociatedPositioningSystem.AssociatedPositioningSystem.create_PositioningSystemRef,'intrinsicCoordinate':railML.Infrastructure.Topology.NetElements.NetElement.AssociatedPositioningSystem.AssociatedPositioningSystem.create_IntrinsicCoordinate,'isValid':railML.Infrastructure.Topology.NetElements.NetElement.AssociatedPositioningSystem.AssociatedPositioningSystem.create_IsValid, # AssociatedPositionyngSystem
                
                'linearCoordinate':railML.Infrastructure.Topology.NetElements.NetElement.AssociatedPositioningSystem.IntrinsicCoordinate.IntrinsicCoordinate.create_LinearCoordinate,'geometricCoordinate':railML.Infrastructure.Topology.NetElements.NetElement.AssociatedPositioningSystem.IntrinsicCoordinate.IntrinsicCoordinate.create_GeometricCoordinate, # IntrinsicCoordinate
                'lateralSide':railML.Infrastructure.Topology.NetElements.NetElement.AssociatedPositioningSystem.IntrinsicCoordinate.RTM_LinearCoordinate.RTM_LinearCoordinate.create_LateralSide,'verticalSide':railML.Infrastructure.Topology.NetElements.NetElement.AssociatedPositioningSystem.IntrinsicCoordinate.RTM_LinearCoordinate.RTM_LinearCoordinate.create_VerticalSide, # LinearCoordinate
                'elementPart':railML.Infrastructure.Topology.NetElements.NetElement.RTM_OrderedCollection.RTM_OrderedCollection.create_ElementPart, # ElementPart
                'navigability':railML.Infrastructure.Topology.NetRelations.NetRelation.NetRelation.create_Navigability,'positionOnA':railML.Infrastructure.Topology.NetRelations.NetRelation.NetRelation.create_PositionOnA,'positionOnB':railML.Infrastructure.Topology.NetRelations.NetRelation.NetRelation.create_PositionOnB,'elementA':railML.Infrastructure.Topology.NetRelations.NetRelation.NetRelation.create_ElementA,'elementB':railML.Infrastructure.Topology.NetRelations.NetRelation.NetRelation.create_ElementB, # Relation
                'netRelation':railML.Infrastructure.Topology.NetRelations.NetRelations.create_Relation, # NetRelations
                'network':railML.Infrastructure.Topology.Networks.Networks.create_Network, # Networks
                'level':railML.Infrastructure.Topology.Networks.Network.RTM_Network.RTM_Network.create_Level,'networkResource':railML.Infrastructure.Topology.Networks.Network.RTM_Network.RTM_LevelNetwork.RTM_LevelNetwork.create_NetworkResource, # RTM_Network
                
                'horizontalCurves':railML.Infrastructure.Geometry.Geometry.create_HorizontalCurves,'gradientCurves':railML.Infrastructure.Geometry.Geometry.create_GradientCurves,'geometryPoints':railML.Infrastructure.Geometry.Geometry.create_GeometryPoints, # Geometry
                'horizontalCurve':railML.Infrastructure.Geometry.HorizontalCurves.HorizontalCurves.create_HorizontalCurve, # HorizontalCurves
                'curveType':railML.Infrastructure.Geometry.HorizontalCurves.HorizontalCurve.HorizontalCurve.create_CurveType,'azimuth':railML.Infrastructure.Geometry.HorizontalCurves.HorizontalCurve.HorizontalCurve.create_Azimuth,'deltaAzimuth':railML.Infrastructure.Geometry.HorizontalCurves.HorizontalCurve.HorizontalCurve.create_DeltaAzimuth,'radius':railML.Infrastructure.Geometry.HorizontalCurves.HorizontalCurve.HorizontalCurve.create_Radius,'length':railML.Infrastructure.Geometry.HorizontalCurves.HorizontalCurve.HorizontalCurve.create_Length, # HorizontalCurve
                'gradienteCurve':railML.Infrastructure.Geometry.GradientCurves.GradientCurves.create_GradientCurve, # GradienteCurves
                'curveType':railML.Infrastructure.Geometry.GradientCurves.GradientCurve.GradientCurve.create_CurveType,'gradient':railML.Infrastructure.Geometry.GradientCurves.GradientCurve.GradientCurve.create_Gradient,'deltaGradient':railML.Infrastructure.Geometry.GradientCurves.GradientCurve.GradientCurve.create_DeltaGradient,'radius':railML.Infrastructure.Geometry.GradientCurves.GradientCurve.GradientCurve.create_Radius,'length':railML.Infrastructure.Geometry.GradientCurves.GradientCurve.GradientCurve.create_Length, # GradientCurve
                'geometryPoint':railML.Infrastructure.Geometry.GeometryPoints.GeometryPoints.create_GeometryPoint, # GeometryPoints
                'radius':railML.Infrastructure.Geometry.GeometryPoints.GeometryPoint.GeometryPoint.create_Radius,'gradient':railML.Infrastructure.Geometry.GeometryPoints.GeometryPoint.GeometryPoint.create_Gradient,'azimuth':railML.Infrastructure.Geometry.GeometryPoints.GeometryPoint.GeometryPoint.create_Azimuth, # GeometryPoint
                
                'balises':railML.Infrastructure.FunctionalInfrastructure.FunctionalInfrastructure.create_Balises,'borders':railML.Infrastructure.FunctionalInfrastructure.FunctionalInfrastructure.create_Borders,'bufferStops':railML.Infrastructure.FunctionalInfrastructure.FunctionalInfrastructure.create_BufferStops,'crossings':railML.Infrastructure.FunctionalInfrastructure.FunctionalInfrastructure.create_Crossings,'derailersIS':railML.Infrastructure.FunctionalInfrastructure.FunctionalInfrastructure.create_DerailersIS,'electrifications':railML.Infrastructure.FunctionalInfrastructure.FunctionalInfrastructure.create_Electrifications,'keyLocksIS':railML.Infrastructure.FunctionalInfrastructure.FunctionalInfrastructure.create_KeyLocksIS,'levelCrossingsIS':railML.Infrastructure.FunctionalInfrastructure.FunctionalInfrastructure.create_LevelCrossingsIS,'lines':railML.Infrastructure.FunctionalInfrastructure.FunctionalInfrastructure.create_Lines,'loadingGauges':railML.Infrastructure.FunctionalInfrastructure.FunctionalInfrastructure.create_LoadingGauges,'operationalPoints':railML.Infrastructure.FunctionalInfrastructure.FunctionalInfrastructure.create_OperationalPoints,'overCrossings':railML.Infrastructure.FunctionalInfrastructure.FunctionalInfrastructure.create_OverCrossings,'platforms':railML.Infrastructure.FunctionalInfrastructure.FunctionalInfrastructure.create_Platforms,'restrictionAreas':railML.Infrastructure.FunctionalInfrastructure.FunctionalInfrastructure.create_RestrictionAreas,'serviceSections':railML.Infrastructure.FunctionalInfrastructure.FunctionalInfrastructure.create_ServiceSections,'signalsIS':railML.Infrastructure.FunctionalInfrastructure.FunctionalInfrastructure.create_SignalsIS,'speeds':railML.Infrastructure.FunctionalInfrastructure.FunctionalInfrastructure.create_Speeds,'stoppingPlaces':railML.Infrastructure.FunctionalInfrastructure.FunctionalInfrastructure.create_StoppingPlaces,'switchesIS':railML.Infrastructure.FunctionalInfrastructure.FunctionalInfrastructure.create_SwitchesIS,'tracks':railML.Infrastructure.FunctionalInfrastructure.FunctionalInfrastructure.create_Tracks,'trackBeds':railML.Infrastructure.FunctionalInfrastructure.FunctionalInfrastructure.create_TrackBeds,'trackGauges':railML.Infrastructure.FunctionalInfrastructure.FunctionalInfrastructure.create_TrackGauges,'trainDetectionElements':railML.Infrastructure.FunctionalInfrastructure.FunctionalInfrastructure.create_TrainDetectionElements,'trainProtectionElements':railML.Infrastructure.FunctionalInfrastructure.FunctionalInfrastructure.create_TrainProtectionElements,'trainRadios':railML.Infrastructure.FunctionalInfrastructure.FunctionalInfrastructure.create_TrainRadios,'underCrossing':railML.Infrastructure.FunctionalInfrastructure.FunctionalInfrastructure.create_UnderCrossings,'weightLimits':railML.Infrastructure.FunctionalInfrastructure.FunctionalInfrastructure.create_WeightLimits, # FunctionalInfrastructure
                
                'balise':railML.Infrastructure.FunctionalInfrastructure.Balises.Balises.create_Balise, # Balises
                'type':railML.Infrastructure.FunctionalInfrastructure.Balises.Balise.Balise.create_Type,'belongsToParent':railML.Infrastructure.FunctionalInfrastructure.Balises.Balise.Balise.create_BelongsToParent,'basedOnTemplate':railML.Infrastructure.FunctionalInfrastructure.Balises.Balise.Balise.create_BasedOnTemplate,'baliseGroupType':railML.Infrastructure.FunctionalInfrastructure.Balises.Balise.Balise.create_BaliseGroupType, # Balise         
                
                'border':railML.Infrastructure.FunctionalInfrastructure.Borders.Borders.create_Border, # Borders
                'type':railML.Infrastructure.FunctionalInfrastructure.Borders.Border.Border.create_Type, # Border 
                'designator':railML.Infrastructure.FunctionalInfrastructure.Borders.Border.Border.create_Designator,
                'external':railML.Infrastructure.FunctionalInfrastructure.Borders.Border.Border.create_External,
                'name':railML.Infrastructure.FunctionalInfrastructure.Borders.Border.Border.create_Name,
                'gmlLocations':railML.Infrastructure.FunctionalInfrastructure.Borders.Border.Border.create_GmlLocations,
                'locationNetwork':railML.Infrastructure.FunctionalInfrastructure.Borders.Border.Border.create_LocationNetwork,
                'areaLocation':railML.Infrastructure.FunctionalInfrastructure.Borders.Border.Border.create_AreaLocation,
                'linearLocation':railML.Infrastructure.FunctionalInfrastructure.Borders.Border.Border.create_LinearLocation,
                'spotLocation':railML.Infrastructure.FunctionalInfrastructure.Borders.Border.Border.create_SpotLocation,
                
                'bufferstop':railML.Infrastructure.FunctionalInfrastructure.BufferStops.BufferStops.create_BufferStop, # BufferStops
                'type':railML.Infrastructure.FunctionalInfrastructure.BufferStops.BufferStop.BufferStop.create_Type, # BufferStop
                
                'crossing':railML.Infrastructure.FunctionalInfrastructure.Crossings.Crossings.create_Crossing, # Crossings
                'derailerIS':railML.Infrastructure.FunctionalInfrastructure.DerailersIS.DerailersIS.create_DerailerIS, # DerailersIS
                'derailSide':railML.Infrastructure.FunctionalInfrastructure.DerailersIS.DerailerIS.DerailerIS.create_DerailSide, # DerailerIs
                
                'electrificationSection':railML.Infrastructure.FunctionalInfrastructure.Electrifications.Electrifications.create_ElectrificationSection, # Electrifications
                'contactLineType':railML.Infrastructure.FunctionalInfrastructure.Electrifications.ElectrificationSection.ElectrificationSection.create_ContactLineType,'isInsulatedSection':railML.Infrastructure.FunctionalInfrastructure.Electrifications.ElectrificationSection.ElectrificationSection.create_IsInsulatedSection,'belongsToParent':railML.Infrastructure.FunctionalInfrastructure.Electrifications.ElectrificationSection.ElectrificationSection.create_BelongsToParent,'electrificationSystemRef':railML.Infrastructure.FunctionalInfrastructure.Electrifications.ElectrificationSection.ElectrificationSection.create_ElectrificationSystemRef,'energyCatenary':railML.Infrastructure.FunctionalInfrastructure.Electrifications.ElectrificationSection.ElectrificationSection.create_EnergyCatenary,'energyPantograph':railML.Infrastructure.FunctionalInfrastructure.Electrifications.ElectrificationSection.ElectrificationSection.create_EnergyPantograph,'energyRollingstock':railML.Infrastructure.FunctionalInfrastructure.Electrifications.ElectrificationSection.ElectrificationSection.create_EnergyRollingstock,'contactWire':railML.Infrastructure.FunctionalInfrastructure.Electrifications.ElectrificationSection.ElectrificationSection.create_ContactWire,'pantographSpacingn':railML.Infrastructure.FunctionalInfrastructure.Electrifications.ElectrificationSection.ElectrificationSection. create_PantographSpacingn,'phaseSeparationSection':railML.Infrastructure.FunctionalInfrastructure.Electrifications.ElectrificationSection.ElectrificationSection.create_PhaseSeparationSection,'systemSeparationSection':railML.Infrastructure.FunctionalInfrastructure.Electrifications.ElectrificationSection.ElectrificationSection.create_SystemSeparationSection, # ElectrificationSection

                'keyLockIS':railML.Infrastructure.FunctionalInfrastructure.KeyLocksIS.KeyLocksIS.create_KeyLockIS, # KeyLocksIS
                'levelCrossingIS':railML.Infrastructure.FunctionalInfrastructure.LevelCrossingsIS.LevelCrossingsIS.create_LevelCrossingIS, # LevelCrossingsIS
                'protection':railML.Infrastructure.FunctionalInfrastructure.LevelCrossingsIS.LevelCrossingIS.LevelCrossingIS.create_Protection, # LevelCrossingIS
                
                'line':railML.Infrastructure.FunctionalInfrastructure.Lines.Lines.create_Line, # Lines
                'beginsInOP':railML.Infrastructure.FunctionalInfrastructure.Lines.Line.Line.create_BeginsInOP,'endsInOP':railML.Infrastructure.FunctionalInfrastructure.Lines.Line.Line.create_EndsInOP,'length':railML.Infrastructure.FunctionalInfrastructure.Lines.Line.Line.create_Length,'lineTrafficCode':railML.Infrastructure.FunctionalInfrastructure.Lines.Line.Line.create_LineTrafficCode,'lineCombinedTransportCode':railML.Infrastructure.FunctionalInfrastructure.Lines.Line.Line.create_LineCombinedTransportCode,'lineLayout':railML.Infrastructure.FunctionalInfrastructure.Lines.Line.Line.create_LineLayout,'linePerformance':railML.Infrastructure.FunctionalInfrastructure.Lines.Line.Line. create_LinePerformance, # Line

                'loadingGauge':railML.Infrastructure.FunctionalInfrastructure.LoadingGauges.LoadingGauges.create_LoadingGauge, # LoadingGauges
                'operationalPoint':railML.Infrastructure.FunctionalInfrastructure.OperationalPoints.OperationalPoints.create_OperationalPoint, # OperationalPoints
                'infrastructureManagerRef':railML.Infrastructure.FunctionalInfrastructure.OperationalPoints.OperationalPoint.OperationalPoint.create_InfrastructureManagerRef,'connectedToLine':railML.Infrastructure.FunctionalInfrastructure.OperationalPoints.OperationalPoint.OperationalPoint.create_ConnectedToLine,'limitedByBorder':railML.Infrastructure.FunctionalInfrastructure.OperationalPoints.OperationalPoint.OperationalPoint.create_LimitedByBorder,'opEquipment':railML.Infrastructure.FunctionalInfrastructure.OperationalPoints.OperationalPoint.OperationalPoint.create_OpEquipment,'opOperations':railML.Infrastructure.FunctionalInfrastructure.OperationalPoints.OperationalPoint.OperationalPoint.create_OpOperations, # OperationalPoint
                
                'overCrossing':railML.Infrastructure.FunctionalInfrastructure.OverCrossings.OverCrossings.create_OverCrossing, # OverCrossings
                'allowedLoadingGauge':railML.Infrastructure.FunctionalInfrastructure.OverCrossings.OverCrossing.OverCrossing.create_AllowedLoadingGauge,'length':railML.Infrastructure.FunctionalInfrastructure.OverCrossings.OverCrossing.OverCrossing.create_Length, # OverCrossing
                
                'platform':railML.Infrastructure.FunctionalInfrastructure.Platforms.Platforms.create_Platform, # Platforms
                'ownsPlatformEdge':railML.Infrastructure.FunctionalInfrastructure.Platforms.Platform.Platform.create_OwnsPlatformEdge,'width':railML.Infrastructure.FunctionalInfrastructure.Platforms.Platform.Platform.create_Width,'length':railML.Infrastructure.FunctionalInfrastructure.Platforms.Platform.Platform.create_Length, # Platform
                
                'restrictionArea':railML.Infrastructure.FunctionalInfrastructure.RestrictionAreas.RestrictionAreas.create_RestrictionArea, # RestrictionAreas
                'serviceSection':railML.Infrastructure.FunctionalInfrastructure.ServiceSections.ServiceSections.create_ServiceSection, # ServiceSections
                
                'signalIS':railML.Infrastructure.FunctionalInfrastructure.SignalsIS.SignalsIS.create_SignalIS, # SignalsIS
                'isSignalAnnouncement':railML.Infrastructure.FunctionalInfrastructure.SignalsIS.SignalIS.SignalIS.create_IsSignalAnnouncement,'isSignalCatenary':railML.Infrastructure.FunctionalInfrastructure.SignalsIS.SignalIS.SignalIS.create_IsSignalCatenary,'isSignalDanger':railML.Infrastructure.FunctionalInfrastructure.SignalsIS.SignalIS.SignalIS.create_IsSignalDanger,'isSignalEtcs':railML.Infrastructure.FunctionalInfrastructure.SignalsIS.SignalIS.SignalIS.create_IsSignalEtcs,'isSignalInformation':railML.Infrastructure.FunctionalInfrastructure.SignalsIS.SignalIS.SignalIS.create_IsSignalInformation,'isSignalLevelCrossing':railML.Infrastructure.FunctionalInfrastructure.SignalsIS.SignalIS.SignalIS.create_IsSignalLevelCrossing,'isSignalMilepost':railML.Infrastructure.FunctionalInfrastructure.SignalsIS.SignalIS.SignalIS.create_IsSignalMilepost,'isSignalSpeed':railML.Infrastructure.FunctionalInfrastructure.SignalsIS.SignalIS.SignalIS.create_IsSignalSpeed,'isSignalStopPost':railML.Infrastructure.FunctionalInfrastructure.SignalsIS.SignalIS.SignalIS.create_IsSignalStopPost,'isSignalTrainMovement':railML.Infrastructure.FunctionalInfrastructure.SignalsIS.SignalIS.SignalIS.create_IsSignalTrainMovement,'isSignalRadio':railML.Infrastructure.FunctionalInfrastructure.SignalsIS.SignalIS.SignalIS.create_IsSignalRadio,'isSignalVehicleEquipment':railML.Infrastructure.FunctionalInfrastructure.SignalsIS.SignalIS.SignalIS.create_IsSignalVehicleEquipment,'connectedWithBaliseGroup':railML.Infrastructure.FunctionalInfrastructure.SignalsIS.SignalIS.SignalIS.create_ConnectedWithBaliseGroup,'signalConstruction':railML.Infrastructure.FunctionalInfrastructure.SignalsIS.SignalIS.SignalIS.create_SignalConstruction, # SignalIS
                
                'speedSection':railML.Infrastructure.FunctionalInfrastructure.Speeds.Speeds.create_SpeedSection, # Speeds
                'validForSpeedProfil':railML.Infrastructure.FunctionalInfrastructure.Speeds.SpeedSection.SpeedSection.create_ValidForSpeedProfile, # SpeedSection
                
                'stoppingPlace':railML.Infrastructure.FunctionalInfrastructure.StoppingPlaces.StoppingPlaces.create_StoppingPlace, # StoppingPlaces
                'validForTrainMovement':railML.Infrastructure.FunctionalInfrastructure.StoppingPlaces.StoppingPlace.StoppingPlace.create_ValidForTrainMovement, # StoppingPlace
                
                'switchIS':railML.Infrastructure.FunctionalInfrastructure.SwitchesIS.SwitchesIS.create_SwitchIS, # SwitchesIS
                
                'leftBranch':railML.Infrastructure.FunctionalInfrastructure.SwitchesIS.SwitchIS.SwitchIS.create_LeftBranch,
                'rightBranch':railML.Infrastructure.FunctionalInfrastructure.SwitchesIS.SwitchIS.SwitchIS.create_RightBranch,
                'straightBranch':railML.Infrastructure.FunctionalInfrastructure.SwitchesIS.SwitchIS.SwitchIS.create_StraightBranch,
                'turningBranch':railML.Infrastructure.FunctionalInfrastructure.SwitchesIS.SwitchIS.SwitchIS.create_TurningBranch, # SwitchIS

                'track':railML.Infrastructure.FunctionalInfrastructure.Tracks.Tracks.create_Track, # Tracks
                'trackBegin':railML.Infrastructure.FunctionalInfrastructure.Tracks.Track.Track.create_TrackBegin,'trackEnd':railML.Infrastructure.FunctionalInfrastructure.Tracks.Track.Track.create_TrackEnd,'length':railML.Infrastructure.FunctionalInfrastructure.Tracks.Track.Track.create_Length,'linearLocation':railML.Infrastructure.FunctionalInfrastructure.Tracks.Track.Track.create_LinearLocation, # Track
                'associatedNetElement':railML.Infrastructure.FunctionalInfrastructure.Tracks.Track.RTM_LinearLocation.RTM_LinearLocation.create_AssociatedNetElement,'linearCoordinate':railML.Infrastructure.FunctionalInfrastructure.Tracks.Track.RTM_LinearLocation.RTM_LinearLocation.create_LinearCoordinate,'geometricCoordinate':railML.Infrastructure.FunctionalInfrastructure.Tracks.Track.RTM_LinearLocation.RTM_LinearLocation.create_GeometricCoordinate, # LinearLocation
    
                'trackBed':railML.Infrastructure.FunctionalInfrastructure.TrackBeds.TrackBeds.create_TrackBed, # TrackBeds
                'trackGauge':railML.Infrastructure.FunctionalInfrastructure.TrackGauges.TrackGauges.create_TrackGauge, # TrackGauges
                'trainDetectionElement':railML.Infrastructure.FunctionalInfrastructure.TrainDetectionElements.TrainDetectionElements.create_TrainDetectionElement, # TrainDetectionElements
                'trainProtectionElement':railML.Infrastructure.FunctionalInfrastructure.TrainProtectionElements.TrainProtectionElements.create_TrainProtectionElement, # TrainProtectionElements
                'trainRadio':railML.Infrastructure.FunctionalInfrastructure.TrainRadios.TrainRadios.create_TrainRadio, # TrainRadios
                
                'underCrossing':railML.Infrastructure.FunctionalInfrastructure.UnderCrossings.UnderCrossings.create_UnderCrossing, # UnderCrossings
                'allowedLoadingGauge':railML.Infrastructure.FunctionalInfrastructure.UnderCrossings.UnderCrossing.UnderCrossing.create_AllowedLoadingGauge,'length':railML.Infrastructure.FunctionalInfrastructure.UnderCrossings.UnderCrossing.UnderCrossing.create_Length, # UnderCrossing
                'weightLimit':railML.Infrastructure.FunctionalInfrastructure.WeightLimits.WeightLimits.create_WeightLimit, # WeightLimits

                'visualization':railML.Infrastructure.InfrastructureVisualizations.InfrastructureVisualizations.create_Visualization, # InfrastructureVisualizations
                'spotElementProjection':railML.Infrastructure.InfrastructureVisualizations.Visualization.Visualization.create_SpotElementProjection,'linearElementProjection':railML.Infrastructure.InfrastructureVisualizations.Visualization.Visualization.create_LinearElementProjection,'areaElementProjection':railML.Infrastructure.InfrastructureVisualizations.Visualization.Visualization.create_AreaElementProjection, # Visualization

                'coordinate':railML.Infrastructure.InfrastructureVisualizations.Visualization.SpotProjection.SpotProjection.create_Coordinate, 
                'usesSymbol':railML.Infrastructure.InfrastructureVisualizations.Visualization.SpotProjection.SpotProjection.create_UsesSymbol, # SpotProjection
                'coordinate':railML.Infrastructure.InfrastructureVisualizations.Visualization.LinearProjection.LinearProjection.create_Coordinate, # LinearProjection
                'coordinate':railML.Infrastructure.InfrastructureVisualizations.Visualization.AreaProjection.AreaProjection.create_Coordinate, # SpotProjection

                'infrastructureState':railML.Infrastructure.InfrastructureStates.InfrastructureStates.create_InfrastructureState, # InfrastructureStates
                'elementState':railML.Infrastructure.InfrastructureStates.InfrastructureState.InfrastructureState.create_ElementState,'validityTime':railML.Infrastructure.InfrastructureStates.InfrastructureState.InfrastructureState.create_ValidityTime, # InfrastructureState
                'validityTime':railML.Infrastructure.InfrastructureStates.InfrastructureState.ElementState.ElementState.create_ValidityTime, # ElementState            
                'period':railML.Infrastructure.InfrastructureStates.InfrastructureState.Period.Period.create_Period,'periodBitmask':railML.Infrastructure.InfrastructureStates.InfrastructureState.Period.Period.create_PeriodBitmask,'periodGeneric':railML.Infrastructure.InfrastructureStates.InfrastructureState.Period.Period.create_PeriodGeneric, # Period
                'periodRule':railML.Infrastructure.InfrastructureStates.InfrastructureState.Period.CalendarTimePeriodWithBitmask.CalendarTimePeriodWithBitmask.create_PeriodRule, # CalendarTimePeriodWithBitmask
                'period':railML.Infrastructure.InfrastructureStates.InfrastructureState.Period.CalendarTimePeriodWithBitmask.PeriodRule.PeriodRule.create_Period, # PeriodRule

                'assetsForIL':railML.Interlocking.Interlocking.create_AssetsForIL,'controllers':railML.Interlocking.Interlocking.create_Controllers,'signalBoxes':railML.Interlocking.Interlocking.create_SignalBoxes,'specificIMs':railML.Interlocking.Interlocking.create_SpecificIMs, # Interlocking

                'tvdSections':railML.Interlocking.AssetsForIL.AssetsForIL.create_TvdSections,'switchesIL':railML.Interlocking.AssetsForIL.AssetsForIL.create_SwitchesIL,'derailersIL':railML.Interlocking.AssetsForIL.AssetsForIL.create_DerailersIL,'movableCrossings':railML.Interlocking.AssetsForIL.AssetsForIL.create_MovableCrossings,'levelCrossingsIL':railML.Interlocking.AssetsForIL.AssetsForIL.create_LevelCrossingsIL,'keys':railML.Interlocking.AssetsForIL.AssetsForIL.create_Keys,'keyLocksIL':railML.Interlocking.AssetsForIL.AssetsForIL.create_KeyLocksIL,'genericDetectors':railML.Interlocking.AssetsForIL.AssetsForIL.create_GenericDetectors,'signalsIL':railML.Interlocking.AssetsForIL.AssetsForIL.create_SignalsIL,'ATPdevices':railML.Interlocking.AssetsForIL.AssetsForIL.create_ATPdevices,'interfaces':railML.Interlocking.AssetsForIL.AssetsForIL.create_Interfaces,'workZones':railML.Interlocking.AssetsForIL.AssetsForIL.create_WorkZones,'localOperationAreas':railML.Interlocking.AssetsForIL.AssetsForIL.create_LocalOperationAreas,'shuntingZones':railML.Interlocking.AssetsForIL.AssetsForIL.create_ShuntingZones,'permissionZones':railML.Interlocking.AssetsForIL.AssetsForIL.create_PermissionZones,'routeReleaseGroupsAhead':railML.Interlocking.AssetsForIL.AssetsForIL.create_RouteReleaseGroupsAhead,'routeReleaseGroupsRear':railML.Interlocking.AssetsForIL.AssetsForIL.create_RouteReleaseGroupsRear,'routes':railML.Interlocking.AssetsForIL.AssetsForIL.create_Routes,'conflictingRoutes':railML.Interlocking.AssetsForIL.AssetsForIL.create_ConflictingRoutes,'routeRelations':railML.Interlocking.AssetsForIL.AssetsForIL.create_RouteRelations,'combinedRoutes':railML.Interlocking.AssetsForIL.AssetsForIL.create_CombinedRoutes,'overlaps':railML.Interlocking.AssetsForIL.AssetsForIL.create_Overlaps,'dangerPoints':railML.Interlocking.AssetsForIL.AssetsForIL.create_DangerPoints,'destinationPoints':railML.Interlocking.AssetsForIL.AssetsForIL.create_DestinationPoints,'powerSuppliesIL':railML.Interlocking.AssetsForIL.AssetsForIL.create_PowerSuppliesIL, # AssetsForIL
                'tvdSection':railML.Interlocking.AssetsForIL.TvdSections.TvdSections.create_TvdSection, # TvdSections
                'designator':railML.Interlocking.AssetsForIL.TvdSections.TvdSection.TvdSection.create_Designator,'hasDemarcatingBufferstop':railML.Interlocking.AssetsForIL.TvdSections.TvdSection.TvdSection.create_HasDemarcatingBufferstop,'hasExitSignal':railML.Interlocking.AssetsForIL.TvdSections.TvdSection.TvdSection.create_HasExitSignal,'hasDemarcatingTraindetector':railML.Interlocking.AssetsForIL.TvdSections.TvdSection.TvdSection.create_HasDemarcatingTraindetector,'hasResetStrategy':railML.Interlocking.AssetsForIL.TvdSections.TvdSection.TvdSection.create_HasResetStrategy, # TvdSection
                'switchIL':railML.Interlocking.AssetsForIL.SwitchesIL.SwitchesIL.create_SwitchIL, # SwitchesIL
                'hasFoulingTrainDetectors':railML.Interlocking.AssetsForIL.SwitchesIL.SwitchIL.SwitchIL.create_HasFoulingTrainDetectors,'branchLeft':railML.Interlocking.AssetsForIL.SwitchesIL.SwitchIL.SwitchIL.create_BranchLeft,'branchRight':railML.Interlocking.AssetsForIL.SwitchesIL.SwitchIL.SwitchIL.create_BranchRight,'hasPositionRestriction':railML.Interlocking.AssetsForIL.SwitchesIL.SwitchIL.SwitchIL.create_HasPositionRestriction,'refersTo':railML.Interlocking.AssetsForIL.SwitchesIL.SwitchIL.SwitchIL.create_RefersTo,'hasGaugeClearanceMarker':railML.Interlocking.AssetsForIL.SwitchesIL.SwitchIL.SwitchIL.create_HasGaugeClearanceMarker,'hasTvdSection':railML.Interlocking.AssetsForIL.SwitchesIL.SwitchIL.SwitchIL.create_HasTvdSection,'connectedToPowerSupply':railML.Interlocking.AssetsForIL.SwitchesIL.SwitchIL.SwitchIL.create_ConnectedToPowerSupply,'relatedMovableElement':railML.Interlocking.AssetsForIL.SwitchesIL.SwitchIL.SwitchIL.create_RelatedMovableElement, # SwitchIL
                'derailerIL':railML.Interlocking.AssetsForIL.DerailersIL.DerailersIL.create_DerailerIL, # DerailersIL
                'movableCrossing':railML.Interlocking.AssetsForIL.MovableCrossings.MovableCrossings.create_MovableCrossing, # MovableCrossings                
                'branchUpLeft':railML.Interlocking.AssetsForIL.MovableCrossings.MovableCrossing.MovableCrossing.create_BranchUpLeft,'branchUpRight':railML.Interlocking.AssetsForIL.MovableCrossings.MovableCrossing.MovableCrossing.create_BranchUpRight,'branchDownLeft':railML.Interlocking.AssetsForIL.MovableCrossings.MovableCrossing.MovableCrossing.create_BranchDownLeft,'branchDownRight':railML.Interlocking.AssetsForIL.MovableCrossings.MovableCrossing.MovableCrossing.create_BranchDownRight,'hasFoulingTrainDetectors':railML.Interlocking.AssetsForIL.MovableCrossings.MovableCrossing.MovableCrossing.create_HasFoulingTrainDetectors, # MovableCrossing
                'levelCrossingIL':railML.Interlocking.AssetsForIL.LevelCrossingsIL.LevelCrossingsIL.create_LevelCrossingIL, # LevelCrossingsIL
                'hasInterface':railML.Interlocking.AssetsForIL.LevelCrossingsIL.LevelCrossingIL.LevelCrossingIL.create_HasInterface,'isLevelCrossingType':railML.Interlocking.AssetsForIL.LevelCrossingsIL.LevelCrossingIL.LevelCrossingIL.create_IsLevelCrossingType,'refersTo':railML.Interlocking.AssetsForIL.LevelCrossingsIL.LevelCrossingIL.LevelCrossingIL.create_RefersTo,'deactivatedBy':railML.Interlocking.AssetsForIL.LevelCrossingsIL.LevelCrossingIL.LevelCrossingIL.create_DeactivatedBy,'activationCondition':railML.Interlocking.AssetsForIL.LevelCrossingsIL.LevelCrossingIL.LevelCrossingIL.create_ActivationCondition,'hasTvdSection':railML.Interlocking.AssetsForIL.LevelCrossingsIL.LevelCrossingIL.LevelCrossingIL.create_HasTvdSection, # LevelCrossingIL
                'key':railML.Interlocking.AssetsForIL.Keys.Keys.create_Key, # Keys
                'keyLockIL':railML.Interlocking.AssetsForIL.KeyLocksIL.KeyLocksIL.create_KeyLockIL, # KeyLocksIL
                'acceptsKey':railML.Interlocking.AssetsForIL.KeyLocksIL.KeyLockIL.KeyLockIL.create_AcceptsKey,'hasTvdSection':railML.Interlocking.AssetsForIL.KeyLocksIL.KeyLockIL.KeyLockIL.create_HasTvdSection,'hasSlaveLock':railML.Interlocking.AssetsForIL.KeyLocksIL.KeyLockIL.KeyLockIL. create_HasSlaveLock, # KeyLockIL
                'genericDetector':railML.Interlocking.AssetsForIL.GenericDetectors.GenericDetectors.create_GenericDetector, # GenericDetectors
                'detectorType':railML.Interlocking.AssetsForIL.GenericDetectors.GenericDetector.GenericDetector.create_DetectorType, # GenericDetector
                'signalIL':railML.Interlocking.AssetsForIL.SignalsIL.SignalsIL.create_SignalIL, # SignalsIL
                'refersTo':railML.Interlocking.AssetsForIL.SignalsIL.SignalIL.SignalIL.create_RefersTo,'protectsBlockExit':railML.Interlocking.AssetsForIL.SignalsIL.SignalIL.SignalIL.create_ProtectsBlockExit, # SignalIL
                'atpdevice':railML.Interlocking.AssetsForIL.ATPdevices.ATPdevices.create_ATPdevice, # ATPdevices
                'atpType':railML.Interlocking.AssetsForIL.ATPdevices.ATPdevice.ATPdevice.create_AtpType,'device':railML.Interlocking.AssetsForIL.ATPdevices.ATPdevice.ATPdevice.create_Device,'exitSignal':railML.Interlocking.AssetsForIL.ATPdevices.ATPdevice.ATPdevice.create_ExitSignal,'entrySignal':railML.Interlocking.AssetsForIL.ATPdevices.ATPdevice.ATPdevice.create_EntrySignal, # ATPdevice
                'interface':railML.Interlocking.AssetsForIL.Interfaces.Interfaces.create_Interface, # Interfaces
                'command':railML.Interlocking.AssetsForIL.Interfaces.Interface.Interface.create_Command,'message':railML.Interlocking.AssetsForIL.Interfaces.Interface.Interface.create_Message,'initStatus':railML.Interlocking.AssetsForIL.Interfaces.Interface.Interface.create_InitStatus, # Interface
                'workZone':railML.Interlocking.AssetsForIL.WorkZones.WorkZones.create_WorkZone, # WorkZones
                'activationLock':railML.Interlocking.AssetsForIL.WorkZones.WorkZone.WorkZone.create_ActivationLock,'switchInPosition':railML.Interlocking.AssetsForIL.WorkZones.WorkZone.WorkZone.create_SwitchInPosition,'derailerInPosition':railML.Interlocking.AssetsForIL.WorkZones.WorkZone.WorkZone.create_DerailerInPosition,'crossingInPosition':railML.Interlocking.AssetsForIL.WorkZones.WorkZone.WorkZone.create_CrossingInPosition,'detectorInState':railML.Interlocking.AssetsForIL.WorkZones.WorkZone.WorkZone.create_DetectorInState,'signalWithAspect':railML.Interlocking.AssetsForIL.WorkZones.WorkZone.WorkZone.create_SignalWithAspect,'keyLockInState':railML.Interlocking.AssetsForIL.WorkZones.WorkZone.WorkZone.create_KeyLockInState,'levelCrossingInState':railML.Interlocking.AssetsForIL.WorkZones.WorkZone.WorkZone.create_LevelCrossingInState,'releasedForLocalOperation':railML.Interlocking.AssetsForIL.WorkZones.WorkZone.WorkZone.create_ReleasedForLocalOperation, # WorkZone
                'localOperationArea':railML.Interlocking.AssetsForIL.LocalOperationAreas.LocalOperationAreas.create_LocalOperationArea, # LocalOperationAreas
                'deactivationKey':railML.Interlocking.AssetsForIL.LocalOperationAreas.LocalOperationArea.LocalOperationArea.create_DeactivationKey,'switchInPosition':railML.Interlocking.AssetsForIL.LocalOperationAreas.LocalOperationArea.LocalOperationArea.create_SwitchInPosition,'derailerInPosition':railML.Interlocking.AssetsForIL.LocalOperationAreas.LocalOperationArea.LocalOperationArea.create_DerailerInPosition,'crossingInPosition':railML.Interlocking.AssetsForIL.LocalOperationAreas.LocalOperationArea.LocalOperationArea.create_CrossingInPosition,'detectorInState':railML.Interlocking.AssetsForIL.LocalOperationAreas.LocalOperationArea.LocalOperationArea.create_DetectorInState,'signalWithAspect':railML.Interlocking.AssetsForIL.LocalOperationAreas.LocalOperationArea.LocalOperationArea.create_SignalWithAspect,'keyLockInState':railML.Interlocking.AssetsForIL.LocalOperationAreas.LocalOperationArea.LocalOperationArea.create_KeyLockInState,'levelCrossingInState':railML.Interlocking.AssetsForIL.LocalOperationAreas.LocalOperationArea.LocalOperationArea.create_LevelCrossingInState,'releasedForLocalOperation':railML.Interlocking.AssetsForIL.LocalOperationAreas.LocalOperationArea.LocalOperationArea.create_ReleasedForLocalOperation, # LocalOperationArea
                'shuntingZone':railML.Interlocking.AssetsForIL.ShuntingZones.ShuntingZones.create_ShuntingZone, # ShuntingZones
                'permissionZone':railML.Interlocking.AssetsForIL.PermissionZones.PermissionZones.create_PermissionZone, # PermissionZones
                'canBeControlledBy':railML.Interlocking.AssetsForIL.PermissionZones.PermissionZone.PermissionZone.create_CanBeControlledBy,'controlledElement':railML.Interlocking.AssetsForIL.PermissionZones.PermissionZone.PermissionZone.create_ControlledElement, # PermissionZone
                'routeReleaseGroupAhead':railML.Interlocking.AssetsForIL.RouteReleaseGroupsAhead.RouteReleaseGroupsAhead.create_RouteReleaseGroupAhead, # RouteReleaseGroupsAhead
                'routeReleaseGroupRear':railML.Interlocking.AssetsForIL.RouteReleaseGroupsRear.RouteReleaseGroupsRear.create_RouteReleaseGroupRear, # RouteReleaseGroupsRear
                'route':railML.Interlocking.AssetsForIL.Routes.Routes.create_Route, # Routes
                'handlesRouteType':railML.Interlocking.AssetsForIL.Routes.Route.Route.create_HandlesRouteType,'routeActivationSection':railML.Interlocking.AssetsForIL.Routes.Route.Route.create_RouteActivationSection,'facingSwitchInPosition':railML.Interlocking.AssetsForIL.Routes.Route.Route.create_FacingSwitchInPosition,'refersToSwitch':railML.Interlocking.AssetsForIL.Routes.Route.SwitchAndPosition.SwitchAndPosition.create_RefersToSwitch,'hasTvdSection':railML.Interlocking.AssetsForIL.Routes.Route.Route.create_HasTvdSection,'routeEntry':railML.Interlocking.AssetsForIL.Routes.Route.Route.create_RouteEntry,'hasReleaseGroup':railML.Interlocking.AssetsForIL.Routes.Route.Route.create_HasReleaseGroup,'switchPositionInDepartureTrack':railML.Interlocking.AssetsForIL.Routes.Route.Route.create_SwitchPositionInDepartureTrack,'routeExit':railML.Interlocking.AssetsForIL.Routes.Route.Route.create_RouteExit,'additionalRelation':railML.Interlocking.AssetsForIL.Routes.Route.Route.create_AdditionalRelation, # Route
                'conflictingRoute':railML.Interlocking.AssetsForIL.ConflictingRoutes.ConflictingRoutes.create_ConflictingRoute, # ConflictingRoutes
                'refersToRoute':railML.Interlocking.AssetsForIL.ConflictingRoutes.ConflictingRoute.ConflictingRoute.create_RefersToRoute,'conflictsWithRoute':railML.Interlocking.AssetsForIL.ConflictingRoutes.ConflictingRoute.ConflictingRoute.create_ConflictsWithRoute,'reasonForConflict':railML.Interlocking.AssetsForIL.ConflictingRoutes.ConflictingRoute.ConflictingRoute.create_ReasonForConflict, # ConflictingRoute
                'routeRelations':railML.Interlocking.AssetsForIL.RouteRelations.RouteRelations.create_RouteRelation, # RouteRelations
                'requiredSwitchPosition':railML.Interlocking.AssetsForIL.RouteRelations.RouteRelation.RouteRelation.create_RequiredSwitchPosition,'requiredDerailerPosition':railML.Interlocking.AssetsForIL.RouteRelations.RouteRelation.RouteRelation.create_RequiredDerailerPosition,'requiredCrossingPosition':railML.Interlocking.AssetsForIL.RouteRelations.RouteRelation.RouteRelation.create_RequiredCrossingPosition,'requiredDetectorState':railML.Interlocking.AssetsForIL.RouteRelations.RouteRelation.RouteRelation.create_RequiredDetectorState,'requiredSignalAspect':railML.Interlocking.AssetsForIL.RouteRelations.RouteRelation.RouteRelation.create_RequiredSignalAspect,'requiredSectionState':railML.Interlocking.AssetsForIL.RouteRelations.RouteRelation.RouteRelation.create_RequiredSectionState,'requiredKeyLockState':railML.Interlocking.AssetsForIL.RouteRelations.RouteRelation.RouteRelation.create_RequiredKeyLockState,'requiredLevelCrossingState':railML.Interlocking.AssetsForIL.RouteRelations.RouteRelation.RouteRelation.create_RequiredLevelCrossingState, # RouteRelation
                'combinedRoute':railML.Interlocking.AssetsForIL.CombinedRoutes.CombinedRoutes.create_CombinedRoute, # CombinedRoutes
                'comboEntry':railML.Interlocking.AssetsForIL.CombinedRoutes.CombinedRoute.CombinedRoute.create_ComboEntry,'comboExit':railML.Interlocking.AssetsForIL.CombinedRoutes.CombinedRoute.CombinedRoute.create_ComboExit,'containsRoute':railML.Interlocking.AssetsForIL.CombinedRoutes.CombinedRoute.CombinedRoute.create_ContainsRoute, # CombinedRoute
                'overlap':railML.Interlocking.AssetsForIL.Overlaps.Overlaps.create_Overlap, # Overlaps
                'activeForApproachRoute':railML.Interlocking.AssetsForIL.Overlaps.Overlap.Overlap.create_ActiveForApproachRoute,'relatedToTrackAsset':railML.Interlocking.AssetsForIL.Overlaps.Overlap.Overlap.create_RelatedToTrackAsset,'requiresSwitchInPosition':railML.Interlocking.AssetsForIL.Overlaps.Overlap.Overlap.create_RequiresSwitchInPosition,'requiresLevelCrossingInState':railML.Interlocking.AssetsForIL.Overlaps.Overlap.Overlap.create_RequiresLevelCrossingInState,'hasTvdSection':railML.Interlocking.AssetsForIL.Overlaps.Overlap.Overlap.create_HasTvdSection,'isLimitedBy':railML.Interlocking.AssetsForIL.Overlaps.Overlap.Overlap.create_IsLimitedBy,'overlapRelease':railML.Interlocking.AssetsForIL.Overlaps.Overlap.Overlap.create_OverlapRelease, # Overlap
                'destinationPoint':railML.Interlocking.AssetsForIL.DestinationPoints.DestinationPoints.create_DestinationPoint, # DestinationPoints
                'refersTo':railML.Interlocking.AssetsForIL.DestinationPoints.RouteExit.RouteExit.create_RefersTo,'hasDangerPoint':railML.Interlocking.AssetsForIL.DestinationPoints.RouteExit.RouteExit.create_HasDangerPoint,'hasOverlap':railML.Interlocking.AssetsForIL.DestinationPoints.RouteExit.RouteExit.create_HasOverlap, # RouteExit
                'powerSupplyIL':railML.Interlocking.AssetsForIL.PowerSuppliesIL.PowerSuppliesIL.create_PowerSupplyIL, # PowerSuppliesIL

                'controller':railML.Interlocking.Controllers.Controllers.create_Controller, # Controllers 
                'controlledAssets':railML.Interlocking.Controllers.Controller.Controller.create_ControlledAssets,'itineraries':railML.Interlocking.Controllers.Controller.Controller.create_Itineraries, # Controller
                'controlledSignalBox':railML.Interlocking.Controllers.Controller.ControlledAssets.ControlledAssets.create_ControlledSignalBox,'systemAssetConnectedToIL':railML.Interlocking.Controllers.Controller.ControlledAssets.ControlledAssets.create_SystemAssetConnectedToIL,    # ControlledAssets
                'connectedSignalBox':railML.Interlocking.Controllers.Controller.ControlledAssets.ControlledSignalBox.ControlledSignalBox.create_ConnectedSignalBox, # ControlledSignalBox
                'connectedSystemAsset':railML.Interlocking.Controllers.Controller.ControlledAssets.SystemAssetConnectedToIL.SystemAssetConnectedToIL.create_ConnectedSystemAsset, # SystemAssetConnectedToIL
                'itinerary':railML.Interlocking.Controllers.Controller.Itineraries.Itineraries.create_Itinerary, # Itineraries

                'signalBox':railML.Interlocking.SignalBoxes.SignalBoxes.create_SignalBox, # SignalBoxes
                'controlsSystemAsset':railML.Interlocking.SignalBoxes.SignalBox.SignalBox.create_ControlsSystemAsset,'controlsTrackAsset':railML.Interlocking.SignalBoxes.SignalBox.SignalBox.create_ControlsTrackAsset,'controlsRoute':railML.Interlocking.SignalBoxes.SignalBox.SignalBox.create_ControlsRoute,'controlsCombinedRoute':railML.Interlocking.SignalBoxes.SignalBox.SignalBox.create_ControlsCombinedRoute,'controlsInterface':railML.Interlocking.SignalBoxes.SignalBox.SignalBox.create_ControlsInterface,'controlledBy':railML.Interlocking.SignalBoxes.SignalBox.SignalBox.create_ControlledBy,'implementsSignalplan':railML.Interlocking.SignalBoxes.SignalBox.SignalBox.create_ImplementsSignalplan,'implementsElementGroup':railML.Interlocking.SignalBoxes.SignalBox.SignalBox.create_ImplementsElementGroup,'hasPermissionZone':railML.Interlocking.SignalBoxes.SignalBox.SignalBox.create_HasPermissionZone,'hasConflictingRoutes':railML.Interlocking.SignalBoxes.SignalBox.SignalBox.create_HasConflictingRoutes,'hasConfiguration':railML.Interlocking.SignalBoxes.SignalBox.SignalBox.create_HasConfiguration, # SignalBox
                'connectedTrackAsset':railML.Interlocking.SignalBoxes.SignalBox.TrackAssetConnectedToIL.TrackAssetConnectedToIL.create_ConnectedTrackAsset, # TrackAssetConnectedToIL
                'lastOwnTvdSection':railML.Interlocking.SignalBoxes.SignalBox.InterlockingInterface.InterlockingInterface.create_LastOwnTvdSection,'firstRemoteTvdSection':railML.Interlocking.SignalBoxes.SignalBox.InterlockingInterface.InterlockingInterface.create_FirstRemoteTvdSection,'incomingRoute':railML.Interlocking.SignalBoxes.SignalBox.InterlockingInterface.InterlockingInterface.create_IncomingRoute,'outgoingRoute':railML.Interlocking.SignalBoxes.SignalBox.InterlockingInterface.InterlockingInterface.create_OutgoingRoute,'hasInterface':railML.Interlocking.SignalBoxes.SignalBox.InterlockingInterface.InterlockingInterface.create_HasInterface, # InterlockingInterface   
                'aspectRelation':railML.Interlocking.SignalBoxes.SignalBox.SignalPlan.SignalPlan.create_AspectRelation,  # SignalPlan
                'masterAspect':railML.Interlocking.SignalBoxes.SignalBox.SignalPlan.AspectRelation.AspectRelation.create_MasterAspect,'slaveAspect':railML.Interlocking.SignalBoxes.SignalBox.SignalPlan.AspectRelation.AspectRelation.create_SlaveAspect,'distantAspect':railML.Interlocking.SignalBoxes.SignalBox.SignalPlan.AspectRelation.AspectRelation.create_DistantAspect,'signalsSpeedProfile':railML.Interlocking.SignalBoxes.SignalBox.SignalPlan.AspectRelation.AspectRelation.create_SignalsSpeedProfile,'appliesToRoute':railML.Interlocking.SignalBoxes.SignalBox.SignalPlan.AspectRelation.AspectRelation.create_AppliesToRoute, # AspectRelation
                'refersToSignal':railML.Interlocking.SignalBoxes.SignalBox.SignalPlan.AspectRelation.SignalAndAspect.SignalAndAspect.create_RefersToSignal,'showsAspect':railML.Interlocking.SignalBoxes.SignalBox.SignalPlan.AspectRelation.SignalAndAspect.SignalAndAspect.create_ShowsAspect, # SignalAndAspect
                'groupType':railML.Interlocking.SignalBoxes.SignalBox.ElementGroup.ElementGroup.create_GroupType,'refersToMember':railML.Interlocking.SignalBoxes.SignalBox.ElementGroup.ElementGroup.create_RefersToMember, # ElementGroup

                'specificIM':railML.Interlocking.GenericIMs.GenericIMs.create_SpecificIM, # GenericIMs
                'ownsSetsOfAssets':railML.Interlocking.GenericIMs.GenericIM.GenericIM.create_OwnsSetsOfAssets,'usesTypes':railML.Interlocking.GenericIMs.GenericIM.GenericIM.create_UsesTypes, # GenericIM
                'hasAspect':railML.Interlocking.GenericIMs.GenericIM.GenericTypes.GenericTypes.create_HasAspect,'hasTVDresetStrategy':railML.Interlocking.GenericIMs.GenericIM.GenericTypes.GenericTypes.create_HasTVDresetStrategy,'hasRouteType':railML.Interlocking.GenericIMs.GenericIM.GenericTypes.GenericTypes.create_HasRouteType,'hasLevelCrossingType':railML.Interlocking.GenericIMs.GenericIM.GenericTypes.GenericTypes.create_HasLevelCrossingType,'hasElementGroupType':railML.Interlocking.GenericIMs.GenericIM.GenericTypes.GenericTypes.create_HasElementGroupType,'hasDetectorTypes':railML.Interlocking.GenericIMs.GenericIM.GenericTypes.GenericTypes.create_HasDetectorTypes, # GenericTypes  
                
                }