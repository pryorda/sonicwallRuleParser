#!/usr/bin/python

import re
import sys
import urllib
import collections
import base64

with open(sys.argv[1], 'r') as f:
    read_data = f.readline()
f.close()

decoded_data = base64.b64decode(read_data)
decoded_data =  decoded_data.split("&")

rules=[]
ruleID=""
ruleSrcNet=""
ruleSrcZone=""
ruleDestNet=""
ruleDestZone=""
ruleDestService=""
ruleComment=""
ruleAction=""
ruleStatus=""

prevSrcZone=""
prevDestZone=""

natRules=[]
natRuleID=""
natOrigSrc=""
natOrigDest=""
natOrigService=""
natTransSrc=""
natTransDest=""
natTransService=""
natSrcInterface=""
natDestInterface=""
natSrcZone=""
natDestZone=""
natReflexive=""
natComment=""
natStatus=""



addrGroups={}
groupID=""
groupObject=""

addrObjects={}
addrName=""
addrIP=""
addrSubnet=""
addrZone=""
addrType=""
addrID=""

addrFqdnObjects = {}
addrID=""
addrName=""
addrType=""
addrFqdn=""
addrZone=""


serviceGroups={}
sgroupID=""
sgroupObject=""

serviceObjects={}
serviceID=""
serviceName=""
serviceStartPort=""
serviceEndPort=""
serviceProtocol=""
serviceType=""

interfaces={}
ifaceIfNum=""
ifaceName=""
ifaceType=""
interfaceZone=""
ifaceComment=""
ifaceIp=""
ifaceMask=""
ifaceVlanTag=""
ifaceVlanParent=""


for line in decoded_data:
    line = line.strip()
    if re.match('^(iface|interface)', line):
        if re.match('^iface_ifnum_', line):
            ifaceID, ifaceIfNum = re.search('^iface_ifnum_(\d+)=(.*)', line).groups()
        elif re.match(str("^iface_name_"+ifaceID), line):
            ifaceName = re.search(str("^iface_name_"+ifaceID+"=(.*)"), line).group(1)
            ifaceName = urllib.unquote(ifaceName)
        elif re.match(str("^iface_phys_type_"+ifaceID), line):
            ifaceType = re.search(str("^iface_phys_type_"+ifaceID+"=(.*)"), line).group(1)
            if ifaceType == "0":
                ifaceType = "Phys"
            elif ifaceType == "2":
                ifaceType = "vlan"
            else:
                ifaceType = "unknown"
        elif re.match(str("^interface_Zone_"+ifaceID), line):
            interfaceZone = re.search(str("^interface_Zone_"+ifaceID+"=(.*)"), line).group(1)
            if interfaceZone:
                interfaceZone = urllib.unquote(interfaceZone)
            else: 
                interfaceZone = "Unknown"
        elif re.match(str("^iface_comment_"+ifaceID), line):
            ifaceComment = re.search(str("^iface_comment_"+ifaceID+"=(.*)"), line).group(1)
            if ifaceComment:
                ifaceComment = urllib.unquote(ifaceComment)
            else:
                ifaceComment = "No Comment!"
        elif re.match(str("^iface_lan_ip_"+ifaceID), line):
            ifaceIp = re.search(str("^iface_lan_ip_"+ifaceID+"=(.*)"), line).group(1)
        elif re.match(str("^iface_lan_mask_"+ifaceID), line):
            ifaceMask = re.search(str("^iface_lan_mask_"+ifaceID+"=(.*)"), line).group(1)
        elif re.match(str("^iface_vlan_tag_"+ifaceID), line):
            ifaceVlanTag = re.search(str("^iface_vlan_tag_"+ifaceID+"=(.*)"), line).group(1)
            if not ifaceVlanTag:
                ifaceVlanTag = 0
        elif re.match(str("^iface_vlan_parent_"+ifaceID), line):
            ifaceVlanParent = re.search(str("^iface_vlan_parent_"+ifaceID+"=(.*)"), line).group(1)
            if not ifaceVlanParent:
                ifaceVlanParent = 0
        # print ifaceID
        # print ifaceIfNum
        # print ifaceName
        # print ifaceType
        # print interfaceZone
        # print ifaceIp
        # print ifaceMask
        # print ifaceVlanTag
        # print ifaceVlanParent
        # print ifaceComment
        if ifaceID and ifaceIfNum and ifaceName and ifaceType and interfaceZone and ifaceComment and ifaceIp and ifaceMask and ifaceVlanTag and ifaceVlanParent:
            interfaces[ifaceIfNum] = {
                "ifaceIfNum": ifaceIfNum,
                "ifaceName": ifaceName,
                "ifaceType": ifaceType,
                "interfaceZone": interfaceZone,
                "ifaceComment": ifaceComment,
                "ifaceIp": ifaceIp,
                "ifaceMask": ifaceMask,
                "ifaceVlanTag": ifaceVlanTag,
                "ifaceVlanParent": ifaceVlanParent,
            }
            ifaceIfNum = ""
            ifaceName = ""
            ifaceType = ""
            interfaceZone = ""
            ifaceComment = ""
            ifaceIp = ""
            ifaceMask = ""
            ifaceVlanTag = ""
            ifaceVlanParent = ""

    if re.match('^policy', line):
        policyField, policyID, policyValue = re.search('^policy(.*)_(\d+)=(.*)', line).groups()
        if re.match('^policySrcZone', line):
            ruleSrcZone = policyValue
        elif re.match('^policyDstZone', line):
            ruleDestZone = policyValue
        elif re.match('^policySrcNet', line):
            if policyValue:
                ruleSrcNet = policyValue
            else:
                ruleSrcNet = "Any"
        elif re.match('^policyDstNet', line):
            if policyValue:
                ruleDestNet = policyValue
            else:
                ruleDestNet = "Any"
        elif re.match('^policyDstSvc', line):
            if policyValue:
                ruleDestService = policyValue
            else:
                ruleDestService = "Any"
        elif re.match('^policyComment', line):
            if not policyValue:
                ruleComment = "No Comment!"
            else:
                ruleComment = policyValue
        elif re.match('^policyAction', line):
            if policyValue == "2":
                ruleAction = "Allow"
            elif policyValue == "1":
                ruleAction = "Discard"
            else:
                ruleAction = "Deny"
        elif re.match('^policyEnabled', line):
            if policyValue == "1":
                ruleStatus = "Enabled"
            else:
                ruleStatus = "Disabled"
        if ruleSrcZone and ruleDestZone and ruleSrcNet and ruleDestNet and ruleDestService and ruleAction and ruleStatus and ruleComment:
            # Sonicwall is goofy and has some enabled rules set to 0 when its an auto-added rule
            if re.match('^Auto', ruleComment) and ruleStatus == "Disabled":
                ruleStatus = "Enabled"

            rule={
                "ruleID": policyID,
                "ruleSrcZone": ruleSrcZone,
                "ruleDestZone": ruleDestZone,
                "ruleSrcNet": urllib.unquote(ruleSrcNet),
                "ruleDestNet": urllib.unquote(ruleDestNet),
                "ruleDestService": urllib.unquote(ruleDestService),
                "ruleAction": ruleAction,
                "ruleStatus": ruleStatus,
                "ruleComment": urllib.unquote(ruleComment)
            }
            rules.append(rule)
            ruleSrcZone=""
            ruleDestZone=""
            ruleSrcNet=""
            ruleDestNet=""
            ruleDestService=""
            ruleAction=""
            ruleComment=""
            ruleStatus=""

    if re.match('^addro_', line):
        if re.match('^addro_atomToGrp_', line):
            groupID, groupObject = re.search('^addro_atomToGrp_(\d+)=(.*)', line).groups()
            groupObject = urllib.unquote(groupObject)
            nextPattern="^addro_grpToGrp_"+groupID
            nextGroupPattern=nextPattern+'=(.*)'
        elif re.match(nextPattern, line):
            groupName = re.search(nextGroupPattern, line).group(1)
            groupName = urllib.unquote(groupName)
            if groupName not in addrGroups:
                addrGroups[groupName] = []
                addrGroups[groupName].append(groupObject)
            else:
                addrGroups[groupName].append(groupObject)


    if re.match('^addrObjFqdn', line):
        if re.match('^addrObjFqdnId_', line):
            addrID, addrName = re.search('^addrObjFqdnId_(.*)=(.*)', line).groups()
            addrName = urllib.unquote(addrName)
        elif re.match(str("^addrObjFqdnType_"+addrID), line):
            addrType = re.search(str("^addrObjFqdnType_"+addrID+"=(.*)"), line).group(1)
        elif re.match(str("^addrObjFqdnZone_"+addrID), line):
            addrZone = re.search(str("^addrObjFqdnZone_"+addrID+"=(.*)"), line).group(1)
            if addrZone == "":
                addrZone = "None"
        elif re.match(str("^addrObjFqdn_"+addrID), line):
            addrFqdn = re.search(str("^addrObjFqdn_"+addrID+"=(.*)"), line).group(1)
        if addrID and addrName and addrType and addrZone and addrFqdn:
            addrFqdnObjects[addrName] = {
                "addrZone": addrZone,
                "addrFqdn": addrFqdn,
            }
            addrID=""
            addrName=""
            addrType=""
            addrFqdn=""
            addrZone=""


    if re.match('^addrObj', line):
        if re.match('^addrObjId_', line):
            addrID, addrName = re.search('^addrObjId_(.*)=(.*)', line).groups()
            addrName = urllib.unquote(addrName)
        elif re.match(str("^addrObjType_"+addrID), line):
            addrType = re.search(str("^addrObjType_"+addrID+"=(.*)"), line).group(1)
        elif re.match(str("^addrObjZone_"+addrID), line):
            addrZone = re.search(str("^addrObjZone_"+addrID+"=(.*)"), line).group(1)
            if addrZone == "":
                addrZone = "None"
        elif re.match(str("^addrObjIp1_"+addrID), line):
            addrIP = re.search(str("^addrObjIp1_"+addrID+"=(.*)"), line).group(1)
        elif re.match(str("^addrObjIp2_"+addrID), line):
            addrSubnet = re.search(str("^addrObjIp2_"+addrID+"=(.*)"), line).group(1)
        if addrID and addrName and addrType and addrZone and addrIP and addrSubnet:
            addrObjects[addrName] = {
                "addrZone": addrZone,
                "addrIP": addrIP,
                "addrSubnet": addrSubnet,
                "addrType": addrType
            }
            addrID=""
            addrName=""
            addrType=""
            addrIP=""
            addrZone=""
            addrSubnet=""

    if re.match('^so_', line):
        if re.match('^so_atomToGrp_', line):
            sgroupID, sgroupObject = re.search('^so_atomToGrp_(\d+)=(.*)', line).groups()
            sgroupObject = urllib.unquote(sgroupObject)
            nextsPattern="^so_grpToGrp_"+sgroupID
            nextsGroupPattern=nextsPattern+'=(.*)'
        elif re.match(nextsPattern, line):
            sgroupName = re.search(nextsGroupPattern, line).group(1)
            sgroupName = urllib.unquote(sgroupName)
            if sgroupName not in serviceGroups:
                serviceGroups[sgroupName] = []
                serviceGroups[sgroupName].append(sgroupObject)
            else:
                serviceGroups[sgroupName].append(sgroupObject)

    if re.match('^svcObj', line):
        if re.match('^svcObjId_', line):
            serviceID, serviceName = re.search('^svcObjId_(.*)=(.*)', line).groups()
            serviceName = urllib.unquote(serviceName)
        elif re.match(str("^svcObjType_"+serviceID), line):
            serviceType = re.search(str("^svcObjType_"+serviceID+"=(.*)"), line).group(1)
        elif re.match(str("^svcObjIpType_"+serviceID), line):
            serviceProtocol = re.search(str("^svcObjIpType_"+serviceID+"=(.*)"), line).group(1)
        elif re.match(str("^svcObjPort1_"+serviceID), line):
            serviceStartPort = re.search(str("^svcObjPort1_"+serviceID+"=(.*)"), line).group(1)
        elif re.match(str("^svcObjPort2_"+serviceID), line):
            serviceEndPort = re.search(str("^svcObjPort2_"+serviceID+"=(.*)"), line).group(1)
        if serviceID and serviceName and serviceProtocol and serviceStartPort and serviceEndPort:
            if serviceType == "2":
                serviceProtocol = "NA"
                serviceType = "Group"
                serviceEndPort = "NA"
                serviceStartPort = "NA"
            elif serviceType == "1":
                serviceType = "Object"
            if serviceProtocol == "17":
                serviceProtocol = "UDP"
            elif serviceProtocol == "6":
                serviceProtocol = "TCP"
            serviceObjects[serviceName] = {
                "serviceStartPort": serviceStartPort,
                "serviceEndPort": serviceEndPort,
                "serviceProtocol": serviceProtocol,
                "serviceType": serviceType
            }
            serviceID=""
            serviceName=""
            serviceStartPort=""
            serviceEndPort=""

    if re.match('^natPolicy', line):
        natField, natRuleID, natValue = re.search('^natPolicy(.*)_(\d+)=(.*)', line).groups()
        if re.match('^natPolicyOrigSrc', line):
            if natValue:
                natOrigSrc = natValue
            else:
                natOrigSrc = "Any"
        elif re.match('^natPolicyOrigDst', line):
            if natValue:
                natOrigDest = natValue
            else:
                natOrigDest = "Any"
        elif re.match('^natPolicyOrigSvc', line):
            if natValue:
                natOrigService = natValue
            else:
                natOrigService = "Any"
        elif re.match('^natPolicyTransSrc', line):
            if natValue:
                natTransSrc = natValue
            else:
                natTransSrc = "Any"
        elif re.match('^natPolicyTransDst', line):
            if natValue:
                natTransDest = natValue
            else:
                natTransDest = "original"
        elif re.match('^natPolicyTransSvc', line):
            if natValue:
                natTransService = natValue
            else:
                natTransService = "original"
        elif re.match('^natPolicySrcIface', line):
            if natValue and natValue != "-1":
                natSrcInterface = interfaces[natValue].get('ifaceName', "Not Found")
            else:
                natSrcInterface = "Any"
            if natValue == '-1':
                natSrcZone == "Not Found"
            else:
                natSrcZone = interfaces[natValue].get('interfaceZone', "Not Found")
        elif re.match('^natPolicyDstIface', line):
            if natValue and natValue != "-1":
                natDestInterface = interfaces[natValue].get('ifaceName', "Not Found")
            else:
                natDestInterface = "Any"
            if natValue == '-1':
                natDestZone == "Not Found"
            else:
                natDestZone = interfaces[natValue].get('interfaceZone', "Not Found")
        elif re.match('^natPolicyReflexive', line):
            if natValue == "1":
                natReflexive = "Enabled"
            elif natValue == "0":
                natReflexive = "Disabled"
        elif re.match('^natPolicyComment', line):
            if not natValue:
                natComment = "No Comment!"
            else:
                natComment = natValue
        elif re.match('^natPolicyEnabled', line):
            if natValue == "1":
                natStatus = "Enabled"
            else:
                natStatus = "Disabled"
        if natRuleID and natOrigSrc and natOrigDest and natOrigService and natTransSrc and natTransDest and natTransService and natSrcInterface and natDestInterface and natReflexive and natComment and natStatus:
            # Sonicwall is goofy and has some enabled rules set to 0 when its an auto-added rule
            if re.match('^Auto', natComment) and natStatus == "Disabled":
                natstatus = "Enabled"
            
            if natSrcZone == '':
                natSrcZone = "Not Found"
            
            if natDestZone == '':
                natDestZone = "Not Found"

            natRule= {
                "natRuleID": natRuleID,
                "natOrigSrc": urllib.unquote(natOrigSrc),
                "natOrigDest": urllib.unquote(natOrigDest),
                "natOrigService": urllib.unquote(natOrigService),
                "natTransSrc": urllib.unquote(natTransSrc),
                "natTransDest": urllib.unquote(natTransDest),
                "natTransService": urllib.unquote(natTransService),
                "natSrcInterface": urllib.unquote(natSrcInterface),
                "natDestInterface": urllib.unquote(natDestInterface),
                "natSrcZone": urllib.unquote(natSrcZone),
                "natDestZone": urllib.unquote(natDestZone),
                "natReflexive": urllib.unquote(natReflexive),
                "natComment": urllib.unquote(natComment),
                "natStatus": natStatus,
            }
            natRules.append(natRule)
            natRuleID = ""
            natOrigSrc = ""
            natOrigDest = ""
            natOrigService = ""
            natTransSrc = ""
            natTransDest = ""
            natTransService = ""
            natSrcInterface = ""
            natDestInterface = ""
            natSrcZone = ""
            natDestZone = ""
            natReflexive = ""
            natComment = ""
            natStatus = ""

print ""
print "=========================================================="
print "================== Interface Objects ====================="
print "=========================================================="
print ""
print "ifaceIfNum, ifaceName, ifaceType, interfaceZone, ifaceIp, ifaceMask, ifaceVlanTag, ifaceVlanParent, ifaceComment"
oInterfaces = collections.OrderedDict(sorted(interfaces.items()))
for interface, interfaceFields in oInterfaces.iteritems():
    print '%s,%s,%s,%s,%s,%s,%s,%s,%s' % (interfaceFields["ifaceIfNum"], interfaceFields["ifaceName"], interfaceFields["ifaceType"], interfaceFields["interfaceZone"], interfaceFields["ifaceIp"], interfaceFields["ifaceMask"], interfaceFields["ifaceVlanTag"], interfaceFields["ifaceVlanParent"], interfaceFields["ifaceComment"])

print "=========================================================="
print "================== Firewall Rules ========================"
print "=========================================================="
print ""
print "RuleID,Source Zone,Dest Zone,Source Net,Dest Net, Dest Service, Action, Status, Comment"
for x in rules:
    if x["ruleSrcZone"] != prevSrcZone or x["ruleDestZone"] != prevDestZone:
        print '\n\nSource Zone: %s, Dest Zone: %s' % (x["ruleSrcZone"], x["ruleDestZone"])
    print '%s,%s,%s,%s,%s,%s,%s,%s,%s' % (x["ruleID"], x["ruleSrcZone"], x["ruleDestZone"], x["ruleSrcNet"], x["ruleDestNet"], x["ruleDestService"], x["ruleAction"], x["ruleStatus"], x["ruleComment"])
    prevSrcZone=x["ruleSrcZone"]
    prevDestZone=x["ruleDestZone"]

print "=========================================================="
print "================== Nat Rules ========================"
print "=========================================================="
print ""
print "natRuleID, natOrigSrc,  natTransSrc, natOrigService, natOrigDest, natTransDest, natTransService, natSrcInterface, natSrcZone, natDestInterface, natDestzone, natReflexive, natStatus, natComment"
for x in natRules:
    if x['natSrcZone'] == 'Not Found':
        if x['natOrigSrc'] in addrGroups:
            x['natSrcZone'] = addrObjects.get(addrGroups[x['natOrigSrc']][0], {'addrZone': 'Unknown'}).get('addrZone', 'Unknown')
        elif x['natOrigSrc'] in addrObjects:
            x['natSrcZone'] = addrObjects[x['natOrigSrc']]['addrZone']
        elif x['natOrigSrc'] in addrFqdnObjects:
            x['natSrcZone'] = addrFqdnObjects[x['natOrigSrc']]['addrZone']
        else:
            x['natSrcZone'] = "Unknown"

    # One more attempt to look up SrcZone
    if x['natSrcZone'] == 'Unknown':
        if x['natOrigDest'] in addrGroups:
            x['natSrcZone'] = addrObjects.get(addrGroups[x['natOrigDest']][0], {'addrZone': 'Unknown'}).get('addrZone', 'Unknown')
        elif x['natOrigDest'] in addrObjects:
            x['natSrcZone'] = addrObjects[x['natOrigDest']]['addrZone']
        elif x['natOrigDest'] in addrFqdnObjects:
            x['natSrcZone'] = addrFqdnObjects[x['natOrigDest']]['addrZone']
        else:
            x['natSrcZone'] = "Unknown"

    if x['natDestZone'] == 'Not Found':
        if x['natTransDest'] in addrGroups:
            x['natDestZone'] = addrObjects.get(addrGroups[x['natTransDest']][0], {'addrZone': 'Unknown'}).get('addrZone', 'Unknown')
        elif x['natTransDest'] in addrObjects:
            x['natDestZone'] = addrObjects[x['natTransDest']]['addrZone']
        elif x['natTransDest'] in addrFqdnObjects:
            x['natDestZone'] = addrFqdnObjects[x['natTransDest']]['addrZone']
        else:
            x['natDestZone'] = "Unknown"

    # One more attempt to look up DestZone
    if x['natDestZone'] == 'Unknown':
        if x['natTransSrc'] in addrGroups:
            x['natDestZone'] = addrObjects.get(addrGroups[x['natTransSrc']][0], {'addrZone': 'Unknown'}).get('addrZone', 'Unknown')
        elif x['natTransSrc'] in addrObjects:
            x['natDestZone'] = addrObjects[x['natTransSrc']]['addrZone']
        elif x['natTransSrc'] in addrFqdnObjects:
            x['natDestZone'] = addrFqdnObjects[x['natTransSrc']]['addrZone']
        else:
            x['natDestZone'] = "Unknown"

    print '%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s' % (x["natRuleID"], x["natOrigSrc"], x["natTransSrc"], x["natOrigService"], x["natOrigDest"], x["natTransDest"], x["natTransService"], x["natSrcInterface"], x["natSrcZone"], x["natDestInterface"], x["natDestZone"], x["natReflexive"], x["natStatus"], x["natComment"])
    
print ""
print "=========================================================="
print "================== IP Address Objects ===================="
print "=========================================================="
print ""
print "Object Name,Zone,IP,Subnet"
oAddrObjects = collections.OrderedDict(sorted(addrObjects.items()))
for addr, addrFields in oAddrObjects.iteritems():
    print '%s,%s,%s,%s' % (addr, addrFields["addrZone"], addrFields["addrIP"], addrFields["addrSubnet"])

print ""
print "=========================================================="
print "================== FQDN Address Objects ======================="
print "=========================================================="
print ""
print "Object Name,Zone,FQDN"
oAddrFqdnObjects = collections.OrderedDict(sorted(addrFqdnObjects.items()))
for addr, addrFields in oAddrFqdnObjects.iteritems():
    print '%s,%s,%s' % (addr, addrFields["addrZone"], addrFields["addrFqdn"])

print ""
print "=========================================================="
print "================== Address Groups ========================"
print "=========================================================="
print ""
for group,groupObjects in addrGroups.iteritems():
    print group
    for groupObj in groupObjects:
        print "\t%s" % groupObj
    print ""

print ""
print "=========================================================="
print "================== Service Objects ======================="
print "=========================================================="
print ""
print "Service Name, Start Port, EndPort, Protocol, ObjectType"
oServiceObjects = collections.OrderedDict(sorted(serviceObjects.items()))
for service,serviceFields in oServiceObjects.iteritems():
    print '%s,%s-%s,%s,%s' % (service, serviceFields["serviceStartPort"], serviceFields["serviceEndPort"], serviceFields["serviceProtocol"], serviceFields["serviceType"])

print ""
print "=========================================================="
print "================== Service Groups ========================"
print "=========================================================="
print ""
for serviceGroup,serviceGroupObjects in serviceGroups.iteritems():
    print serviceGroup
    for serviceObj in serviceGroupObjects:
        #print serviceObj
        print "\t%s" % serviceObj
    print ""

