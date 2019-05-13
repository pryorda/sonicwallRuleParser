#!/usr/local/bin/python

import re
import sys
import urllib
import collections
import base64
from netaddr import IPAddress
import uuid


with open(sys.argv[1], 'r') as f:
    read_data = f.readline()
f.close()

decoded_data = base64.b64decode(read_data)
decoded_data = decoded_data.split("&")

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
ifaceGateway=""
ifaceStaticIp = ""
ifaceStaticMask = ""

# function: terraformEncode(dirty_data)
# descrtion: you know encodes it in a friendly way for terraform and pan providers
def terraformEncode(dirty_data):
    remove_special = re.sub("[^A-Za-z0-9]+", '_', dirty_data)
    clean_data = re.sub("_{2,4}", '', remove_special)
    return clean_data

for line in decoded_data:
    # print line
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
            elif ifaceType == "8":
                ifaceType = "tunnel"
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
        elif re.match(str("^iface_static_ip_"+ifaceID), line):
            ifaceStaticIp = re.search(str("^iface_static_ip_"+ifaceID+"=(.*)"), line).group(1)
        elif re.match(str("^iface_static_mask_"+ifaceID), line):
            ifaceStaticMask = re.search(str("^iface_static_mask_"+ifaceID+"=(.*)"), line).group(1)
        elif re.match(str("^iface_static_gateway_"+ifaceID), line):
            ifaceGateway = re.search(str("^iface_static_gateway_"+ifaceID+"=(.*)"), line).group(1)
        
        if ifaceID and ifaceIfNum and ifaceName and ifaceType and interfaceZone and ifaceComment and ifaceIp and ifaceMask and ifaceVlanTag and ifaceVlanParent:
            if ifaceStaticMask != "255.255.255.0" and ifaceStaticIp != "0.0.0.0":
                ifaceIp = ifaceStaticIp
                ifaceMask = ifaceStaticMask
            
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
                "ifaceGateway": ifaceGateway
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
            ifaceGateway = ""
            ifaceStaticMask = ""
            ifaceStaticIp = ""

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
                natTransSrc = "original"
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

policy_builder=""
with open("security-policies.tf", "w+") as security_policies:
    for rule in rules:    
        if ("Auto-added" in rule["ruleComment"]) or ("Auto added" in rule["ruleComment"]) or ("Disabled" in rule['ruleStatus']):
            continue
        if rule["ruleSrcZone"] != prevSrcZone or rule["ruleDestZone"] != prevDestZone:
            if rules.index(rule) != 0 and policy_builder != "":
                policy_builder += ' }'
            policy_builder += ' resource "panos_security_policy_group" "' + rule["ruleSrcZone"] + "_to_" + rule["ruleDestZone"] + '" {'
        action = ""
        if rule['ruleAction'] == "Discard":
            action = "drop"
        else:
            action = rule['ruleAction'].lower()
        
        src_net = ""
        formatted_src_net = terraformEncode(rule['ruleSrcNet'])
        if rule['ruleSrcNet'].lower() == "any":
            src_net = "any"
        elif rule['ruleSrcNet'] in addrGroups:
            src_net = "${panos_address_group." + formatted_src_net + ".name}"
        elif rule['ruleSrcNet'] in addrObjects or rule['ruleSrcNet'] in addrFqdnObjects:
            src_net = "${panos_address_object." + formatted_src_net + ".name}"
        else:
            print "src_net: " + src_net + "orig: " + rule['ruleSrcNet']
        
        
        dest_net = ""
        formatted_dest_net = terraformEncode(rule['ruleDestNet'])
        if rule['ruleDestNet'].lower() == "any":
            dest_net = "any"
        elif rule['ruleDestNet'] in addrGroups:
            dest_net = "${panos_address_group." + formatted_dest_net + ".name}"
        elif rule['ruleDestNet'] in addrObjects or rule['ruleDestNet'] in addrFqdnObjects:
            dest_net = "${panos_address_object." + formatted_dest_net + ".name}"
        else:
            print "dest_net: " + dest_net + "orig: " + rule['ruleDestNet']
        
        service = ""
        formatted_service = terraformEncode(rule['ruleDestService'])
        if rule['ruleDestService'].lower() == "any":
            service = "any"
        elif rule['ruleDestService'] in serviceGroups:
            service = "${panos_service_group." + formatted_service + ".name}"
        elif rule['ruleDestService'] in serviceObjects:
            service = "${panos_service_object." + formatted_service + ".name}"
        else:
            print "service: " + service + "orig: " + rule['ruleDestService']
   
        name = "{src_zone}:{src_net} to {dest_zone}:{dest_net} service:{service} {action}".format(src_net=src_net, dest_net=dest_net, service=service, action=action,src_zone=rule["ruleSrcZone"],dest_zone=rule["ruleDestZone"])
        policy_builder += '''
    rule {{
        name = "${{sha1(\"{name}\")}}"
        source_zones = ["${{panos_zone.{src_zone}.name}}"]
        source_addresses = ["{src_net}"]
        source_users = ["any"]
        hip_profiles = ["any"]
        destination_zones = ["${{panos_zone.{dest_zone}.name}}"]
        destination_addresses = ["{dest_net}"]
        applications = ["any"]
        services = ["{service}"]
        categories = ["any"]
        action = "{action}"
        description = "{name} : {description}"
        tags = ["${{panos_administrative_tag.{src_zone}.name}}", "${{panos_administrative_tag.{dest_zone}.name}}", "${{panos_administrative_tag.MIGRATED.name}}"]
    }}
        '''.format(src_zone=rule["ruleSrcZone"], src_net=src_net, dest_zone=rule["ruleDestZone"], 
                    dest_net=dest_net, service=service, action=action,
                    description=rule["ruleComment"], name=name
                )
        
        prevSrcZone=rule["ruleSrcZone"]
        prevDestZone=rule["ruleDestZone"] 
    policy_builder += "}"
    security_policies.write(policy_builder)

with open("address-objects.tf", "w+") as address_objects:
    oAddrObjects = collections.OrderedDict(sorted(addrObjects.items()))
    for addr, addrFields in oAddrObjects.iteritems():
        if addrFields['addrType'] == '8':
           continue
        # print addr,addrFields
        terraform_friendly_name = terraformEncode(addr)
        cidr = IPAddress(addrFields['addrSubnet']).netmask_bits()
        if cidr == 0:
            cidr = 32
        if addrFields["addrZone"] == 'None':
            addrFields["addrZone"] = 'LAN'
        address_objects.write('\nresource "panos_address_object" "{terraform_friendly_name}" {{ \n name        = "{terraform_friendly_name}"\n tags = ["${{panos_administrative_tag.{zone}.name}}", "${{panos_administrative_tag.MIGRATED.name}}"] \n description = "{addr} in zone: {zone}" \n value       = "{ip}/{cidr}" \n}}'.format(terraform_friendly_name=terraform_friendly_name, addr=addr, zone=addrFields["addrZone"],ip=addrFields["addrIP"], cidr=cidr))

    oAddrFqdnObjects = collections.OrderedDict(sorted(addrFqdnObjects.items()))
    for addr, addrFields in oAddrFqdnObjects.iteritems():
        # print '"%s","%s","%s"' % (addr, addrFields["addrZone"], addrFields["addrFqdn"])
        terraform_friendly_name = terraformEncode(addr)
        address_objects.write('\nresource "panos_address_object" "{terraform_friendly_name}" {{ \n name        = "{addr}" \n type = "fqdn" \n tags = ["${{panos_administrative_tag.{zone}.name}}", "${{panos_administrative_tag.MIGRATED.name}}"] \n description = "{addr} in zone: {zone}" \n value       = "{fqdn}" \n}}'.format(terraform_friendly_name=terraform_friendly_name, addr=addr, zone=addrFields["addrZone"],fqdn=addrFields["addrFqdn"]))

with open("address-groups.tf", "w+") as address_groups:
    for group,groupObjects in addrGroups.iteritems():
        if group in ('Firewalled IPv6 Subnets'):
            continue
        formatted_name = terraformEncode(group)
        formatted_group_list = ""
        formatted_group_depends_list = ""
        for groupObj in groupObjects:
            if groupObj in ('DMZ Subnets', 'WLAN Subnets', 'Firewalled IPv6 Subnets'):
                continue
            formatted_object_name = terraformEncode(groupObj)
            if (groupObj in addrObjects or groupObj in addrFqdnObjects) and (groupObj not in addrGroups):
                formatted_group_list += "\"${{panos_address_object.{0}.name}}\",".format(formatted_object_name)
                formatted_group_depends_list += "\"panos_address_object.{0}\",".format(formatted_object_name)
            elif groupObj in addrGroups:
                formatted_group_list += "\"${{panos_address_group.{0}.name}}\",".format(formatted_object_name)
                formatted_group_depends_list += "\"panos_address_group.{0}\",".format(formatted_object_name)
        
        # Palo Alto does not support groups with 0 objects
        if formatted_group_list == "":
            continue
        address_groups.write('\nresource "panos_address_group" "{formatted_name}" {{\n  name = "{formatted_name}" \ntags = ["${{panos_administrative_tag.MIGRATED.name}}"]\n description = "{group}"\n static_addresses = [{formatted_group_list}] \n depends_on = [{formatted_group_depends_list}]}}'.format(formatted_name=formatted_name, group=group, formatted_group_list=formatted_group_list, formatted_group_depends_list=formatted_group_depends_list))

with open("service-objects.tf", "w+") as service_objects:
    oServiceObjects = collections.OrderedDict(sorted(serviceObjects.items()))
    for service,serviceFields in oServiceObjects.iteritems():
        service_formatted_name = terraformEncode(service)
        end_port = serviceFields["serviceEndPort"]
        start_port = serviceFields["serviceStartPort"]
        protocol = serviceFields["serviceProtocol"]
        service_type = serviceFields["serviceType"]
        if end_port != start_port:
            destination_port = start_port + "-" + end_port
        else:
            destination_port = end_port
        
        if (service_type not in ('Object')) or (protocol not in ('TCP','UDP')):
            continue

        service_objects.write('''
    resource "panos_service_object" "{service_formatted_name}" {{
        name = "{service_formatted_name}"
        tags = ["${{panos_administrative_tag.MIGRATED.name}}"]
        description = "{service}"
        protocol = "{protocol}"
        source_port = "{source_port}"
        destination_port = "{destination_port}"
    }}
        '''.format(service_formatted_name=service_formatted_name, service=service,
                protocol=protocol.lower(), source_port="any", destination_port=destination_port))

with open("service-groups.tf", "w+") as service_groups:
    for serviceGroup,serviceGroupObjects in serviceGroups.iteritems():
        if serviceGroup in ('Idle HF', 'Router Renumbering IPv6 Group', 'Destination Unreachable Group', "ICMP", "OSPF", "ICMP Node Information Query (IPv6) Group",
                            "Destination Unreachable (IPv6) Group", "Time Exceeded IPv6 Group", "Parameter Problem Group", "IGMP", "ICMPv6", "Time Exceeded Group",
                            "Parameter Problem (IPv6) Group", "Neighbor Discovery", "Ping", "Redirect Group", "Time Exceeded (IPv6) Group", "Ping6", "Router Renumbering (IPv6) Group",
                            "ICMP Node Information Response (IPv6) Group"
                            ):
                continue
        # print serviceGroup,serviceGroupObjects
        formatted_name = terraformEncode(serviceGroup)
        formatted_service_group_list = ""
        formatted_service_depends_list = ""
        for serviceObj in serviceGroupObjects:
            formatted_object_name = terraformEncode(serviceObj)
            if serviceObj in ("Ping 0", "Ping 8", "Ping"):
                continue
            if (serviceObj in serviceObjects) and (serviceObj not in serviceGroups):
                formatted_service_group_list += "\"${{panos_service_object.{0}.name}}\",".format(formatted_object_name)
                formatted_service_depends_list += "\"panos_service_object.{0}\",".format(formatted_object_name)
            elif serviceObj in serviceGroups:
                formatted_service_group_list += "\"${{panos_service_group.{0}.name}}\",".format(formatted_object_name)
                formatted_service_depends_list += "\"panos_service_group.{0}\",".format(formatted_object_name)
        # Palo Alto does not support groups with 0 objects
        if formatted_service_group_list == "":
            continue

        service_groups.write('''
        resource "panos_service_group" "{formatted_name}" {{
            name = "{formatted_name}"
            tags = ["${{panos_administrative_tag.MIGRATED.name}}"]
            services = [{formatted_service_group_list}]
            depends_on = [{formatted_service_depends_list}]
        }}'''.format(formatted_name=formatted_name, formatted_object_name=formatted_object_name, service_group=serviceGroup, formatted_service_group_list=formatted_service_group_list, formatted_service_depends_list=formatted_service_depends_list))

with open("nat-policies.tf", "w+") as nat_policies:
    exclusions = ["Management", "IKE NAT Policy", "Stack NAT Policy", " U0 ", " U1 ", "OSPF"]
    for x in natRules:
        skip = ""
        for exclusion in exclusions:
            if exclusion in x['natComment']:
                skip = True

        if skip == True:
            continue 

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

        nat_orig_src = x["natOrigSrc"]
        nat_trans_src = x["natTransSrc"]
        nat_orig_svc = x["natOrigService"]
        nat_orig_dest = x["natOrigDest"]
        nat_trans_dest = x["natTransDest"]
        nat_trans_svc = x["natTransService"]
        nat_src_iface = x["natSrcInterface"]
        nat_src_zone = x["natSrcZone"]
        nat_dest_iface = x["natDestInterface"]
        nat_dest_zone = x["natDestZone"]
        nat_reflexive = ["natReflexive"]
        nat_status = x["natStatus"]
        nat_comment = x["natComment"]
        
        # print '%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s' % (x["natRuleID"], x["natOrigSrc"], x["natTransSrc"], x["natOrigService"], x["natOrigDest"], x["natTransDest"], x["natTransService"], x["natSrcInterface"], x["natSrcZone"], x["natDestInterface"], x["natDestZone"], x["natReflexive"], x["natStatus"], x["natComment"])
        name = '%s:%s:%s:%s to %s:%s:%s:%s port %s:%s' % (nat_src_zone, nat_orig_src, nat_trans_src, nat_src_iface, nat_dest_zone, nat_orig_dest, nat_trans_dest, nat_dest_iface, nat_orig_svc,nat_trans_svc)
        formatted_name = terraformEncode(name)

        nat_tf_resource = ''' 
resource "panos_nat_rule" "{formatted_name}" {{
    name = "${{sha1(\"{name}\")}}"
    description = "{name} : {nat_comment}"\n'''.format(
                name=name, 
                formatted_name=formatted_name,
                nat_comment=nat_comment
            )

        formatted_nat_src_zone = terraformEncode(nat_src_zone)
        nat_tf_resource += '\tsource_zones = [ "${{panos_zone.{nat_src_zone}.name}}" ] \n'.format(nat_src_zone=formatted_nat_src_zone)
        formatted_nat_dest_zone = terraformEncode(nat_dest_zone)
        nat_tf_resource += '\tdestination_zone = "${{panos_zone.{nat_dest_zone}.name}}" \n'.format(nat_dest_zone=formatted_nat_dest_zone)
        # Update once you have the interfaces added
        # nat_tf_resource += '''\tto_interface = "${{panos_ethernet_interface or vlan interface}}"
        nat_tf_resource += '\tto_interface = "ethernet1/3"\n'
        
        # Look up orig src objects
        orig_src = ""
        sat_type = ""
        formatted_nat_orig_src = terraformEncode(nat_orig_src)
        if nat_orig_src.lower() == "any":
            orig_src = "any"
        elif nat_orig_src in addrGroups:
            orig_src = "${panos_address_group." + formatted_nat_orig_src + ".name}"
        elif nat_orig_src in addrObjects or nat_orig_src in addrFqdnObjects:
            orig_src = "${panos_address_object." + formatted_nat_orig_src + ".name}"
        else:
            print "orig_src: " + orig_src + "orig: " + nat_orig_src
        nat_tf_resource += '\tsource_addresses = ["{orig_src}"]\n'.format(orig_src=orig_src)
        
        # Look up translated src objects
        trans_src = ""
        formatted_nat_trans_src = terraformEncode(nat_trans_src)
        if nat_trans_src.lower() == "original":
            trans_src = "original"
        elif nat_trans_src in addrGroups:
            trans_src = "${panos_address_group." + formatted_nat_trans_src + ".name}"
        elif nat_trans_src in addrObjects or nat_trans_src in addrFqdnObjects:
            trans_src = "${panos_address_object." + formatted_nat_trans_src + ".name}"
        else:
            print "trans_src: " + trans_src + "orig: " + nat_trans_src

        # Set Source Address Translation if needed
        if trans_src != "original":
            nat_tf_resource += '\tsat_type = "static-ip"\n'
            nat_tf_resource += '\tsat_address_type = "translated-address"\n'
            # nat_tf_resource += '\tsat_interface         = "ethernet1/2"\n'
            nat_tf_resource += '\tsat_static_translated_address = "{trans_src}"\n'.format(trans_src=trans_src)
        else:
            nat_tf_resource += '\tsat_type = "none"\n'
        
        # Look up orig dest objects
        orig_dest = ""
        dat_type = ""
        formatted_nat_orig_dest = terraformEncode(nat_orig_dest)
        if nat_orig_dest.lower() == "any":
            orig_dest = "any"
        elif nat_orig_dest in addrGroups:
            orig_dest = "${panos_address_group." + formatted_nat_orig_dest + ".name}"
        elif nat_orig_dest in addrObjects or nat_orig_dest in addrFqdnObjects:
            orig_dest = "${panos_address_object." + formatted_nat_orig_dest + ".name}"
        else:
            print "orig_dest: " + orig_dest + "orig: " + nat_orig_dest
        nat_tf_resource += '\tdestination_addresses = ["{orig_dest}"]\n'.format(orig_dest=orig_dest)

        # Look up translated dest objects
        trans_dest = ""
        formatted_nat_trans_dest = terraformEncode(nat_trans_dest)
        if nat_trans_dest.lower() == "original":
            trans_dest = "original"
        elif nat_trans_dest in addrGroups:
            trans_dest = "${panos_address_group." + formatted_nat_trans_dest + ".name}"
        elif nat_trans_dest in addrObjects or nat_trans_dest in addrFqdnObjects:
            trans_dest = "${panos_address_object." + formatted_nat_trans_dest + ".name}"
        else:
            print "trans_dest: " + trans_dest + "orig: " + nat_trans_dest

        # Set Dest Address Translation
        if trans_dest != "original":
            nat_tf_resource += '\tdat_type = "static"\n'
            nat_tf_resource += '\tdat_address = "{trans_dest}"\n'.format(trans_dest=trans_dest)
        
        # Disable the rule
        if nat_status != "Enabled":
            nat_tf_resource += '\tdisabled = true\n'
        
        # Bidirectional nat 
        if nat_reflexive == "Enabled":
            nat_tf_resource += '\tsat_static_bi_directional = true\n'
        
        # Add ports here
        service = ""
        formatted_nat_orig_svc = terraformEncode(nat_orig_svc)
        if nat_orig_svc.lower() == "any":
            service = "any"
        elif nat_orig_svc in serviceGroups:
            service = "${panos_service_group." + formatted_nat_orig_svc + ".name}"
        elif nat_orig_svc in serviceObjects:
            service = "${panos_service_object." + formatted_nat_orig_svc + ".name}"
        else:
            print "service: " + service + "orig: " + nat_orig_svc
        
        if nat_orig_svc.lower() != "any":
            nat_tf_resource += '\tservice = "{service}"\n'.format(service=service)
        
        trans_svc = ""
        formatted_nat_trans_svc = terraformEncode(nat_trans_svc)
        if nat_trans_svc.lower() == "original":
            trans_svc = "original"
        elif nat_trans_svc in serviceGroups:
            # Keeping this here so if in the future they allow service groups in the dat_port.
            # When blank or not set it uses the original ports.
            # https://docs.paloaltonetworks.com/pan-os/8-0/pan-os-web-interface-help/policies/policies-nat/nat-translated-packet-tab.html
            # trans_svc = "${panos_service_group." + formatted_nat_trans_svc + ".destination_port}"
            # setting to original so it gets skipped.
            # Annoying.
            trans_svc = "original"
        elif nat_trans_svc in serviceObjects:
            trans_svc = "${panos_service_object." + formatted_nat_trans_svc + ".destination_port}"
        else:
            print "service: " + service + "orig: " + nat_trans_svc
        
        if trans_svc.lower() != "original":
            nat_tf_resource += '\tdat_port = "{trans_svc}"\n'.format(trans_svc=trans_svc)

        
        nat_tf_resource += '}\n'
        nat_policies.write(nat_tf_resource)

with open("interfaces.tf", "w+") as interfaces_resources:
    oInterfaces = collections.OrderedDict(sorted(interfaces.items()))
    for interface, interfaceFields in oInterfaces.iteritems():
        interface_num = interfaceFields["ifaceIfNum"]
        interface_name = urllib.unquote(interfaceFields["ifaceName"])
        interface_type = interfaceFields["ifaceType"]
        interface_zone = urllib.unquote(interfaceFields["interfaceZone"])
        interface_ip = interfaceFields["ifaceIp"]
        interface_mask = interfaceFields["ifaceMask"]
        interface_vlan_tag = interfaceFields["ifaceVlanTag"]
        interface_vlan_parent = interfaceFields["ifaceVlanParent"]
        interface_comment = urllib.unquote(interfaceFields["ifaceComment"])
        interface_tf_resource = ''

        if interface_ip == "0.0.0.0" and interface_mask == "255.255.255.0":
            continue
        
        interface_mask_cidr = IPAddress(interface_mask).netmask_bits() 
        parsed_interface_id = re.match('[A-Z](\d+)', interface_name).group(1)

        interface_friendly_name = terraformEncode(interface_name)
        if interface_type == "vlan" or interface_name == "X0":
            interface_tf_resource = '''
resource "panos_vlan_interface" "{interface_friendly_name}" {{
    name = "vlan.{interface_vlan_tag}"
    static_ips = ["{interface_ip}/{interface_mask_cidr}"]
    comment = "{interface_comment}"
}}
            '''.format(
                    interface_friendly_name=interface_friendly_name, 
                    interface_vlan_tag=interface_vlan_tag, 
                    interface_ip=interface_ip, 
                    interface_mask_cidr=interface_mask_cidr,
                    interface_comment=interface_comment
                )

        elif interface_type == "tunnel":
            interface_tf_resource = '''
resource "panos_tunnel_interface" "{interface_friendly_name}" {{
    name = "tunnel.{parsed_interface_id}"
    static_ips = ["{interface_ip}/{interface_mask_cidr}"]
    comment = "{interface_comment}"
}}
            '''.format(
                    interface_friendly_name=interface_friendly_name,
                    parsed_interface_id=parsed_interface_id,
                    interface_ip=interface_ip,
                    interface_mask_cidr=interface_mask_cidr,
                    interface_comment=interface_comment
                )
        elif interface_type == "Phys":
            interface_tf_resource = '''
resource "panos_ethernet_interface" "{interface_friendly_name}" {{
    name = "ethernet1/{parsed_interface_id}"
    mode = "layer3"
    static_ips = ["{interface_ip}/{interface_mask_cidr}"]
    comment = "{interface_comment}"
}}
            '''.format(
                    interface_friendly_name=interface_friendly_name,
                    parsed_interface_id=parsed_interface_id,
                    interface_ip=interface_ip, 
                    interface_mask_cidr=interface_mask_cidr,
                    interface_comment=interface_comment
                )
        
        if interface_tf_resource != "": 
            interfaces_resources.write(interface_tf_resource)

"""

        print '%s,%s,%s,%s,%s,%s,%s,%s,%s' % (interface_num, interface_name, interface_type, interface_zone, interface_ip, interface_mask_cidr, interface_vlan_tag, interface_vlan_parent, interface_comment)


resource "panos_vlan_interface" "example" {
    name = "vlan.17"
    vsys = "vsys1"
    mode = "layer3"
    static_ips = ["10.1.1.1/24"]
    comment = "Configured for internal traffic"
}
resource "panos_ethernet_interface" "example1" {
    name = "ethernet1/3"
    vsys = "vsys1"
    mode = "layer3"
    static_ips = ["10.1.1.1/24"]
    comment = "Configured for internal traffic"
}
"""


    