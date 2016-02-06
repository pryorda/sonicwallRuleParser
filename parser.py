#!/usr/bin/python

import re
import sys
import urllib
import collections



with open(sys.argv[1], 'r') as f:
    read_data = f.readlines()
f.close()

rules=[]
ruleSrcNet=""
ruleSrcZone=""
ruleDestNet=""
ruleDestZone=""
ruleDestService=""
ruleComment=""
ruleAction=""
addrGroups={}
id=""
groupObject=""
addrObjects={}
addrName=""
addrIP=""
addrSubnet=""
addrZone=""
addrType=""
addrID=""

for line in read_data:
    line = line.strip()
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
                ruleAction = "ALLOW"
            else:
                ruleAction = "DENY"
        if ruleSrcZone and ruleDestZone and ruleSrcNet and ruleDestNet and ruleDestService and ruleAction and ruleComment:
            rule={
                "ruleID": policyID,
                "ruleSrcZone": ruleSrcZone,
                "ruleDestZone": ruleDestZone,
                "ruleSrcNet": urllib.unquote(ruleSrcNet),
                "ruleDestNet": urllib.unquote(ruleDestNet),
                "ruleDestService": urllib.unquote(ruleDestService),
                "ruleAction": ruleAction,
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

    if re.match('^addro_', line):
        if re.match('^addro_atomToGrp_', line):
            id, groupObject = re.search('^addro_atomToGrp_(\d+)=(.*)', line).groups()
            groupObject = urllib.unquote(groupObject)
            nextPattern="^addro_grpToGrp_"+id
            nextGroupPattern=nextPattern+'=(.*)'
        elif re.match(nextPattern, line):
            groupName = re.search(nextGroupPattern, line).group(1)
            groupName = urllib.unquote(groupName)
            if groupName not in addrGroups:
                addrGroups[groupName] = []
                addrGroups[groupName].append(groupObject)
            else:
                addrGroups[groupName].append(groupObject)

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



print "Source Zone,Dest Zone,Source Net,Dest Net, Dest Service, Action, Comment"
for x in rules:
#    #for k,v in x.iteritems():
#    #    print k, v
    print '%s,%s,%s,%s,%s,%s,%s' % (x["ruleSrcZone"], x["ruleDestZone"], x["ruleSrcNet"], x["ruleDestNet"], x["ruleDestService"], x["ruleAction"], x["ruleComment"])

print ""
print "=========================================================="
print "================== Address Objects ======================="
print "=========================================================="
print "Address Name, Zone,IP, Subnet"
oAddrObjects = collections.OrderedDict(sorted(addrObjects.items()))
for addr,addrFields in oAddrObjects.iteritems():
    print '%s,%s,%s,%s' % (addr, addrFields["addrZone"], addrFields["addrIP"], addrFields["addrSubnet"])
print ""
print "=========================================================="
print "================== Address Groups ========================"
print "=========================================================="
for group,groupObjects in addrGroups.iteritems():
    print group
    for groupObj in groupObjects:
        print "\t", groupObj
    print ""

