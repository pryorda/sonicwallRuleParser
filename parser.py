#!/usr/bin/python

import re
import sys
import urllib


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

for x in rules:
    #for k,v in x.iteritems():
    #    print k, v
    print '%s,%s,%s,%s,%s,%s,%s' % (x["ruleSrcZone"], x["ruleDestZone"], x["ruleSrcNet"], x["ruleDestNet"], x["ruleDestService"], x["ruleAction"], x["ruleComment"])
