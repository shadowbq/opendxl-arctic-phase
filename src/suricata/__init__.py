# Suricata methods
import os
import json
import yaml
from datetime import datetime

from common import *

# TIE Provider Map
providerMap = {1: 'GTI', 3: 'Enterprise Reputation', 5: 'ATD', 7: 'MWG'}
gid = 969
severityMap = {'unknown': 0, 'bad':1, 'medium':2, 'good':3}
protoMap = {6: 'TCP', 17: 'UDP'}
BlacklistFile="/etc/suricata/rules/blacklist.md5"
AlertFile="/var/log/suricata/tieAlerts.eve.json"

"""

## Although we dont write these rules, the post-processor would create alerts like this
## alert http any any -> any any (msg:"McAfee TIE - Bad file reputation identified by GTI"; filemagic:"exe"; filemd5:blacklist.md5; gid:969; sid:11; rev:1;)

# This standard alert can be written for blocking anything already in the blacklist.
## alert http any any -> any any (msg:"Blacklisted File traversed"; filemagic:"exe"; filemd5:blacklist.md5; gid:1; sid:9000011; rev:1;)

# Severity maps to reputation score
GID is always 969.
SID 10's digit is the products / 1's digit is the verdict

[1,3,5,7] is Product maps GTI/ER/ATD/MWG
[1,2,3] are the levels bad/medium/good


"gid": 969,
"signature_id" :11,
"rev": 1,
"signature": "McAfee TIE - Bad file reputation identified by GTI",

"gid": 969,
"signature_id" :31,
"rev": 1,
"signature": "McAfee TIE - Bad file reputation identified by Enterprise Reputation",

"gid": 969,
"signature_id" :51,
"rev": 1,
"signature": "McAfee TIE - Bad file reputation identified by ATD",

"gid": 969,
"signature_id" :71,
"rev": 1,
"signature": "McAfee TIE - Bad file reputation identified by MWG",



"gid": 969,
"signature_id" :12,
"rev": 1,
"signature": "McAfee TIE - Medium file reputation identified by GTI",
"""

def addtosuricatablacklist(md5):
  try:
      blacklist_fh = open(BlacklistFile, "a")
      blacklist_fh.write(md5)
      blacklist_fh.write("\n")
      blacklist_fh.close()
  except:
      print "suricata blacklist file is not available"


class SuricataEve(object):

    def __init__(self, metaFile, reputation):
        timestamp = datetime.now().strftime('%Y-%m-%dT%H:%M:%S.%f')
        sig = self.build_signature(reputation)
        eve_dict = \
          {
              "timestamp": timestamp,
              "event_type": "alert",
              "src_ip": metaFile["SRC IP"],
              "src_port": metaFile["SRC PORT"],
              "dest_ip": metaFile["DST IP"],
              "dest_port": metaFile["DST PORT"],
              "proto": protoMap[metaFile["PROTO"]],
              "alert": {
                  "action": "allowed",
                  "gid": gid,
                  "signature_id" :sig['sig_id'],
                  "rev": 1,
                  "signature": sig['signature'],
                  "category": "A Network Trojan was detected",
                  "severity": 1
              }
          }

        logger.warning(json.dumps(eve_dict, sort_keys=True, indent=4, separators=(',', ': ')))
        self.add_to_alert_file(json.dumps(eve_dict, separators=(',',':')))

    def build_signature(self, reputation):
        #import code; code.interact(local=dict(globals(), **locals()))
        sig_id = reputation[2]*10 + severityMap[reputation[1]]
        return {'sig_id': sig_id, 'signature': 'McAfee TIE - '+ reputation[1] +' file reputation identified by ' + providerMap[reputation[2]]}

    def add_to_alert_file(self, jsonAlert):
      try:
          alertfile_fh = open(AlertFile, "a")
          alertfile_fh.write(jsonAlert)
          alertfile_fh.write("\n")
          alertfile_fh.close()
      except:
          print "suricata alert file is not available"
