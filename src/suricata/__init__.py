# Suricata methods
import os
import json

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

BLACKLIST="/etc/suricata/rules/blacklist.md5"

def addtosuricatablacklist(md5):
  try:
      blacklist_fh = open(BLACKLIST, "a")
      blacklist_fh.write(md5)
      blacklist_fh.write("\n")
      blacklist_fh.close()
  except:
      print "suricata blacklist file is not available"


class SuricataEve(object):

    def __init__(self, options):
        eve_dict = \
          {
              "timestamp": "2009-11-24T21:27:09.534255",
              "event_type": "alert",
              "src_ip": "192.168.2.7",
              "src_port": 1041,
              "dest_ip": "x.x.250.50",
              "dest_port": 80,
              "proto": "TCP",
              "alert": {
                  "action": "allowed",
                  "gid": 1,
                  "signature_id" :2001999,
                  "rev": 9,
                  "signature": "ET MALWARE BTGrab.com Spyware Downloading Ads",
                  "category": "A Network Trojan was detected",
                  "severity": 1
              }
          }
        print json.dumps(eve_dict, sort_keys=True, indent=4, separators=(',', ': '))
