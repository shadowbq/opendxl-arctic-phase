# Suricata methods
import os
import json

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
