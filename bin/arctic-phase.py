#!/usr/bin/env python
import yaml
import sys
import re
import json
import logging
import os

from dxlclient.client import DxlClient
from dxlclient.client_config import DxlClientConfig
from dxltieclient import TieClient
from dxltieclient.constants import HashType

LOCAL_SAMPLES="samples/"
LOCAL_RESULTS="var/log/suricata/"

# Import common logging and configuration
sys.path.append(os.path.dirname(os.path.abspath(__file__)) + "/../src/")
from common import *

# Configure local logger
logging.getLogger().setLevel(logging.ERROR)
logger = logging.getLogger(__name__)

# Create DXL configuration from file
config = DxlClientConfig.create_dxl_config_from_file(CONFIG_FILE)

# Create the client
with DxlClient(config) as client:

  # Connect to the fabric
  client.connect()

  # Create the McAfee Threat Intelligence Exchange (TIE) client
  tie_client = TieClient(client)


  with open(LOCAL_RESULTS + "files/file.44.meta", 'r') as stream:
    try:
        dataMap = yaml.load(stream)
    except yaml.YAMLError as exc:
      print(exc)

  print ""
  print "=-----------="
  print "dataMap is a ", type(dataMap), dataMap
  print "=-----------="
  print "product items are", dataMap['STATE']
  print "product items are", dataMap['MD5']
  print "product items are", dataMap['SHA1']
  print "product items are", dataMap['MAGIC']
  print "=-----------="
  print ""

  if dataMap['STATE'] == 'CLOSED':

    print "the file is closed"
    p = re.compile('PE32')
    match = p.match(dataMap['MAGIC'])
    if match:
        print 'Found PE32 file'
        reputation_lookup_dict = \
          {
            HashType.MD5: dataMap['MD5'],
            HashType.SHA1: dataMap['SHA1']
          }
        print "rep_lookup is a ", type(reputation_lookup_dict), reputation_lookup_dict
        reputations_dict = tie_client.get_file_reputation(reputation_lookup_dict)
        print json.dumps(reputations_dict, sort_keys=True, indent=4, separators=(',', ': ')) + "\n"
    else:
        print 'No Match'

sys.exit(0)
