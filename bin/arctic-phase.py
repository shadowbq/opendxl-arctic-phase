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
from dxltieclient.constants import HashType, ReputationProp, FileProvider, FileEnterpriseAttrib, \
    CertProvider, CertEnterpriseAttrib

VERBOSE = 0

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

def verbose(x, y=0):
    if VERBOSE > y:
        print x
    else:
        0 #No Op


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

  #print ""
  #print "=-----------="
  #print "dataMap is a ", type(dataMap), dataMap
  verbose("=-----------=")
  verbose("File State: {0}".format(dataMap['STATE']))
  verbose("MD5: {0}".format(dataMap['MD5']))
  verbose("SHA1: {0}".format(dataMap['SHA1']))
  verbose("MAGIC: {0}".format(dataMap['MAGIC']))
  verbose("=-----------=")

  if dataMap['STATE'] == 'CLOSED':

    #print "the file is closed"
    p = re.compile('PE32')
    match = p.match(dataMap['MAGIC'])
    if match:
        verbose('Found PE32 file', 2)
        verbose("=-----------=", 2)
        reputation_lookup_dict = \
          {
            HashType.MD5: dataMap['MD5'],
            HashType.SHA1: dataMap['SHA1']
          }
        #print "rep_lookup is a ", type(reputation_lookup_dict), reputation_lookup_dict
        reputations_dict = tie_client.get_file_reputation(reputation_lookup_dict)
        output = json.dumps(reputations_dict, sort_keys=True, indent=4, separators=(',', ': ')) + "\n"
        verbose(output, 2)

        # Display the Global Threat Intelligence (GTI) trust level for the file
        if FileProvider.GTI in reputations_dict:
            gti_rep = reputations_dict[FileProvider.GTI]
            print "Global Threat Intelligence (GTI) trust level: " + \
                  str(gti_rep[ReputationProp.TRUST_LEVEL])

        # Display the Enterprise reputation information
        if FileProvider.ENTERPRISE in reputations_dict:
            ent_rep = reputations_dict[FileProvider.ENTERPRISE]

            print "Threat Intelligence Exchange (Local) trust level: " + \
                  str(ent_rep[ReputationProp.TRUST_LEVEL])

            # Retrieve the enterprise reputation attributes
            ent_rep_attribs = ent_rep[ReputationProp.ATTRIBUTES]

            # Display prevalence (if it exists)
            if FileEnterpriseAttrib.PREVALENCE in ent_rep_attribs:
                print "Enterprise prevalence: " + \
                      ent_rep_attribs[FileEnterpriseAttrib.PREVALENCE]

            # Display first contact date (if it exists)
            if FileEnterpriseAttrib.FIRST_CONTACT in ent_rep_attribs:
                print "First contact: " + \
                      FileEnterpriseAttrib.to_localtime_string(
                          ent_rep_attribs[FileEnterpriseAttrib.FIRST_CONTACT])

    else:
        print 'No Match'

sys.exit(0)
