#!/usr/bin/env python
import yaml
import sys
import time
import re
import json
import logging
import os
import tempfile

from watchdog.observers import Observer
import watchdog.events

from dxlclient.client import DxlClient
from dxlclient.client_config import DxlClientConfig
from dxltieclient import TieClient
from dxltieclient.constants import HashType, ReputationProp, FileProvider, FileEnterpriseAttrib, \
    CertProvider, CertEnterpriseAttrib

VERBOSE = 0

LOCAL_SAMPLES="samples/"
LOCAL_RESULTS="/opt/opendxl-arctic-phase/var/log/suricata/"

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

class TIEHandler(watchdog.events.PatternMatchingEventHandler):

    def on_created(self, event):
        print "Looking at ", event.src_path
        #try:
        tieLookup(event.src_path)
        #except:
        #  print "invalid file"

class ScanFolder:

  def __init__(self, options={}):
    self.options = options
    #self.path = options.directory
    self.path = LOCAL_RESULTS + "files/"
    self.event_handler = TIEHandler(patterns=["*.meta"], ignore_patterns=[], ignore_directories=True)
    self.observer = Observer()
    print self.path
    self.observer.schedule(self.event_handler, self.path, recursive=True)
    self.observer.start()

  def stop(self):
    self.observer.stop()
    self.observer.join()
    #os.rmdir(self.temp_dir)

  def get_filepaths(self, directory):
  
    file_paths = []
    for root, directories, files in os.walk(directory):
      files = [ f for f in files if not f[0] == '.']
      directories[:] = [d for d in directories if not d[0] == '.']
      for filename in files:
        filepath = os.path.join(root, filename)
        file_paths.append(filepath)

    return file_paths 


def printTIE(reputations_dict):
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


def tieLookup(filename):
  with open(filename, 'r') as stream:
    try:
        dataMap = yaml.load(stream)
    except yaml.YAMLError as exc:
      print(exc)
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

        try:
            fo = open(filename + ".verdict", "w")
            fo.write(output)
            fo.close()
        except:
            print "could not write to directory"
            
 
        printTIE(reputations_dict)


    else:
        print 'No Match'





# Create the client
with DxlClient(config) as client:

  # Connect to the fabric
  client.connect()

  # Create the McAfee Threat Intelligence Exchange (TIE) client
  tie_client = TieClient(client)

  # Watch directory loop

  job = ScanFolder()

  try: 
      while True:
            time.sleep(1)
  except KeyboardInterrupt:
      job.stop()
      sys.exit(0)

