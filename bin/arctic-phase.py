#!/usr/bin/env python

# standard libs
import sys
import time
import re
import json
import logging
import os
import tempfile

# pip libs
from named_constants import Constants

import yaml
from watchdog.observers import Observer
import watchdog.events

from dxlclient.client import DxlClient
from dxlclient.client_config import DxlClientConfig
from dxltieclient import TieClient
from dxltieclient.constants import HashType, ReputationProp, FileProvider, FileEnterpriseAttrib, \
    CertProvider, CertEnterpriseAttrib, TrustLevel

# local libs
sys.path.append(os.path.dirname(os.path.abspath(__file__)) + "/../src/")
from common import *
from utils import *
from const import *


# Configure local logger
logging.getLogger().setLevel(logging.ERROR)
logger = logging.getLogger(__name__)

# Create DXL configuration from file
config = DxlClientConfig.create_dxl_config_from_file(CONFIG_FILE)

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
    self.path = Testing.LOCAL_RESULTS + "files/"
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

        rep = calcRep(reputations_dict)

        if rep <= TrustLevel.MOST_LIKELY_TRUSTED:
            if rep <= TrustLevel.MOST_LIKELY_MALICIOUS:
                addtosuricatablacklist(dataMap['MD5'])
                print "added to blacklist"
                rep_str = "bad"
            else:
                if FileProvider.ATD in reputations_dict:
                    print "ATD Graded it Medium - Malware.Dynamic"
                    rep_str = "medium"
                else:
                    print "submit to ATD"
                    rep_str = "unknown"
        else:
            print "good file"
            rep_str = "good"

        try:
            fo = open(filename + '.' + rep_str + ".verdict", "w")
            fo.write(output)
            fo.close()
        except:
            print "could not write verdict to directory"

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
