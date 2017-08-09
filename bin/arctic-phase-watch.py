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
import yaml
from named_constants import Constants


# local libs
sys.path.append(os.path.dirname(os.path.abspath(__file__)) + "/../")
sys.path.append(os.path.dirname(os.path.abspath(__file__)) + "/../src/")

import utils

from common import *
from utils import *
from const import *
from dxlwrapper import DxlConfigWrapper
from dxlclient.client import DxlClient
from tie import TieSubmit
from cliargs import CliArgs

#import code; code.interact(local=dict(globals(), **locals()))

class TIEHandler(watchdog.events.PatternMatchingEventHandler):

    def on_created(self, event):
        print "Looking at ", event.src_path
        #try:
        tieLookup(event.src_path)
        #except:
        #  print "invalid file"
    def tieLookup(filename):
        with open(filename, 'r') as stream:
            try:
                dataMap = yaml.load(stream)
            except yaml.YAMLError as exc:
                print(exc)
        if dataMap['STATE'] == 'CLOSED':
            p = re.compile('PE32')
            match = p.match(dataMap['MAGIC'])
            if match:
                reputation_lookup_dict = \
                  {
                    HashType.MD5: dataMap['MD5'],
                    HashType.SHA1: dataMap['SHA1']
                  }
                sample = TieSubmit(options, client, reputation_lookup_dict)
                print sample.tieResponse(),
                


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

if __name__ == '__main__':
    # Get the list of parameters passed from command line
    options = CliArgs('watch')

    if options.verbosity:
        utils.license()

    # Options wrapper for DXLClientConfig
    try:
        dxlconfig = DxlConfigWrapper(options)
    except Exception as inst:
        print inst
        sys.exit(1)

    # Create the client
    with DxlClient(dxlconfig.config) as client:
        # Connect to the fabric
        client.connect()
        job = ScanFolder()
        try:
            while True:
                  time.sleep(1)
        except KeyboardInterrupt:
            job.stop()
            sys.exit(0)
