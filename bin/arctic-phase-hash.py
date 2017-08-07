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

from common import *
from utils import *
from const import *
from dxlwrapper import DxlConfigWrapper
from tie import TieSubmit
from cliargs import CliArgs

#import code; code.interact(local=dict(globals(), **locals()))

if __name__ == '__main__':
    # Get the list of parameters passed from command line
    options = CliArgs('hash')

    if options.hash is None:
        options.hash = raw_input("File Hash: ")

    if options.verbosity:
        utils.license()

    # Options wrapper for DXLClientConfig
    dxlconfig = DxlConfigWrapper(options)

    # Create the client
    with DxlClient(dxlconfig) as client:
      # Connect to the fabric
      client.connect()
      sample = TieSubmit(options, client)
