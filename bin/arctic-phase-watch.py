#!/usr/bin/env python

# standard libs
import sys
import time
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
from scanner import ScanFolder
from dxlwrapper import DxlConfigWrapper
from dxlclient.client import DxlClient
from cliargs import CliArgs


#import code; code.interact(local=dict(globals(), **locals()))

if __name__ == '__main__':
    # Get the list of parameters passed from command line
    options = CliArgs('watch')

    if options.verbosity:
        logger.setLevel(logging.INFO)
    else:
        logger.setLevel(logging.WARNING)

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
        job = ScanFolder(options)
        try:
            while True:
                  time.sleep(1)
        except KeyboardInterrupt:
            job.stop()
            sys.exit(0)
