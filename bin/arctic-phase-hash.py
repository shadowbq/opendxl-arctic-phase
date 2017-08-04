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


from dxlclient.client import DxlClient
from dxlclient.client_config import DxlClientConfig
from dxltieclient import TieClient
from dxltieclient.constants import HashType, ReputationProp, FileProvider, FileEnterpriseAttrib, \
    CertProvider, CertEnterpriseAttrib, TrustLevel



# local libs
sys.path.append(os.path.dirname(os.path.abspath(__file__)) + "/../")
sys.path.append(os.path.dirname(os.path.abspath(__file__)) + "/../src/")

from common import *
from utils import *
from const import *
from cliargs import CliArgs


EXIT_SUCCESS = 0
EXIT_FAILURE = 1


if __name__ == '__main__':
    # Get the list of parameters passed from command line
    options = CliArgs('hash')

    if options.hash is None:
        options.hash = raw_input("File Hash: ")

    if options.verbosity:
        utils.copyleftnotice()

    sample = SampleSubmit(options)
    severity = sample.rtnv
    md5 = sample.rtv_md5

    sys.exit(severity)
