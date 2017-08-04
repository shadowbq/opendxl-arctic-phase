"""
Defining the path to the configuration file used to initialize the DXL client
and setting up the logger appropriately.
"""

import os
import logging

# Config file name.
CONFIG_FILE_NAME = "dxlclient.config"
CONFIG_FILE = os.path.dirname(os.path.abspath(__file__)) + "/../etc/" + CONFIG_FILE_NAME

print "Loading configuration from:", CONFIG_FILE

# Enable logging, this will also direct built-in DXL log messages.
# See - https://docs.python.org/2/howto/logging-cookbook.html
log_formatter = logging.Formatter('%(asctime)s %(name)s - %(levelname)s - %(message)s')

console_handler = logging.StreamHandler()
console_handler.setFormatter(log_formatter)

logger = logging.getLogger()
logger.addHandler(console_handler)
logger.setLevel(logging.INFO)
