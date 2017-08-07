import os

from dxlclient.client import DxlClient
from dxlclient.client_config import DxlClientConfig

# Options wrapper for DXLClientConfig
class DxlConfigWrapper():

    def __init__(self, options):
        print("__init__")

        # Config file name.
        CONFIG_FILE_NAME = "dxlclient.config"
        CONFIG_FILE = os.path.dirname(os.path.abspath(__file__)) + "/../../etc/" + CONFIG_FILE_NAME
        self.options = options
        self.connection = None

        print "Loading configuration from:", CONFIG_FILE
        # Create DXL configuration from file
        self.config = DxlClientConfig.create_dxl_config_from_file(CONFIG_FILE)
        return self.config
