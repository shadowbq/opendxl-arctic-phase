import os

from dxlclient.client import DxlClient
from dxlclient.client_config import DxlClientConfig

class DXLClientWrapper():

    def __init__(self, options):
        # Config file name.
        CONFIG_FILE_NAME = "dxlclient.config"
        CONFIG_FILE = os.path.dirname(os.path.abspath(__file__)) + "/../../etc/" + CONFIG_FILE_NAME

        print "Loading configuration from:", CONFIG_FILE

        # Create DXL configuration from file
        self.config = DxlClientConfig.create_dxl_config_from_file(CONFIG_FILE)

    def connect(self):
        # Create the client
        with DxlClient(self.config) as client:
          # Connect to the fabric
          client.connect()
