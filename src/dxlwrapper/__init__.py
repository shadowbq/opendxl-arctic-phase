import os

from dxlclient.client_config import DxlClientConfig

# Options wrapper for DXLClientConfig
class DxlConfigWrapper(object):

    def __init__(self, options):
        print("__init__")

        # Config file name.
        self.options = options
        self.connection = None

        CONFIG_FILE = self.options.dxlclient

        # TODO: Hardcoded, FIX for TESTING
        # CONFIG_FILE_NAME = "dxlclient.config"
        # CONFIG_FILE = os.path.dirname(os.path.abspath(__file__)) + "/../../etc/" + CONFIG_FILE_NAME
        # print "Loading configuration from:", CONFIG_FILE

        # Create DXL configuration from file
        self._config = DxlClientConfig.create_dxl_config_from_file(CONFIG_FILE)

    @property
    def config(self):
        return self._config
