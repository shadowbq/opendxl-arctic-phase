# CLI methods
import sys
import argparse
import ConfigParser
import os.path

# local libs
import src
import utils

class CliArgError(Exception):

    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)

class CliArgs():

    def __init__(self, tool, explicit=None):
        # Complete Arg Dictionary for Help
        self.arg_dict = {
            'config': '(c)onfiguration file for arctic phase\n\t\t(default: %(default)s)',
            'hash': 'h(a)sh md5|sha1|sha256 to test lookup\n\t\t(default: %(default)s)',
            'dxlclient': 'd(x)lclient.config file location\n\t\t(default: %(default)s)',
            'watch': '(w)atch dir for new suricata meta files (fileXX.meta)\n\t\t(default: %(default)s)',
            'existing': '(e)xisting meta files in watch directory will be evaluated\n\t\t(default: %(default)s)',
            'sandbox': '(s)ubmit unknown samples using robust-atd\n\t\t(default: %(default)s)',
            'sandboxconfig': '(r)robust-config location for sandbox\n\t\t(default: %(default)s)',
            'quiet': '(q)uiet all output\n\t\t(default: %(default)s)',
            'verbosity': 'increase output (v)erbosity\n\t\t(default: %(default)s)'
        }

        self.description = 'OpenDXL Arctic Phase - Hash integrations'
        self.epilog = ''
        self.dot_arctic_phase = self.dot_arctic_phase_helper()

        self.parser = argparse.ArgumentParser(epilog=self.epilog, description=self.description, formatter_class=argparse.RawTextHelpFormatter)

        # Build Args
        if tool == 'hash':
            self.dxl_args()
            self.hash_args()
        elif tool == 'watch':
            self.dxl_args()
            self.watch_args()
        else:
            raise CliArgError(tool)
        # Always add common
        self.unix_common_args()

        if explicit is None:
            self.parser.parse_args(namespace=self)
        else:
            self.parser.parse_args(args=explicit, namespace=self)

    def config_section_map(self, config, section, defaults):
        dict1 = {}
        options = config.options(section)

        for option in options:
            try:
                dict1[option] = config.get(section, option)
                if dict1[option] == -1:
                    DebugPrint("skip: %s" % option)
            except:
                try:
                    dict1[option] = defaults[option]
                except:
                    print("exception on %s!" % option)
                    dict1[option] = None

        for k,v in defaults.iteritems():
            if not k in dict1:
                dict1[k] = v

        return dict1

    def dot_arctic_phase_helper(self):
        dxl_defaults = {'dxlclient': '/etc/dxlclient.config'}
        watch_defaults = {'watch': '/var/log/suricata/files/', 'existing': False, 'sandbox': False, 'sandboxconfig': '~/.robust'}

        config = ConfigParser.ConfigParser({})
        fname = os.path.expanduser("~/.opendxl-arctic-phase")

        if os.path.isfile(fname):
            config.read(fname)
            if config.has_section("opendxl"):
                opendxl = self.config_section_map(config, "opendxl", dxl_defaults)
                dot_arctic_phase_opendxl = {
                    'dxlclient': opendxl["dxlclient"]
                }
            else:
                dot_arctic_phase_opendxl = dxl_defaults

            if config.has_section("watch"):
                watch = self.config_section_map(config, "watch", watch_defaults)
                dot_arctic_phase_connection = {
                    'watch': watch["watch"],
                    'existing': watch["existing"],
                    'sandbox': watch["sandbox"],
                    'sandboxconfig': watch["sandboxconfig"]
                }
            else:
                dot_arctic_phase_watch = watch_defaults

            # config file present, merge sections
            dot_arctic_phase_dict = utils.merge_dicts(dot_arctic_phase_opendxl, dot_arctic_phase_watch)
        else:

            # No config file, just merge default dicts
            dot_arctic_phase_dict = utils.merge_dicts(dxl_defaults, watch_defaults)
        return dot_arctic_phase_dict

    def unix_common_args(self):
        self.parser.add_argument('--version', action='version', version=src.__version__)

        exclusive = self.parser.add_mutually_exclusive_group()
        exclusive.add_argument('-v', "--verbosity", action="count", help=self.arg_dict['verbosity'])
        exclusive.add_argument('-q', "--quiet", required=False, action='store_true', dest='quiet', help=self.arg_dict['quiet'])

    def dxl_args(self):

        dxl_group = self.parser.add_argument_group('OpenDXL parameters')

        if self.dot_arctic_phase['dxlclient']:
            dxl_group.add_argument('-x', required=False, action='store', default=self.dot_arctic_phase['dxlclient'], dest='dxlclient', help=self.arg_dict['dxlclient'])
        else:
            dxl_group.add_argument('-x', required=True, action='store', dest='dxlclient', help=self.arg_dict['dxlclient'])

    def hash_args(self):

        hash_group = self.parser.add_argument_group('Hash parameters')
        hash_group.add_argument('-a', required=True, type=utils.valid_hash, action='store', dest='hash', help=self.arg_dict['hash'])

    def watch_args(self):

        watch_group = self.parser.add_argument_group('Watch parameters')
        if self.dot_arctic_phase['watch']:
            watch_group.add_argument('-w', required=False, action='store', default=self.dot_arctic_phase['watch'], dest='watch', help=self.arg_dict['watch'])
        else:
            watch_group.add_argument('-w', required=True, action='store', dest='watch', help=self.arg_dict['watch'])

        if self.dot_arctic_phase['existing']:
            watch_group.add_argument('-e', required=False, action='store_true', default=self.dot_arctic_phase['existing'], dest='existing', help=self.arg_dict['existing'])
        else:
            watch_group.add_argument('-e', required=False, action='store_true', dest='existing', help=self.arg_dict['existing'])

        if self.dot_arctic_phase['sandbox']:
            watch_group.add_argument('-w', required=False, action='store_true', default=self.dot_arctic_phase['sandbox'], dest='sandbox', help=self.arg_dict['sandbox'])
        else:
            watch_group.add_argument('-w', required=False, action='store_true', dest='sandbox', help=self.arg_dict['sandbox'])

        if self.dot_arctic_phase['sandboxconfig']:
            watch_group.add_argument('-r', required=False, action='store', default=self.dot_arctic_phase['sandboxconfig'], dest='sandboxconfig', help=self.arg_dict['sandboxconfig'])
        else:
            watch_group.add_argument('-r', required=True, action='store', dest='sandboxconfig', help=self.arg_dict['sandboxconfig'])
