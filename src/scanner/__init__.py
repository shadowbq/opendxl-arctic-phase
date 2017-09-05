import os
import json
import re
import yaml

from common import *

from watchdog.observers import Observer
import watchdog.events

from tie import TieSample
from dxltieclient.constants import HashType, ReputationProp, FileProvider, FileEnterpriseAttrib, \
    CertProvider, CertEnterpriseAttrib, TrustLevel

from suricata import addtosuricatablacklist, SuricataEve

class JobHandler(watchdog.events.PatternMatchingEventHandler):

    def __init__(self, patterns=None, ignore_patterns=None,
                 ignore_directories=False, case_sensitive=False, options=None, client=None):
        super(watchdog.events.PatternMatchingEventHandler, self).__init__()

        self._patterns = patterns
        self._ignore_patterns = ignore_patterns
        self._ignore_directories = ignore_directories
        self._case_sensitive = case_sensitive

        self.options = options
        self.client = client
        self.query = {}


    def on_created(self, event):
        logger.info("Looking at {0}".format(event.src_path))
        #try:
        self.metaFile = self.load_metaFile(event.src_path)
        self.query = self.create_query()
        sample = self.tieLookup()

        #TODO: refactor this ..extract properties etc.
        self.combined_reputation = sample.calcRep()
        self.sideeffects(sample.reputations_dict)
        self.create_verdict(event.src_path, sample.reputations_dict)
        #except:
        #  print "invalid file"

    def load_metaFile(self, filename):
        with open(filename, 'r') as stream:
            try:
                return yaml.load(stream)
            except yaml.YAMLError as exc:
                logger.error(exc)

    def create_query(self):
        if self.metaFile['STATE'] == 'CLOSED':
            p = re.compile('PE32')
            match = p.match(self.metaFile['MAGIC'])
            if match:
                reputation_lookup_dict = \
                  {
                    HashType.MD5: self.metaFile['MD5'],
                    HashType.SHA1: self.metaFile['SHA1']
                  }
                return reputation_lookup_dict

    def tieLookup(self):
        sample = TieSample(self.options, self.client, self.query)
        logger.info(sample.tieResponse())
        return sample

    def sideeffects(self, reputations_dict):
        if self.combined_reputation[0] <= TrustLevel.MOST_LIKELY_TRUSTED:
            if self.combined_reputation[0] <= TrustLevel.MOST_LIKELY_MALICIOUS:
                addtosuricatablacklist(self.query['md5'])
                self.create_eve()
                logger.info("added to blacklist")
            else:
                if FileProvider.ATD in reputations_dict:
                    self.create_eve()
                    logger.info("ATD Graded it Medium - Malware.Dynamic")
                else:
                    logger.info("submit to ATD")
        else:
            logger.info("good file")

    def create_eve(self):
        #try:
        SuricataEve(self.metaFile, self.combined_reputation)
        #except:
        #    logger.info("could not write eve alert to output")

    def create_verdict(self, filename, reputations_dict):

        try:
            fo = open(filename + '.' + self.combined_reputation[1] + ".verdict", "w")
            output = json.dumps(reputations_dict, sort_keys=True, indent=4, separators=(',', ': ')) + "\n"
            fo.write(output)
            fo.close()
        except:
            logger.info("could not write verdict to directory")



class ScanFolder:

    def __init__(self, options={}, client=None):
        self.options = options
        self.path = options.watch
        self.event_handler = JobHandler(patterns=["*.meta"], ignore_patterns=[], ignore_directories=True, case_sensitive=False, options=options, client=client)
        self.observer = Observer()
        logger.info ("Scanning directory: {}".format(self.path))
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
