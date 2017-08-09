import os
import json
import re
import yaml
from watchdog.observers import Observer
import watchdog.events

from tie import TieSubmit
from dxltieclient.constants import HashType, ReputationProp, FileProvider, FileEnterpriseAttrib, \
    CertProvider, CertEnterpriseAttrib, TrustLevel


class JobHandler(watchdog.events.PatternMatchingEventHandler):

    def on_created(self, event):
        logger.info("Looking at {0}".format(event.src_path))
        #try:
        sample = self.tieLookup(event.src_path)

        #TODO: refactor this ..extract properties etc.
        self.combined_reputation = sample.calcRep()
        self.sideeffects(sample.reputations_dict)
        self.create_verdict(event.src_path, sample.reputations_dict)
        #except:
        #  print "invalid file"

    def tieLookup(self, filename):
        with open(filename, 'r') as stream:
            try:
                dataMap = yaml.load(stream)
            except yaml.YAMLError as exc:
                logger.error(exc)
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
                logger.info(sample.tieResponse())
                return sample

    def sideeffects(self, reputations_dict):
        if self.combined_reputation[0] <= TrustLevel.MOST_LIKELY_TRUSTED:
            if self.combined_reputation[0] <= TrustLevel.MOST_LIKELY_MALICIOUS:
                addtosuricatablacklist(dataMap['MD5'])
                logger.info("added to blacklist")
            else:
                if FileProvider.ATD in reputations_dict:
                    logger.info("ATD Graded it Medium - Malware.Dynamic")
                else:
                    logger.info("submit to ATD")
        else:
            logger.info("good file")

    def create_verdict(self, filename, reputations_dict):

        try:
            fo = open(filename + '.' + self.combined_reputation[1] + ".verdict", "w")
            output = json.dumps(reputations_dict, sort_keys=True, indent=4, separators=(',', ': ')) + "\n"
            fo.write(output)
            fo.close()
        except:
            logger.info("could not write verdict to directory")



class ScanFolder:

    def __init__(self, options={}):
        self.options = options
        self.path = options.watch
        self.event_handler = JobHandler(patterns=["*.meta"], ignore_patterns=[], ignore_directories=True)
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