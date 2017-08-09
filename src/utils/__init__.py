# utils

import errno
import os
import sys
import time

from const import Testing

def license():
    print '# Author - Shadowbq 2017'
    print '# MIT LICENSE'
    print 'https://github.com/shadowbq/opendxl-arctic-phase/blob/master/LICENSE'

def verbose(x, y=0):
    if Testing.VERBOSE > y:
        print x
    else:
        0 #No Op

def time_to_str(myTime):
    return time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(myTime))
#Validators
def valid_hash(value):
    if not is_md5(value):
        if not is_sha1(value):
            if not is_sha256(value):
                raise Exception("%s is an invalid hash (md5|sha1|sha256) value" % value)
    return value

def is_sha1(maybe_sha):
    # Check if it is a SHA1
    if len(maybe_sha) != 40:
        return False
    try:
        int(maybe_sha, 16)
    except ValueError:
        return False
    return True


def is_sha256(maybe_sha):
    # Check if it is a SHA256
    if len(maybe_sha) != 64:
        return False
    try:
        int(maybe_sha, 16)
    except ValueError:
        return False
    return True


def is_md5(maybe_md5):
    # Check if it is an MD5
    if len(maybe_md5) != 32:
        return False
    try:
        md5_int = int(maybe_md5, 16)
    except ValueError:
        return False
    return True

def slash_dir(value):
    if value[len(value)-1] != "/":
        raise argparse.ArgumentTypeError("%s should end in a slash" % value)
    value = os.path.expanduser(value)
    return value

def merge_dicts(*dict_args):
    '''
    Given any number of dicts, shallow copy and merge into a new dict,
    precedence goes to key value pairs in latter dicts.
    '''
    result = {}
    for dictionary in dict_args:
        result.update(dictionary)
    return result

class Mkdirs:

    '''Class defining the mkdir_p algorithm folder'''
    def __init__(self, options):
        self.options = options
        self.path = options.directory
        try:
            if self.options.dirtydir:
                self.mkdir_p(self.options.dirtydir)
        except AttributeError:
            pass

        try:
            if self.options.cleandir:
                self.mkdir_p(self.options.cleandir)
        except AttributeError:
            pass

        try:
            if self.options.errordir:
                self.mkdir_p(self.options.errordir)
        except AttributeError:
            pass

        try:
            if self.options.reportdir:
                self.mkdir_p(self.options.reportdir)
        except AttributeError:
            pass

    def mkdir_p(self, path):
        try:
            os.makedirs(path)
            if self.options.verbosity:
                print ('mkdir_p %s' % path)
                sys.stdout.flush()
        except OSError as exc:  # Python >2.5
            if exc.errno == errno.EEXIST and os.path.isdir(path):
                pass
            else:
                raise
