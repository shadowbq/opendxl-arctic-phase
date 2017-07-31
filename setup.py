#!/usr/bin/env python

NAME = 'ArticPhase'
VERSION = get_version()
DESCRIPTION = 'OPENDXL suricata tie atd integration client'
LONG_DESCRIPTION = """\
OPENDXL suricata tie atd integration client. Includes suricata config examples etc.
"""

AUTHOR = 'shadowbq'
AUTHOR_EMAIL = 'shadowbq@gmail.com'
LICENSE = 'MIT'
PLATFORM = "ANY"
URL = 'https://github.com/shadowbq/articphase'

CLASSIFIERS = [
    "Development Status :: 4 - Beta",
    "Intended Audience :: Developers",
    "License :: OSI Approved :: MIT License",
    "Operating System :: OS Independent",
    "Environment :: Other Environment",
    "Programming Language :: Python",
    "Programming Language :: Python :: 2",
    "Programming Language :: Python :: 2.7",
    "Topic :: Software Development :: Libraries :: Python Modules",
    "Topic :: Security",
]

import sys, os.path, platform
from os.path import abspath, dirname, join, realpath
from setuptools import setup, find_packages


BASE_DIR = dirname(abspath(__file__))
INIT_FILE = join(BASE_DIR, 'src', '__init__.py')

def get_version():
    with open(INIT_FILE) as f:
        for line in f.readlines():
            if line.startswith("__version__"):
                version = line.split()[-1].strip('"')
                return version
        raise AttributeError("Package does not have a __version__")

def install_requires():
    req_list = []
    with open('requirements.txt', 'rt') as f:
      for line in f:
        if line.strip().startswith('#'):
          continue
        if not line.strip():
          continue
        req_list.append(line.strip())
        print "Registering Requirement: " + line.strip()
    return req_list

py_maj, py_minor = sys.version_info[:2]

if py_maj != 2:
    raise Exception('arctic-phase requires Python 2.6/2.7')

if (py_maj, py_minor) < (2, 6):
    raise Exception('arctic-phase requires Python 2.6/2.7')

fn_readme = join(BASE_DIR, "README.md")
with open(fn_readme) as f:
    readme = f.read()

extras_require = {
    'docs': [
        'Sphinx==1.2.1',
        'sphinxcontrib-napoleon==0.2.4',
    ],
    'test': [
        "nose==1.3.0",
        "tox==1.6.1"
    ],
}

setup(
    name=NAME,
    version=VERSION,
    description=DESCRIPTION,
    long_description=readme,
    author=AUTHOR,
    author_email=AUTHOR_EMAIL,
    license=LICENSE,
    platforms=PLATFORMS,
    url=URL,
    download_url=DOWNLOAD_URL,
    classifiers=CLASSIFIERS,
    packages=find_packages(),
    scripts=['bin/arctic-phase.py'],
    install_requires=install_requires(),
    extras_require=extras_require,
    keywords="opendxl suricata atd mcafee"
)
