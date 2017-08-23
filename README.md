# OpenDXL ArticPhase

## OpenDXL Suricata TIE ATD integration client

This is a set of configurations and clients to integrate Suricata file carving

## Usage

### Hash Lookup

```
./bin/arctic-phase-hash.py --help
Loading configuration from: /home/shadowbq/sandbox/foo/opendxl-arctic-phase/src/../test/etc/dxlclient.config
usage: arctic-phase-hash.py [-h] [-x DXLCLIENT] -a HASH [--version] [-v | -q]

OpenDXL Arctic Phase - Hash integrations

optional arguments:
  -h, --help       show this help message and exit
  --version        show program's version number and exit
  -v, --verbosity  increase output (v)erbosity
                   		(default: None)
  -q, --quiet      (q)uiet all output
                   		(default: False)

OpenDXL parameters:
  -x DXLCLIENT     d(x)lclient.config file location
                   		(default: /etc/dxlclient.config)

Hash parameters:
  -a HASH          h(a)sh md5|sha1|sha256 to test lookup
                   		(default: None)
```

```
opendxl-arctic-phase$ ./bin/arctic-phase-hash.py -x /opt/opendxl/dxlclient.config -f C2FBCC87C157F4F70515A69199E50F82
File Hash C2FBCC87C157F4F70515A69199E50F82 Reputation

Provider: GTI
Creation Date: 2017-08-09 08:08:55
Reputation: Not Set

Provider: Enterprise Reputation
Creation Date: 2017-08-09 08:08:55
Reputation: Not Set

opendxl-arctic-phase$ ./bin/arctic-phase-hash.py -x /opt/opendxl/dxlclient.config -f 91E9E3CC7A1843027AC77377144566CE
File Hash 91E9E3CC7A1843027AC77377144566CE Reputation

Provider: GTI
Creation Date: 2017-08-01 17:23:17
Reputation: Known Malicious

Provider: Enterprise Reputation
Creation Date: 2017-08-01 17:23:17
Reputation: Not Set

Provider: ATD
Creation Date: 2017-08-01 17:23:17
Reputation: Known Malicious
```

### OpenDXL

DXL configuration:

The ArcticPhase client contains a configuration file (dxlclient.config) located in the etc sub-directory that must be populated in order for the Hashes to be able to be looked up on the DXL fabric.

See: https://opendxl.github.io/opendxl-tie-client-python/pydoc/sampleconfig.html

#### TIE

Prerequisites:

* The samples configuration step has been completed (see Samples Configuration)
* A McAfee Threat Intelligence Exchange (TIE) Service is available on the DXL fabric

### File Carving using Suricata

* http://suricata.readthedocs.io/en/latest/rules/file-keywords.html

#### Example Suricata Stanzas

Suricata uses yaml files to configure the file carving.

There are two configuration files required to enable file carving of files up to 64mb in size.

* [ouputs.yaml](etc/suricata/outputs.yaml)
* [streams.yaml](etc/suricata/streams.yaml)


#### Catch PE32:
```
alert http any any -> any any (filemagic:”executable for MS Windows”;)
```

Suricata 3.2 & 4.0 Configs

File Hashes:
Feature #509: add SHA1 and SHA256 checksum support for files


## Invoke

`invoke` is included to run common commands and task listed in `tasks.py`.

```
$ invoke -l
Available tasks:

  build       Build the setup.py
  clean       Clean up docs, bytecode, and extras
  codestats   Run pycodestyle tests for code stats
  release     ``version`` should be a string like '0.4' or '1.0'.
  smell       Run pycodestyle tests
  test        Run Unit tests
```
