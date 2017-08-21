# OpenDXL ArticPhase

## OpenDXL Suricata TIE ATD integration client

This is a set of configurations and clients to integrate Suricata file carving

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

Running Suricata as test
see: https://github.com/jasonish/suricata-verify

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
