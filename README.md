# OpenDXL ArticPhase

## OpenDXL Suricata TIE ATD integration client

This is a set of configurations and clients to integrate Suricata file carving


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

Suricata 3.2

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
