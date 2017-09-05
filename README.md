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


#### Suricata Run

Running suricata from the cli with `pcap` carving from the sample

```
root@suricata:~# suricata -c /etc/suricata/suricata.yaml -r putty_wget.pcap -k none
31/8/2017 -- 17:52:05 - <Notice> - This is Suricata version 4.0.0 RELEASE
31/8/2017 -- 17:52:11 - <Notice> - all 3 packet processing threads, 4 management threads initialized, engine started.
31/8/2017 -- 17:52:11 - <Notice> - Signal Received.  Stopping engine.
31/8/2017 -- 17:52:11 - <Notice> - Pcap-file module read 902 packets, 914025 bytes
```

The `suricata` output will be:

```
root@suricata:~# ls -la /var/log/suricata/files/
total 848
drwxr-xr-x 2 root root   4096 Aug 31 17:52 .
drwxr-xr-x 5 root root   4096 Aug 28 16:46 ..
-rw-r--r-- 1 root root 854072 Aug 31 17:52 file.1
-rw-r--r-- 1 root root    610 Aug 31 17:52 file.1.meta

root@suricata:~# ls -la /var/log/suricata/files/file.1.meta 
-rw-r--r-- 1 root root 610 Aug 31 17:52 /var/log/suricata/files/file.1.meta

root@suricata:~# cat /var/log/suricata/files/file.1.meta 
TIME:              08/31/2017-17:50:53.452017
PCAP PKT NUM:      8
SRC IP:            10.0.10.192
DST IP:            10.0.3.3
PROTO:             6
SRC PORT:          80
DST PORT:          34098
APP PROTO:         http
HTTP URI:          /putty.exe
HTTP HOST:         10.0.10.192
HTTP REFERER:      <unknown>
HTTP USER AGENT:   Wget/1.17.1 (linux-gnu)
FILENAME:          /putty.exe
MAGIC:             PE32+ executable (GUI) x86-64, for MS Windows
STATE:             CLOSED
MD5:               54cb91395cdaad9d47882533c21fc0e9
SHA1:              3b1333f826e5fe36395042fe0f1b895f4a373f1b
SIZE:              854072
```

The original sample `putty.exe` that was fetched via wget over plain http.

```
$ openssl md5 putty.exe 
MD5(putty.exe)= 54cb91395cdaad9d47882533c21fc0e9
```

Validating the *GTI* and *Enterprise* reputation score of the sample `putty.exe`


```
$ ./bin/arctic-phase-hash.py -f 54cb91395cdaad9d47882533c21fc0e9
File Hash 54cb91395cdaad9d47882533c21fc0e9 Reputation

Provider: GTI
Creation Date: 2017-08-31 17:53:31
Reputation: Known Trusted

Provider: Enterprise Reputation
Creation Date: 2017-08-31 17:53:31
Reputation: Not Set
```


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
