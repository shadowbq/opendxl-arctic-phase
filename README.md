# OpenDXL Suricata TIE ATD

This is a set of configurations and clients to integrate Suricata file carving


## File Carving using Suricata

http://suricata.readthedocs.io/en/latest/rules/file-keywords.html

### Catch PE32:
```
alert http any any -> any any (filemagic:”executable for MS Windows”;)
```
Suricata 3.2

File Hashes:
Feature #509: add SHA1 and SHA256 checksum support for files
