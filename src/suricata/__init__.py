# Suricata methods

def addtosuricatablacklist(md5):
  try:
      blacklist_fh = open(BLACKLIST, "a")
      blacklist_fh.write(md5)
      blacklist_fh.write("\n")
      blacklist_fh.close()
  except:
      print "suricata blacklist file is not available"
