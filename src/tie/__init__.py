# TIE Methods

# TIE Reputation Average Map
tiescoreMap = {0: 'Not Set', 1: 'Known Malicious', 15: 'Most Likely Malicious', 30: 'Might Be Malicious', 50: 'Unknown',
               70: "Might Be Trusted", 85: "Most Likely Trusted", 99: "Known Trusted", 100: "Known Trusted Installer"}
# TIE Provider Map
providerMap = {1: 'GTI', 3: 'Enterprise Reputation', 5: 'ATD', 7: "MWG"}


def getFileProps(fileProps):
    # Get File Properties and Map with Providers and TIE Score
    propList = []

    if FileProvider.GTI in fileProps:
        propDict = {}
        propDict['provider'] = providerMap[fileProps[FileProvider.GTI]['providerId']]
        propDict['reputation'] = tiescoreMap[fileProps[FileProvider.GTI]['trustLevel']]
        propDict['createDate'] = fileProps[FileProvider.GTI]['createDate']
        propList.append(propDict)

    if FileProvider.ENTERPRISE in fileProps:
        propDict = {}
        propDict['provider'] = providerMap[fileProps[FileProvider.ENTERPRISE]['providerId']]
        propDict['reputation'] = tiescoreMap[fileProps[FileProvider.ENTERPRISE]['trustLevel']]
        propDict['createDate'] = fileProps[FileProvider.ENTERPRISE]['createDate']
        propList.append(propDict)

    if FileProvider.ATD in fileProps:
        propDict = {}
        propDict['provider'] = providerMap[fileProps[FileProvider.ATD]['providerId']]
        propDict['reputation'] = tiescoreMap[fileProps[FileProvider.ATD]['trustLevel']]
        propDict['createDate'] = fileProps[FileProvider.ATD]['createDate']
        propList.append(propDict)

    if FileProvider.MWG in fileProps:
        propDict = {}
        propDict['provider'] = providerMap[fileProps[FileProvider.MWG]['providerId']]
        propDict['reputation'] = tiescoreMap[fileProps[FileProvider.MWG]['trustLevel']]
        propDict['createDate'] = fileProps[FileProvider.MWG]['createDate']
        propList.append(propDict)

    return propList


def getTieRep(tie_client, md5, sha1, sha256, ):

    #
    # Request and display reputation for notepad.exe
    #
    if md5:
        reputations_dict = tie_client.get_file_reputation({HashType.MD5: md5})
    if sha1:
        reputations_dict = tie_client.get_file_reputation({HashType.SHA1: sha1})
    if sha256:
        reputations_dict = tie_client.get_file_reputation({HashType.SHA256: sha256})

    return reputations_dict

def getFileRep(tie_client, md5=None, sha1=None, sha256=None):
    if md5 == None and sha1 == None and sha256 == None:
        return "no file hash"
    else:
        # Verify SHA1 string
        if sha1 != None:
            if not is_sha1(sha1):
                return "invalid sha1"

        # Verify SHA256 string
        if sha256 != None:
            if not is_sha256(sha256):
                return "invalid sha256"

        if md5 != None:
            if not is_md5(md5):
                return "invalid md5"

        return getTieRep(tie_client, md5, sha1, sha256)

def calcRep(reputations_dict):
  # Return a Summary Cascade 0-100 Value for Reputation.
  # OOP: Enterprise -> ATD -> MWG -> GTI

  # If there is TIE ENTERPRISE rep, use it, then look at ATD, then GTI.
  if FileProvider.ENTERPRISE in reputations_dict:
      ent_rep = reputations_dict[FileProvider.ENTERPRISE]
      rep = ent_rep[ReputationProp.TRUST_LEVEL]
      if rep == 0:
        if FileProvider.ATD in reputations_dict:
          atd_rep = reputations_dict[FileProvider.ATD]
          rep = atd_rep[ReputationProp.TRUST_LEVEL]
        if rep == 0:
          if FileProvider.MWG in reputations_dict:
            mwg_rep = reputations_dict[FileProvider.MWG]
            rep = atd_rep[ReputationProp.TRUST_LEVEL]
          if rep == 0:
            if FileProvider.GTI in reputations_dict:
              gti_rep = reputations_dict[FileProvider.GTI]
              rep = gti_rep[ReputationProp.TRUST_LEVEL]
  else:
    if FileProvider.GTI in reputations_dict:
      gti_rep = reputations_dict[FileProvider.GTI]
      rep = gti_rep[ReputationProp.TRUST_LEVEL]
  return rep


def printTIE(reputations_dict):
  # Display the Global Threat Intelligence (GTI) trust level for the file
  if FileProvider.GTI in reputations_dict:
      gti_rep = reputations_dict[FileProvider.GTI]
      print "Global Threat Intelligence (GTI) trust level: " + \
            str(gti_rep[ReputationProp.TRUST_LEVEL])

  # Display the Enterprise reputation information
  if FileProvider.ENTERPRISE in reputations_dict:
      ent_rep = reputations_dict[FileProvider.ENTERPRISE]

      print "Threat Intelligence Exchange (Local) trust level: " + \
            str(ent_rep[ReputationProp.TRUST_LEVEL])

      # Retrieve the enterprise reputation attributes
      ent_rep_attribs = ent_rep[ReputationProp.ATTRIBUTES]

      # Display prevalence (if it exists)
      if FileEnterpriseAttrib.PREVALENCE in ent_rep_attribs:
          print "Enterprise prevalence: " + \
                ent_rep_attribs[FileEnterpriseAttrib.PREVALENCE]

      # Display first contact date (if it exists)
      if FileEnterpriseAttrib.FIRST_CONTACT in ent_rep_attribs:
          print "First contact: " + \
                FileEnterpriseAttrib.to_localtime_string(
                    ent_rep_attribs[FileEnterpriseAttrib.FIRST_CONTACT])

  if FileProvider.ATD in reputations_dict:
      atd_rep = reputations_dict[FileProvider.ATD]
      print "ATD (sandbox) trust level: " + \
        str(atd_rep[ReputationProp.TRUST_LEVEL])

  if FileProvider.MWG in reputations_dict:
      mwg_rep = reputations_dict[FileProvider.MWG]
      print "MWG (WebGatewayy) trust level: " + \
        str(mwg_rep[ReputationProp.TRUST_LEVEL])
