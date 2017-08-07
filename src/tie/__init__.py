# TIE Methods
import utils
from dxltieclient import TieClient
from dxltieclient.constants import HashType, ReputationProp, FileProvider, FileEnterpriseAttrib, \
    CertProvider, CertEnterpriseAttrib, TrustLevel

# TIE Reputation Average Map
tiescoreMap = {0: 'Not Set', 1: 'Known Malicious', 15: 'Most Likely Malicious', 30: 'Might Be Malicious', 50: 'Unknown',
               70: "Might Be Trusted", 85: "Most Likely Trusted", 99: "Known Trusted", 100: "Known Trusted Installer"}
# TIE Provider Map
providerMap = {1: 'GTI', 3: 'Enterprise Reputation', 5: 'ATD', 7: "MWG"}

class TieSubmit():
    def __init__(self, options, dxlclient):
        # Create the McAfee Threat Intelligence Exchange (TIE) client
        self.tie_client = TieClient(dxlclient)
        self.file_hash = options.hash
        if file_hash == None:
            return "no file hash"
        self.reputations_dict = _getFileRep()
        self.content = _getFileProps()
        #printTIE(reputations_dict)
        #calcRep(reputations_dict)

    def _getFileRep(self):
        if utils.is_sha1(self.file_hash):
            reputations_dict = self.tie_client.get_file_reputation({HashType.SHA1: self.file_hash})
        elif utils.is_sha256(self.file_hash):
            reputations_dict = self.tie_client.get_file_reputation({HashType.SHA256: self.file_hash})
        elif utils.is_md5(self.file_hash):
            reputations_dict = self.tie_client.get_file_reputation({HashType.MD5: self.file_hash})
        else:
            return "not a valid file hash"
        return reputations_dict

    def _getFileProps(self, fileProps=self.reputations_dict):
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

    def calcRep(self, reputations_dict):
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

    def tieResponse(self):
        rtv_string = "File Hash " + self.file_hash + " Reputation\n"
        # Format a String Response
        i = 1
        for key in self.content:
            rtv_string = rtv_string + "Provider: " + key['provider'] + "\n"
            rtv_string = rtv_string + "Creation Date: " + utils.time_to_str(key['createDate']) + "\n"
            rtv_string = rtv_string + "Reputation: " + key['reputation'] + "\n"
            rtv_string += "\n"
            i += 1

        return rtv_string



## Debug functions

def __printTIE(reputations_dict):
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
