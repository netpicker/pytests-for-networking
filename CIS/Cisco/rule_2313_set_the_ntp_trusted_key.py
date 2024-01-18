
import pytest
from comfy.compliance import Source, low

@low(
  name = rule_2313_set_the_ntp_trusted_key,
  platform = ['cisco_ios']
)
def rule_2313_set_the_ntp_trusted_key(configuration,commands,device):
    assert 'ude ntp trusted -key' in configuration  

#Remediation: 

#References: 1. http://www.cisco.com/en/US/docs/ios -xml/ios/bsm/command/bsm -cr-
