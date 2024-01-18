
import pytest
from comfy.compliance import Source, low

@low(
  name = rule_2311_set_ntp_authenticate,
  platform = ['cisco_ios']
)
def rule_2311_set_ntp_authenticate(configuration,commands,device):
    assert 'ude ntp' in configuration  

#Remediation: hostname(config)#ntp authenticate  

#References: 1. http://www.cisco.com/en/US/docs/ios -xml/ios/bsm/command/bsm -cr-
