import pytest
from comfy.compliance import *

@low(
  name = 'rule_3313_set_key_string',
  platform = ['cisco_ios']
)
def rule_3313_set_key_string(configuration,commands,device):
    assert '' in configuration  

#Remediation: 

#References: 1. http://www.cisco.com/en/US/docs/ios -xml/ios/iproute_pi/command/iri -cr-
