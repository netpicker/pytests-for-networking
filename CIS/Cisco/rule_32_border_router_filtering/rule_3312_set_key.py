import pytest
from comfy.compliance import *

@low(
  name = 'rule_3312_set_key',
  platform = ['cisco_ios']
)
def rule_3312_set_key(configuration,commands,device):
    assert '' in configuration  

#Remediation: 

#References: 1. http://www.cisco.com/en/US/docs/ios -xml/ios/iproute_pi/command/iri -cr-
