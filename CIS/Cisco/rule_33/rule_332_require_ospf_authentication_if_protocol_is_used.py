import pytest
from comfy.compliance import *

@low(
  name = rule_332_require_ospf_authentication_if_protocol_is_used,
  platform = ['cisco_ios']
)
def rule_332_require_ospf_authentication_if_protocol_is_used(configuration,commands,device):
    assert '' in configuration  

#Remediation: 

#References: 
