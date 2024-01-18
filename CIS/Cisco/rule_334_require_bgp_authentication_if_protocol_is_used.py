
import pytest
from comfy.compliance import Source, low

@low(
  name = rule_334_require_bgp_authentication_if_protocol_is_used,
  platform = ['cisco_ios']
)
def rule_334_require_bgp_authentication_if_protocol_is_used(configuration,commands,device):
    assert '' in configuration  

#Remediation: 

#References: 
