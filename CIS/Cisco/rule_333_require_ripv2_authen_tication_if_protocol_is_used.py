
import pytest
from comfy.compliance import Source, low

@low(
  name = rule_333_require_ripv2_authen_tication_if_protocol_is_used,
  platform = ['cisco_ios']
)
def rule_333_require_ripv2_authen_tication_if_protocol_is_used(configuration,commands,device):
    assert '' in configuration  

#Remediation: 

#References: 
