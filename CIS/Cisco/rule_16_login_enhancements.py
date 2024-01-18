
import pytest
from comfy.compliance import Source, low

@low(
  name = rule_16_login_enhancements,
  platform = ['cisco_ios']
)
def rule_16_login_enhancements(configuration,commands,device):
    assert '' in configuration  

#Remediation: 

#References: 
