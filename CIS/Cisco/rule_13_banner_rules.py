
import pytest
from comfy.compliance import Source, low

@low(
  name = rule_13_banner_rules,
  platform = ['cisco_ios']
)
def rule_13_banner_rules(configuration,commands,device):
    assert '' in configuration  

#Remediation: 

#References: 
