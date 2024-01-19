import pytest
from comfy.compliance import *

@low(
  name = rule_24_loopback_rules,
  platform = ['cisco_ios']
)
def rule_24_loopback_rules(configuration,commands,device):
    assert '' in configuration  

#Remediation: 

#References: 
