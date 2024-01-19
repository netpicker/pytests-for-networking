import pytest
from comfy.compliance import *

@low(
  name = rule_12_access_rules,
  platform = ['cisco_ios']
)
def rule_12_access_rules(configuration,commands,device):
    assert '' in configuration  

#Remediation: 

#References: 
