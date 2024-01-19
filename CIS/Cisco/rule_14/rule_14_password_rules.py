import pytest
from comfy.compliance import *

@low(
  name = rule_14_password_rules,
  platform = ['cisco_ios']
)
def rule_14_password_rules(configuration,commands,device):
    assert '' in configuration  

#Remediation: 

#References: 
