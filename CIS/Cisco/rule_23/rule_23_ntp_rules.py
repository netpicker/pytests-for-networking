import pytest
from comfy.compliance import *

@low(
  name = rule_23_ntp_rules,
  platform = ['cisco_ios']
)
def rule_23_ntp_rules(configuration,commands,device):
    assert '' in configuration  

#Remediation: 

#References: 
