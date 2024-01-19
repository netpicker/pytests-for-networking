import pytest
from comfy.compliance import *

@low(
  name = rule_15_snmp_rules,
  platform = ['cisco_ios']
)
def rule_15_snmp_rules(configuration,commands,device):
    assert '' in configuration  

#Remediation: 

#References: 
