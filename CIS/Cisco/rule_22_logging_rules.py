
import pytest
from comfy.compliance import Source, low

@low(
  name = rule_22_logging_rules,
  platform = ['cisco_ios']
)
def rule_22_logging_rules(configuration,commands,device):
    assert '' in configuration  

#Remediation: 

#References: 
