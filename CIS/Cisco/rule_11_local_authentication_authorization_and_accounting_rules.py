
import pytest
from comfy.compliance import Source, low

@low(
  name = rule_11_local_authentication_authorization_and_accounting_rules,
  platform = ['cisco_ios']
)
def rule_11_local_authentication_authorization_and_accounting_rules(configuration,commands,device):
    assert '' in configuration  

#Remediation: 

#References: 
