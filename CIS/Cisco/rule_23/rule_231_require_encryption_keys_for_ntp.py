import pytest
from comfy.compliance import *

@low(
  name = rule_231_require_encryption_keys_for_ntp,
  platform = ['cisco_ios']
)
def rule_231_require_encryption_keys_for_ntp(configuration,commands,device):
    assert '' in configuration  

#Remediation: 

#References: 
