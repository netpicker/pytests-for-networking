import pytest
from comfy.compliance import *

@low(
  name = 'rule_162_autosecure',
  platform = ['cisco_ios']
)
def rule_162_autosecure(configuration,commands,device):
    assert '' in configuration  

#Remediation: 

#References: 
