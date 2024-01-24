import pytest
from comfy.compliance import *

@low(
  name = rule_161_configure_login_block_automated,
  platform = ['cisco_ios']
)
def rule_161_configure_login_block_automated(configuration,commands,device):
    assert 'login block' in configuration  

#Remediation: 

#References: 
