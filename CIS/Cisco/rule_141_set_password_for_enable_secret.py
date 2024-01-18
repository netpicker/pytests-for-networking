
import pytest
from comfy.compliance import Source, medium

@medium(
  name = rule_141_set_password_for_enable_secret,
  platform = ['cisco_ios']
)
def rule_141_set_password_for_enable_secret(configuration,commands,device):
    assert '' in configuration  

#Remediation: hostname(config)#enable secret 9 {ENABLE_SECRET_PASSWORD}  

#References: 
