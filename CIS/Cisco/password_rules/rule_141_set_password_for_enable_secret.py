import pytest
from comfy.compliance import *

@medium(
  name = 'rule_141_set_password_for_enable_secret',
  platform = ['cisco_ios']
)
def rule_141_set_password_for_enable_secret(configuration, commands, device):
    assert 'hostname#sh run | incl enable secret' in configuration

# Remediation: hostname(config)#enable secret 9 {ENABLE_SECRET_PASSWORD}  

# References: 1.https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9600/software/releas