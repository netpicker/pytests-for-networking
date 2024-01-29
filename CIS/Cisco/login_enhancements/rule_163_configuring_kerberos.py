import pytest
from comfy.compliance import *

@low(
  name = 'rule_163_configuring_kerberos',
  platform = ['cisco_ios']
)
def rule_163_configuring_kerberos(configuration, commands, device):
    assert '' in configuration

# Remediation: 

# References: 1. https://www.cisco.com/c/en/u s/td/docs/ios -xml/ios/sec_usr_cfg/configuration/xe -
