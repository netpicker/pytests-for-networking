import pytest
from comfy.compliance import *

@low(
  name = 'rule_161_configure_login_block_automated',
  platform = ['cisco_ios']
)
def rule_161_configure_login_block_automated(configuration, commands, device):
    assert 'login block' in configuration

# Remediation: 

# References: 1.https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/sec_usr_cfg/configuration/xe-16-5/sec-usr-cfg-xe-16-5-book/sec-login-enhance.html
