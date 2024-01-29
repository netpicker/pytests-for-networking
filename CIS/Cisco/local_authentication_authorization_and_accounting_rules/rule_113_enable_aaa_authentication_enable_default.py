import pytest
from comfy.compliance import *

@medium(
  name = 'rule_113_enable_aaa_authentication_enable_default',
  platform = ['cisco_ios']
)
def rule_113_enable_aaa_authentication_enable_default(configuration, commands, device):
    assert 'hostname#show running-config | incl aaa authentication enable' in configuration

# Remediation: hostname(config)#aaa authentication enable default {method1} enable  

# References: 1. http://www.cisco.com/en/US/docs/ios-xml/ios/security/a 1/sec-cr-a1.html#GUID -
