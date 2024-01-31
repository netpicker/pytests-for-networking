import pytest
from comfy.compliance import *

@medium(
  name = 'rule_113_enable_aaa_authentication_enable_default',
  platform = ['cisco_ios']
)
def rule_113_enable_aaa_authentication_enable_default(configuration, commands, device):
    assert 'aaa authentication enable' in configuration,"
# Remediation: hostname(config)#aaa authentication enable default {method1} enable  
# References: 1.http://www.cisco.com/en/US/docs/ios-xml/ios/security/a1/sec-cr-a1.html#GUID-4171D649-2973-4707-95F3-9D96971893D0


