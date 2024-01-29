import pytest
from comfy.compliance import *

@low(
  name = 'rule_1110_set_aaa_accounting_system',
  platform = ['cisco_ios']
)
def rule_1110_set_aaa_accounting_system(configuration, commands, device):
    assert 'aaa accounting system' in configuration

# Remediation: hostname(config)#aaa accounting system {default | list -name | guarantee -

# References: 1. http://www.cisco.com/en/US/docs/ios -xml/ios/security/a1/sec -cr-a1.html#GUID -
