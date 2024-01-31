import pytest
from comfy.compliance import *

@low(
  name = 'rule_119_set_aaa_accounting_network',
  platform = ['cisco_ios']
)
def rule_119_set_aaa_accounting_network(configuration, commands, device):
    assert 'aaa accounting network' in configuration,"
# Remediation: hostname(config)#aaa accounting network {default | list-name | guarantee -
# References: 1.http://www.cisco.com/en/US/docs/ios-xml/ios/security/a1/sec-cr-a1.html#GUID-0520BCEF-89FB-4505-A5DF-D7F1389F1BBA


