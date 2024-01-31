import pytest
from comfy.compliance import *

@low(
  name = 'rule_117_set_aaa_accounting_connection',
  platform = ['cisco_ios']
)
def rule_117_set_aaa_accounting_connection(configuration, commands, device):
    assert 'aaa accounting connection' in configuration,"\n# Remediation: hostname(config)#aaa accounting connection {default | list-name | guarantee -\n# References: 1.http://www.cisco.com/en/US/docs/ios-xml/ios/security/a1/sec-cr-a1.html#GUID-0520BCEF-89FB-4505-A5DF-D7F1389F1BBA\n\n
