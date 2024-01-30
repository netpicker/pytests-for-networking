import pytest
from comfy.compliance import *

@low(
  name = 'rule_118_set_aaa_accounting_exec',
  platform = ['cisco_ios']
)
def rule_118_set_aaa_accounting_exec(configuration, commands, device):
    assert 'hostname#show running-config | incl aaa accounting exec' in configuration

# Remediation: hostname(config)#aaa accounting exec {default | list-name | guarantee-first}  

# References: 1.http://www.cisco.com/en/US/docs/ios-xml/ios/security/a1/sec-cr-a1.html#GUID-0520BCEF-89FB-4505-A5DF-D7F1389F1BBA
