import pytest
from comfy.compliance import *

@low(
  name = rule_117_set_aaa_accounting_connection,
  platform = ['cisco_ios']
)
def rule_117_set_aaa_accounting_connection(configuration,commands,device):
    assert 'aaa accounting connection' in configuration  

#Remediation: hostname(config)#aaa accounting connection {default | list -name | guarantee -

#References: 1. http://www.cisco.com/en/US/docs/ios -xml/ios/security/a1/sec -cr-a1.html#GUID -
