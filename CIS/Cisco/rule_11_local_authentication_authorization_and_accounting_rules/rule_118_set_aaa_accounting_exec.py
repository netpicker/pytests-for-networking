import pytest
from comfy.compliance import *

@low(
  name = rule_118_set_aaa_accounting_exec,
  platform = ['cisco_ios']
)
def rule_118_set_aaa_accounting_exec(configuration,commands,device):
    assert 'aaa accounting exec' in configuration  

#Remediation: hostname(config)#aaa accounting exec {default | list -name | guarantee -first}  

#References: 1. http://www.cisco.com/en/US/docs/ios -xml/ios/security/a1/sec -cr-a1.html#GUID -
