import pytest
from comfy.compliance import *

@medium(
  name = 'rule_156_create_an_access_list_for_use_with_snmp',
  platform = ['cisco_ios']
)
def rule_156_create_an_access_list_for_use_with_snmp(configuration, commands, device):
    assert 'hostname#sh ip access-list <<em>snmp_acl_number</em>>' in configuration

# Remediation: hostname(config)#access-list deny any log  

# References: 1. http://www.cisco.com/en/US/docs/ios-xml/ios/secu rity/a1/sec-cr-a2.html#GUID -
