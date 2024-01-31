import pytest
from comfy.compliance import *

@medium(
  name = 'rule_156_create_an_access_list_for_use_with_snmp',
  platform = ['cisco_ios'],
  commands=dict(check_command='sh ip access-list <<em>snmp_acl_number</em>>')
)
def rule_156_create_an_access_list_for_use_with_snmp(configuration, commands, device):
    assert f'hostname#sh ip access-list <<em>snmp_acl_number</em>>' in commands.check_command

# Remediation: hostname(config)#access-list deny any log  

# References: 1.http://www.cisco.com/en/US/docs/ios-xml/ios/security/a1/sec-cr-a2.html#GUID-9EA733A3-1788-4882-B8C3-AB0A2949120C
