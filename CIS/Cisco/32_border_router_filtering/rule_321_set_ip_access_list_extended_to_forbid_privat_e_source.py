import pytest
from comfy.compliance import *

@low(
  name = 'rule_321_set_ip_access_list_extended_to_forbid_privat_e_source',
  platform = ['cisco_ios'],
  commands=dict(check_command='sh ip access-list {<em>name | number</em>}')
)
def rule_321_set_ip_access_list_extended_to_forbid_privat_e_source(configuration, commands, device):
    assert f'hostname#sh ip access-list {<em>name | number</em>}' in commands.check_command,"\n# Remediation: hostname(config)#interface <external_<em>interface</em>>  \n# References: 1.http://www.cisco.com/en/US/docs/ios-xml/ios/security/d1/sec-cr-i1.html#GUID-BD76E065-8EAC-4B32-AF25-04BA94DD2B11\n\n
