import pytest
from comfy.compliance import *

@medium(
  name = 'rule_124_create_access_list_for_use_with_line_v_ty',
  platform = ['cisco_ios'],
  commands=dict(check_command='sh ip access-list <vty_acl_number>')
)
def rule_124_create_access_list_for_use_with_line_v_ty(configuration, commands, device):
    assert f'hostname#sh ip access-list <vty_acl_number>' in commands.check_command

# Remediation: hostname(config)#deny ip any any log  

# References: 1.http://www.cisco.com/en/US/docs/ios-xml/ios/security/a1/sec-cr-a2.html#GUID-9EA733A3-1788-4882-B8C3-AB0A2949120C
