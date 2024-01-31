import pytest
from comfy.compliance import *

@low(
  name = 'rule_3319_set_ip_authentication_mode_eigrp',
  platform = ['cisco_ios'],
  commands=dict(check_command='sh run int {<em>interface_name</em>} | incl authentication mode')
)
def rule_3319_set_ip_authentication_mode_eigrp(configuration, commands, device):
    assert f' authentication mode' in commands.check_command,"
# Remediation: hostname(config)#interface {<em>interface_name</em>}  
# References: 2.http://www.cisco.com/en/US/docs/ios-xml/ios/iproute_eigrp/command/ire-i1.html#GUID-8D1B0697-8E96-4D8A-BD20-536956D68506


