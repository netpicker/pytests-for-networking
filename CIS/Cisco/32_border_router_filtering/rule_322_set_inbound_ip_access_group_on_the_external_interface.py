import pytest
from comfy.compliance import *

@low(
  name = 'rule_322_set_inbound_ip_access_group_on_the_external_interface',
  platform = ['cisco_ios'],
  commands=dict(check_command='sh run | sec interface {<em>external_interface</em>}')
)
def rule_322_set_inbound_ip_access_group_on_the_external_interface(configuration, commands, device):
    assert f' interface {<em>external_interface</em>}' in commands.check_command,"\n# Remediation: hostname(config)#interface {external_interface}  \n# References: 2.http://www.cisco.com/en/US/docs/ios-xml/ios/security/d1/sec-cr-i1.html#GUID-D9FE7E44-7831-4C64-ACB8-840811A0C993\n\n"
