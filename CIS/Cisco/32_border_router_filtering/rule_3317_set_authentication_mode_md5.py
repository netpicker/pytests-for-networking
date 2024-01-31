import pytest
from comfy.compliance import *

@medium(
  name = 'rule_3317_set_authentication_mode_md5',
  platform = ['cisco_ios'],
  commands=dict(check_command='sh run | sec router eigrp')
)
def rule_3317_set_authentication_mode_md5(configuration, commands, device):
    assert f' router eigrp' in commands.check_command,"\n# Remediation: hostname(config)#router eigrp <virtual-instance-name> \n# References: 3.http://www.cisco.com/en/US/docs/ios-xml/ios/iproute_eigrp/command/ire-a1.html#GUID-A29E0EF6-4CEF-40A7-9824-367939001B73\n\n
