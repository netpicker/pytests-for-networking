import pytest
from comfy.compliance import *

@low(
  name = 'rule_3316_set_authentication_key_chain',
  platform = ['cisco_ios'],
  commands=dict(check_command='sh run | sec router eigrp')
)
def rule_3316_set_authentication_key_chain(configuration, commands, device):
    assert f' router eigrp' in commands.check_command,"\n# Remediation: hostname(config)#router eigrp  <virtual-instance-name> \n# References: 3.http://www.cisco.com/en/US/docs/ios-xml/ios/iproute_eigrp/command/ire-a1.html#GUID-6B6ED6A3-1AAA-4EFA-B6B8-9BF11EEC37A0\n\n
