import pytest
from comfy.compliance import *

@medium(
  name = 'rule_313_set_no_interface_tunnel',
  platform = ['cisco_ios'],
  commands=dict(check_command='sh ip int brief | incl tunnel')
)
def rule_313_set_no_interface_tunnel(configuration, commands, device):
    assert f' tunnel' in commands.check_command,"\n# Remediation: hostname(config)#no interface tunnel {<em>instance</em>}  \n# References: 1.http://www.cisco.com/en/US/docs/ios-xml/ios/interface/command/ir-i1.html#GUID-0D6BDFCD-3FBB-4D26-A274-C1221F8592DF\n\n
