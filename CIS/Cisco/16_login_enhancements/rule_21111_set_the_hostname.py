import pytest
from comfy.compliance import *

@medium(
  name = 'rule_21111_set_the_hostname',
  platform = ['cisco_ios']
)
def rule_21111_set_the_hostname(configuration, commands, device):
    assert 'hostname' in configuration,"\n# Remediation: hostname(config)#hostname {<em>router_name</em>}  \n# References: 1.http://www.cisco.com/en/US/docs/ios-xml/ios/fundamentals/command/F_through_K.html#GUID-F3349988-EC16-484A-BE81-4C40110E6625\n\n
