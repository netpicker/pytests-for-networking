import pytest
from comfy.compliance import *

@medium(
  name = 'rule_313_set_no_interface_tunnel',
  platform = ['cisco_ios']
)
def rule_313_set_no_interface_tunnel(configuration, commands, device):
    assert 'hostname#sh ip int brief | incl tunnel' in configuration

# Remediation: hostname(config)#no interface tunnel {<em>instance</em>}  

# References: 1. http://ww w.cisco.com/en/US/docs/ios-xml/ios/interface/command/ir -
