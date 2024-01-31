import pytest
from comfy.compliance import *

@low(
  name = 'rule_241_create_a_single_interface_loopback',
  platform = ['cisco_ios'],
  commands=dict(check_command='hostname#sh ip int brief | incl Loopback')
)
def rule_241_create_a_single_interface_loopback(configuration, commands, device):
    assert ' Loopback' in configuration

# Remediation: hostname(config)#interface loopback <<em>number</em>>  

# References: 1.http://www.cisco.com/en/US/docs/ios-xml/ios/interface/command/ir-i1.html#GUID-0D6BDFCD-3FBB-4D26-A274-C1221F8592DF
