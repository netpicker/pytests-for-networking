
import pytest
from comfy.compliance import Source, low

@low(
  name = rule_241_create_a_single_interface_loopback,
  platform = ['cisco_ios']
)
def rule_241_create_a_single_interface_loopback(configuration,commands,device):
    assert '' in configuration  

#Remediation: hostname(config)#interface loopback <<em>number</em>>  

#References: 1. http://www. cisco.com/en/US/docs/ios -xml/ios/interface/command/ir -
