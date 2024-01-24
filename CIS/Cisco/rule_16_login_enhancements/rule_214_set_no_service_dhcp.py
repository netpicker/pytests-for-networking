import pytest
from comfy.compliance import *

@medium(
  name = rule_214_set_no_service_dhcp,
  platform = ['cisco_ios']
)
def rule_214_set_no_service_dhcp(configuration,commands,device):
    assert 'dhcp' in configuration  

#Remediation: hostname(config)#<strong>no service dhcp</strong>  

#References: 1. http://www.cisco.c om/en/US/docs/ios -xml/ios/ipaddr/command/ipaddr -
