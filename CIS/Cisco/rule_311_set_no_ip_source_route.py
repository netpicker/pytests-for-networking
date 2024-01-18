
import pytest
from comfy.compliance import Source, medium

@medium(
  name = rule_311_set_no_ip_source_route,
  platform = ['cisco_ios']
)
def rule_311_set_no_ip_source_route(configuration,commands,device):
    assert '' in configuration  

#Remediation: hostname(config)#no ip source -route 

#References: 1. http://www.cisco.com/en/US/docs/ios -xml/ios/ipaddr/command/ipaddr -
