import pytest
from comfy.compliance import *

@low(
  name = 'rule_322_set_inbound_ip_access_group_on_the_external_interface',
  platform = ['cisco_ios']
)
def rule_322_set_inbound_ip_access_group_on_the_external_interface(configuration, commands, device):
    assert '' in configuration

# Remediation: hostname(config)#interface {external_interface}  

# References: 2. http://www.cisco.com/en/US/docs/ios-xml/ios/security/d1/sec-cr-i1.html#GUID -
