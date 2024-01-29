import pytest
from comfy.compliance import *

@low(
  name = 'rule_3314_set_address_family_ipv4_autonomous_system_',
  platform = ['cisco_ios']
)
def rule_3314_set_address_family_ipv4_autonomous_system_(configuration, commands, device):
    assert '' in configuration

# Remediation: hostname(config)#router eigrp <<em>virtual-instance-name</em>>  

# References: 2. http://www.cisco.com/en/US/docs/ios-xml/ios/iproute_eigrp/command/ire -
