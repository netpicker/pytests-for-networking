import pytest
from comfy.compliance import *

@low(
  name = 'rule_3314_set_address_family_ipv4_autonomous_system_',
  platform = ['cisco_ios'],
  commands=dict(check_command=hostname#sh run | sec router eigrp)
)
def rule_3314_set_address_family_ipv4_autonomous_system_(configuration, commands, device):
    assert ' router eigrp' in configuration

# Remediation: hostname(config)#router eigrp <<em>virtual-instance-name</em>>  

# References: 2.http://www.cisco.com/en/US/docs/ios-xml/ios/iproute_eigrp/command/ire-a1.html#GUID-C03CFC8A-3CE3-4CF9-9D65-52990DBD3377
