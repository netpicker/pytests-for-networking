import pytest
from comfy.compliance import *

@low(
  name = 'rule_3315_set_af_interface_default',
  platform = ['cisco_ios'],
  commands=dict(check_command='hostname#sh run | sec router eigrp')
)
def rule_3315_set_af_interface_default(configuration, commands, device):
    assert ' router eigrp' in configuration

# Remediation: hostname(config)#router eigrp <<em>virtual-instance-name</em>>  

# References: 3.http://www.cisco.com/en/US/docs/ios-xml/ios/iproute_eigrp/command/ire-a1.html#GUID-DC0EF1D3-DFD4-45DF-A553-FA432A3E7233
