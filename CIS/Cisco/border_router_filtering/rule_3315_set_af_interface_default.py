import pytest
from comfy.compliance import *

@low(
  name = 'rule_3315_set_af_interface_default',
  platform = ['cisco_ios']
)
def rule_3315_set_af_interface_default(configuration, commands, device):
    assert '' in configuration

# Remediation: hostname(config)#router eigrp <<em>virtual -instance -name</em>>  

# References: 3. http://www.cisco.com/en/US/docs/ios -xml/ios/iproute_eigrp/command/ire -
