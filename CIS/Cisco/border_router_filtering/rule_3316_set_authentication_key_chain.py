import pytest
from comfy.compliance import *

@low(
  name = 'rule_3316_set_authentication_key_chain',
  platform = ['cisco_ios']
)
def rule_3316_set_authentication_key_chain(configuration, commands, device):
    assert '' in configuration

# Remediation: hostname(config)#router eigrp  <virtual-instance-name> 

# References: 3. http://www.cisco.com/en/US/docs/ios-xml/ios/ipro ute_eigrp/command/ire -
