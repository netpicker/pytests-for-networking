import pytest
from comfy.compliance import *

@medium(
  name = 'rule_21112_set_the_ip_domain_name',
  platform = ['cisco_ios']
)
def rule_21112_set_the_ip_domain_name(configuration, commands, device):
    assert '' in configuration

# Remediation: 

# References: 1. http://www.cisco.com/en/US/docs/ios -xml/ios/ipaddr/command/ipaddr -
