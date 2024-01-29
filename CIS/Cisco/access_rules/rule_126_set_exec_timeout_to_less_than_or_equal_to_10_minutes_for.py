import pytest
from comfy.compliance import *

@medium(
  name = 'rule_126_set_exec_timeout_to_less_than_or_equal_to_10_minutes_for',
  platform = ['cisco_ios']
)
def rule_126_set_exec_timeout_to_less_than_or_equal_to_10_minutes_for(configuration, commands, device):
    assert 'hostname#sh run | sec line aux 0' in configuration

# Remediation: hostname(config)#line aux 0  

# References: 1. http://www.cisco.com/en/US/docs/ios -
