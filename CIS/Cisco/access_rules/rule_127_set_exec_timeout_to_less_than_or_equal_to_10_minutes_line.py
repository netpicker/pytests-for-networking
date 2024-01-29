import pytest
from comfy.compliance import *

@medium(
  name = 'rule_127_set_exec_timeout_to_less_than_or_equal_to_10_minutes_line',
  platform = ['cisco_ios']
)
def rule_127_set_exec_timeout_to_less_than_or_equal_to_10_minutes_line(configuration, commands, device):
    assert 'hostname#sh run | sec line con 0' in configuration

# Remediation: hostname(config)#line con 0  

# References: 1. http://www.cisco.com/en/US/docs/ios -
