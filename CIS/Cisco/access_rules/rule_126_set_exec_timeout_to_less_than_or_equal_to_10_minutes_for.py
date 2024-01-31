import pytest
from comfy.compliance import *

@medium(
  name = 'rule_126_set_exec_timeout_to_less_than_or_equal_to_10_minutes_for',
  platform = ['cisco_ios'],
  commands=dict(check_command='hostname#sh run | sec line aux 0')
)
def rule_126_set_exec_timeout_to_less_than_or_equal_to_10_minutes_for(configuration, commands, device):
    assert ' line aux 0' in configuration

# Remediation: hostname(config)#line aux 0  

# References: 1.http://www.cisco.com/en/US/docs/ios-xml/ios/fundamentals/command/D_through_E.html#GUID-76805E6F-9E89-4457-A9DC-5944C8FE5419
