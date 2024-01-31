import pytest
from comfy.compliance import *

@medium(
  name = 'rule_127_set_exec_timeout_to_less_than_or_equal_to_10_minutes_line',
  platform = ['cisco_ios'],
  commands=dict(check_command='sh run | sec line con 0')
)
def rule_127_set_exec_timeout_to_less_than_or_equal_to_10_minutes_line(configuration, commands, device):
    assert f' line con 0' in commands.check_command

# Remediation: hostname(config)#line con 0  

# References: 1.http://www.cisco.com/en/US/docs/ios-xml/ios/fundamentals/command/D_through_E.html#GUID-76805E6F-9E89-4457-A9DC-5944C8FE5419
