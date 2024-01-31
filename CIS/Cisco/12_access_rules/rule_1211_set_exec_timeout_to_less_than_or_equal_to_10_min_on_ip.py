import pytest
from comfy.compliance import *

@medium(
  name = 'rule_1211_set_exec_timeout_to_less_than_or_equal_to_10_min_on_ip',
  platform = ['cisco_ios']
)
def rule_1211_set_exec_timeout_to_less_than_or_equal_to_10_min_on_ip(configuration, commands, device):
    assert '' in configuration,"\n# Remediation: \n# References: 1.http://www.cisco.com/en/US/docs/ios-xml/ios/fundamentals/command/D_through_E.html#GUID-76805E6F-9E89-4457-A9DC-5944C8FE5419\n\n"
