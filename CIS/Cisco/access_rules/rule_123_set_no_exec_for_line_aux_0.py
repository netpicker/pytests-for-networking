import pytest
from comfy.compliance import *

@medium(
  name = 'rule_123_set_no_exec_for_line_aux_0',
  platform = ['cisco_ios'],
  commands=dict(check_command=hostname#show line aux 0 | incl exec)
)
def rule_123_set_no_exec_for_line_aux_0(configuration, commands, device):
    assert ' exec' in configuration

# Remediation: hostname(config)#line aux 0  

# References: 1.http://www.cisco.com/en/US/docs/ios-xml/ios/fundamentals/command/D_through_E.html#GUID-429A2B8C-FC26-49C4-94C4-0FD99C32EC34
