import pytest
from comfy.compliance import *

@medium(
  name = 'rule_225_set_logging_trap_informational',
  platform = ['cisco_ios'],
  commands=dict(check_command='sh log | incl trap logging')
)
def rule_225_set_logging_trap_informational(configuration, commands, device):
    assert f' trap logging' in commands.check_command

# Remediation: hostname(config)#logging trap informational  

# References: 1.http://www.cisco.com/en/US/docs/ios/netmgmt/command/reference/nm_09.html#
