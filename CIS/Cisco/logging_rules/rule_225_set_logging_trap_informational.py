import pytest
from comfy.compliance import *

@medium(
  name = 'rule_225_set_logging_trap_informational',
  platform = ['cisco_ios']
)
def rule_225_set_logging_trap_informational(configuration, commands, device):
    assert '' in configuration

# Remediation: hostname(config)#logging trap informational  

# References: 1. http://www.cisco.com/en/US/docs/ios/netmgmt/command/reference/nm_09.html#
