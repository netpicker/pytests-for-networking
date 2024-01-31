import pytest
from comfy.compliance import *

@medium(
  name = 'rule_122_set_transport_input_ssh_for_line_vty_connections',
  platform = ['cisco_ios'],
  commands=dict(check_command='hostname#show running-config | sec vty')
)
def rule_122_set_transport_input_ssh_for_line_vty_connections(configuration, commands, device):
    assert ' vty' in configuration

# Remediation: hostname(config)#line vty <line-number> <ending-line-number> 

# References: 1.http://www.cisco.com/en/US/docs/ios/termserv/command/reference/tsv_s1.html#
