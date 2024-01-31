import pytest
from comfy.compliance import *

@low(
  name = 'rule_1510_require_aes_128_as_minimum_for_snmp_server_user_when',
  platform = ['cisco_ios'],
  commands=dict(check_command='show snmp user')
)
def rule_1510_require_aes_128_as_minimum_for_snmp_server_user_when(configuration, commands, device):
    assert 'hostname#show snmp user' in configuration

# Remediation: hostname(config)#snmp-server user {user_name} {group_name} v3 auth sha 

# References: 1.http://www.cisco.com/en/US/docs/ios-xml/ios/snmp/command/nm-snmp-cr-s5.html#GUID-4EED4031-E723-4B84-9BBF-610C3CF60E31
