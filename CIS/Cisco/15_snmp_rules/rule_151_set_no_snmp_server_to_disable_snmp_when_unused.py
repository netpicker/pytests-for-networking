import pytest
from comfy.compliance import *

@medium(
  name = 'rule_151_set_no_snmp_server_to_disable_snmp_when_unused',
  platform = ['cisco_ios'],
  commands=dict(check_command='show snmp community')
)
def rule_151_set_no_snmp_server_to_disable_snmp_when_unused(configuration, commands, device):
    assert f'hostname#show snmp community' in commands.check_command,"\n# Remediation: hostname(config)#no snmp-server  \n# References: 1.http://www.cisco.com/en/US/docs/ios-xml/ios/snmp/command/nm-snmp-cr-book.html\n\n
