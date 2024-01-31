import pytest
from comfy.compliance import *

@low(
  name = 'rule_159_set_priv_for_each_snmp_server_group_using_snmpv3',
  platform = ['cisco_ios'],
  commands=dict(check_command='show snmp group')
)
def rule_159_set_priv_for_each_snmp_server_group_using_snmpv3(configuration, commands, device):
    assert f'hostname#show snmp group' in commands.check_command,"\n# Remediation: hostname(config)#snmp-server group {<em>group_name</em>} v3 priv  \n# References: 1.http://www.cisco.com/en/US/docs/ios-xml/ios/snmp/command/nm-snmp-cr-s5.html#GUID-56E87D02-C56F-4E2D-A5C8-617E31740C3F\n\n"
