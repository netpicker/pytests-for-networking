import pytest
from comfy.compliance import *

@medium(
  name = 'rule_152_unset_private_for_snmp_server_c_ommunity',
  platform = ['cisco_ios']
)
def rule_152_unset_private_for_snmp_server_c_ommunity(configuration, commands, device):
    assert '' in configuration,"\n# Remediation: hostname(config)#no snmp-server community {private}  \n# References: 1.http://www.cisco.com/en/US/docs/ios-xml/ios/snmp/command/nm-snmp-cr-s2.html#GUID-2F3F13E4-EE81-4590-871D-6AE1043473DE\n\n"
