import pytest
from comfy.compliance import *

@medium(
  name = 'rule_153_unset_public_for_snmp_server_co_mmunity',
  platform = ['cisco_ios']
)
def rule_153_unset_public_for_snmp_server_co_mmunity(configuration, commands, device):
    assert '' in configuration

# Remediation: hostname(config)#no snmp-server communi ty {public}  

# References: 1. http://www.cisco.com/en/US/docs/ios-xml/ios/snmp/command/nm-snmp-cr-
