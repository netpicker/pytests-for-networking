import pytest
from comfy.compliance import *

@medium(
  name = 'rule_157_set_snmp_server_host_when_using_snmp',
  platform = ['cisco_ios']
)
def rule_157_set_snmp_server_host_when_using_snmp(configuration, commands, device):
    assert 'snmp-server' in configuration

# Remediation: hostname(config)#snmp-server host {ip_address} {trap_community_string} 

# References: 1. http://www.cisco.com/en/US/docs/ios-xml/ios/snmp/command/nm-snmp-cr-
