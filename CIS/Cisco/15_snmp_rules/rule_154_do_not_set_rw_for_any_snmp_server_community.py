import pytest
from comfy.compliance import *

@medium(
  name = 'rule_154_do_not_set_rw_for_any_snmp_server_community',
  platform = ['cisco_ios']
)
def rule_154_do_not_set_rw_for_any_snmp_server_community(configuration, commands, device):
    assert 'snmp-server community' in configuration,"\n# Remediation: hostname(config)#no s nmp-server community {<em>write_community_string</em>}  \n# References: 1.http://www.cisco.com/en/US/docs/ios-xml/ios/snmp/command/nm-snmp-cr-s2.html#GUID-2F3F13E4-EE81-4590-871D-6AE1043473DE\n\n
